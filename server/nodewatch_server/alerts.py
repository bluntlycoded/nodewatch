"""
Alert delivery - the master's replacement for the send-alerts Edge
Function, whose source was never in this repository.

The contract is the one the database already defines: triggers call
queue_alert(), which decides cooldown, muting and suppression and writes a
'pending' row to alert_log with its email recipients resolved. This module
claims pending rows (pending -> sending, so overlapping runs cannot double
send; requeue_stuck_alerts() recovers anything stranded), delivers to email
and every matching channel, and records each attempt in alert_deliveries.
"""

import json
import logging
import smtplib
import ssl
from email.message import EmailMessage

import psycopg
import requests
from psycopg.rows import dict_row

log = logging.getLogger("nodewatch.alerts")

RANK = {"info": 0, "warning": 1, "critical": 2}
HTTP_TIMEOUT = 15
BATCH = 50


class AlertSender:

    def __init__(self, db_url: str, smtp: dict | None, user_agent: str):
        self.db_url = db_url
        self.smtp = smtp or {}
        self.http = requests.Session()
        self.http.headers["User-Agent"] = user_agent

    # ------------------------------------------------------------ queue

    def drain(self) -> int:
        with psycopg.connect(self.db_url, autocommit=True, row_factory=dict_row) as conn:
            conn.execute("select requeue_stuck_alerts()")
            alerts = conn.execute(
                """
                update alert_log set status = 'sending'
                 where id in (select id from alert_log where status = 'pending'
                               order by id limit %s for update skip locked)
                returning id, agent_id, tenant_id, rule, severity, subject, body,
                          recipients, created_at
                """, (BATCH,)).fetchall()
            for a in alerts:
                try:
                    self._deliver(conn, a)
                except Exception as e:
                    # Marked failed rather than left in 'sending', where
                    # requeue_stuck_alerts() would resend it every 5 minutes.
                    log.exception("alert %s could not be processed", a["id"])
                    conn.execute("update alert_log set status = 'failed', error = %s where id = %s",
                                 (f"delivery error: {e}"[:1000], a["id"]))
        return len(alerts)

    def _deliver(self, conn, a: dict) -> None:
        channels = conn.execute(
            """
            select id, kind, config, min_severity from alert_channels
             where enabled
               and (agent_id = %s or agent_id is null)
               and tenant_id is not distinct from %s
            """, (a["agent_id"], a["tenant_id"])).fetchall()
        channels = [c for c in channels if RANK[a["severity"]] >= RANK.get(c["min_severity"], 1)]

        ok, errors = 0, []

        if a["recipients"]:
            sent, detail = self._email(a)
            conn.execute(
                "insert into alert_deliveries (alert_id, channel_id, kind, status, detail, tenant_id) "
                "values (%s, null, 'email', %s, %s, %s)",
                (a["id"], "sent" if sent else "failed", detail, a["tenant_id"]))
            ok += sent
            if not sent:
                errors.append(f"email: {detail}")

        for c in channels:
            status, detail = self._channel(c["kind"], c["config"] or {}, a)
            conn.execute(
                "insert into alert_deliveries (alert_id, channel_id, kind, status, detail, tenant_id) "
                "values (%s, %s, %s, %s, %s, %s)",
                (a["id"], c["id"], c["kind"], status, detail, a["tenant_id"]))
            if status == "sent":
                ok += 1
                conn.execute("update alert_channels set last_ok_at = now() where id = %s", (c["id"],))
            elif status == "failed":
                errors.append(f"{c['kind']}: {detail}")
                conn.execute("update alert_channels set last_error = %s, last_error_at = now() "
                             "where id = %s", (detail, c["id"]))

        if ok:
            conn.execute("update alert_log set status = 'sent', sent_at = now(), error = %s where id = %s",
                         ("; ".join(errors)[:1000] or None, a["id"]))
        else:
            conn.execute("update alert_log set status = 'failed', error = %s where id = %s",
                         ("; ".join(errors)[:1000] or "no destination accepted the alert", a["id"]))
        log.info("alert %s [%s] %s -> %d delivered, %d failed",
                 a["id"], a["severity"], a["rule"], ok, len(errors))

    # ------------------------------------------------------------ email

    def _email(self, a: dict) -> tuple[bool, str]:
        s = self.smtp
        if not s.get("host"):
            return False, "email is not configured on this master (SMTP)"
        msg = EmailMessage()
        msg["Subject"] = a["subject"]
        msg["From"] = s.get("from") or s.get("username")
        msg["To"] = ", ".join(a["recipients"])
        msg.set_content(a["body"] or a["subject"])
        port = int(s.get("port") or 587)
        try:
            if s.get("security") == "ssl" or port == 465:
                server = smtplib.SMTP_SSL(s["host"], port, timeout=HTTP_TIMEOUT,
                                          context=ssl.create_default_context())
            else:
                server = smtplib.SMTP(s["host"], port, timeout=HTTP_TIMEOUT)
                if s.get("security", "starttls") == "starttls":
                    server.starttls(context=ssl.create_default_context())
            with server:
                if s.get("username"):
                    server.login(s["username"], s.get("password", ""))
                server.send_message(msg)
            return True, f"{len(a['recipients'])} recipient(s)"
        except Exception as e:
            return False, str(e)[:300]

    # ------------------------------------------------------------ channels

    def _channel(self, kind: str, cfg: dict, a: dict) -> tuple[str, str]:
        text = f"{a['subject']}\n\n{a['body'] or ''}".strip()
        try:
            if kind == "telegram":
                r = self.http.post(f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                                   json={"chat_id": cfg["chat_id"], "text": text[:4000]},
                                   timeout=HTTP_TIMEOUT)
            elif kind == "slack":
                r = self.http.post(cfg["url"], json={"text": text[:3000]}, timeout=HTTP_TIMEOUT)
            elif kind == "webhook":
                r = self.http.post(cfg["url"], timeout=HTTP_TIMEOUT, json={
                    "id": a["id"], "rule": a["rule"], "severity": a["severity"],
                    "subject": a["subject"], "body": a["body"],
                    "agent_id": str(a["agent_id"]) if a["agent_id"] else None,
                    "created_at": a["created_at"].isoformat(),
                })
            elif kind == "teams":
                return self._teams(cfg, text)
            elif kind == "botim":
                return self._botim(cfg, a, text)
            else:
                return "skipped", f"unknown channel kind {kind}"
        except KeyError as e:
            return "failed", f"channel config is missing {e}"
        except requests.RequestException as e:
            return "failed", str(e)[:300]
        except Exception as e:
            # One broken channel must not fail the alert for the others,
            # nor discard the deliveries already recorded.
            log.exception("channel %s failed", kind)
            return "failed", f"{type(e).__name__}: {e}"[:300]
        if r.status_code >= 300:
            return "failed", f"HTTP {r.status_code}: {r.text[:200]}"
        return "sent", f"HTTP {r.status_code}"

    def _botim(self, cfg: dict, a: dict, text: str) -> tuple[str, str]:
        """
        Botim's Official Account API is documented only behind a Botim
        developer login, so its request body is not hard-coded here: the
        admin pastes the JSON body from their OA console into the channel's
        `body` field, with {text}, {subject}, {severity}, {target} and
        {app_id} where the alert's values go. The token is sent as a Bearer
        token. Without a template the delivery is recorded as skipped with
        the reason, rather than posting a guessed shape.
        """
        template = (cfg.get("body") or "").strip()
        if not template:
            return "skipped", "set the request body template from your Botim OA console on this channel"
        try:
            body = json.loads(template)
        except ValueError as e:
            return "failed", f"body template is not valid JSON: {e}"
        values = {"text": text[:4000], "subject": a["subject"], "severity": a["severity"],
                  "target": cfg.get("target", ""), "app_id": cfg.get("app_id", "")}
        body = _fill(body, values)
        headers = {"Authorization": f"Bearer {cfg['token']}"} if cfg.get("token") else {}
        r = self.http.post(cfg["url"], json=body, headers=headers, timeout=HTTP_TIMEOUT)
        if r.status_code >= 300:
            return "failed", f"HTTP {r.status_code}: {r.text[:200]}"
        return "sent", f"HTTP {r.status_code}"

    def _teams(self, cfg: dict, text: str) -> tuple[str, str]:
        import teams_app
        if not teams_app.TEAMS_CLIENT_ID:
            return "failed", "Teams app credentials are not configured on this master"
        try:
            token = teams_app._fresh_access_token(cfg["refresh_token"], cfg["tenant_id"])
        except Exception as e:
            return "failed", f"token refresh failed: {getattr(e, 'detail', e)}"[:300]
        r = self.http.post(
            f"{teams_app.GRAPH}/teams/{cfg['team_id']}/channels/{cfg['channel_id']}/messages",
            headers={"Authorization": f"Bearer {token}"},
            json={"body": {"contentType": "text", "content": text[:4000]}},
            timeout=HTTP_TIMEOUT)
        if r.status_code >= 300:
            return "failed", f"HTTP {r.status_code}: {r.text[:200]}"
        return "sent", f"HTTP {r.status_code}"


def _fill(node, values: dict):
    """Substitute {placeholders} inside the string values of parsed JSON, so
    alert text can never break the template's JSON structure."""
    if isinstance(node, dict):
        return {k: _fill(v, values) for k, v in node.items()}
    if isinstance(node, list):
        return [_fill(v, values) for v in node]
    if isinstance(node, str):
        for k, v in values.items():
            node = node.replace("{" + k + "}", str(v))
        return node
    return node
