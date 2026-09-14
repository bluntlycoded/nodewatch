"""
Slack OAuth for alert channels - replaces manually pasting an incoming
webhook URL with a real "Connect Slack" flow. Same shape as
api/github_app.py: a short-lived signed state token stands in for auth on
the callback, since Slack redirects the browser there directly.

The `incoming-webhook` OAuth scope is what makes this simple: Slack's
token exchange hands back an `incoming_webhook.url` scoped to whichever
channel the admin picked during authorization, which is exactly the
config shape alert_channels already uses for a manually-entered Slack
webhook (kind='slack', config={url: ...}) - this never adds a new channel
kind or a new table, it only automates how that one field gets filled in.
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import RedirectResponse

router = APIRouter()

JWT_SECRET = os.environ.get("NW_JWT_SECRET", "dev-secret-change-me")
SUPABASE_JWT_SECRET = os.environ.get("NW_SUPABASE_JWT_SECRET", "")

SLACK_CLIENT_ID = os.environ.get("NW_SLACK_CLIENT_ID", "")
SLACK_CLIENT_SECRET = os.environ.get("NW_SLACK_CLIENT_SECRET", "")
NW_API_URL = os.environ.get("NW_API_URL", "")
DASHBOARD_URL = os.environ.get("NW_DASHBOARD_URL", "https://example.github.io/nodewatch/")


def require_admin(conn, authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing bearer token")
    if not SUPABASE_JWT_SECRET:
        raise HTTPException(500, "NW_SUPABASE_JWT_SECRET is not configured")
    try:
        claims = jwt.decode(authorization[7:], SUPABASE_JWT_SECRET,
                             algorithms=["HS256"], audience="authenticated")
    except jwt.InvalidTokenError as e:
        raise HTTPException(401, f"invalid session: {e}")
    row = conn.execute("select role from profiles where id = %s",
                        (claims["sub"],)).fetchone()
    if not row or row[0] != "admin":
        raise HTTPException(403, "admin role required")
    return claims["sub"]


def _state_token() -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"typ": "slack_oauth_state", "iat": now,
                        "exp": now + timedelta(minutes=10)},
                       JWT_SECRET, algorithm="HS256")


def _verify_state(state: str | None):
    if not state:
        raise HTTPException(400, "missing state")
    try:
        claims = jwt.decode(state, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(400, "invalid or expired state - start the connection again")
    if claims.get("typ") != "slack_oauth_state":
        raise HTTPException(400, "invalid state")


def install(app, pool):
    """Call once from app.py: install(app, pool)."""

    @router.get("/oauth/slack/start")
    def start(authorization: str | None = Header(default=None)):
        with pool.connection() as conn:
            require_admin(conn, authorization)
        if not SLACK_CLIENT_ID or not NW_API_URL:
            raise HTTPException(500, "NW_SLACK_CLIENT_ID / NW_API_URL is not configured")
        params = urllib.parse.urlencode({
            "client_id": SLACK_CLIENT_ID,
            "scope": "incoming-webhook",
            "redirect_uri": f"{NW_API_URL}/oauth/slack/callback",
            "state": _state_token(),
        })
        return {"url": f"https://slack.com/oauth/v2/authorize?{params}"}

    @router.get("/oauth/slack/callback")
    def callback(code: str | None = None, state: str | None = None,
                 error: str | None = None):
        _verify_state(state)
        if error or not code:
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?slack=cancelled")

        body = urllib.parse.urlencode({
            "client_id": SLACK_CLIENT_ID,
            "client_secret": SLACK_CLIENT_SECRET,
            "code": code,
            "redirect_uri": f"{NW_API_URL}/oauth/slack/callback",
        }).encode()
        req = urllib.request.Request("https://slack.com/api/oauth.v2.access",
                                      data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                token_res = json.loads(r.read())
        except urllib.error.HTTPError:
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?slack=error")

        if not token_res.get("ok"):
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?slack=error")

        hook = token_res.get("incoming_webhook") or {}
        team = token_res.get("team") or {}
        label = f"{team.get('name', 'Slack')} → #{hook.get('channel', '?')}"

        with pool.connection() as conn:
            conn.execute(
                """insert into alert_channels (kind, label, config, enabled)
                   values ('slack', %s, %s, true)""",
                (label, json.dumps({"url": hook.get("url")})),
            )
        return RedirectResponse(f"{DASHBOARD_URL}#/settings?slack=connected")

    app.include_router(router)
