"""
Microsoft Teams OAuth for alert channels.

Unlike Slack, Teams has no OAuth scope that hands back a post-to-this-URL
webhook - Microsoft deprecated that model (Office 365 Connectors), so
this uses the Microsoft identity platform's authorization code flow
against Microsoft Graph instead. Two differences from api/slack_app.py
and api/github_app.py follow directly from that:

1. The grant isn't scoped to one channel the way Slack's is, so the admin
   picks a team and then a channel in a second step after the OAuth
   redirect returns - /teams/list-teams and /teams/list-channels, called
   from the dashboard's own session, not from GitHub/Slack/Microsoft
   redirecting the browser.
2. Posting needs a live access token, refreshed from a long-lived refresh
   token (offline_access scope) rather than a token that just works
   forever. /teams/finalize is what actually gets stored in
   alert_channels.config; send-alerts (the Edge Function that delivers
   alerts, not in this repository) needs updating to refresh a Teams
   channel's token and call Graph's /teams/{id}/channels/{id}/messages
   before this channel kind can actually deliver anything - connecting
   an account is necessary but not sufficient on its own.

Whether ChannelMessage.Send needs a tenant admin's consent (rather than
the connecting user's own delegated consent) depends on the tenant's
Enterprise Applications consent policy - verify against the actual
Entra ID app registration and tenant before assuming a non-admin user can
complete this flow unassisted.
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
from psycopg.rows import dict_row
from pydantic import BaseModel

router = APIRouter()

JWT_SECRET = os.environ.get("NW_JWT_SECRET", "dev-secret-change-me")
SUPABASE_JWT_SECRET = os.environ.get("NW_SUPABASE_JWT_SECRET", "")

TEAMS_CLIENT_ID = os.environ.get("NW_TEAMS_CLIENT_ID", "")
TEAMS_CLIENT_SECRET = os.environ.get("NW_TEAMS_CLIENT_SECRET", "")
# 'organizations' works for any single-tenant admin consent setup; set to
# a specific tenant id if the App registration restricts sign-in to one.
TEAMS_TENANT_ID = os.environ.get("NW_TEAMS_TENANT_ID", "organizations")
NW_API_URL = os.environ.get("NW_API_URL", "")
DASHBOARD_URL = os.environ.get("NW_DASHBOARD_URL", "https://example.github.io/nodewatch/")

GRAPH = "https://graph.microsoft.com/v1.0"


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
    return jwt.encode({"typ": "teams_oauth_state", "iat": now,
                        "exp": now + timedelta(minutes=10)},
                       JWT_SECRET, algorithm="HS256")


def _verify_state(state: str | None):
    if not state:
        raise HTTPException(400, "missing state")
    try:
        claims = jwt.decode(state, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(400, "invalid or expired state - start the connection again")
    if claims.get("typ") != "teams_oauth_state":
        raise HTTPException(400, "invalid state")


def _token_endpoint(tenant: str) -> str:
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def _fresh_access_token(refresh_token: str, tenant: str) -> str:
    body = urllib.parse.urlencode({
        "client_id": TEAMS_CLIENT_ID,
        "client_secret": TEAMS_CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
        "scope": "ChannelMessage.Send offline_access",
    }).encode()
    req = urllib.request.Request(_token_endpoint(tenant), data=body, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())["access_token"]
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"could not refresh the Teams token: "
                                  f"{e.read().decode(errors='replace')[:200]}")


def _graph(path: str, access_token: str) -> dict:
    req = urllib.request.Request(f"{GRAPH}{path}",
                                  headers={"Authorization": f"Bearer {access_token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"Microsoft Graph error: {e.code} "
                                  f"{e.read().decode(errors='replace')[:200]}")


def install(app, pool):
    """Call once from app.py: install(app, pool)."""

    @router.get("/oauth/teams/start")
    def start(authorization: str | None = Header(default=None)):
        with pool.connection() as conn:
            require_admin(conn, authorization)
        if not TEAMS_CLIENT_ID or not NW_API_URL:
            raise HTTPException(500, "NW_TEAMS_CLIENT_ID / NW_API_URL is not configured")
        params = urllib.parse.urlencode({
            "client_id": TEAMS_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": f"{NW_API_URL}/oauth/teams/callback",
            "response_mode": "query",
            "scope": "ChannelMessage.Send offline_access",
            "state": _state_token(),
        })
        return {"url": f"https://login.microsoftonline.com/{TEAMS_TENANT_ID}"
                        f"/oauth2/v2.0/authorize?{params}"}

    @router.get("/oauth/teams/callback")
    def callback(code: str | None = None, state: str | None = None,
                 error: str | None = None):
        _verify_state(state)
        if error or not code:
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?teams=cancelled")

        body = urllib.parse.urlencode({
            "client_id": TEAMS_CLIENT_ID,
            "client_secret": TEAMS_CLIENT_SECRET,
            "code": code,
            "redirect_uri": f"{NW_API_URL}/oauth/teams/callback",
            "grant_type": "authorization_code",
            "scope": "ChannelMessage.Send offline_access",
        }).encode()
        req = urllib.request.Request(_token_endpoint(TEAMS_TENANT_ID), data=body, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                tokens = json.loads(r.read())
        except urllib.error.HTTPError:
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?teams=error")

        refresh_token = tokens.get("refresh_token")
        if not refresh_token:
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?teams=error")

        with pool.connection() as conn:
            row = conn.cursor(row_factory=dict_row).execute(
                """insert into teams_oauth_pending (refresh_token, tenant_id)
                   values (%s, %s) returning id""",
                (refresh_token, TEAMS_TENANT_ID),
            ).fetchone()

        return RedirectResponse(f"{DASHBOARD_URL}#/settings?teams=pick&pending={row['id']}")

    def _pending(conn, pending_id: str) -> dict:
        row = conn.cursor(row_factory=dict_row).execute(
            """select * from teams_oauth_pending
                where id = %s and created_at > now() - interval '1 hour'""",
            (pending_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, "connection expired - reconnect Teams")
        return row

    @router.get("/teams/list-teams")
    def list_teams(pending: str, authorization: str | None = Header(default=None)):
        with pool.connection() as conn:
            require_admin(conn, authorization)
            p = _pending(conn, pending)
        token = _fresh_access_token(p["refresh_token"], p["tenant_id"])
        data = _graph("/me/joinedTeams", token)
        return {"data": [{"id": t["id"], "name": t["displayName"]}
                          for t in data.get("value", [])]}

    @router.get("/teams/list-channels")
    def list_channels(pending: str, team_id: str,
                       authorization: str | None = Header(default=None)):
        with pool.connection() as conn:
            require_admin(conn, authorization)
            p = _pending(conn, pending)
        token = _fresh_access_token(p["refresh_token"], p["tenant_id"])
        data = _graph(f"/teams/{team_id}/channels", token)
        return {"data": [{"id": c["id"], "name": c["displayName"]}
                          for c in data.get("value", [])]}

    class FinalizeBody(BaseModel):
        pending: str
        team_id: str
        team_name: str
        channel_id: str
        channel_name: str

    @router.post("/teams/finalize")
    def finalize(body: FinalizeBody, authorization: str | None = Header(default=None)):
        with pool.connection() as conn:
            require_admin(conn, authorization)
            p = _pending(conn, body.pending)
            conn.execute(
                """insert into alert_channels (kind, label, config, enabled)
                   values ('teams', %s, %s, true)""",
                (f"{body.team_name} → {body.channel_name}",
                 json.dumps({"refresh_token": p["refresh_token"], "tenant_id": p["tenant_id"],
                             "team_id": body.team_id, "channel_id": body.channel_id})),
            )
            conn.execute("delete from teams_oauth_pending where id = %s", (body.pending,))
        return {"ok": True}

    app.include_router(router)
