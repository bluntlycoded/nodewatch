"""
GitHub App installation flow, for connecting private repositories to
Supply Chain checks without a hand-entered personal access token.

Two admin-only-in-effect routes: /oauth/github/start builds the GitHub
installation URL with our own short-lived signed state token embedded, so
the callback can prove it followed a real authenticated admin action
rather than trusting whatever installation_id shows up in the redirect;
/oauth/github/callback is where GitHub sends the browser back after the
admin installs the App, and is necessarily unauthenticated in the normal
sense - GitHub is the caller, not the dashboard - so the signed state
token stands in for auth there instead.

Does not mint installation access tokens itself - that happens in
probe/prober.py at scan time, directly against GitHub's API, using the
same App private key. A 1-hour token isn't worth persisting; minting a
fresh one per scan is simpler than building a refresh path for one that
expires on its own regardless.
"""

import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import RedirectResponse

router = APIRouter()

JWT_SECRET = os.environ.get("NW_JWT_SECRET", "dev-secret-change-me")
# Supabase signs dashboard-session tokens with its own project secret, a
# different value from the one above (which is this service's own, used
# only for agent enrolment tokens and the state token below). A dashboard
# session and an agent enrolment token must never be interchangeable, and
# two different secrets makes that true by construction, not convention.
SUPABASE_JWT_SECRET = os.environ.get("NW_SUPABASE_JWT_SECRET", "")

GITHUB_APP_ID = os.environ.get("NW_GITHUB_APP_ID", "")
GITHUB_APP_SLUG = os.environ.get("NW_GITHUB_APP_SLUG", "")
GITHUB_APP_PRIVATE_KEY_PATH = os.environ.get("NW_GITHUB_APP_PRIVATE_KEY_PATH", "")
DASHBOARD_URL = os.environ.get("NW_DASHBOARD_URL", "https://example.github.io/nodewatch/")


def mint_app_jwt() -> str:
    """
    Short-lived (9 min - GitHub allows up to 10) App-identity JWT, per
    https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app.
    Proves "this request is nodewatch's GitHub App", not tied to any one
    installation - that's what an installation access token is for.
    """
    if not GITHUB_APP_ID or not GITHUB_APP_PRIVATE_KEY_PATH:
        raise HTTPException(500, "GitHub App is not configured on this host")
    with open(GITHUB_APP_PRIVATE_KEY_PATH) as f:
        private_key = f.read()
    now = int(datetime.now(timezone.utc).timestamp())
    return jwt.encode({"iat": now - 60, "exp": now + 9 * 60, "iss": GITHUB_APP_ID},
                       private_key, algorithm="RS256")


def _github_api(path: str, app_jwt: str) -> dict:
    req = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={"Authorization": f"Bearer {app_jwt}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"GitHub API error: {e.code} "
                                  f"{e.read().decode(errors='replace')[:200]}")


def require_admin(conn, authorization: str | None) -> str:
    """
    Verifies a Supabase-issued dashboard session token and that the caller
    is an admin, by looking their role up the same way is_admin() does in
    Postgres - this service has its own DB connection, so it can just ask
    directly rather than needing RLS in the loop.
    """
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
    return jwt.encode({"typ": "github_oauth_state", "iat": now,
                        "exp": now + timedelta(minutes=10)},
                       JWT_SECRET, algorithm="HS256")


def _verify_state(state: str | None):
    if not state:
        raise HTTPException(400, "missing state")
    try:
        claims = jwt.decode(state, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError:
        raise HTTPException(400, "invalid or expired state - start the connection again")
    if claims.get("typ") != "github_oauth_state":
        raise HTTPException(400, "invalid state")


def install(app, pool):
    """Call once from app.py: install(app, pool)."""

    @router.get("/oauth/github/start")
    def start(authorization: str | None = Header(default=None)):
        with pool.connection() as conn:
            require_admin(conn, authorization)
        if not GITHUB_APP_SLUG:
            raise HTTPException(500, "NW_GITHUB_APP_SLUG is not configured")
        return {"url": f"https://github.com/apps/{GITHUB_APP_SLUG}"
                        f"/installations/new?state={_state_token()}"}

    @router.get("/oauth/github/callback")
    def callback(installation_id: int | None = None, setup_action: str | None = None,
                 state: str | None = None):
        _verify_state(state)
        if setup_action != "install" or not installation_id:
            return RedirectResponse(f"{DASHBOARD_URL}#/settings?github=cancelled")

        info = _github_api(f"/app/installations/{installation_id}", mint_app_jwt())
        account = info.get("account") or {}

        with pool.connection() as conn:
            conn.execute(
                """insert into github_installations
                       (installation_id, account_login, account_type)
                   values (%s, %s, %s)
                   on conflict (installation_id) do update set
                       account_login = excluded.account_login,
                       account_type  = excluded.account_type""",
                (installation_id, account.get("login"), account.get("type")),
            )
        return RedirectResponse(f"{DASHBOARD_URL}#/settings?github=connected")

    app.include_router(router)
