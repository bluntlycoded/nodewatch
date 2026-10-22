"""
Sign-in for the dashboard, and user management - the master's replacements
for Supabase Auth and the manage-users Edge Function.

Implements the part of Supabase Auth's HTTP API that supabase-js calls -
password sign-in, refresh, current user, sign-out - so the dashboard's
existing sign-in code works unchanged. Access tokens are short-lived HS256
JWTs carrying role=authenticated and the user's id, which PostgREST turns
into `set role authenticated` plus request.jwt.claims for row-level
security. Refresh tokens are random, stored only as hashes, and rotated on
every use.

Self-serve signup is refused: on a master, the admin creates accounts.
"""

import hashlib
import json
import logging
import secrets
import threading
import time
import uuid
from datetime import datetime

import jwt
import psycopg
from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse, Response
from psycopg.rows import dict_row

log = logging.getLogger("nodewatch.auth")

ACCESS_TTL_S = 3600
REFRESH_TTL_S = 30 * 86400
MIN_PASSWORD = 10
FAIL_LIMIT = 8
LOCK_S = 900


def _err(status: int, msg: str, code: str = "invalid_request") -> JSONResponse:
    # supabase-js reads msg / error_description for the message it shows.
    return JSONResponse({"code": status, "error_code": code, "msg": msg,
                         "error": code, "error_description": msg}, status)


def _iso(ts) -> str | None:
    return ts.isoformat() if isinstance(ts, datetime) else ts


class Auth:

    def __init__(self, db_url: str, secret: str):
        self.db_url = db_url
        self.secret = secret
        self.fails: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    # ------------------------------------------------------------ tokens

    def access_token(self, user: dict) -> tuple[str, int]:
        now = int(time.time())
        exp = now + ACCESS_TTL_S
        token = jwt.encode({"sub": str(user["id"]), "email": user["email"], "role": "authenticated",
                            "aud": "authenticated", "iat": now, "exp": exp, "iss": "nodewatch"},
                           self.secret, algorithm="HS256")
        return token, exp

    def anon_key(self) -> str:
        return jwt.encode({"role": "anon", "iss": "nodewatch", "iat": int(time.time())},
                          self.secret, algorithm="HS256")

    def verify(self, authorization: str | None) -> dict | None:
        if not authorization or not authorization.lower().startswith("bearer "):
            return None
        try:
            claims = jwt.decode(authorization[7:], self.secret, algorithms=["HS256"],
                                audience="authenticated")
        except jwt.InvalidTokenError:
            return None
        return claims if claims.get("role") == "authenticated" else None

    def _session(self, conn, user: dict) -> dict:
        refresh = secrets.token_urlsafe(32)
        conn.execute("insert into auth.refresh_tokens (token_hash, user_id, expires_at) "
                     "values (%s, %s, now() + make_interval(secs => %s))",
                     (hashlib.sha256(refresh.encode()).hexdigest(), user["id"], REFRESH_TTL_S))
        access, exp = self.access_token(user)
        return {"access_token": access, "token_type": "bearer", "expires_in": ACCESS_TTL_S,
                "expires_at": exp, "refresh_token": refresh, "user": self._user_json(user)}

    @staticmethod
    def _user_json(u: dict) -> dict:
        return {"id": str(u["id"]), "aud": "authenticated", "role": "authenticated",
                "email": u["email"], "app_metadata": {"provider": "email", "providers": ["email"]},
                "user_metadata": {}, "created_at": _iso(u.get("created_at")),
                "updated_at": _iso(u.get("updated_at")), "last_sign_in_at": _iso(u.get("last_sign_in_at"))}

    # ------------------------------------------------------------ brute force

    def _locked(self, key: str) -> bool:
        with self.lock:
            recent = [t for t in self.fails.get(key, []) if time.time() - t < LOCK_S]
            self.fails[key] = recent
            return len(recent) >= FAIL_LIMIT

    def _failed(self, key: str) -> None:
        with self.lock:
            self.fails.setdefault(key, []).append(time.time())

    # ------------------------------------------------------------ routes

    def router(self) -> APIRouter:
        r = APIRouter()

        @r.post("/auth/v1/token")
        async def token(request: Request, grant_type: str = ""):
            try:
                body = json.loads(await request.body() or b"{}")
            except ValueError:
                return _err(400, "invalid JSON body")
            if grant_type == "password":
                return self.password_grant(body, request.client.host if request.client else "?")
            if grant_type == "refresh_token":
                return self.refresh_grant(body.get("refresh_token") or "")
            return _err(400, "unsupported grant type", "unsupported_grant_type")

        @r.get("/auth/v1/user")
        def user(authorization: str | None = Header(default=None)):
            claims = self.verify(authorization)
            if not claims:
                return _err(401, "invalid or expired session", "bad_jwt")
            with psycopg.connect(self.db_url, row_factory=dict_row) as conn:
                u = conn.execute("select * from auth.users where id = %s", (claims["sub"],)).fetchone()
            if not u:
                return _err(401, "user no longer exists", "user_not_found")
            return self._user_json(u)

        @r.post("/auth/v1/logout")
        def logout(authorization: str | None = Header(default=None)):
            claims = self.verify(authorization)
            if claims:
                with psycopg.connect(self.db_url) as conn:
                    conn.execute("update auth.refresh_tokens set revoked = true where user_id = %s",
                                 (claims["sub"],))
            return Response(status_code=204)

        @r.post("/auth/v1/signup")
        def signup():
            return _err(403, "Accounts on this nodewatch master are created by its admin.", "signup_disabled")

        @r.post("/functions/v1/manage-users")
        async def manage_users(request: Request, authorization: str | None = Header(default=None)):
            claims = self.verify(authorization)
            if not claims:
                return JSONResponse({"error": "sign in again"}, 401)
            try:
                body = json.loads(await request.body() or b"{}")
            except ValueError:
                return JSONResponse({"error": "invalid JSON body"}, 400)
            return self.manage(claims["sub"], body)

        return r

    def password_grant(self, body: dict, ip: str):
        email = str(body.get("email") or "").strip().lower()
        password = str(body.get("password") or "")
        if self._locked(f"ip:{ip}") or self._locked(f"email:{email}"):
            return _err(429, "Too many failed sign-in attempts. Try again in 15 minutes.",
                        "over_request_rate_limit")
        with psycopg.connect(self.db_url, row_factory=dict_row) as conn:
            u = conn.execute(
                "select * from auth.users where lower(email) = %s "
                "and encrypted_password = crypt(%s, encrypted_password)", (email, password)).fetchone()
            if not u:
                # Same bcrypt cost whether or not the account exists, so
                # response time does not reveal which emails have one.
                if not conn.execute("select 1 from auth.users where lower(email) = %s", (email,)).fetchone():
                    conn.execute("select crypt(%s, gen_salt('bf', 12))", (password,))
                self._failed(f"ip:{ip}")
                self._failed(f"email:{email}")
                log.warning("failed sign-in for %r from %s", email, ip)
                return _err(400, "Invalid login credentials", "invalid_credentials")
            conn.execute("update auth.users set last_sign_in_at = now() where id = %s", (u["id"],))
            conn.execute("update profiles set last_seen = now() where id = %s", (u["id"],))
            session = self._session(conn, u)
        log.info("signed in %s from %s", email, ip)
        return session

    def refresh_grant(self, refresh: str):
        digest = hashlib.sha256(refresh.encode()).hexdigest()
        with psycopg.connect(self.db_url, row_factory=dict_row) as conn:
            row = conn.execute(
                "update auth.refresh_tokens set revoked = true "
                "where token_hash = %s and not revoked and expires_at > now() returning user_id",
                (digest,)).fetchone()
            if not row:
                return _err(400, "Invalid Refresh Token", "refresh_token_not_found")
            u = conn.execute("select * from auth.users where id = %s", (row["user_id"],)).fetchone()
            if not u:
                return _err(400, "user no longer exists", "user_not_found")
            return self._session(conn, u)

    # ------------------------------------------------------------ users

    def manage(self, caller: str, body: dict) -> JSONResponse | dict:
        action = body.get("action")
        with psycopg.connect(self.db_url, row_factory=dict_row) as conn:
            me = conn.execute("select role, tenant_id from profiles where id = %s", (caller,)).fetchone()
            if not me or me["role"] != "admin":
                return JSONResponse({"error": "only an admin can manage users"}, 403)
            tenant = me["tenant_id"]

            def target():
                try:
                    uuid.UUID(str(body.get("id")))
                except ValueError:
                    return None
                t = conn.execute("select id from profiles where id = %s and tenant_id = %s",
                                 (body.get("id"), tenant)).fetchone()
                return t["id"] if t else None

            if action == "list":
                users = conn.execute(
                    "select p.id, p.email, p.role, u.last_sign_in_at, u.created_at "
                    "from profiles p join auth.users u using (id) "
                    "where p.tenant_id = %s order by lower(p.email)", (tenant,)).fetchall()
                # Accounts here are created by an admin, never by email
                # signup, so there is nothing to confirm.
                return {"users": [{**u, "id": str(u["id"]), "confirmed": True,
                                   "last_sign_in_at": _iso(u["last_sign_in_at"]),
                                   "created_at": _iso(u["created_at"])} for u in users]}

            if action == "create":
                email = str(body.get("email") or "").strip().lower()
                role = body.get("role") if body.get("role") in ("admin", "viewer") else "viewer"
                if "@" not in email:
                    return JSONResponse({"error": "enter a valid email address"}, 400)
                if len(str(body.get("password") or "")) < MIN_PASSWORD:
                    return JSONResponse({"error": f"use a password of at least {MIN_PASSWORD} characters"}, 400)
                if conn.execute("select 1 from auth.users where lower(email) = %s", (email,)).fetchone():
                    return JSONResponse({"error": "a user with that email already exists"}, 409)
                uid = conn.execute(
                    "insert into auth.users (email, encrypted_password) "
                    "values (%s, crypt(%s, gen_salt('bf', 12))) returning id",
                    (email, body["password"])).fetchone()["id"]
                conn.execute("update profiles set role = %s, tenant_id = %s where id = %s", (role, tenant, uid))
                log.info("user %s created as %s by %s", email, role, caller)
                return {"ok": True, "id": str(uid)}

            if action == "set_role":
                uid = target()
                if not uid:
                    return JSONResponse({"error": "no such user"}, 404)
                if str(uid) == caller:
                    return JSONResponse({"error": "you cannot change your own role"}, 400)
                if body.get("role") not in ("admin", "viewer"):
                    return JSONResponse({"error": "role must be admin or viewer"}, 400)
                conn.execute("update profiles set role = %s where id = %s", (body["role"], uid))
                return {"ok": True}

            if action == "reset_password":
                uid = target()
                if not uid:
                    return JSONResponse({"error": "no such user"}, 404)
                if len(str(body.get("password") or "")) < MIN_PASSWORD:
                    return JSONResponse({"error": f"use a password of at least {MIN_PASSWORD} characters"}, 400)
                conn.execute("update auth.users set encrypted_password = crypt(%s, gen_salt('bf', 12)), "
                             "updated_at = now() where id = %s", (body["password"], uid))
                # Existing sessions end at their next refresh.
                conn.execute("update auth.refresh_tokens set revoked = true where user_id = %s", (uid,))
                return {"ok": True}

            if action == "delete":
                uid = target()
                if not uid:
                    return JSONResponse({"error": "no such user"}, 404)
                if str(uid) == caller:
                    return JSONResponse({"error": "you cannot remove yourself"}, 400)
                conn.execute("delete from auth.users where id = %s", (uid,))
                log.info("user %s removed by %s", uid, caller)
                return {"ok": True}

        return JSONResponse({"error": f"unknown action {action!r}"}, 400)

