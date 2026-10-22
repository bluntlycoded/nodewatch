"""
Database operations the master performs on its owner's behalf: creating the
first admin, renaming the tenant, issuing enrolment tokens.

Tokens are issued through the same new_enroll_token() the dashboard calls,
inside a transaction that carries the admin's identity in
request.jwt.claims, so is_admin() and current_tenant() apply exactly as
they do for a signed-in user rather than being bypassed.
"""

import json

from .config import TENANT_ZERO


def create_admin(conn, email: str, password: str, org_name: str) -> str:
    with conn.transaction():
        if conn.execute("select 1 from profiles where role = 'admin' limit 1").fetchone():
            raise ValueError("this master already has an admin")
        # bcrypt via pgcrypto: the same hash format Supabase Auth stores, so
        # the phase 2 login can verify it with crypt() in one query.
        uid = conn.execute(
            "insert into auth.users (email, encrypted_password) "
            "values (lower(%s), crypt(%s, gen_salt('bf', 12))) returning id",
            (email.strip(), password)).fetchone()[0]
        # handle_new_user() made a viewer profile with no tenant.
        conn.execute("update profiles set role = 'admin', tenant_id = %s where id = %s",
                     (TENANT_ZERO, uid))
        conn.execute("update tenants set name = %s, plan = 'self-hosted' where id = %s",
                     (org_name, TENANT_ZERO))
    return str(uid)


def admin_id(conn) -> str:
    row = conn.execute(
        "select id from profiles where role = 'admin' and tenant_id = %s "
        "order by created_at nulls last limit 1", (TENANT_ZERO,)).fetchone()
    if not row:
        raise RuntimeError("no admin exists yet - finish setup first")
    return str(row[0])


def issue_token(conn, kind: str = "agent", label: str | None = None, hours: int = 24) -> str:
    uid = admin_id(conn)
    with conn.transaction():
        conn.execute("select set_config('request.jwt.claims', %s, true)",
                     (json.dumps({"sub": uid, "role": "authenticated"}),))
        return conn.execute("select new_enroll_token(%s, %s, %s)", (label, hours, kind)).fetchone()[0]


def node_count(conn) -> int:
    return conn.execute("select count(*) from agents where tenant_id = %s", (TENANT_ZERO,)).fetchone()[0]
