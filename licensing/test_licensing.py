"""
End-to-end test of the licence server against the master's own activation
code: a local Postgres, the Edge Function under Deno, and a stand-in for
Supabase Auth's /auth/v1/user. No Supabase project or Docker needed.

    NW_PG_BIN=<postgres bin dir> NW_VENDOR_KEY=<signing key> \
        python licensing/test_licensing.py

NW_PG_BIN defaults to the Postgres a macOS master unpacked; NW_VENDOR_KEY
to ~/.nodewatch-vendor/license-signing.key (the key the master's
license_pubkey.txt belongs to - it is only used locally).
"""
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tools"))

import psycopg  # noqa: E402
import requests  # noqa: E402

from nodewatch_server import activation, license as lic  # noqa: E402
from nodewatch_server.pg import EmbeddedPostgres  # noqa: E402

PG_BIN = Path(os.environ.get("NW_PG_BIN") or
              next(Path("/Library/Application Support/nodewatch-server/pg").glob("*/bin")))
VENDOR_KEY = Path(os.environ.get("NW_VENDOR_KEY") or Path.home() / ".nodewatch-vendor" / "license-signing.key")
WORK = Path(tempfile.mkdtemp(prefix="lictest."))
FN = "http://127.0.0.1:8000/licensing"
os.environ["NW_LICENSING_URL"] = FN

passed = failed = 0


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok    {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}  {detail}")


class Auth(BaseHTTPRequestHandler):
    def do_GET(self):
        tok = self.headers.get("Authorization", "")
        email = {"Bearer admin-token": "admin@test.local", "Bearer other-token": "someone@test.local"}.get(tok)
        body = json.dumps({"email": email} if email else {"msg": "bad jwt"}).encode()
        self.send_response(200 if email else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def admin(path, body=None, token="admin-token"):
    return requests.post(f"{FN}/admin/{path}", json=body or {}, headers={"Authorization": f"Bearer {token}"}, timeout=20)


def main():
    pg = EmbeddedPostgres(PG_BIN, WORK, 54400, "testpw")
    pg.init()
    pg.start()
    deno = None
    try:
        with psycopg.connect(pg.url(), autocommit=True) as c:
            c.execute((ROOT / "licensing/supabase/migrations/20261022000000_licensing.sql").read_text())
            c.execute("insert into licensing.admins (email) values ('admin@test.local')")
        auth = HTTPServer(("127.0.0.1", 54401), Auth)
        threading.Thread(target=auth.serve_forever, daemon=True).start()

        env = dict(os.environ, LICENCE_SIGNING_KEY=VENDOR_KEY.read_text(), SUPABASE_DB_URL=pg.url(),
                   SUPABASE_URL="http://127.0.0.1:54401", SUPABASE_ANON_KEY="anon")
        deno = subprocess.Popen(["deno", "run", "--allow-net", "--allow-env", "--quiet",
                                 str(ROOT / "licensing/supabase/functions/licensing/index.ts")],
                                env=env, stdout=open(WORK / "deno.log", "w"), stderr=subprocess.STDOUT)
        for _ in range(60):
            try:
                requests.post(FN + "/none", json={}, timeout=1)
                break
            except requests.RequestException:
                time.sleep(1)

        print("admin")
        check("no session -> 401", admin("me", token="").status_code == 401)
        r = admin("me", token="other-token")
        check("signed in but not an admin -> 403", r.status_code == 403, r.text)
        r = admin("me")
        pub = (ROOT / "server/nodewatch_server/license_pubkey.txt").read_text().split()[0]
        check("admin -> public key matches the master's", r.ok and r.json()["public_key"] == pub, r.text)

        r = admin("issue", {"customer": "Acme Ltd", "email": "it@acme.test", "nodes": 5, "days": 30,
                            "features": "msp, sso", "moves_per_year": 1})
        check("issue", r.ok, r.text)
        issued = r.json()
        L = lic.parse(issued["key"])                      # signed in TypeScript, verified in Python
        check("key issued by the server verifies in the master",
              L.customer == "Acme Ltd" and L.nodes == 5 and L.features == ["msp", "sso"]
              and L.expires == dt.date.today() + dt.timedelta(days=30), L)
        check("bad input -> 400", admin("issue", {"customer": "x", "nodes": 0}).status_code == 400)

        print("activation")
        A = activation.Activator(WORK / "a", "0.2.0")
        B = activation.Activator(WORK / "b", "0.2.0")
        for x, m in ((A, "a" * 32), (B, "b" * 32)):
            x.dir.mkdir()
            x._machine = m
        st = A.state(L)
        check("unactivated master is pending with 14 days", st == {"activation": "pending", "activate_within_days": 14}, st)
        got = A.activate_online(L)
        check("activate on A", A.valid_for(L) and got.raw == L.raw)
        A.activate_online(L)
        check("activate A again is fine", A.valid_for(L))
        check("A state active", A.state(L)["activation"] == "active", A.state(L))
        try:
            B.activate_online(L, allow_move=False)
            check("B automatic attempt refused (in use)", False)
        except activation.ActivationError as e:
            check("B automatic attempt refused (in use)", e.code == "in_use" and not e.unreachable, e)
        check("B sync does not take it", B.sync(L) is None and not B.valid_for(L))
        B.activate_online(L, allow_move=True)
        check("B explicit activation moves it", B.valid_for(L))
        A.sync(L)
        st = A.state(L)
        check("A learns at check-in it was moved", st["activation"] == "released" and "moved" in st["activation_message"], st)
        try:
            A.activate_online(L)
            check("moving back exceeds 1 move/year", False)
        except activation.ActivationError as e:
            check("moving back exceeds 1 move/year", e.code == "move_limit", e)

        r = admin("release", {"id": L.lid})
        check("admin releases B (does not use a move)", r.ok, r.text)
        B.sync(L)
        check("B learns it was released", B.state(L)["activation"] == "released", B.state(L))
        A.activate_online(L)
        check("A can activate after the release", A.valid_for(L) and A.state(L)["activation"] == "active", A.state(L))

        print("renewal")
        r = admin("renew", {"id": L.lid, "days": 365, "nodes": 50})
        check("renew", r.ok, r.text)
        new = A.sync(L)
        check("check-in delivers the renewed key", new is not None and new.nodes == 50
              and new.expires == L.expires + dt.timedelta(days=365) and new.lid == L.lid, new)
        check("activation still valid for the renewed key", A.valid_for(new))
        check("check-in with the renewed key returns nothing new", A.sync(new) is None)

        print("revocation")
        check("revoke", admin("revoke", {"id": L.lid, "reason": "unpaid invoice"}).ok)
        A.sync(new)
        st = A.state(new)
        check("A sees revoked with the reason", st["activation"] == "revoked" and "unpaid invoice" in st["activation_message"], st)
        try:
            A.activate_online(new)
            check("revoked licence cannot activate", False)
        except activation.ActivationError as e:
            check("revoked licence cannot activate", e.code == "revoked", e)
        check("unrevoke", admin("unrevoke", {"id": L.lid}).ok)
        A.sync(new)
        check("A active again after check-in", A.state(new)["activation"] == "active", A.state(new))

        print("offline activation + key issued by license_tool.py")
        import license_tool
        tool_key = license_tool.issue(VENDOR_KEY, "Air Gap Co", 10, 365, [])
        T = lic.parse(tool_key)
        C = activation.Activator(WORK / "c", "0.2.0")
        C.dir.mkdir()
        C._machine = "c" * 32
        req = C.request_code(T)
        r = requests.post(FN + "/offline", json={"key": L.raw, "request": req}, timeout=20).json()
        check("offline: request for another licence is refused", not r["ok"] and r["code"] == "mismatch", r)
        r = requests.post(FN + "/offline", json={"key": tool_key, "request": "NWR1-garbage"}, timeout=20).json()
        check("offline: damaged request code is refused", not r["ok"], r)
        r = requests.post(FN + "/offline", json={"key": tool_key, "request": req}, timeout=20).json()
        check("offline: activation code issued", r["ok"], r)
        try:
            A.install(T, r["activation"])
            check("offline code refused on another machine", False)
        except activation.ActivationError as e:
            check("offline code refused on another machine", "different machine" in str(e), e)
        C.install(T, r["activation"])
        st = C.state(T)
        check("offline-activated master is active", st["activation"] == "active" and st["activation_method"] == "offline", st)
        forged = r["activation"][:-4] + ("AAAA" if not r["activation"].endswith("AAAA") else "BBBB")
        try:
            activation.parse_activation(forged)
            check("tampered activation code rejected", False)
        except activation.ActivationError:
            check("tampered activation code rejected", True)
        # A licence signature can never stand in for an activation.
        body, sig = tool_key[4:].split(".")
        try:
            activation.parse_activation("NWA1-" + body + "." + sig)
            check("licence signature cannot pass as an activation", False)
        except activation.ActivationError:
            check("licence signature cannot pass as an activation", True)
        rows = admin("list").json()
        ext = [x for x in rows if x["id"] == T.lid]
        check("tool-issued key registered as external", ext and ext[0]["source"] == "external"
              and ext[0]["machine_name"] == C.name, ext)

        print("master")
        from nodewatch_server.main import Master
        md = WORK / "m"
        M = Master(md)
        (md / "licence.key").write_text(tool_key)
        M.activator._machine = "d" * 32
        s = M.licence_summary()
        check("master: pending, still writable", s["activation"] == "pending" and not M.read_only(), s)
        st = json.loads((md / "activation.json").read_text())
        st["grace"]["from"] = (dt.date.today() - dt.timedelta(days=15)).isoformat()
        (md / "activation.json").write_text(json.dumps(st))
        s = M.licence_summary()
        check("master: after 14 days unactivated -> inactive, read-only, enrolment closed",
              s["state"] == "inactive" and M.read_only() and M.licence_limits()[1], s)
        M.sync_licence()
        check("master: automatic attempt does not steal C's licence", M.read_only())
        detail = admin("get", {"id": T.lid}).json()
        kinds = [e["kind"] for e in detail["events"]]
        check("history recorded", "registered" in kinds and "activated" in kinds, kinds)

        print("http edges")
        check("unknown route -> 404", requests.post(FN + "/nope", json={}, timeout=10).status_code == 404)
        check("non-JSON -> 400", requests.post(FN + "/activate", data="x", timeout=10).status_code == 400)
        r = requests.post(FN + "/activate", json={"key": "NW1-x.y", "machine": "z"}, timeout=10)
        check("bad machine id -> 400", r.status_code == 400, r.text)
        r = requests.post(FN + "/activate", json={"key": "NW1-abc.def", "machine": "e" * 32}, timeout=10).json()
        check("forged licence key refused", not r["ok"] and r["code"] == "invalid", r)
        r = requests.options(FN + "/activate", timeout=10)
        check("CORS preflight", r.headers.get("Access-Control-Allow-Origin") == "*")
        os.environ["NW_LICENSING_URL"] = "http://127.0.0.1:9/licensing"
        try:
            A.activate_online(new)
            check("unreachable server -> offline path", False)
        except activation.ActivationError as e:
            check("unreachable server -> offline path", e.unreachable, e)
        check("unreachable check-in changes nothing", A.sync(new) is None and A.state(new)["activation"] == "active")
    finally:
        if deno:
            deno.terminate()
        pg.stop()
        print(f"\n{passed} passed, {failed} failed  (work dir {WORK})")
        if failed:
            print((WORK / "deno.log").read_text()[-3000:])


main()
sys.exit(1 if failed else 0)
