"""
The master's own pages: the first-run setup wizard, the post-setup landing
page, and the CA certificate download. Everything else is the existing
ingest API, mounted underneath.

Plain HTML forms parsed by hand, so the master needs no template engine or
python-multipart. Every value rendered back into a page goes through
html.escape.
"""

import hmac
import html
import json
import logging
import sys
import threading
import urllib.parse
from pathlib import Path

import anyio

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from . import activation
from . import license as lic

log = logging.getLogger("nodewatch.web")

MAX_CODE_ATTEMPTS = 10

STYLE = """
<style>
 :root{color-scheme:light dark;--ink:#16181d;--muted:#6b7280;--rule:#d9dce1;--bg:#f6f7f9;--paper:#fff;--accent:#0f766e;--bad:#b42318}
 @media(prefers-color-scheme:dark){:root{--ink:#e6e8eb;--muted:#9aa1ab;--rule:#30343b;--bg:#111317;--paper:#181b20;--accent:#2dd4bf;--bad:#f97066}}
 *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
 main{max-width:640px;margin:48px auto;padding:0 20px}
 .card{background:var(--paper);border:1px solid var(--rule);padding:28px}
 h1{font-size:20px;margin:0 0 4px}h2{font-size:13px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);margin:28px 0 10px}
 p.sub{color:var(--muted);margin:0 0 8px}label{display:block;font-size:13px;margin:14px 0 4px}
 input,textarea,select{width:100%;padding:9px 10px;border:1px solid var(--rule);background:var(--bg);color:var(--ink);font:inherit}
 textarea{font-family:ui-monospace,Menlo,monospace;font-size:12px;height:84px}
 .row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.hint{color:var(--muted);font-size:12px;margin-top:4px}
 button{margin-top:24px;width:100%;padding:11px;border:0;background:var(--accent);color:#fff;font:600 15px system-ui;cursor:pointer}
 .err{border:1px solid var(--bad);color:var(--bad);padding:10px 12px;margin:16px 0}
 code{font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all}
 details{margin-top:20px}summary{cursor:pointer;color:var(--muted);font-size:13px}
</style>"""


def page(title: str, body: str) -> HTMLResponse:
    return HTMLResponse(f"<!doctype html><html lang=en><head><meta charset=utf-8>"
                        f"<meta name=viewport content='width=device-width,initial-scale=1'>"
                        f"<title>{html.escape(title)}</title>{STYLE}</head>"
                        f"<body><main>{body}</main></body></html>")


def setup_form(cfg, suggestions: list[str], error: str = "", values: dict | None = None,
               request_code: str = "") -> HTMLResponse:
    v = {k: html.escape(str(x)) for k, x in (values or {}).items()}
    opts = "".join(f"<option value='{html.escape(a)}'>" for a in suggestions)
    err = f"<div class=err>{html.escape(error)}</div>" if error else ""
    offline = ""
    if request_code or v.get("activation"):
        page_url = html.escape(activation.OFFLINE_PAGE)
        offline = f"""
  <h2>Offline activation</h2>
  <p class=sub>This master cannot reach the licence server. On any device with internet, open
   <a href="{page_url}" target=_blank rel=noopener>{page_url}</a>, enter your licence key and the
   request code below, then paste the activation code it gives you here.</p>
  <label>Request code</label>
  <code>{html.escape(request_code)}</code>
  <label>Activation code</label>
  <textarea name=activation>{v.get('activation', '')}</textarea>"""
    return page("Set up nodewatch", f"""
<div class=card>
 <h1>Set up this nodewatch master</h1>
 <p class=sub>This machine will hold the dashboard, the database and the alerting for your whole network.</p>
 {err}
 <form method=post action=/setup autocomplete=off>
  <label>Setup code</label>
  <input name=setup_code value="{v.get('setup_code', '')}" required>
  <div class=hint>Printed in the master's console and log when it started. Proves you are the person who installed it.</div>

  <h2>Licence</h2>
  <label>Licence key</label>
  <textarea name=license required>{v.get('license', '')}</textarea>
  <label>Organisation name</label>
  <input name=org value="{v.get('org', '')}" placeholder="Defaults to the name on the licence">
  <div class=hint>The licence is activated on this machine when you finish, over the internet;
   a master without internet access is offered offline activation instead.</div>
{offline}

  <h2>Address</h2>
  <label>Address your nodes will use to reach this master</label>
  <input name=address list=addrs value="{v.get('address', '')}" required>
  <datalist id=addrs>{opts}</datalist>
  <div class=hint>A hostname or IP that every machine you monitor can reach. Agents connect to
   <code>https://&lt;this address&gt;:{cfg.https_port}</code>. You can change it later.</div>

  <h2>Administrator</h2>
  <label>Email</label>
  <input name=email type=email value="{v.get('email', '')}" required>
  <div class=row>
   <div><label>Password</label><input name=password type=password minlength=12 required></div>
   <div><label>Confirm password</label><input name=password2 type=password minlength=12 required></div>
  </div>

  <details><summary>Email alerts (SMTP) - optional, can be set later</summary>
   <div class=row>
    <div><label>SMTP host</label><input name=smtp_host value="{v.get('smtp_host', '')}"></div>
    <div><label>Port</label><input name=smtp_port value="{v.get('smtp_port', '587')}"></div>
   </div>
   <div class=row>
    <div><label>Username</label><input name=smtp_user value="{v.get('smtp_user', '')}"></div>
    <div><label>Password</label><input name=smtp_password type=password></div>
   </div>
   <label>From address</label><input name=smtp_from value="{v.get('smtp_from', '')}">
  </details>

  <button type=submit>Finish setup</button>
 </form>
</div>""")


def build_setup_app(cfg, store, on_complete, suggestions: list[str], activator) -> FastAPI:
    """
    The only app served before setup. on_complete(form, licence) does the
    database work and raises ValueError with a message for the user.
    activator (activation.Activator) binds the licence to this machine
    before that.
    """
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    state = {"attempts": 0, "done": False}
    lock = threading.Lock()

    @app.get("/setup")
    def get_setup():
        if state["done"]:
            return RedirectResponse("/", 303)
        return setup_form(cfg, suggestions, values={"address": cfg.public_address or suggestions[0]})

    @app.post("/setup")
    async def post_setup(request: Request):
        raw = (await request.body()).decode("utf-8", "replace")
        form = {k: v[0].strip() for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}
        keep = {k: v for k, v in form.items() if "password" not in k}

        with lock:
            if state["done"]:
                return RedirectResponse("/", 303)
            if state["attempts"] >= MAX_CODE_ATTEMPTS:
                return setup_form(cfg, suggestions, "Too many wrong setup codes. Restart the master to try again.", keep)
            if not hmac.compare_digest(form.get("setup_code", "").upper(), cfg.setup_code):
                state["attempts"] += 1
                log.warning("wrong setup code from %s", request.client.host if request.client else "?")
                return setup_form(cfg, suggestions, "That setup code is not right.", keep)

            try:
                licence = lic.parse(form.get("license", ""))
            except lic.LicenseError as e:
                return setup_form(cfg, suggestions, str(e), keep)
            if licence.state == "expired":
                return setup_form(cfg, suggestions, f"This licence expired on {licence.expires}.", keep)
            if len(form.get("password", "")) < 12:
                return setup_form(cfg, suggestions, "Use a password of at least 12 characters.", keep)
            if form.get("password") != form.get("password2"):
                return setup_form(cfg, suggestions, "The passwords do not match.", keep)
            if not form.get("address"):
                return setup_form(cfg, suggestions, "Enter the address nodes will use to reach this master.", keep)

            try:
                if form.get("activation"):
                    activator.install(licence, form["activation"])
                elif activation.enforced() and not activator.valid_for(licence):
                    # The server's current key: newer than the one typed in
                    # if the licence was renewed since it was sent out.
                    licence = activator.activate_online(licence, allow_move=True)
            except activation.ActivationError as e:
                if e.unreachable:
                    return setup_form(cfg, suggestions, f"The licence could not be activated online: {e}.",
                                      keep, request_code=activator.request_code(licence))
                return setup_form(cfg, suggestions, f"The licence could not be activated: {e}", keep,
                                  request_code=activator.request_code(licence) if keep.get("activation") else "")

            try:
                on_complete(form, licence)
            except ValueError as e:
                return setup_form(cfg, suggestions, str(e), keep)
            state["done"] = True

        url = html.escape(cfg.public_url)
        return page("nodewatch is ready", f"""
<div class=card>
 <h1>Setup complete</h1>
 <p class=sub>The master is restarting with its new certificate. Sign in to the dashboard at:</p>
 <p><a href="{url}">{url}</a></p>
 <p class=sub>Your browser will warn about the certificate until you trust this master's own
  certificate authority: <a href="/ca.crt">download ca.crt</a>.</p>
</div>""")

    add_common(app, store)

    @app.middleware("http")
    async def only_setup(request: Request, call_next):
        path = request.url.path
        if path in ("/setup", "/ca.crt"):
            return await call_next(request)
        if path.startswith("/v1/") or path == "/health":
            return JSONResponse({"detail": "this master has not been set up yet"}, 503)
        return RedirectResponse("/setup", 303)

    return app


def add_common(app: FastAPI, store) -> None:
    @app.get("/ca.crt")
    def ca_crt():
        return FileResponse(store.dir / "pki" / "ca.crt", media_type="application/x-x509-ca-cert",
                            filename="nodewatch-master-ca.crt")


def dashboard_dir() -> Path:
    """The single-file dashboard (dashboard/ in the repository)."""
    if hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "dashboard"
    return Path(__file__).resolve().parents[2] / "dashboard"


# Request and response headers that matter to PostgREST and supabase-js.
PROXY_REQUEST_HEADERS = ("authorization", "accept", "content-type", "prefer", "range",
                         "range-unit", "accept-profile", "content-profile")
PROXY_RESPONSE_HEADERS = ("content-type", "content-range", "preference-applied", "location")


def build_main_app(api_app, cfg, store, ctx) -> FastAPI:
    """
    Everything the master serves on one origin:

        /                  the dashboard (dashboard/index.html)
        /config.js         tells the dashboard it is on a self-hosted master
        /rest/v1/*         PostgREST, proxied, row-level security applies
        /auth/v1/*         sign-in (auth.py)
        /functions/v1/manage-users
        /download/agent/*  agent binaries for joining nodes
        /ca.crt            this master's CA certificate
        /v1/*, /oauth/*    the ingest API and OAuth callbacks (api/app.py)
    """
    import requests as http

    root = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    add_common(root, store)
    root.include_router(ctx.auth.router())
    dash = dashboard_dir()
    pgrst = http.Session()

    @root.get("/", include_in_schema=False)
    def index():
        return FileResponse(dash / "index.html", media_type="text/html",
                            headers={"Cache-Control": "no-cache"})

    @root.get("/vendor/{name}", include_in_schema=False)
    def vendor(name: str):
        path = (dash / "vendor" / name).resolve()
        if path.parent != (dash / "vendor").resolve() or not path.is_file():
            return JSONResponse({"detail": "not found"}, 404)
        return FileResponse(path, headers={"Cache-Control": "public, max-age=86400"})

    @root.get("/config.js", include_in_schema=False)
    def config_js():
        conf = {
            "anonKey": ctx.auth.anon_key(),
            "publicUrl": cfg.public_url,
            "caFingerprint": ctx.ca_fingerprint,
            "agents": ctx.agents.public(),
            "licence": ctx.licence_summary(),
        }
        return Response(f"window.NW_CONFIG = {json.dumps(conf)};\n", media_type="application/javascript",
                        headers={"Cache-Control": "no-store"})

    @root.get("/setup", include_in_schema=False)
    def setup_done():
        return RedirectResponse("/", 303)

    @root.get("/download/agents.json")
    def agents_json():
        return ctx.agents.public()

    @root.get("/download/agent/{platform}")
    def download(platform: str):
        a = ctx.agents.find(platform)
        if not a:
            return JSONResponse({"detail": f"no agent build for {platform} on this master"}, 404)
        name = "nodewatch-agent.exe" if a["path"].suffix == ".exe" else "nodewatch-agent"
        return FileResponse(a["path"], media_type="application/octet-stream", filename=name,
                            headers={"X-Checksum-SHA256": a["sha256"]})

    @root.api_route("/rest/v1/{path:path}", methods=["GET", "HEAD", "POST", "PATCH", "PUT", "DELETE"],
                    include_in_schema=False)
    async def rest(path: str, request: Request):
        # After the licence grace period the dashboard is read-only: data can
        # be read and functions called, tables cannot be changed.
        if ctx.read_only() and request.method not in ("GET", "HEAD") and not path.startswith("rpc/"):
            return JSONResponse({"message": "The licence for this master has expired; it is read-only "
                                            "until a new licence is installed.", "code": "licence"}, 403)
        headers = {k: v for k, v in request.headers.items() if k.lower() in PROXY_REQUEST_HEADERS}
        body = await request.body()

        def call():
            return pgrst.request(request.method, f"{ctx.postgrest_url}/{path}",
                                 params=list(request.query_params.multi_items()),
                                 headers=headers, data=body or None, timeout=60)
        try:
            r = await anyio.to_thread.run_sync(call)
        except http.RequestException as e:
            log.warning("postgrest unreachable: %s", e)
            return JSONResponse({"message": "the data service is restarting - try again"}, 503)
        out = {k: v for k, v in r.headers.items() if k.lower() in PROXY_RESPONSE_HEADERS}
        return Response(r.content, status_code=r.status_code, headers=out)

    root.mount("/", api_app)
    return root
