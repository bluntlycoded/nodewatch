// nodewatch licence server - one Edge Function, deployed with
// verify_jwt = false because masters call it without a Supabase session.
//
//   POST /licensing/activate   a master activates its licence key
//   POST /licensing/checkin    a master's daily check-in
//   POST /licensing/offline    the offline activation page (air-gapped masters)
//   POST /licensing/admin/*    the vendor admin page; needs a Supabase Auth
//                              session whose email is in licensing.admins
//
// Secrets: LICENCE_SIGNING_KEY (the vendor's Ed25519 PEM key - the same key
// tools/license_tool.py signs with). SUPABASE_DB_URL, SUPABASE_URL and
// SUPABASE_ANON_KEY are provided by Supabase.

import postgres from "npm:postgres@3.4.5";
import { isDate, isMachine, isUuid, KeyError, parseRequest, Signer } from "./keys.ts";

const signer = new Signer(Deno.env.get("LICENCE_SIGNING_KEY") ?? "");
const sql = postgres(Deno.env.get("SUPABASE_DB_URL") ?? "", { prepare: false, max: 3, idle_timeout: 20 });
const AUTH_URL = (Deno.env.get("SUPABASE_URL") ?? "").replace(/\/$/, "") + "/auth/v1/user";
const ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

const text = (v: unknown, max: number) => String(v ?? "").trim().slice(0, max);
const today = () => new Date().toISOString().slice(0, 10);
// postgres.js returns date columns as Date; jsonb timestamps arrive as strings.
const day = (v: unknown) => (v instanceof Date ? v.toISOString() : String(v)).slice(0, 10);

function uuidOf(v: unknown): string {
  const id = text(v, 64);
  if (!isUuid(id)) throw new HttpError(400, "id must be a UUID");
  return id;
}

function machineFields(b: Record<string, unknown>) {
  const machine = text(b.machine, 64);
  if (!isMachine(machine)) throw new HttpError(400, "machine must be 32 lowercase hex characters");
  return { machine, name: text(b.name, 100), version: text(b.version, 40) };
}

// ------------------------------------------------------------------ masters

async function activate(key: string, m: { machine: string; name: string; version: string },
                        method: "online" | "offline", allowMove: boolean, actor: string) {
  let l;
  try {
    l = signer.parseLicence(key);
  } catch (e) {
    if (e instanceof KeyError) return { ok: false, code: "invalid", message: e.message };
    throw e;
  }
  const [{ r }] = await sql`
    select licensing.activate(${l.lid}::uuid, ${l.customer}, ${l.nodes}, ${l.features}::text[],
      ${l.issued}::date, ${l.expires}::date, ${l.key}, ${m.machine}, ${m.name}, ${m.version},
      ${method}, ${allowMove}, ${actor}) as r`;
  if (!r.ok) return r;
  const activated = day(r.activated_at);
  return {
    ok: true,
    activation: signer.activation({ lid: l.lid, machine: m.machine, name: m.name, activated,
                                    method: r.method }),
    key: r.key,                       // the current key: newer than the one sent if it was renewed
    moved_from: r.moved_from ?? null,
  };
}

const routes: Record<string, (b: Record<string, unknown>, req: Request) => Promise<unknown>> = {
  async activate(b) {
    return await activate(String(b.key ?? ""), machineFields(b), "online", b.allow_move !== false, "master");
  },

  async checkin(b) {
    const lid = text(b.lid, 64);
    if (!isUuid(lid)) throw new HttpError(400, "lid must be a UUID");
    const { machine, version } = machineFields(b);
    const [{ r }] = await sql`select licensing.checkin(${lid}::uuid, ${machine}, ${version}) as r`;
    return r;
  },

  async offline(b) {
    let req;
    try {
      req = parseRequest(String(b.request ?? ""));
    } catch (e) {
      if (e instanceof KeyError) return { ok: false, code: "invalid", message: e.message };
      throw e;
    }
    let l;
    try {
      l = signer.parseLicence(String(b.key ?? ""));
    } catch (e) {
      if (e instanceof KeyError) return { ok: false, code: "invalid", message: e.message };
      throw e;
    }
    if (l.lid !== req.lid) {
      return { ok: false, code: "mismatch",
               message: "The request code was made for a different licence key than the one entered." };
    }
    return await activate(l.key, { machine: req.machine, name: req.name, version: "" }, "offline", true,
                          "offline page");
  },
};

// ------------------------------------------------------------------ admin

async function adminEmail(req: Request): Promise<string> {
  const auth = req.headers.get("authorization") ?? "";
  if (!auth.toLowerCase().startsWith("bearer ")) throw new HttpError(401, "sign in first");
  const r = await fetch(AUTH_URL, { headers: { Authorization: auth, apikey: ANON_KEY } });
  if (!r.ok) throw new HttpError(401, "your session has expired - sign in again");
  const email = String((await r.json()).email ?? "").toLowerCase();
  const [row] = await sql`select 1 from licensing.admins where email = ${email}`;
  if (!email || !row) throw new HttpError(403, `${email || "this account"} is not a licence administrator`);
  return email;
}

async function licenceRow(id: unknown) {
  const [l] = await sql`select * from licensing.licences where id = ${uuidOf(id)}`;
  if (!l) throw new HttpError(404, "no such licence");
  return l;
}

const event = (lid: string, actor: string, kind: string, detail: Record<string, unknown> = {}) =>
  sql`insert into licensing.events (lid, actor, kind, detail) values (${lid}, ${actor}, ${kind}, ${sql.json(detail as never)})`;

function intIn(v: unknown, lo: number, hi: number, what: string): number {
  const n = Number(v);
  if (!Number.isInteger(n) || n < lo || n > hi) throw new HttpError(400, `${what} must be a whole number from ${lo} to ${hi}`);
  return n;
}

function expiryFrom(b: Record<string, unknown>, from = today()): string {
  if (b.expires) {
    const e = text(b.expires, 10);
    if (!isDate(e)) throw new HttpError(400, "expires must be a date (YYYY-MM-DD)");
    return e;
  }
  const days = intIn(b.days ?? 365, 1, 3650, "days");
  const d = new Date(from + "T00:00:00Z");
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

function features(v: unknown): string[] {
  const list = Array.isArray(v) ? v : String(v ?? "").split(",");
  return list.map((f) => text(f, 40)).filter(Boolean).slice(0, 20);
}

const admin: Record<string, (b: Record<string, unknown>, who: string) => Promise<unknown>> = {
  async me(_b, who) {
    return { email: who, public_key: signer.publicHex() };
  },

  async list() {
    return await sql`
      select l.id, l.customer, l.email, l.nodes, l.features, l.issued, l.expires, l.moves_per_year,
             l.source, l.revoked_at, l.created_at,
             a.machine_name, a.method, a.activated_at, a.last_seen_at,
             (select count(*)::int from licensing.activations m
               where m.lid = l.id and m.released_reason = 'moved'
                 and m.released_at > now() - interval '365 days') as moves_used
        from licensing.licences l
        left join licensing.activations a on a.lid = l.id and a.released_at is null
       order by l.created_at desc`;
  },

  async get(b) {
    const lid = uuidOf(b.id);
    const [l] = await sql`select * from licensing.licences where id = ${lid}`;
    if (!l) throw new HttpError(404, "no such licence");
    const activations = await sql`select * from licensing.activations where lid = ${lid} order by activated_at desc`;
    const events = await sql`select at, actor, kind, detail from licensing.events where lid = ${lid} order by at desc limit 200`;
    return { licence: l, activations, events };
  },

  async issue(b, who) {
    const customer = text(b.customer, 200);
    if (!customer) throw new HttpError(400, "customer is required");
    const lic = {
      lid: crypto.randomUUID(), customer, nodes: intIn(b.nodes, 1, 100000, "nodes"),
      issued: today(), expires: expiryFrom(b), features: features(b.features),
    };
    const key = signer.licenceKey(lic);
    await sql.begin(async (tx) => {
      await tx`insert into licensing.licences (id, customer, email, nodes, features, issued, expires, key,
                 moves_per_year, notes, source)
               values (${lic.lid}, ${customer}, ${text(b.email, 200)}, ${lic.nodes}, ${lic.features}::text[],
                 ${lic.issued}, ${lic.expires}, ${key}, ${intIn(b.moves_per_year ?? 3, 0, 100, "moves_per_year")},
                 ${text(b.notes, 2000)}, 'admin')`;
      await tx`insert into licensing.events (lid, actor, kind, detail)
               values (${lic.lid}, ${who}, 'issued', ${tx.json({ nodes: lic.nodes, expires: lic.expires })})`;
    });
    return { id: lic.lid, key };
  },

  // A new key for the same licence: new expiry and/or node count. Masters
  // pick it up at their next check-in; air-gapped ones need it pasted in.
  async renew(b, who) {
    return await sql.begin(async (tx) => {
      const [l] = await tx`select * from licensing.licences where id = ${uuidOf(b.id)} for update`;
      if (!l) throw new HttpError(404, "no such licence");
      // "days" extends from the current expiry, or from today if it has passed.
      const current = day(l.expires);
      const from = current > today() ? current : today();
      const lic = {
        lid: l.id, customer: text(b.customer, 200) || l.customer,
        nodes: b.nodes == null ? l.nodes : intIn(b.nodes, 1, 100000, "nodes"),
        issued: today(), features: b.features == null ? l.features : features(b.features),
        expires: b.expires || b.days ? expiryFrom(b, from) : current,
      };
      const key = signer.licenceKey(lic);
      await tx`update licensing.licences set customer = ${lic.customer}, nodes = ${lic.nodes},
                 features = ${lic.features}::text[], issued = ${lic.issued}, expires = ${lic.expires},
                 key = ${key}, updated_at = now() where id = ${l.id}`;
      await tx`insert into licensing.events (lid, actor, kind, detail)
               values (${l.id}, ${who}, 'renewed', ${tx.json({ nodes: lic.nodes, expires: lic.expires })})`;
      return { id: l.id, key };
    });
  },

  async update(b, who) {
    return await sql.begin(async (tx) => {
      const [l] = await tx`select * from licensing.licences where id = ${uuidOf(b.id)} for update`;
      if (!l) throw new HttpError(404, "no such licence");
      const moves = b.moves_per_year == null ? l.moves_per_year : intIn(b.moves_per_year, 0, 100, "moves_per_year");
      const email = b.email == null ? l.email : text(b.email, 200);
      const notes = b.notes == null ? l.notes : text(b.notes, 2000);
      await tx`update licensing.licences set moves_per_year = ${moves}, email = ${email}, notes = ${notes},
                 updated_at = now() where id = ${l.id}`;
      await tx`insert into licensing.events (lid, actor, kind, detail)
               values (${l.id}, ${who}, 'updated', ${tx.json({ moves_per_year: moves })})`;
      return { id: l.id };
    });
  },

  async revoke(b, who) {
    const l = await licenceRow(b.id);
    const reason = text(b.reason, 300);
    await sql`update licensing.licences set revoked_at = now(), revoked_reason = ${reason}, updated_at = now()
               where id = ${l.id}`;
    await event(l.id, who, "revoked", { reason });
    return { id: l.id };
  },

  async unrevoke(b, who) {
    const l = await licenceRow(b.id);
    await sql`update licensing.licences set revoked_at = null, revoked_reason = '', updated_at = now()
               where id = ${l.id}`;
    await event(l.id, who, "unrevoked");
    return { id: l.id };
  },

  // Free the licence from its machine without using one of the customer's
  // moves (e.g. that machine died). The old master learns at its next check-in.
  async release(b, who) {
    const l = await licenceRow(b.id);
    const [a] = await sql`update licensing.activations set released_at = now(), released_reason = 'admin'
                           where lid = ${l.id} and released_at is null returning machine_name`;
    if (!a) throw new HttpError(409, "this licence is not active on any machine");
    await event(l.id, who, "released", { machine: a.machine_name });
    return { id: l.id };
  },
};

// ------------------------------------------------------------------ http

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
  if (req.method !== "POST") return json({ message: "POST only" }, 405);
  const path = new URL(req.url).pathname.replace(/^.*?\/licensing\/?/, "").replace(/\/$/, "");
  let body: Record<string, unknown>;
  try {
    body = await req.json();
    if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error();
  } catch {
    return json({ message: "the body must be a JSON object" }, 400);
  }
  try {
    if (path.startsWith("admin/")) {
      const fn = admin[path.slice(6)];
      if (!fn) return json({ message: "not found" }, 404);
      const who = await adminEmail(req);
      return json(await fn(body, who));
    }
    const fn = routes[path];
    if (!fn) return json({ message: "not found" }, 404);
    return json(await fn(body, req));
  } catch (e) {
    if (e instanceof HttpError) return json({ message: e.message }, e.status);
    console.error(path, e);
    return json({ message: "the licence server had a problem - try again shortly" }, 500);
  }
});
