// Licence keys, activation codes and request codes - the formats the master
// reads in server/nodewatch_server/license.py. Keep the two in step.
//
//   NW1-<payload>.<signature>    licence key: signature over the payload
//   NWA1-<payload>.<signature>   activation: signature over
//                                "nodewatch-activation:" + payload, so a
//                                licence signature can never pass as one
//   NWR1-<payload>               offline request from a master, unsigned
//
// payload and signature are base64url without padding; payloads are JSON.

import { ed25519 } from "npm:@noble/curves@1.9.1/ed25519";

export const LICENCE_PREFIX = "NW1-";
export const ACTIVATION_PREFIX = "NWA1-";
export const REQUEST_PREFIX = "NWR1-";
const ACTIVATION_DOMAIN = new TextEncoder().encode("nodewatch-activation:");

export class KeyError extends Error {}

export type Licence = {
  lid: string;
  customer: string;
  nodes: number;
  issued: string;
  expires: string;
  features: string[];
  key: string;
};

export function b64e(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64d(s: string): Uint8Array {
  const t = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(t + "=".repeat((4 - (t.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// The vendor key as tools/license_tool.py writes it: PKCS#8 PEM, unencrypted.
const PKCS8_ED25519 = "302e020100300506032b657004220420";

export class Signer {
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;

  constructor(pem: string) {
    const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
    const head = Array.from(der.slice(0, 16), (x) => x.toString(16).padStart(2, "0")).join("");
    if (der.length !== 48 || head !== PKCS8_ED25519) {
      throw new Error("LICENCE_SIGNING_KEY is not an unencrypted Ed25519 PKCS#8 PEM key");
    }
    this.seed = der.slice(16);
    this.publicKey = ed25519.getPublicKey(this.seed);
  }

  publicHex(): string {
    return Array.from(this.publicKey, (x) => x.toString(16).padStart(2, "0")).join("");
  }

  // Same payload shape and field order as license_tool.py's issue().
  licenceKey(l: Omit<Licence, "key">): string {
    const payload = new TextEncoder().encode(JSON.stringify({
      v: 1, lid: l.lid, customer: l.customer, nodes: l.nodes,
      issued: l.issued, expires: l.expires, features: l.features,
    }));
    return LICENCE_PREFIX + b64e(payload) + "." + b64e(ed25519.sign(payload, this.seed));
  }

  activation(a: { lid: string; machine: string; name: string; activated: string; method: string }): string {
    const payload = new TextEncoder().encode(JSON.stringify({ v: 1, kind: "activation", ...a }));
    const signed = new Uint8Array(ACTIVATION_DOMAIN.length + payload.length);
    signed.set(ACTIVATION_DOMAIN);
    signed.set(payload, ACTIVATION_DOMAIN.length);
    return ACTIVATION_PREFIX + b64e(payload) + "." + b64e(ed25519.sign(signed, this.seed));
  }

  parseLicence(raw: string): Licence {
    const key = (raw || "").replace(/\s+/g, "");
    if (!key.startsWith(LICENCE_PREFIX) || !key.includes(".")) throw new KeyError("not a nodewatch licence key");
    const [body, sig] = key.slice(LICENCE_PREFIX.length).split(".", 2);
    let payload: Uint8Array, signature: Uint8Array;
    try {
      payload = b64d(body);
      signature = b64d(sig);
    } catch {
      throw new KeyError("licence key is damaged");
    }
    let good = false;
    try {
      good = ed25519.verify(signature, payload, this.publicKey);
    } catch { /* malformed signature */ }
    if (!good) throw new KeyError("licence key signature is not valid");
    try {
      const p = JSON.parse(new TextDecoder().decode(payload));
      const l: Licence = {
        lid: String(p.lid), customer: String(p.customer), nodes: Number(p.nodes),
        issued: String(p.issued ?? p.expires), expires: String(p.expires),
        features: Array.isArray(p.features) ? p.features.map(String) : [], key,
      };
      if (!isUuid(l.lid) || !Number.isInteger(l.nodes) || !isDate(l.expires) || !isDate(l.issued)) {
        throw new Error("fields");
      }
      return l;
    } catch {
      throw new KeyError("licence key payload is invalid");
    }
  }
}

export function parseRequest(raw: string): { lid: string; machine: string; name: string } {
  const code = (raw || "").replace(/\s+/g, "");
  if (!code.startsWith(REQUEST_PREFIX)) throw new KeyError("not a nodewatch activation request code");
  try {
    const p = JSON.parse(new TextDecoder().decode(b64d(code.slice(REQUEST_PREFIX.length))));
    const r = { lid: String(p.lid), machine: String(p.m), name: String(p.n ?? "").slice(0, 100) };
    if (!isUuid(r.lid) || !isMachine(r.machine)) throw new Error("fields");
    return r;
  } catch {
    throw new KeyError("the request code is damaged - copy it again from the master");
  }
}

export const isUuid = (s: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
export const isMachine = (s: string) => /^[0-9a-f]{32}$/.test(s);
export const isDate = (s: string) => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
