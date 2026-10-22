-- 049: per-node signing keys.
--
-- An on-premise node used to re-enrol with nothing but its machine id -
-- readable by any local user on Linux, and shown to dashboard viewers - so
-- anyone who knew it could obtain that node's session and send telemetry
-- in its name. From agent 0.5 each node generates an Ed25519 key, registers
-- the public half at first enrolment, and signs every later enrolment with
-- it; the API refuses a returning node whose signature does not verify
-- against the stored key.
--
-- Rows from older agents have no key until their first 0.5 enrolment
-- registers one. A self-hosted master sets NW_REQUIRE_NODE_KEY=true and
-- refuses unsigned enrolment outright.

alter table agents add column if not exists node_key text;

comment on column agents.node_key is
    'Hex Ed25519 public key the node registered at first signed enrolment; every later enrolment must be signed by it.';
