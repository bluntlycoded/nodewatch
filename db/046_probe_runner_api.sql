-- 046: phase 2 of multi-tenancy - the probe runner stops connecting to
-- Postgres directly (NW_DATABASE_URL, a service-role credential that
-- bypasses RLS and can read/write every tenant's data) and becomes an
-- authenticated API client instead, exactly like an agent already is.
-- This is what the approved plan flagged as the actual blocker for
-- "master node" meaning anything a customer can run on their own
-- infrastructure - see the plan's phase 2 section for the full design.
--
-- This migration only adds what the API needs server-side: a kind
-- discriminator on enroll_tokens (a probe-runner token must not be
-- usable to enroll an agent, or vice versa) and master_nodes, the
-- probe-runner equivalent of agents - one row per enrolled runner,
-- identified by a locally-generated client_id rather than any cloud
-- attestation, since a probe runner is a service process, not a
-- specific piece of cloud-identified hardware.

alter table enroll_tokens add column if not exists kind text not null default 'agent'
    check (kind in ('agent', 'probe_runner'));

-- create or replace cannot change a function's parameter list in place -
-- adding p_kind here would leave the old (text, integer) signature
-- alongside this one as an overload, and a bare two-argument call (the
-- dashboard's existing "Issue token" button) then fails at runtime with
-- "function is not unique", since Postgres cannot pick between them when
-- both parameters are passed by name. Drop the old signature explicitly
-- rather than relying on create or replace to do it - verified against a
-- live Postgres, since this exact ambiguity is easy to write and not
-- catch by reading the file.
drop function if exists new_enroll_token(text, integer);

create or replace function new_enroll_token(p_label text default null,
                                            p_hours integer default 24,
                                            p_kind text default 'agent')
returns text
language plpgsql
security definer
set search_path = public
as $$
declare t text;
begin
    if not is_admin() then
        raise exception 'only an admin can issue enrolment tokens';
    end if;
    if p_kind not in ('agent', 'probe_runner') then
        raise exception 'unknown token kind %', p_kind;
    end if;
    t := encode(gen_random_bytes(24), 'hex');
    insert into enroll_tokens (token, label, expires_at, tenant_id, kind)
    values (t, p_label, now() + make_interval(hours => p_hours), current_tenant(), p_kind);
    return t;
end $$;

create table if not exists master_nodes (
    id           uuid primary key default gen_random_uuid(),
    tenant_id    uuid not null references tenants(id),
    -- Generated once by the probe runner on first successful enrolment and
    -- kept in local state (see probe/prober.py's STATE_PATH) - the same
    -- role instance_id plays for an agent, but with no cloud attestation
    -- backing it, since this is a service process, not identified hardware.
    client_id    uuid not null,
    label        text,
    hostname     text,
    version      text,
    enrolled_at  timestamptz not null default now(),
    last_seen    timestamptz,
    enroll_count integer not null default 0
);
create unique index if not exists master_nodes_tenant_client_idx
    on master_nodes (tenant_id, client_id);
create index if not exists master_nodes_tenant_idx on master_nodes (tenant_id);

alter table master_nodes enable row level security;
-- Written only by the API's service-role connection (bypasses RLS), same
-- as agents - authenticated users only ever read this table.
drop policy if exists master_nodes_read on master_nodes;
create policy master_nodes_read on master_nodes for select to authenticated
    using (tenant_id = current_tenant());
grant select on master_nodes to authenticated;
revoke all on master_nodes from anon;

-- enroll_token_status (db/012_rbac.sql) needs kind added to its column
-- list so the dashboard can tell an agent token from a master-node one
-- without a second query. kind is appended at the end, not inserted
-- alongside the other source columns - create or replace view cannot
-- reorder or insert into an existing view's column list, only append
-- (42P16, the same class of error this repo hit earlier tidying up
-- db/022's views), verified against a live Postgres rather than assumed.
create or replace view enroll_token_status as
select token, label, created_at, expires_at, used_at, used_by, revoked,
       case when revoked            then 'revoked'
            when used_at is not null then 'used'
            when expires_at < now()  then 'expired'
            else 'open' end as status,
       kind
from enroll_tokens;
alter view enroll_token_status set (security_invoker = on);
