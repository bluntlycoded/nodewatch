-- 006: node management and alert configuration, all driven from the dashboard.
--
-- Write access is deliberately narrow: the dashboard can set a display name
-- and pre-register a node, but cannot touch instance_id, enrolment counters,
-- or any telemetry. That is enforced with column-level grants rather than
-- trusting the client to only send the right fields.

alter table agents add column if not exists display_name text;
alter table agents add column if not exists notes        text;
alter table agents add column if not exists muted        boolean not null default false;

comment on column agents.display_name is
    'Operator-assigned label. Survives re-enrolment because the ingest API''s upsert never touches this column.';
comment on column agents.muted is
    'Suppresses alerts for this node without deleting its recipients.';

-- ---------------------------------------------------------------- recipients

create table if not exists alert_recipients (
    id         uuid primary key default gen_random_uuid(),
    agent_id   uuid references agents (id) on delete cascade,  -- null = all nodes
    email      text not null check (email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
    digest     boolean not null default true,
    instant    boolean not null default true,
    created_at timestamptz not null default now()
);

comment on column alert_recipients.agent_id is
    'Null means every node, so a standing recipient does not have to be re-added per node.';

create unique index if not exists alert_recipients_unique
    on alert_recipients (coalesce(agent_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(email));

-- Cap recipients per node. Enforced in the database so it holds regardless
-- of which client is talking to it.
create or replace function enforce_recipient_cap() returns trigger as $$
declare n integer;
begin
    select count(*) into n from alert_recipients
     where agent_id is not distinct from new.agent_id;
    if n >= 5 then
        raise exception 'At most 5 recipients per node (or 5 global recipients)';
    end if;
    return new;
end $$ language plpgsql;

drop trigger if exists alert_recipients_cap on alert_recipients;
create trigger alert_recipients_cap before insert on alert_recipients
    for each row execute function enforce_recipient_cap();

-- ---------------------------------------------------------------- alert plumbing

-- Per-rule, per-node cooldown. Without this a flapping host would send
-- one email per poll cycle.
create table if not exists alert_state (
    agent_id  uuid not null references agents (id) on delete cascade,
    rule      text not null,
    last_sent timestamptz not null default now(),
    primary key (agent_id, rule)
);

create table if not exists alert_log (
    id         bigserial primary key,
    agent_id   uuid references agents (id) on delete set null,
    rule       text not null,
    severity   text not null check (severity in ('critical','warning','info')),
    subject    text not null,
    body       text,
    recipients text[] not null default '{}',
    status     text not null default 'pending'
               check (status in ('pending','sent','failed','suppressed')),
    error      text,
    created_at timestamptz not null default now(),
    sent_at    timestamptz
);

create index if not exists alert_log_pending_idx on alert_log (created_at)
    where status = 'pending';
create index if not exists alert_log_agent_idx on alert_log (agent_id, created_at desc);

-- ---------------------------------------------------------------- rls

alter table alert_recipients enable row level security;
alter table alert_state      enable row level security;
alter table alert_log        enable row level security;

drop policy if exists alert_recipients_all on alert_recipients;
create policy alert_recipients_all on alert_recipients
    for all to authenticated using (true) with check (true);

drop policy if exists alert_log_read on alert_log;
create policy alert_log_read on alert_log for select to authenticated using (true);

drop policy if exists alert_state_read on alert_state;
create policy alert_state_read on alert_state for select to authenticated using (true);

grant select, insert, update, delete on alert_recipients to authenticated;
grant select on alert_log, alert_state to authenticated;
grant usage, select on sequence alert_log_id_seq to authenticated;
revoke all on alert_recipients, alert_log, alert_state from anon;

-- Agents: the dashboard may rename, annotate, mute, and pre-register.
-- Nothing else. Column-level grants make that structural.
drop policy if exists agents_write on agents;
create policy agents_write on agents
    for update to authenticated using (true) with check (true);

drop policy if exists agents_insert on agents;
create policy agents_insert on agents
    for insert to authenticated with check (true);

grant update (display_name, notes, muted) on agents to authenticated;
grant insert (instance_id, display_name, notes)  on agents to authenticated;

-- ---------------------------------------------------------------- views

-- Adds the operator label and recipient count to the trust view, so the
-- dashboard needs one query rather than three.
drop view if exists agent_overview;
create view agent_overview as
select
    t.id, t.instance_id, t.hostname, t.os, t.region, t.agent_version, t.last_seen,
    t.seconds_since_seen, t.external_ports, t.failed_logins_1h,
    t.new_exposure_24h, t.account_changes_24h, t.priv_changes_24h,
    t.checks_failed, t.checks_failed_high,
    t.f_recency, t.f_exposure, t.f_auth, t.f_churn, t.f_posture,

    -- A node registered from the dashboard but never contacted is 'pending',
    -- not 'down'. Reporting it as down would be a false alarm on day one,
    -- and reporting it healthy would be worse.
    case when t.agent_version is null then 'pending' else t.status end as status,
    case when t.agent_version is null then null      else t.trust  end as trust,
    case when t.agent_version is null then false
         else t.needs_reverification end                               as needs_reverification,

    a.display_name,
    a.notes,
    a.muted,
    coalesce(a.display_name, t.hostname, t.instance_id)          as label,
    (select count(*) from alert_recipients r
      where r.agent_id = t.id or r.agent_id is null)             as recipient_count,
    (select max(created_at) from alert_log l where l.agent_id = t.id) as last_alert_at
from agent_trust t
join agents a on a.id = t.id;

alter view agent_overview set (security_invoker = on);
grant select on agent_overview to authenticated;
revoke all on agent_overview from anon;
