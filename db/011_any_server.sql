-- 011: any server, anywhere - plus deletion and multi-channel alerting.

-- ---------------------------------------------------------------- provider

-- instance_id was AWS-shaped. Generalise without breaking existing rows:
-- for AWS nodes node_id stays the instance ID, for others it is the GCP
-- numeric ID, the Azure vmId, or the machine-id of an on-premise host.
alter table agents add column if not exists provider text not null default 'aws'
    check (provider in ('aws','gcp','azure','generic'));
alter table agents add column if not exists account       text;
alter table agents add column if not exists machine_id    text;
alter table agents add column if not exists fingerprint   jsonb;
alter table agents add column if not exists identity_proof text not null default 'unverified'
    check (identity_proof in ('signed','account','token','unverified'));
alter table agents add column if not exists site text;

comment on column agents.identity_proof is
    'How strongly this node proved itself at last enrolment. signed = a cloud provider cryptographically vouched for it; account = the provider API confirmed it exists; token = only a dashboard-issued invitation; unverified = neither. Displayed rather than hidden, because an on-premise box genuinely is weaker evidence than a signed AWS document.';

comment on column agents.machine_id is
    'Stable per-install identifier. Not proof, but a change means the name was reused by a different machine.';

create index if not exists agents_provider_idx on agents (provider);

-- ---------------------------------------------------------------- deletion

-- Every child table already cascades, so removing an agent removes its
-- telemetry. Deliberate: a deleted server should not leave orphan metrics
-- inflating counts.
drop policy if exists agents_delete on agents;
create policy agents_delete on agents for delete to authenticated using (true);
grant delete on agents to authenticated;

-- Widen the dashboard's insert grant so a server can be registered with a
-- provider and site, not just an AWS instance ID.
grant insert (instance_id, display_name, notes, provider, site) on agents to authenticated;
grant update (display_name, notes, muted, site) on agents to authenticated;

-- ---------------------------------------------------------------- channels

-- Email lives in alert_recipients and keeps working. Everything else routes
-- through here: one row per destination, per node or fleet-wide.
create table if not exists alert_channels (
    id         uuid primary key default gen_random_uuid(),
    agent_id   uuid references agents (id) on delete cascade,   -- null = all nodes
    kind       text not null check (kind in ('telegram','webhook','botim','slack')),
    label      text,
    -- Per-kind settings. telegram: {bot_token, chat_id}
    --                   webhook/slack: {url}
    --                   botim: {url, token, target}
    config     jsonb not null default '{}',
    min_severity text not null default 'warning'
                 check (min_severity in ('critical','warning','info')),
    enabled    boolean not null default true,
    last_ok_at   timestamptz,
    last_error   text,
    last_error_at timestamptz,
    created_at timestamptz not null default now()
);

comment on table alert_channels is
    'Non-email delivery destinations. Secrets live in config and are only ever read by the send-alerts Edge Function using the service role key.';

create index if not exists alert_channels_active_idx on alert_channels (kind)
    where enabled;

alter table alert_channels enable row level security;
drop policy if exists alert_channels_rw on alert_channels;
create policy alert_channels_rw on alert_channels for all to authenticated
    using (true) with check (true);
grant select, insert, update, delete on alert_channels to authenticated;
revoke all on alert_channels from anon;

-- Delivery attempts per channel, so "did the Telegram message arrive" is
-- answerable in the dashboard rather than only in a function log.
create table if not exists alert_deliveries (
    id         bigserial primary key,
    alert_id   bigint  references alert_log (id) on delete cascade,
    channel_id uuid    references alert_channels (id) on delete set null,
    kind       text    not null,
    status     text    not null check (status in ('sent','failed','skipped')),
    detail     text,
    created_at timestamptz not null default now()
);

create index if not exists alert_deliveries_alert_idx on alert_deliveries (alert_id);
create index if not exists alert_deliveries_ts_brin  on alert_deliveries using brin (created_at);

alter table alert_deliveries enable row level security;
drop policy if exists alert_deliveries_read on alert_deliveries;
create policy alert_deliveries_read on alert_deliveries for select to authenticated using (true);
grant select on alert_deliveries to authenticated;
revoke all on alert_deliveries from anon;

-- ---------------------------------------------------------------- queueing

-- queue_alert previously refused to queue when no email recipient existed.
-- A node with a Telegram channel and no email address is now legitimate,
-- so the check widens to "any destination at all".
create or replace function queue_alert(
    p_agent uuid, p_rule text, p_subject text, p_body text
) returns boolean as $$
declare
    r       alert_rules%rowtype;
    last    timestamptz;
    muted_  boolean;
    people  text[];
    chans   integer;
begin
    select * into r from alert_rules where rule = p_rule and enabled;
    if not found then return false; end if;

    select muted into muted_ from agents where id = p_agent;
    if coalesce(muted_, false) then
        insert into alert_log (agent_id, rule, severity, subject, body, status)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed');
        return false;
    end if;

    select last_sent into last from alert_state where agent_id = p_agent and rule = p_rule;
    if last is not null and now() - last < r.cooldown then
        return false;
    end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients
     where (agent_id = p_agent or agent_id is null) and instant;

    select count(*) into chans
      from alert_channels
     where enabled and (agent_id = p_agent or agent_id is null);

    if coalesce(cardinality(people), 0) = 0 and chans = 0 then
        insert into alert_log (agent_id, rule, severity, subject, body, status, error)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed',
                'no destinations configured');
        return false;
    end if;

    insert into alert_log (agent_id, rule, severity, subject, body, recipients)
    values (p_agent, p_rule, r.severity, p_subject, p_body, coalesce(people, '{}'));

    insert into alert_state (agent_id, rule, last_sent) values (p_agent, p_rule, now())
    on conflict (agent_id, rule) do update set last_sent = now();

    return true;
end $$ language plpgsql security definer;

-- ---------------------------------------------------------------- views

drop view if exists agent_overview;
create view agent_overview as
select
    o.id, o.instance_id, o.hostname, o.os, o.region, o.agent_version, o.last_seen,
    o.seconds_since_seen, o.external_ports, o.failed_logins_1h, o.new_exposure_24h,
    o.account_changes_24h, o.priv_changes_24h, o.file_changes_24h,
    o.critical_file_changes_24h, o.checks_failed, o.checks_failed_high,
    o.vulns_total, o.vulns_severe,
    o.f_recency, o.f_exposure, o.f_auth, o.f_churn, o.f_posture, o.f_integrity,
    case when o.agent_version is null then 'pending' else o.status end as status,
    case when o.agent_version is null then null      else o.trust  end as trust,
    case when o.agent_version is null then false else o.needs_reverification end as needs_reverification,
    o.display_name, o.notes, o.muted, o.label, o.recipient_count, o.last_alert_at,
    o.files_watched, o.package_count,
    o.provider, o.account, o.site, o.machine_id, o.identity_proof,
    o.channel_count
from (
    select t.*, a.display_name, a.notes, a.muted,
           a.provider, a.account, a.site, a.machine_id, a.identity_proof,
           coalesce(a.display_name, t.hostname, t.instance_id) as label,
           (select count(*) from alert_recipients r
             where r.agent_id = t.id or r.agent_id is null)    as recipient_count,
           (select count(*) from alert_channels c
             where c.enabled and (c.agent_id = t.id or c.agent_id is null)) as channel_count,
           (select max(created_at) from alert_log l where l.agent_id = t.id) as last_alert_at,
           (select files_watched from fim_state f where f.agent_id = t.id)   as files_watched,
           (select count(*) from host_packages p where p.agent_id = t.id)    as package_count
      from agent_trust t join agents a on a.id = t.id
) o;

alter view agent_overview set (security_invoker = on);
grant select on agent_overview to authenticated;
revoke all on agent_overview from anon;

-- Channel health, so a broken Telegram token is visible without log digging.
drop view if exists alert_channel_status;
create view alert_channel_status as
select c.id, c.agent_id, c.kind, c.label, c.config, c.min_severity, c.enabled,
       c.last_ok_at, c.last_error, c.last_error_at, c.created_at,
       -- Which node this channel belongs to; null means fleet-wide.
       coalesce(a.display_name, a.hostname, a.instance_id) as node_label,
       (select count(*) from alert_deliveries d
         where d.channel_id = c.id and d.status = 'sent'
           and d.created_at > now() - interval '7 days')   as sent_7d,
       (select count(*) from alert_deliveries d
         where d.channel_id = c.id and d.status = 'failed'
           and d.created_at > now() - interval '7 days')   as failed_7d
from alert_channels c
left join agents a on a.id = c.agent_id;

alter view alert_channel_status set (security_invoker = on);
grant select on alert_channel_status to authenticated;
revoke all on alert_channel_status from anon;

-- ---------------------------------------------------------------- token helper

-- A token plus the provider it is intended for, so the dashboard can render
-- a ready-to-paste install command per platform.
create or replace function new_enroll_token(p_label text default null,
                                            p_hours integer default 24)
returns text as $$
declare t text;
begin
    t := encode(gen_random_bytes(24), 'hex');
    insert into enroll_tokens (token, label, expires_at)
    values (t, p_label, now() + make_interval(hours => p_hours));
    return t;
end $$ language plpgsql security definer;
