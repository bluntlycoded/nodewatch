-- 019: desktops, and ad-hoc network tools.

-- ---------------------------------------------------------------- role

-- A laptop and a database server run the same agent and report the same
-- telemetry, but they are not the same thing operationally: a desktop being
-- offline overnight is expected, a server being offline is an incident.
alter table agents add column if not exists role text not null default 'server'
    check (role in ('server','desktop'));

comment on column agents.role is
    'Operator classification, not detection. Guessed once at enrolment from the platform, then editable - only a person knows whether a given machine is someone''s laptop.';

create index if not exists agents_role_idx on agents (role);

-- Initial guess: macOS is almost always someone's machine, Windows usually
-- is, Linux usually is not. Wrong guesses are corrected in the dashboard.
update agents set role = 'desktop'
 where role = 'server' and platform in ('macos', 'windows');

grant update (display_name, notes, muted, site, role) on agents to authenticated;

-- ---------------------------------------------------------------- net tools

-- Diagnostics run on demand from the probe host, which is the only place
-- with a route to internal targets. Requests are queued rather than executed
-- inline so the dashboard never blocks on a traceroute.
create table if not exists nettool_jobs (
    id          uuid primary key default gen_random_uuid(),
    tool        text not null check (tool in ('ping','traceroute','dns','portscan','http')),
    target      text not null,
    options     jsonb not null default '{}',
    status      text not null default 'queued'
                check (status in ('queued','running','done','failed')),
    output      text,
    duration_ms integer,
    requested_by text,
    created_at  timestamptz not null default now(),
    started_at  timestamptz,
    finished_at timestamptz
);

create index if not exists nettool_queue_idx on nettool_jobs (created_at)
    where status = 'queued';
create index if not exists nettool_recent_idx on nettool_jobs (created_at desc);

alter table nettool_jobs enable row level security;

drop policy if exists nettool_read on nettool_jobs;
drop policy if exists nettool_write on nettool_jobs;
-- Anyone signed in may read results, but only an admin may run a tool: a
-- port scan is an active probe of someone else's network, not a lookup.
create policy nettool_read  on nettool_jobs for select to authenticated using (true);
create policy nettool_write on nettool_jobs for insert to authenticated
    with check (is_admin());

grant select, insert on nettool_jobs to authenticated;
revoke all on nettool_jobs from anon;

-- Results are diagnostic, not evidence. A week is plenty.
select cron.unschedule('nodewatch-nettool-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-nettool-retention');
select cron.schedule('nodewatch-nettool-retention', '55 4 * * *',
    $$delete from nettool_jobs where created_at < now() - interval '7 days';$$);

-- ---------------------------------------------------------------- views

drop view if exists agent_overview cascade;

create view agent_overview as
select
    o.id, o.instance_id, o.hostname, o.os, o.region, o.agent_version, o.last_seen,
    o.seconds_since_seen, o.offline_for, o.external_ports, o.failed_logins_1h,
    o.new_exposure_24h, o.account_changes_24h, o.priv_changes_24h,
    o.file_changes_24h, o.critical_file_changes_24h, o.checks_failed,
    o.checks_failed_high, o.vulns_total, o.vulns_severe,
    o.f_recency, o.f_exposure, o.f_auth, o.f_churn, o.f_posture, o.f_integrity,
    case when o.agent_version is null then 'pending' else o.status end as status,
    case when o.agent_version is null then null      else o.trust  end as trust,
    case when o.agent_version is null then false else o.needs_reverification end as needs_reverification,
    o.display_name, o.notes, o.muted, o.label, o.recipient_count, o.last_alert_at,
    o.files_watched, o.package_count,
    o.provider, o.platform, o.role, o.account, o.site, o.machine_id,
    o.identity_proof, o.channel_count
from (
    select t.*, a.display_name, a.notes, a.muted,
           a.provider, a.platform, a.role, a.account, a.site, a.machine_id,
           a.identity_proof,
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

create or replace view health_matrix as
select 'INFRASTRUCTURE'::text as band, upper(coalesce(provider,'other')) as category,
       count(*) as total, count(*) filter (where status='healthy') as healthy,
       round(100.0*count(*) filter (where status='healthy')/nullif(count(*),0)) as pct
  from agent_overview where agent_version is not null and role='server' group by provider
union all
select 'ENDPOINTS', upper(platform), count(*), count(*) filter (where status='healthy'),
       round(100.0*count(*) filter (where status='healthy')/nullif(count(*),0))
  from agent_overview where agent_version is not null and role='desktop' group by platform
union all
select 'OPERATING SYSTEM', upper(platform), count(*), count(*) filter (where status='healthy'),
       round(100.0*count(*) filter (where status='healthy')/nullif(count(*),0))
  from agent_overview where agent_version is not null group by platform
union all
select 'SYNTHETIC', upper(kind), count(*), count(*) filter (where status='up'),
       round(100.0*count(*) filter (where status='up')/nullif(count(*),0))
  from probe_state where enabled group by kind;

alter view health_matrix set (security_invoker = on);
grant select on health_matrix to authenticated;
revoke all on health_matrix from anon;

create or replace view availability_summary as
select 'host'::text as object_kind, a.id as object_id,
       coalesce(a.display_name, a.hostname, a.instance_id) as name,
       coalesce(a.provider,'aws') as category, a.site,
       (select pct from host_availability(interval '24 hours') h where h.agent_id=a.id) as avail_24h,
       (select pct from host_availability(interval '7 days')   h where h.agent_id=a.id) as avail_7d,
       (select pct from host_availability(interval '30 days')  h where h.agent_id=a.id) as avail_30d
  from agents a where a.agent_version is not null
union all
select 'probe', p.id, p.name, p.category, p.site,
       (select pct from probe_availability(interval '24 hours') q where q.probe_id=p.id),
       (select pct from probe_availability(interval '7 days')   q where q.probe_id=p.id),
       (select pct from probe_availability(interval '30 days')  q where q.probe_id=p.id)
  from probes p;

alter view availability_summary set (security_invoker = on);
grant select on availability_summary to authenticated;
revoke all on availability_summary from anon;
