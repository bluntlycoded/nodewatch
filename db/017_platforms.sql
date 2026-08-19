-- 017: Windows and macOS hosts.
--
-- The agent now runs on Linux, Windows and macOS. Telemetry keeps the same
-- shape everywhere - the platform modules normalise it - but the platform
-- itself is worth recording: posture check ids differ per OS, and an
-- operator wants to see the estate split by OS, not only by cloud.

alter table agents add column if not exists platform text not null default 'linux'
    check (platform in ('linux','windows','macos'));

comment on column agents.platform is
    'Set from the agent''s own detection at enrolment. provider says where a host runs; platform says what it runs.';

create index if not exists agents_platform_idx on agents (platform);

-- Existing rows are all Linux, which the default already handles. Anything
-- whose reported OS says otherwise gets corrected here.
update agents set platform = 'windows' where os ilike 'windows%' and platform = 'linux';
update agents set platform = 'macos'   where os ilike 'macos%'   and platform = 'linux';

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
    o.provider, o.platform, o.account, o.site, o.machine_id, o.identity_proof,
    o.channel_count
from (
    select t.*, a.display_name, a.notes, a.muted,
           a.provider, a.platform, a.account, a.site, a.machine_id, a.identity_proof,
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

-- Group the estate by operating system as well as by provider: on a mixed
-- fleet "how are the Windows machines doing" is the more useful question.
create or replace view health_matrix as
select 'INFRASTRUCTURE'::text as band,
       upper(coalesce(provider, 'other')) as category,
       count(*)                                   as total,
       count(*) filter (where status = 'healthy') as healthy,
       round(100.0 * count(*) filter (where status = 'healthy')
             / nullif(count(*), 0)) as pct
  from agent_overview where agent_version is not null
 group by provider
union all
select 'OPERATING SYSTEM',
       case platform when 'linux' then 'LINUX'
                     when 'windows' then 'WINDOWS'
                     else 'MACOS' end,
       count(*),
       count(*) filter (where status = 'healthy'),
       round(100.0 * count(*) filter (where status = 'healthy') / nullif(count(*), 0))
  from agent_overview where agent_version is not null
 group by platform
union all
select 'SYNTHETIC', upper(kind), count(*),
       count(*) filter (where status = 'up'),
       round(100.0 * count(*) filter (where status = 'up') / nullif(count(*), 0))
  from probe_state where enabled
 group by kind;

alter view health_matrix set (security_invoker = on);
grant select on health_matrix to authenticated;
revoke all on health_matrix from anon;

create or replace view availability_summary as
select 'host'::text as object_kind, a.id as object_id,
       coalesce(a.display_name, a.hostname, a.instance_id) as name,
       coalesce(a.provider, 'aws') as category, a.site,
       (select pct from host_availability(interval '24 hours') h where h.agent_id = a.id) as avail_24h,
       (select pct from host_availability(interval '7 days')   h where h.agent_id = a.id) as avail_7d,
       (select pct from host_availability(interval '30 days')  h where h.agent_id = a.id) as avail_30d
  from agents a where a.agent_version is not null
union all
select 'probe', p.id, p.name, p.category, p.site,
       (select pct from probe_availability(interval '24 hours') q where q.probe_id = p.id),
       (select pct from probe_availability(interval '7 days')   q where q.probe_id = p.id),
       (select pct from probe_availability(interval '30 days')  q where q.probe_id = p.id)
  from probes p;

alter view availability_summary set (security_invoker = on);
grant select on availability_summary to authenticated;
revoke all on availability_summary from anon;
