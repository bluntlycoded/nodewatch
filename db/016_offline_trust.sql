-- 016: an unreachable host scores zero.
--
-- Recency decays linearly to zero at five minutes, but a host is called
-- 'down' at three. In that two-minute window the dashboard showed a host as
-- down while still reporting a trust of eight or twenty, which reads as a
-- contradiction and undersells the point: we cannot verify anything about a
-- host we cannot reach, so there is nothing to be partly confident about.
--
-- Also exposes offline_for, so the interface can say how long contact has
-- been lost rather than only that it has.

-- availability_summary and health_matrix read agent_overview, so the drop
-- has to cascade and both are rebuilt at the end of this file.
drop view if exists agent_overview cascade;
drop view if exists agent_trust cascade;

create view agent_trust as
with base as (
    select
        a.id, a.instance_id, a.hostname, a.os, a.region, a.agent_version, a.last_seen,
        extract(epoch from (now() - a.last_seen)) as age_s,
        (select count(*) from port_state p
          where p.agent_id = a.id and p.external)                as external_ports,
        (select count(*) from auth_events e
          where e.agent_id = a.id and e.kind = 'login_failed'
            and e.ts > now() - interval '1 hour')                as failed_1h,
        (select count(*) from port_events v
          where v.agent_id = a.id and v.action = 'opened' and v.external
            and v.ts > now() - interval '24 hours')              as new_exposure_24h,
        (select count(*) from user_events u
          where u.agent_id = a.id
            and u.ts > now() - interval '24 hours')              as account_changes_24h,
        (select count(*) from user_events u
          where u.agent_id = a.id and u.sudoer
            and u.action in ('added','modified')
            and u.ts > now() - interval '24 hours')              as priv_changes_24h,
        (select count(*) from fim_events f
          where f.agent_id = a.id
            and f.ts > now() - interval '24 hours')              as file_changes_24h,
        (select count(*) from fim_events f
          where f.agent_id = a.id and f.critical
            and f.ts > now() - interval '24 hours')              as critical_file_changes_24h,
        coalesce((select score from agent_posture q where q.agent_id = a.id), 1.0)::float as posture,
        coalesce((select failed from agent_posture q where q.agent_id = a.id), 0)      as checks_failed,
        coalesce((select failed_high from agent_posture q where q.agent_id = a.id), 0) as checks_failed_high,
        coalesce((select severe from agent_vulns v where v.agent_id = a.id), 0)        as vulns_severe,
        coalesce((select total  from agent_vulns v where v.agent_id = a.id), 0)        as vulns_total
    from agents a
),
factors as (
    select *,
        greatest(0, least(1, (300 - age_s) / 255.0))       as f_recency,
        1.0 / (1 + 0.25 * greatest(0, external_ports - 1)) as f_exposure,
        1.0 / (1 + 0.5 * failed_1h)                        as f_auth,
        1.0 / (1 + 0.5 * new_exposure_24h
                 + 0.3 * account_changes_24h
                 + 1.0 * priv_changes_24h)                 as f_churn,
        posture                                            as f_posture,
        1.0 / (1 + 0.05 * file_changes_24h
                 + 0.50 * critical_file_changes_24h
                 + 0.10 * vulns_severe)                    as f_integrity,
        case when age_s < 45 then 'healthy'
             when age_s < 180 then 'degraded'
             else 'down' end                               as status_
    from base
)
select
    id, instance_id, hostname, os, region, agent_version, last_seen,
    age_s::int as seconds_since_seen,
    -- How long contact has been lost. Null while the host is still reporting.
    case when status_ = 'down' then age_s::int else null end as offline_for,
    external_ports, failed_1h as failed_logins_1h, new_exposure_24h,
    account_changes_24h, priv_changes_24h,
    file_changes_24h, critical_file_changes_24h,
    checks_failed, checks_failed_high, vulns_total, vulns_severe,
    status_ as status,

    round(f_recency::numeric,3)   as f_recency,
    round(f_exposure::numeric,3)  as f_exposure,
    round(f_auth::numeric,3)      as f_auth,
    round(f_churn::numeric,3)     as f_churn,
    round(f_posture::numeric,3)   as f_posture,
    round(f_integrity::numeric,3) as f_integrity,

    -- Unreachable is not "slightly trusted". Everything we know about a
    -- silent host is stale by definition, so the score is zero rather than
    -- a decayed remainder.
    case when status_ = 'down' then 0
         else round(100 * f_recency * (
                0.18 * f_exposure +
                0.26 * f_auth +
                0.13 * f_churn +
                0.23 * f_posture +
                0.20 * f_integrity)::numeric)::int
    end as trust,

    case when status_ = 'down' then true
         when 100 * f_recency * (0.18*f_exposure + 0.26*f_auth + 0.13*f_churn
                               + 0.23*f_posture + 0.20*f_integrity) < 70
         then true else false end as needs_reverification
from factors;

alter view agent_trust set (security_invoker = on);
grant select on agent_trust to authenticated;
revoke all on agent_trust from anon;

create view agent_overview as
select
    o.id, o.instance_id, o.hostname, o.os, o.region, o.agent_version, o.last_seen,
    o.seconds_since_seen, o.offline_for, o.external_ports, o.failed_logins_1h,
    o.new_exposure_24h, o.account_changes_24h, o.priv_changes_24h,
    o.file_changes_24h, o.critical_file_changes_24h, o.checks_failed,
    o.checks_failed_high, o.vulns_total, o.vulns_severe,
    o.f_recency, o.f_exposure, o.f_auth, o.f_churn, o.f_posture, o.f_integrity,
    -- A node registered from the dashboard but never contacted is 'pending',
    -- not offline: it was never on.
    case when o.agent_version is null then 'pending' else o.status end as status,
    case when o.agent_version is null then null      else o.trust  end as trust,
    case when o.agent_version is null then false else o.needs_reverification end as needs_reverification,
    o.display_name, o.notes, o.muted, o.label, o.recipient_count, o.last_alert_at,
    o.files_watched, o.package_count,
    o.provider, o.account, o.site, o.machine_id, o.identity_proof, o.channel_count
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

-- ---------------------------------------------------------------- rebuilt dependents

create or replace view health_matrix as
select 'INFRASTRUCTURE'::text as band,
       upper(coalesce(provider, 'other')) as category,
       count(*)                                   as total,
       count(*) filter (where status = 'healthy') as healthy,
       round(100.0 * count(*) filter (where status = 'healthy')
             / nullif(count(*), 0)) as pct
  from agent_overview
 where agent_version is not null
 group by provider
union all
select 'SYNTHETIC',
       upper(kind),
       count(*),
       count(*) filter (where status = 'up'),
       round(100.0 * count(*) filter (where status = 'up') / nullif(count(*), 0))
  from probe_state
 where enabled
 group by kind;

alter view health_matrix set (security_invoker = on);
grant select on health_matrix to authenticated;
revoke all on health_matrix from anon;

create or replace view availability_summary as
select 'host'::text as object_kind,
       a.id         as object_id,
       coalesce(ag.display_name, ag.hostname, ag.instance_id) as name,
       coalesce(ag.provider, 'aws')  as category,
       ag.site,
       (select pct from host_availability(interval '24 hours') h where h.agent_id = a.id) as avail_24h,
       (select pct from host_availability(interval '7 days')   h where h.agent_id = a.id) as avail_7d,
       (select pct from host_availability(interval '30 days')  h where h.agent_id = a.id) as avail_30d
  from agents a
  join agents ag on ag.id = a.id
 where a.agent_version is not null
union all
select 'probe', p.id, p.name, p.category, p.site,
       (select pct from probe_availability(interval '24 hours') q where q.probe_id = p.id),
       (select pct from probe_availability(interval '7 days')   q where q.probe_id = p.id),
       (select pct from probe_availability(interval '30 days')  q where q.probe_id = p.id)
  from probes p;

alter view availability_summary set (security_invoker = on);
grant select on availability_summary to authenticated;
revoke all on availability_summary from anon;
