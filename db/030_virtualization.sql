-- 030: type 1 and type 2 hypervisors.
--
-- A host's virtualisation role changes what its failure means. A type 1 host
-- going down takes every guest with it; a type 2 host going down is someone
-- closing a laptop; a guest going down may be one of twenty on a machine
-- that is itself fine.
--
-- The role is inferred from two independent lines of evidence: direct
-- detection (systemd-detect-virt, DMI vendor strings, running hypervisor
-- processes) and hardware evidence (fan RPM, CPU temperature, NICs
-- reporting a negotiated link speed). Bare metal has the latter; a VM has
-- none of it, because there is no fan to spin and no PHY to negotiate.
--
-- Both are stored. Where they disagree, that disagreement is itself worth
-- seeing: a host claiming to be physical with no hardware sensors at all is
-- either lying or misconfigured.

alter table agents add column if not exists virt_role text
    check (virt_role in ('physical','type1_host','type2_host','guest'));
alter table agents add column if not exists hypervisor text;
alter table agents add column if not exists virt_detail jsonb;

create index if not exists agents_virt_role_idx on agents (virt_role);

comment on column agents.virt_role is
    'Inferred, not asserted. virt_detail carries the evidence and the basis so the inference can be argued with.';

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
    o.identity_proof, o.channel_count,
    o.virt_role, o.hypervisor, o.virt_detail,
    -- The number of physical signals found, surfaced directly so a
    -- contradiction is visible without unpacking the json.
    (o.virt_detail -> 'evidence' ->> 'physical_signals')::int as physical_signals
from (
    select t.*, a.display_name, a.notes, a.muted,
           a.provider, a.platform, a.role, a.account, a.site, a.machine_id,
           a.identity_proof, a.virt_role, a.hypervisor, a.virt_detail,
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

-- A type 1 host and everything believed to be running on it. Guests are
-- attributed by site and hypervisor family, which is a guess until the
-- hypervisor's own API confirms it - Proxmox and Nutanix would.
create or replace view virtualization_overview as
select o.id, o.label, o.virt_role, o.hypervisor, o.platform, o.site,
       o.status, o.trust, o.physical_signals,
       o.virt_detail ->> 'basis'              as basis,
       (o.virt_detail ->> 'nested')::boolean  as nested,
       o.virt_detail -> 'runs'                as runs,
       o.virt_detail -> 'evidence'            as evidence,
       case when o.virt_role = 'type1_host' then
         (select count(*) from agent_overview g
           where g.virt_role = 'guest'
             and g.site is not distinct from o.site
             and g.id <> o.id)
       end as guests_here,
       -- Direct detection said physical, hardware said nothing did. Worth a
       -- look: either sensors are not exposed, or the host is not what it
       -- claims.
       (o.virt_role in ('physical','type1_host') and coalesce(o.physical_signals,0) = 0)
         as evidence_conflict
  from agent_overview o
 where o.agent_version is not null;

alter view virtualization_overview set (security_invoker = on);
grant select on virtualization_overview to authenticated;
revoke all on virtualization_overview from anon;

-- The estate split by what each machine is for, alongside the existing bands.
create or replace view health_matrix as
select 'INFRASTRUCTURE'::text as band, upper(coalesce(provider,'other')) as category,
       count(*) as total, count(*) filter (where status='healthy') as healthy,
       round(100.0*count(*) filter (where status='healthy')/nullif(count(*),0)) as pct
  from agent_overview where agent_version is not null and role='server' group by provider
union all
select 'VIRTUALISATION',
       case virt_role when 'type1_host' then 'TYPE 1 HOST'
                      when 'type2_host' then 'TYPE 2 HOST'
                      when 'physical'   then 'BARE METAL'
                      when 'guest'      then 'GUEST'
                      else 'UNKNOWN' end,
       count(*), count(*) filter (where status='healthy'),
       round(100.0*count(*) filter (where status='healthy')/nullif(count(*),0))
  from agent_overview where agent_version is not null group by virt_role
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

-- A type 1 host failing is categorically worse than one guest failing.
insert into alert_rules (rule, severity, cooldown, description) values
    ('hypervisor_down', 'critical', interval '15 minutes',
     'A hypervisor host is offline, taking its guests with it')
on conflict (rule) do nothing;

create or replace function sweep_hypervisors() returns integer
language plpgsql security definer set search_path = public as $$
declare r record; n integer := 0;
begin
    for r in select * from virtualization_overview
              where virt_role = 'type1_host' and status = 'down'
    loop
        if queue_alert(r.id, 'hypervisor_down',
            format('[critical] hypervisor %s is offline', r.label),
            format(E'Host: %s (%s)\nGuests believed to be on it: %s\n\n'
                   'Every guest on this host is unreachable while it is down.',
                   r.label, coalesce(r.hypervisor, 'unknown'),
                   coalesce(r.guests_here, 0)))
        then n := n + 1; end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-hypervisors')
 where exists (select 1 from cron.job where jobname = 'nodewatch-hypervisors');
select cron.schedule('nodewatch-hypervisors', '* * * * *', $$select sweep_hypervisors();$$);
