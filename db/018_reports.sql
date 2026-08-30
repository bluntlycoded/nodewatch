-- 018: reports.
--
-- Each report is a function taking a period, returning a flat result set.
-- Computed in the database rather than the browser so the same numbers back
-- an on-screen table, a CSV export, and anything queried directly later.
--
-- All three read data already collected; nothing new ships from the agent.

-- ---------------------------------------------------------------- availability

create or replace function report_availability(p_days integer default 30)
returns table (
    object_kind  text,
    name         text,
    category     text,
    site         text,
    samples      bigint,
    uptime_pct   numeric,
    downtime_min numeric,
    outages      bigint,
    mttr_min     numeric,
    worst_min    numeric,
    last_outage  timestamptz
)
language sql stable security definer set search_path = public as $$
    with win as (select make_interval(days => p_days) as iv)
    -- Hosts: availability derived from the 5-minute trust snapshots, which
    -- measures whether the agent was reporting. That is what an agent-based
    -- figure can honestly claim; it is observability, not service health.
    select 'host'::text,
           coalesce(a.display_name, a.hostname, a.instance_id),
           coalesce(a.provider, 'unknown'),
           a.site,
           count(t.*),
           round(100.0 * count(*) filter (where t.status <> 'down')
                 / nullif(count(t.*), 0), 3),
           round(count(*) filter (where t.status = 'down') * 5.0, 1),
           (select count(*) from host_outages o where o.agent_id = a.id),
           (select round(avg(o.duration_s)/60.0, 1) from host_outages o where o.agent_id = a.id),
           (select round(max(o.duration_s)/60.0, 1) from host_outages o where o.agent_id = a.id),
           (select max(o.ended) from host_outages o where o.agent_id = a.id)
      from agents a
      cross join win
      left join trust_history t
        on t.agent_id = a.id and t.ts > now() - win.iv
     where a.agent_version is not null
     group by a.id, a.display_name, a.hostname, a.instance_id, a.provider, a.site
    union all
    -- Probes: availability from actual check results.
    select 'check',
           p.name, p.category, p.site,
           count(r.*),
           round(100.0 * count(*) filter (where r.ok) / nullif(count(r.*), 0), 3),
           round(count(*) filter (where not r.ok) * (p.interval_s / 60.0), 1),
           null, null, null, null
      from probes p
      cross join win
      left join probe_results r
        on r.probe_id = p.id and r.ts > now() - win.iv
     group by p.id, p.name, p.category, p.site, p.interval_s
     order by 6 nulls last;
$$;

-- ---------------------------------------------------------------- performance

create or replace function report_performance(p_days integer default 7)
returns table (
    name        text,
    platform    text,
    site        text,
    samples     bigint,
    cpu_avg     numeric,
    cpu_p95     numeric,
    cpu_max     numeric,
    mem_avg     numeric,
    mem_max     numeric,
    disk_avg    numeric,
    disk_max    numeric,
    load_avg    numeric,
    uptime_days numeric
)
language sql stable security definer set search_path = public as $$
    select coalesce(a.display_name, a.hostname, a.instance_id),
           a.platform,
           a.site,
           count(m.*),
           round(avg(m.cpu_pct)::numeric, 1),
           -- p95 rather than max alone: one spike should not characterise a
           -- week, but sustained pressure should be visible.
           round(percentile_cont(0.95) within group (order by m.cpu_pct)::numeric, 1),
           round(max(m.cpu_pct)::numeric, 1),
           round(avg(m.mem_pct)::numeric, 1),
           round(max(m.mem_pct)::numeric, 1),
           round(avg(m.disk_pct)::numeric, 1),
           round(max(m.disk_pct)::numeric, 1),
           round(avg(m.load1)::numeric, 2),
           round(max(m.uptime_s) / 86400.0, 1)
      from agents a
      left join metrics m
        on m.agent_id = a.id and m.ts > now() - make_interval(days => p_days)
     where a.agent_version is not null
     group by a.id, a.display_name, a.hostname, a.instance_id, a.platform, a.site
     order by 5 desc nulls last;
$$;

-- ---------------------------------------------------------------- posture

create or replace function report_posture(p_days integer default 30)
returns table (
    name              text,
    platform          text,
    provider          text,
    trust             integer,
    posture_pct       numeric,
    checks_pass       bigint,
    checks_fail       bigint,
    checks_fail_high  bigint,
    vulns_severe      bigint,
    vulns_total       bigint,
    priv_changes      bigint,
    critical_files    bigint,
    failed_logins     bigint,
    external_ports    bigint,
    identity_proof    text
)
language sql stable security definer set search_path = public as $$
    select o.label, o.platform, o.provider, o.trust,
           round(100.0 * coalesce(q.score, 1), 1),
           coalesce(q.passed, 0),
           coalesce(q.failed, 0),
           coalesce(q.failed_high, 0),
           o.vulns_severe, o.vulns_total,
           (select count(*) from user_events u
             where u.agent_id = o.id and u.sudoer
               and u.ts > now() - make_interval(days => p_days)),
           (select count(*) from fim_events f
             where f.agent_id = o.id and f.critical
               and f.ts > now() - make_interval(days => p_days)),
           (select count(*) from auth_events e
             where e.agent_id = o.id and e.kind = 'login_failed'
               and e.ts > now() - make_interval(days => p_days)),
           o.external_ports,
           o.identity_proof
      from agent_overview o
      left join agent_posture q on q.agent_id = o.id
     where o.agent_version is not null
     order by o.trust nulls last;
$$;

-- Every failing check across the fleet, for the detail section of the
-- posture report.
create or replace function report_findings()
returns table (
    name      text,
    platform  text,
    severity  text,
    check_id  text,
    title     text,
    detail    text,
    since     timestamptz
)
language sql stable security definer set search_path = public as $$
    select o.label, o.platform, c.severity, c.check_id, c.title, c.detail, c.last_changed
      from host_checks c
      join agent_overview o on o.id = c.agent_id
     where c.status = 'fail'
     order by case c.severity when 'high' then 0 when 'medium' then 1 else 2 end,
              o.label;
$$;

grant execute on function report_availability(integer) to authenticated;
grant execute on function report_performance(integer)  to authenticated;
grant execute on function report_posture(integer)      to authenticated;
grant execute on function report_findings()            to authenticated;
