-- 024: IIS.
--
-- Unlike every other application kind, IIS is not polled from outside. The
-- Windows agent already runs on the web server with the rights to read its
-- performance counters, so a probe with credentials would be a second way in
-- for information already reachable.
--
-- That means application metrics can now arrive from an agent as well as a
-- probe, so app_metrics gains an agent_id and exactly one of the two must be
-- set.

-- The primary key includes probe_id, so it has to go before the column can
-- be made nullable.
alter table app_metrics drop constraint if exists app_metrics_pkey;
alter table app_metrics alter column probe_id drop not null;
alter table app_metrics add column if not exists agent_id uuid
    references agents (id) on delete cascade;
alter table app_metrics add column if not exists app_name text;
create unique index if not exists app_metrics_key on app_metrics (
    coalesce(probe_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(agent_id, '00000000-0000-0000-0000-000000000000'::uuid),
    coalesce(app_name, ''),
    ts
);

alter table app_metrics drop constraint if exists app_metrics_source_check;
alter table app_metrics add constraint app_metrics_source_check
    check ((probe_id is not null) <> (agent_id is not null));

comment on column app_metrics.agent_id is
    'Set when the measurement came from an agent rather than a probe. IIS is the only such source today: the agent is already on the host, so polling it from outside would need credentials for data it can already read.';

create index if not exists app_metrics_agent_idx on app_metrics (agent_id, ts desc)
    where agent_id is not null;

-- ---------------------------------------------------------------- rates

-- Rates now partition by whichever source produced the row, and by app name,
-- because one Windows host reports several IIS sites.
-- Column order changes, and CREATE OR REPLACE cannot rename or reorder
-- view columns, so the dependent views are dropped and rebuilt.
drop view if exists application_overview;
drop view if exists app_rates;
create view app_rates as
with paired as (
    select probe_id, agent_id, app_name, ts,
           active_conns, p95_latency_s, avg_latency_s,
           memory_bytes, cpu_seconds, uptime_s, extra,
           requests_total, errors_total,
           lag(requests_total) over w as p_req,
           lag(errors_total)   over w as p_err,
           lag(cpu_seconds)    over w as p_cpu,
           extract(epoch from (ts - lag(ts) over w)) as dt
      from app_metrics
     where ts > now() - interval '24 hours'
    window w as (partition by probe_id, agent_id, app_name order by ts)
)
select probe_id, agent_id, app_name, ts, dt, active_conns,
       p95_latency_s, avg_latency_s, memory_bytes, uptime_s, extra,
       case when dt > 0 and requests_total >= p_req
            then (requests_total - p_req) / dt end as rps,
       case when dt > 0 and errors_total >= p_err
            then (errors_total - p_err) / dt end as eps,
       case when requests_total >= p_req then requests_total - p_req end as req_delta,
       case when errors_total   >= p_err then errors_total   - p_err end as err_delta,
       case when dt > 0 and cpu_seconds >= p_cpu
            then 100.0 * (cpu_seconds - p_cpu) / dt end as cpu_pct
  from paired
 where p_req is not null or p_cpu is not null;

alter view app_rates set (security_invoker = on);
grant select on app_rates to authenticated;
revoke all on app_rates from anon;

-- ---------------------------------------------------------------- overview

-- Probe-sourced and agent-sourced applications in one list, so the page does
-- not have to care which mechanism produced a row.
create view application_overview as
with latest as (
    select distinct on (probe_id, agent_id, app_name) *
      from app_rates order by probe_id, agent_id, app_name, ts desc
),
hour as (
    select probe_id, agent_id, app_name,
           sum(coalesce(req_delta, 0)) as req_1h,
           sum(coalesce(err_delta, 0)) as err_1h,
           avg(p95_latency_s)          as p95_1h,
           max(p95_latency_s)          as p95_max_1h
      from app_rates where ts > now() - interval '1 hour'
     group by probe_id, agent_id, app_name
)
select p.id, p.kind, p.name, p.target, p.category, p.site, p.enabled, p.interval_s,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       null::uuid as agent_id, null::text as host,
       l.ts as measured_at,
       round(l.rps::numeric, 2) as rps, round(l.cpu_pct::numeric, 1) as cpu_pct,
       l.active_conns, l.p95_latency_s, l.avg_latency_s, l.memory_bytes,
       l.uptime_s, l.extra,
       coalesce(h.req_1h, 0) as requests_1h,
       coalesce(h.err_1h, 0) as errors_1h,
       case when coalesce(h.req_1h, 0) > 0
            then round(100.0 * h.err_1h / h.req_1h, 2) end as error_rate,
       round(h.p95_1h::numeric, 4)     as p95_avg_1h,
       round(h.p95_max_1h::numeric, 4) as p95_max_1h
  from probes p
  join probe_state st on st.id = p.id
  left join latest l on l.probe_id = p.id
  left join hour   h on h.probe_id = p.id
 where p.kind in ('prometheus', 'nginx', 'tomcat', 'jboss')

union all

select
       -- A site has no probe row, so its identity is the agent plus the site
       -- name. Deterministic so the dashboard can key on it across polls.
       md5(l.agent_id::text || coalesce(l.app_name, ''))::uuid as id,
       'iis'::text as kind,
       coalesce(l.app_name, 'IIS') as name,
       o.label as target,
       'application'::text as category,
       o.site,
       true as enabled,
       60 as interval_s,
       -- An agent-sourced application is only as reachable as its host.
       case when o.status = 'down' then 'down' else 'up' end as status,
       l.ts as last_check,
       null::integer as latency_ms,
       case when o.status = 'down' then 'host is offline' end as detail,
       0 as consecutive,
       l.agent_id, o.label as host,
       l.ts as measured_at,
       round(l.rps::numeric, 2), round(l.cpu_pct::numeric, 1),
       l.active_conns, l.p95_latency_s, l.avg_latency_s, l.memory_bytes,
       l.uptime_s, l.extra,
       coalesce(h.req_1h, 0), coalesce(h.err_1h, 0),
       case when coalesce(h.req_1h, 0) > 0
            then round(100.0 * h.err_1h / h.req_1h, 2) end,
       round(h.p95_1h::numeric, 4), round(h.p95_max_1h::numeric, 4)
  from latest l
  join agent_overview o on o.id = l.agent_id
  left join hour h on h.agent_id = l.agent_id
                  and coalesce(h.app_name, '') = coalesce(l.app_name, '')
 where l.agent_id is not null;

alter view application_overview set (security_invoker = on);
grant select on application_overview to authenticated;
revoke all on application_overview from anon;
