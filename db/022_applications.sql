-- 022: application monitoring.
--
-- Two probe kinds cover most of what a lab actually runs:
--
--   prometheus  any app exposing /metrics in the text exposition format -
--               FastAPI, Flask, Django, Go services, exporters
--   nginx       the stub_status endpoint, which is not Prometheus format
--
-- Throughput and error rate come from counter deltas computed on read, the
-- same approach as network interfaces: a counter reset then reads as a gap
-- rather than an enormous spike.

alter table probes drop constraint if exists probes_kind_check;
alter table probes add constraint probes_kind_check
    check (kind in ('ping','port','url','postgres','mysql','prometheus','nginx'));

create table if not exists app_metrics (
    probe_id       uuid        not null references probes (id) on delete cascade,
    ts             timestamptz not null,
    -- Cumulative counters, differenced on read.
    requests_total  bigint,
    errors_total    bigint,
    -- Point-in-time gauges.
    active_conns    integer,
    p95_latency_s   real,
    avg_latency_s   real,
    memory_bytes    bigint,
    cpu_seconds     double precision,
    uptime_s        bigint,
    extra           jsonb,
    primary key (probe_id, ts)
);

create index if not exists app_metrics_ts_brin on app_metrics using brin (ts);
create index if not exists app_metrics_recent  on app_metrics (probe_id, ts desc);

alter table app_metrics enable row level security;
drop policy if exists app_metrics_read on app_metrics;
create policy app_metrics_read on app_metrics for select to authenticated using (true);
grant select on app_metrics to authenticated;
revoke all on app_metrics from anon;

-- ---------------------------------------------------------------- rates

create or replace view app_rates as
with paired as (
    select probe_id, ts, active_conns, p95_latency_s, avg_latency_s,
           memory_bytes, cpu_seconds, uptime_s, extra,
           requests_total, errors_total,
           lag(requests_total) over w as p_req,
           lag(errors_total)   over w as p_err,
           lag(cpu_seconds)    over w as p_cpu,
           extract(epoch from (ts - lag(ts) over w)) as dt
      from app_metrics
     where ts > now() - interval '24 hours'
    window w as (partition by probe_id order by ts)
)
select probe_id, ts, dt, active_conns, p95_latency_s, avg_latency_s,
       memory_bytes, uptime_s, extra,
       -- A negative delta means the process restarted and its counters reset.
       -- Discard rather than report a spike.
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

create or replace view application_overview as
with latest as (
    select distinct on (probe_id) * from app_rates order by probe_id, ts desc
),
hour as (
    select probe_id,
           sum(coalesce(req_delta, 0)) as req_1h,
           sum(coalesce(err_delta, 0)) as err_1h,
           avg(p95_latency_s)          as p95_1h,
           max(p95_latency_s)          as p95_max_1h
      from app_rates where ts > now() - interval '1 hour'
     group by probe_id
)
select p.id, p.kind, p.name, p.target, p.category, p.site, p.enabled, p.interval_s,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       l.ts as measured_at,
       round(l.rps::numeric, 2)         as rps,
       round(l.cpu_pct::numeric, 1)     as cpu_pct,
       l.active_conns,
       l.p95_latency_s,
       l.avg_latency_s,
       l.memory_bytes,
       l.uptime_s,
       l.extra,
       coalesce(h.req_1h, 0) as requests_1h,
       coalesce(h.err_1h, 0) as errors_1h,
       -- Error rate over the hour rather than the instant: a single failed
       -- request in a quiet minute should not read as 100% errors.
       case when coalesce(h.req_1h, 0) > 0
            then round(100.0 * h.err_1h / h.req_1h, 2) else null end as error_rate,
       round(h.p95_1h::numeric, 4)     as p95_avg_1h,
       round(h.p95_max_1h::numeric, 4) as p95_max_1h
  from probes p
  join probe_state st on st.id = p.id
  left join latest l on l.probe_id = p.id
  left join hour   h on h.probe_id = p.id
 where p.kind in ('prometheus', 'nginx');

alter view application_overview set (security_invoker = on);
grant select on application_overview to authenticated;
revoke all on application_overview from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('app_errors',  'warning',  interval '30 minutes',
     'An application is returning errors above its normal rate'),
    ('app_latency', 'warning',  interval '1 hour',
     'An application''s 95th percentile response time has degraded')
on conflict (rule) do nothing;

create or replace function sweep_applications() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from application_overview where status = 'up' loop
        -- Errors: needs both a rate and enough volume for the rate to mean
        -- anything. Five percent of twenty requests is one request.
        if r.error_rate is not null and r.error_rate >= 5 and r.requests_1h >= 100 then
            select cooldown into cd from alert_rules where rule = 'app_errors' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'app_errors:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (null, 'app_errors', 'warning',
                        format('[warning] %s is returning %s%% errors', r.name, r.error_rate),
                        format(E'Application: %s\nErrors: %s of %s requests in the last hour\n'
                               'Current rate: %s req/s',
                               r.name, r.errors_1h, r.requests_1h, coalesce(r.rps, 0)),
                        coalesce(people, '{}'));
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'app_errors:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent)
                    values (null, 'app_errors:' || r.id::text, now());
                end if;
                n := n + 1;
            end if;
        end if;

        if r.p95_avg_1h is not null and r.p95_avg_1h >= 2 then
            select cooldown into cd from alert_rules where rule = 'app_latency' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'app_latency:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (null, 'app_latency', 'warning',
                        format('[warning] %s p95 response time is %ss', r.name, r.p95_avg_1h),
                        format(E'Application: %s\np95 over the last hour: %ss\nWorst: %ss',
                               r.name, r.p95_avg_1h, r.p95_max_1h),
                        coalesce(people, '{}'));
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'app_latency:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent)
                    values (null, 'app_latency:' || r.id::text, now());
                end if;
                n := n + 1;
            end if;
        end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-app-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-app-sweep');
select cron.schedule('nodewatch-app-sweep', '* * * * *', $$select sweep_applications();$$);

select cron.unschedule('nodewatch-app-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-app-retention');
select cron.schedule('nodewatch-app-retention', '10 5 * * *',
    $$delete from app_metrics where ts < now() - interval '30 days';$$);
