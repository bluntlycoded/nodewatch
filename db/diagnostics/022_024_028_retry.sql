-- Combined, cascade-safe retry of 022 (trimmed) + 024 + 028's view layer.
-- Every view below is dropped with cascade first, then created fresh -
-- sidesteps "cannot drop columns from view" (42P16) regardless of which
-- one currently has a mismatched shape from an earlier partial attempt.
-- cascade on a drop is safe here: everything downstream gets recreated
-- later in this same script.
--
-- Run this INSTEAD of 022_retry.sql / 024_iis.sql / 028_bsm.sql for the
-- view-creation parts. If you already ran any of those and they
-- succeeded, the table/policy/index/function/cron statements below are
-- all idempotent (if not exists / drop-then-create) so re-running them
-- is harmless.

-- ---------------------------------------------------------------- tables (022)

create table if not exists app_metrics (
    probe_id       uuid        not null references probes (id) on delete cascade,
    ts             timestamptz not null,
    requests_total  bigint,
    errors_total    bigint,
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

-- ---------------------------------------------------------------- tables (024, IIS)

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

create index if not exists app_metrics_agent_idx on app_metrics (agent_id, ts desc)
    where agent_id is not null;

-- ---------------------------------------------------------------- tables (028, BSM)

create table if not exists services (
    id          uuid primary key default gen_random_uuid(),
    name        text not null unique,
    description text,
    owner       text,
    tier        integer not null default 2 check (tier between 1 and 3),
    created_at  timestamptz not null default now()
);

create table if not exists service_components (
    id         uuid primary key default gen_random_uuid(),
    service_id uuid not null references services (id) on delete cascade,
    agent_id   uuid references agents (id) on delete cascade,
    probe_id   uuid references probes (id) on delete cascade,
    required   boolean not null default true,
    group_name text,
    note       text,
    constraint one_component check ((agent_id is not null) <> (probe_id is not null))
);

create index if not exists svc_comp_service on service_components (service_id);

create table if not exists service_dependencies (
    service_id uuid not null references services (id) on delete cascade,
    depends_on uuid not null references services (id) on delete cascade,
    primary key (service_id, depends_on),
    constraint no_self_dependency check (service_id <> depends_on)
);

alter table services             enable row level security;
alter table service_components   enable row level security;
alter table service_dependencies enable row level security;

drop policy if exists svc_read  on services;
drop policy if exists svc_admin on services;
drop policy if exists comp_read  on service_components;
drop policy if exists comp_admin on service_components;
drop policy if exists dep_read  on service_dependencies;
drop policy if exists dep_admin on service_dependencies;
create policy svc_read   on services for select to authenticated using (true);
create policy svc_admin  on services for all to authenticated
    using (is_admin()) with check (is_admin());
create policy comp_read  on service_components for select to authenticated using (true);
create policy comp_admin on service_components for all to authenticated
    using (is_admin()) with check (is_admin());
create policy dep_read   on service_dependencies for select to authenticated using (true);
create policy dep_admin  on service_dependencies for all to authenticated
    using (is_admin()) with check (is_admin());

grant select, insert, update, delete
    on services, service_components, service_dependencies to authenticated;
revoke all on services, service_components, service_dependencies from anon;

-- ---------------------------------------------------------------- views, cascade-safe

drop view if exists service_impact cascade;
drop view if exists service_health cascade;
drop view if exists service_component_state cascade;
drop view if exists application_overview cascade;
drop view if exists app_rates cascade;

create view app_rates as
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

create view application_overview as
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
       case when coalesce(h.req_1h, 0) > 0
            then round(100.0 * h.err_1h / h.req_1h, 2) else null end as error_rate,
       round(h.p95_1h::numeric, 4)     as p95_avg_1h,
       round(h.p95_max_1h::numeric, 4) as p95_max_1h
  from probes p
  join probe_state st on st.id = p.id
  left join latest l on l.probe_id = p.id
  left join hour   h on h.probe_id = p.id
 where p.kind in ('prometheus', 'nginx', 'tomcat', 'jboss');

alter view application_overview set (security_invoker = on);
grant select on application_overview to authenticated;
revoke all on application_overview from anon;

create view service_component_state as
select c.id, c.service_id, c.required, c.group_name, c.note,
       coalesce(c.agent_id, c.probe_id)                       as ref_id,
       case when c.agent_id is not null then 'host' else 'check' end as kind,
       coalesce(o.label, p.name)                              as name,
       case
         when c.agent_id is not null then o.status
         when st.status = 'up'      then 'healthy'
         when st.status = 'down'    then 'down'
         when st.status = 'stale'   then 'degraded'
         when st.status = 'paused'  then 'paused'
         else 'pending'
       end                                                     as status,
       o.trust
  from service_components c
  left join agent_overview o on o.id = c.agent_id
  left join probes p        on p.id = c.probe_id
  left join probe_state st  on st.id = c.probe_id;

alter view service_component_state set (security_invoker = on);
grant select on service_component_state to authenticated;
revoke all on service_component_state from anon;

create view service_health as
with comp as (
    select * from service_component_state
),
agg as (
    select s.id, s.name, s.description, s.owner, s.tier,
           count(c.id)                                              as components,
           count(c.id) filter (where c.status = 'down')             as down,
           count(c.id) filter (where c.status = 'degraded')         as degraded,
           count(c.id) filter (where c.required and c.status = 'down') as required_down,
           (select count(*) from (
              select c2.group_name
                from comp c2
               where c2.service_id = s.id and not c2.required
                 and c2.group_name is not null
               group by c2.group_name
              having count(*) filter (where c2.status <> 'down') = 0
            ) g)                                                    as groups_lost,
           count(c.id) filter (where not c.required and c.status = 'down') as redundant_down,
           round(avg(c.trust) filter (where c.trust is not null))    as avg_trust
      from services s
      left join comp c on c.service_id = s.id
     group by s.id, s.name, s.description, s.owner, s.tier
)
select a.*,
       case
         when a.components = 0            then 'unknown'
         when a.required_down > 0         then 'down'
         when a.groups_lost > 0           then 'down'
         when a.degraded > 0
           or a.redundant_down > 0        then 'degraded'
         else 'healthy'
       end as status,
       case
         when a.components = 0    then 'no components mapped'
         when a.required_down > 0 then a.required_down || ' required component(s) down'
         when a.groups_lost > 0   then a.groups_lost || ' redundant group(s) fully down'
         when a.redundant_down > 0 then a.redundant_down || ' redundant component(s) down'
         when a.degraded > 0      then a.degraded || ' component(s) degraded'
         else 'all components healthy'
       end as reason
  from agg a;

alter view service_health set (security_invoker = on);
grant select on service_health to authenticated;
revoke all on service_health from anon;

create view service_impact as
select h.id, h.name, h.tier, h.status, h.reason,
       array_remove(array_agg(d.depends_on), null)  as depends_on,
       array_remove(array_agg(dh.name) filter (where dh.status in ('down','degraded')),
                    null)                            as failing_dependencies,
       case when h.status = 'down' or bool_or(dh.status = 'down')       then 'down'
            when h.status = 'degraded' or bool_or(dh.status = 'degraded') then 'degraded'
            when h.status = 'unknown'                                    then 'unknown'
            else 'healthy' end                       as effective_status
  from service_health h
  left join service_dependencies d on d.service_id = h.id
  left join service_health dh      on dh.id = d.depends_on
 group by h.id, h.name, h.tier, h.status, h.reason;

alter view service_impact set (security_invoker = on);
grant select on service_impact to authenticated;
revoke all on service_impact from anon;

-- ---------------------------------------------------------------- alerting + functions

insert into alert_rules (rule, severity, cooldown, description) values
    ('app_errors',  'warning',  interval '30 minutes',
     'An application is returning errors above its normal rate'),
    ('app_latency', 'warning',  interval '1 hour',
     'An application''s 95th percentile response time has degraded'),
    ('service_down', 'critical', interval '30 minutes',
     'A mapped business service has lost a required component')
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

create or replace function sweep_services() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
begin
    select cooldown into cd from alert_rules where rule = 'service_down' and enabled;
    if cd is null then return 0; end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from service_health where status = 'down' loop
        select last_sent into last from alert_state
         where agent_id is null and rule = 'service_down:' || r.id::text;
        continue when last is not null and now() - last < cd;

        insert into alert_log (agent_id, rule, severity, subject, body, recipients)
        values (null, 'service_down', 'critical',
                format('[critical] %s is down', r.name),
                format(E'Service: %s (tier %s)\nCause: %s\nComponents: %s, %s down\n\n%s',
                       r.name, r.tier, r.reason, r.components, r.down,
                       coalesce(r.description, '')),
                coalesce(people, '{}'));

        update alert_state set last_sent = now()
         where agent_id is null and rule = 'service_down:' || r.id::text;
        if not found then
            insert into alert_state (agent_id, rule, last_sent)
            values (null, 'service_down:' || r.id::text, now());
        end if;
        n := n + 1;
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

select cron.unschedule('nodewatch-services')
 where exists (select 1 from cron.job where jobname = 'nodewatch-services');
select cron.schedule('nodewatch-services', '* * * * *', $$select sweep_services();$$);
