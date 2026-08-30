-- 014: agentless probes, availability, MTTR, health matrix.
--
-- Until now nodewatch only knew hosts that run the agent. A probe is the
-- other direction: something reaches out to a target on a schedule. That is
-- how anything without an agent gets monitored - a switch, a URL, an iDRAC,
-- a database - so this migration is the foundation for those as much as it
-- is for ping and port checks.

create table if not exists probes (
    id           uuid primary key default gen_random_uuid(),
    kind         text not null check (kind in ('ping','port','url')),
    name         text not null,
    target       text not null,               -- host, IP, or URL
    port         integer,                     -- port checks only
    interval_s   integer not null default 60 check (interval_s between 15 and 3600),
    timeout_ms   integer not null default 5000 check (timeout_ms between 200 and 30000),
    expect_status integer,                    -- url checks; null means any 2xx/3xx
    expect_text  text,                        -- url checks; body must contain this
    category     text not null default 'synthetic',
    site         text,
    enabled      boolean not null default true,
    created_at   timestamptz not null default now()
);

-- Expressions are not allowed in a table-level UNIQUE constraint, so the
-- "same check twice" guard is an index. coalesce because a null port must
-- still collide with another null port.
create unique index if not exists probes_unique_target
    on probes (kind, target, coalesce(port, -1));

comment on table probes is
    'Agentless checks. The runner polls these from the API host, so targets only need to be reachable from there, not from the internet.';

create table if not exists probe_results (
    probe_id   uuid        not null references probes (id) on delete cascade,
    ts         timestamptz not null,
    ok         boolean     not null,
    latency_ms integer,
    detail     text,
    primary key (probe_id, ts)
);

create index if not exists probe_results_ts_brin on probe_results using brin (ts);
create index if not exists probe_results_recent  on probe_results (probe_id, ts desc);

alter table probes        enable row level security;
alter table probe_results enable row level security;

drop policy if exists probes_read on probes;
drop policy if exists probes_admin on probes;
create policy probes_read  on probes for select to authenticated using (true);
create policy probes_admin on probes for all to authenticated
    using (is_admin()) with check (is_admin());

drop policy if exists probe_results_read on probe_results;
create policy probe_results_read on probe_results for select to authenticated using (true);

grant select, insert, update, delete on probes to authenticated;
grant select on probe_results to authenticated;
revoke all on probes, probe_results from anon;

-- ---------------------------------------------------------------- current state

create or replace view probe_state as
with latest as (
    select distinct on (probe_id) probe_id, ts, ok, latency_ms, detail
      from probe_results order by probe_id, ts desc
),
streak as (
    -- How long has it been in its current condition? Counting consecutive
    -- same-result samples is cheaper than scanning for the transition.
    select r.probe_id, count(*) as runs
      from probe_results r
      join latest l on l.probe_id = r.probe_id
     where r.ok = l.ok
       and r.ts > coalesce((select max(ts) from probe_results x
                             where x.probe_id = r.probe_id and x.ok <> l.ok),
                           '-infinity'::timestamptz)
     group by r.probe_id
)
select p.id, p.kind, p.name, p.target, p.port, p.category, p.site, p.enabled,
       p.interval_s,
       l.ts            as last_check,
       l.ok,
       l.latency_ms,
       l.detail,
       coalesce(s.runs, 0) as consecutive,
       case when not p.enabled then 'paused'
            when l.ts is null then 'pending'
            when l.ts < now() - make_interval(secs => p.interval_s * 4) then 'stale'
            when l.ok then 'up' else 'down' end as status
from probes p
left join latest l on l.probe_id = p.id
left join streak s on s.probe_id = p.id;

alter view probe_state set (security_invoker = on);
grant select on probe_state to authenticated;
revoke all on probe_state from anon;

-- ---------------------------------------------------------------- availability

-- Hosts: derived from the 5-minute trust snapshots. A sample counts as
-- available when the agent was reporting at all, so this measures
-- observability rather than application health - which is what an
-- agent-based availability figure can honestly claim.
create or replace function host_availability(p_window interval)
returns table (agent_id uuid, pct numeric, samples bigint) as $$
    select agent_id,
           round(100.0 * count(*) filter (where status <> 'down') / nullif(count(*), 0), 2),
           count(*)
      from trust_history
     where ts > now() - p_window
     group by agent_id;
$$ language sql stable security definer set search_path = public;

create or replace function probe_availability(p_window interval)
returns table (probe_id uuid, pct numeric, samples bigint) as $$
    select probe_id,
           round(100.0 * count(*) filter (where ok) / nullif(count(*), 0), 2),
           count(*)
      from probe_results
     where ts > now() - p_window
     group by probe_id;
$$ language sql stable security definer set search_path = public;

-- One row per monitored thing, agent or probe, so the dashboard can show a
-- single availability table without caring which mechanism produced it.
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
select 'probe',
       p.id,
       p.name,
       p.category,
       p.site,
       (select pct from probe_availability(interval '24 hours') q where q.probe_id = p.id),
       (select pct from probe_availability(interval '7 days')   q where q.probe_id = p.id),
       (select pct from probe_availability(interval '30 days')  q where q.probe_id = p.id)
  from probes p;

alter view availability_summary set (security_invoker = on);
grant select on availability_summary to authenticated;
revoke all on availability_summary from anon;

-- ---------------------------------------------------------------- outages / MTTR

-- Gaps and islands over the trust snapshots: find each run of consecutive
-- 'down' samples and treat it as one outage. Counting individual down
-- samples would make a single 20-minute outage look like four incidents.
create or replace view host_outages as
with marked as (
    select agent_id, ts, status,
           case when status = 'down' then 1 else 0 end as is_down,
           row_number() over (partition by agent_id order by ts)
             - row_number() over (partition by agent_id,
                                  case when status = 'down' then 1 else 0 end
                                  order by ts) as grp
      from trust_history
     where ts > now() - interval '30 days'
)
select agent_id,
       min(ts) as started,
       max(ts) as ended,
       extract(epoch from (max(ts) - min(ts)))::int + 300 as duration_s,
       count(*) as samples
  from marked
 where is_down = 1
 group by agent_id, grp;

alter view host_outages set (security_invoker = on);
grant select on host_outages to authenticated;
revoke all on host_outages from anon;

create or replace view mttr_summary as
select o.agent_id,
       coalesce(a.display_name, a.hostname, a.instance_id) as name,
       count(*)                       as outages_30d,
       round(avg(o.duration_s))::int  as mttr_s,
       max(o.duration_s)              as worst_s,
       max(o.ended)                   as last_outage
  from host_outages o
  join agents a on a.id = o.agent_id
 group by o.agent_id, a.display_name, a.hostname, a.instance_id;

alter view mttr_summary set (security_invoker = on);
grant select on mttr_summary to authenticated;
revoke all on mttr_summary from anon;

-- ---------------------------------------------------------------- health matrix

-- Everything monitored, grouped the way an operator thinks about it rather
-- than the way it happens to be collected.
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

-- ---------------------------------------------------------------- response times

create or replace view probe_latency as
select p.id as probe_id, p.name, p.kind,
       round(avg(r.latency_ms))::int as avg_ms,
       percentile_disc(0.95) within group (order by r.latency_ms)::int as p95_ms,
       max(r.latency_ms) as max_ms,
       count(*) as samples
  from probes p
  join probe_results r on r.probe_id = p.id
 where r.ts > now() - interval '1 hour' and r.ok
 group by p.id, p.name, p.kind;

alter view probe_latency set (security_invoker = on);
grant select on probe_latency to authenticated;
revoke all on probe_latency from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('probe_down', 'critical', interval '15 minutes',
     'An agentless check (ping, port or URL) started failing')
on conflict (rule) do nothing;

-- Probes have no agent_id, so they cannot use queue_alert, which is keyed to
-- a node. They write to alert_log directly against the fleet-wide recipient
-- list, with the same cooldown discipline.
create or replace function sweep_probes() returns integer as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
begin
    select cooldown into cd from alert_rules where rule = 'probe_down' and enabled;
    if cd is null then return 0; end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from probe_state
              where status = 'down' and enabled
                and consecutive >= 2      -- one bad sample is noise, two is a fault
    loop
        select last_sent into last from alert_state
         where agent_id is null and rule = 'probe_down:' || r.id::text;

        continue when last is not null and now() - last < cd;

        insert into alert_log (agent_id, rule, severity, subject, body, recipients)
        values (null, 'probe_down', 'critical',
                format('[critical] %s is unreachable', r.name),
                format(E'Check: %s (%s)\nTarget: %s%s\nFailing for %s consecutive checks.\nLast detail: %s',
                       r.name, r.kind, r.target,
                       case when r.port is null then '' else ':' || r.port end,
                       r.consecutive, coalesce(r.detail, 'no detail')),
                coalesce(people, '{}'));

        -- ON CONFLICT cannot infer an expression index, so do it explicitly.
        update alert_state set last_sent = now()
         where agent_id is null and rule = 'probe_down:' || r.id::text;
        if not found then
            insert into alert_state (agent_id, rule, last_sent)
            values (null, 'probe_down:' || r.id::text, now());
        end if;

        n := n + 1;
    end loop;
    return n;
end $$ language plpgsql security definer set search_path = public;

-- alert_state is keyed (agent_id, rule) with agent_id in the primary key, so
-- it cannot be null. Probes are not tied to a node and need a fleet-level
-- cooldown row, so drop the primary key first, then relax the column, then
-- re-key on a coalesced expression.
alter table alert_state drop constraint if exists alert_state_pkey;
alter table alert_state alter column agent_id drop not null;
create unique index if not exists alert_state_key
    on alert_state (coalesce(agent_id, '00000000-0000-0000-0000-000000000000'::uuid), rule);

select cron.unschedule('nodewatch-probe-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-probe-sweep');
select cron.schedule('nodewatch-probe-sweep', '* * * * *', $$select sweep_probes();$$);

select cron.unschedule('nodewatch-probe-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-probe-retention');
select cron.schedule('nodewatch-probe-retention', '50 4 * * *',
    $$delete from probe_results where ts < now() - interval '30 days';$$);
