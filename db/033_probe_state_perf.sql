-- 033: fix a quadratic query in probe_state.
--
-- The "consecutive" column - how long a probe has been in its current
-- state - was computed with a correlated subquery: for every row sharing
-- the latest ok value, find the most recent row with a *different* ok
-- value. probe_results has no index on ok, so each of those subquery
-- calls falls back to scanning probe_results for that probe_id, filtered
-- by ok in the scan itself. With one row per poll and no ceiling on how
-- long a probe keeps running, that is a per-row scan happening once per
-- row - quadratic in the number of results for that probe, not linear.
--
-- At a few hundred results this is invisible. At ~22k results for a
-- single probe (roughly two weeks at a one-minute interval) it was
-- measured hanging for 55+ seconds inside sweep_databases() and
-- sweep_db_extras(), both of which scan probe_state via database_overview
-- every minute on a cron schedule - so the next invocation started before
-- the last one finished, compounding rather than recovering.
--
-- The replacement computes the same "current streak length" with a
-- single ordered pass instead of one subquery per row: mark every row
-- where ok changed from the previous sample for that probe, turn those
-- marks into a running streak id via a windowed sum, then count how many
-- rows belong to the most recent streak id. Same result, no correlated
-- subquery, no per-row table scan.

create or replace view probe_state as
with latest as (
    select distinct on (probe_id) probe_id, ts, ok, latency_ms, detail
      from probe_results order by probe_id, ts desc
),
marked as (
    select probe_id, ts, ok,
           case when ok is distinct from
                     lag(ok) over (partition by probe_id order by ts)
                then 1 else 0 end as is_break
      from probe_results
),
grouped as (
    select probe_id, ts,
           sum(is_break) over (partition by probe_id order by ts) as streak_id
      from marked
),
streak as (
    select g.probe_id, count(*) as runs
      from grouped g
      join (select probe_id, max(streak_id) as top from grouped group by probe_id) m
        on m.probe_id = g.probe_id and g.streak_id = m.top
     group by g.probe_id
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
