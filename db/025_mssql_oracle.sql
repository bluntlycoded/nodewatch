-- 025: SQL Server and Oracle.
--
-- Both fit the existing database shape - credentials in probe_secrets,
-- measurements in db_metrics - so this migration only widens the allowed
-- kinds and teaches the overview what a "database" now includes.
--
-- Neither needs a vendor client on the probe host: pymssql ships prebuilt
-- wheels, and python-oracledb's thin mode speaks the wire protocol directly
-- rather than shelling out to Instant Client.

alter table probes drop constraint if exists probes_kind_check;
alter table probes add constraint probes_kind_check
    check (kind in ('ping','port','url',
                    'postgres','mysql','mssql','oracle',
                    'prometheus','nginx','tomcat','jboss'));

create or replace view database_overview as
with latest as (
    select distinct on (probe_id) * from db_metrics order by probe_id, ts desc
)
select p.id, p.kind, p.name, p.category, p.site, p.enabled, p.interval_s,
       s.host, s.dbname, s.port, s.configured,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       l.ts as measured_at,
       l.connections, l.max_connections, l.conn_pct, l.cache_hit_pct,
       l.slow_queries, l.longest_query_s, l.replication_lag_s,
       l.size_bytes, l.uptime_s, l.qps, l.extra,
       case
         when st.status <> 'up' then 100
         when l.conn_pct is null then null
         else least(100, round(
              0.6 * coalesce(l.conn_pct, 0)
            + 0.25 * greatest(0, 100 - coalesce(l.cache_hit_pct, 100))
            + 0.15 * least(100, coalesce(l.replication_lag_s, 0) * 2)
         ))::int
       end as pressure
  from probes p
  join probe_state st on st.id = p.id
  left join probe_secret_status s on s.probe_id = p.id
  left join latest l on l.probe_id = p.id
 where p.kind in ('postgres','mysql','mssql','oracle');

alter view database_overview set (security_invoker = on);
grant select on database_overview to authenticated;
revoke all on database_overview from anon;

-- Two conditions worth alerting on that only these engines report.
insert into alert_rules (rule, severity, cooldown, description) values
    ('db_blocked',    'warning', interval '30 minutes',
     'Sessions are blocked waiting on locks'),
    ('db_tablespace', 'critical', interval '6 hours',
     'An Oracle tablespace is nearly full')
on conflict (rule) do nothing;

create or replace function sweep_db_extras() returns integer
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

    for r in select * from database_overview where status = 'up' loop
        -- Blocked sessions: a handful is normal under load, sustained
        -- blocking is not.
        if coalesce((r.extra ->> 'blocked_sessions')::int, 0) >= 5 then
            select cooldown into cd from alert_rules where rule = 'db_blocked' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_blocked:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (null, 'db_blocked', 'warning',
                        format('[warning] %s has %s blocked sessions',
                               r.name, r.extra ->> 'blocked_sessions'),
                        format(E'Database: %s (%s)\nBlocked sessions: %s\n\n'
                               'Something is holding a lock other work is waiting on.',
                               r.name, r.kind, r.extra ->> 'blocked_sessions'),
                        coalesce(people, '{}'));
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_blocked:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent)
                    values (null, 'db_blocked:' || r.id::text, now());
                end if;
                n := n + 1;
            end if;
        end if;

        -- A full tablespace stops writes outright, so this is critical
        -- rather than a warning.
        if coalesce((r.extra ->> 'tablespace_worst_pct')::numeric, 0) >= 90 then
            select cooldown into cd from alert_rules where rule = 'db_tablespace' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_tablespace:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (null, 'db_tablespace', 'critical',
                        format('[critical] %s tablespace is %s%% full',
                               r.name, round((r.extra ->> 'tablespace_worst_pct')::numeric)),
                        format(E'Database: %s\nWorst tablespace: %s%%\nOver 90%%: %s\n\n'
                               'Writes stop when a tablespace fills.',
                               r.name, r.extra ->> 'tablespace_worst_pct',
                               r.extra ->> 'tablespaces_over_90'),
                        coalesce(people, '{}'));
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_tablespace:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent)
                    values (null, 'db_tablespace:' || r.id::text, now());
                end if;
                n := n + 1;
            end if;
        end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-db-extras')
 where exists (select 1 from cron.job where jobname = 'nodewatch-db-extras');
select cron.schedule('nodewatch-db-extras', '* * * * *', $$select sweep_db_extras();$$);
