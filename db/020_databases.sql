-- 020: PostgreSQL and MySQL monitoring.
--
-- Database checks are probes like any other, but they differ in two ways
-- that shape the schema: they need credentials, and they return a set of
-- measurements rather than a single up/down.
--
-- Credentials live in a separate table so the probes list itself stays
-- readable by viewers. Column-level RLS does not exist in Postgres, so
-- splitting the table is the only way to let one role read the name of a
-- check while another role reads its password.

alter table probes drop constraint if exists probes_kind_check;
alter table probes add constraint probes_kind_check
    check (kind in ('ping','port','url','postgres','mysql'));

create table if not exists probe_secrets (
    probe_id uuid primary key references probes (id) on delete cascade,
    -- {host, port, user, password, dbname, sslmode}
    config   jsonb not null default '{}',
    updated_at timestamptz not null default now()
);

comment on table probe_secrets is
    'Connection credentials, admin-only. Separate from probes because Postgres has no column-level RLS: a viewer must be able to see that a database check exists without being able to read its password.';

alter table probe_secrets enable row level security;
drop policy if exists probe_secrets_admin on probe_secrets;
create policy probe_secrets_admin on probe_secrets for all to authenticated
    using (is_admin()) with check (is_admin());
grant select, insert, update, delete on probe_secrets to authenticated;
revoke all on probe_secrets from anon;

-- Whether a check is configured, without revealing what with.
create or replace view probe_secret_status as
select p.id as probe_id,
       (s.probe_id is not null) as configured,
       s.config ->> 'host'   as host,
       s.config ->> 'dbname' as dbname,
       (s.config ->> 'port')::int as port,
       s.updated_at
  from probes p left join probe_secrets s on s.probe_id = p.id;

-- Deliberately owner-privileged so viewers can see host and database name
-- without a grant on the credential table. The password is simply not
-- selected: unreachable rather than unrendered.
alter view probe_secret_status set (security_invoker = off);
grant select on probe_secret_status to authenticated;
revoke all on probe_secret_status from anon;

-- ---------------------------------------------------------------- measurements

-- Common columns cover what both engines expose and what an operator
-- actually watches; anything engine-specific goes in extra.
create table if not exists db_metrics (
    probe_id        uuid        not null references probes (id) on delete cascade,
    ts              timestamptz not null,
    connections     integer,
    max_connections integer,
    conn_pct        real,
    cache_hit_pct   real,
    slow_queries    bigint,
    longest_query_s real,
    replication_lag_s real,
    size_bytes      bigint,
    uptime_s        bigint,
    qps             real,
    extra           jsonb,
    primary key (probe_id, ts)
);

create index if not exists db_metrics_ts_brin on db_metrics using brin (ts);
create index if not exists db_metrics_recent  on db_metrics (probe_id, ts desc);

alter table db_metrics enable row level security;
drop policy if exists db_metrics_read on db_metrics;
create policy db_metrics_read on db_metrics for select to authenticated using (true);
grant select on db_metrics to authenticated;
revoke all on db_metrics from anon;

-- ---------------------------------------------------------------- views

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
       -- Pressure is the single number an operator scans for. Connection
       -- saturation dominates because that is what takes an application
       -- down; a poor cache ratio makes it slow, which is worse but later.
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
 where p.kind in ('postgres','mysql');

alter view database_overview set (security_invoker = on);
grant select on database_overview to authenticated;
revoke all on database_overview from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('db_connections', 'warning', interval '1 hour',
     'A database is close to its connection limit'),
    ('db_replication', 'critical', interval '30 minutes',
     'Database replication has fallen behind')
on conflict (rule) do nothing;

create or replace function sweep_databases() returns integer
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
        -- connection saturation
        if r.conn_pct is not null and r.conn_pct >= 85 then
            select cooldown into cd from alert_rules where rule='db_connections' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_connections:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (null, 'db_connections', 'warning',
                        format('[warning] %s is at %s%% of its connection limit',
                               r.name, round(r.conn_pct)),
                        format(E'Database: %s (%s)\nConnections: %s of %s\n\n'
                               'New connections will be refused at the limit.',
                               r.name, r.kind, r.connections, r.max_connections),
                        coalesce(people, '{}'));
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_connections:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent)
                    values (null, 'db_connections:' || r.id::text, now());
                end if;
                n := n + 1;
            end if;
        end if;

        -- replication lag
        if r.replication_lag_s is not null and r.replication_lag_s >= 60 then
            select cooldown into cd from alert_rules where rule='db_replication' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_replication:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (null, 'db_replication', 'critical',
                        format('[critical] %s replication is %s seconds behind',
                               r.name, round(r.replication_lag_s)),
                        format(E'Database: %s (%s)\nLag: %s seconds\n\n'
                               'A failover now would lose everything written in that window.',
                               r.name, r.kind, round(r.replication_lag_s)),
                        coalesce(people, '{}'));
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_replication:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent)
                    values (null, 'db_replication:' || r.id::text, now());
                end if;
                n := n + 1;
            end if;
        end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-db-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-db-sweep');
select cron.schedule('nodewatch-db-sweep', '* * * * *', $$select sweep_databases();$$);

select cron.unschedule('nodewatch-db-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-db-retention');
select cron.schedule('nodewatch-db-retention', '58 4 * * *',
    $$delete from db_metrics where ts < now() - interval '30 days';$$);
