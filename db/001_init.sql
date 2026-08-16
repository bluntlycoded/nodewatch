-- nodewatch schema
-- Target: Supabase (Postgres 15+). No TimescaleDB; BRIN + pg_cron instead.
-- Writes come from the ingest API using the service_role key.
-- Reads come from the Netlify dashboard using the anon key + Supabase Auth.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- agents

create table if not exists agents (
    id            uuid primary key default gen_random_uuid(),
    instance_id   text        not null unique,
    account_id    text,
    region        text,
    instance_type text,
    hostname      text,
    os            text,
    agent_version text,
    enrolled_at   timestamptz not null default now(),
    first_seen    timestamptz not null default now(),
    last_seen     timestamptz not null default now(),
    enroll_count  integer     not null default 1
);

comment on table agents is
    'One row per EC2 instance. instance_id is proven via the IMDSv2 signed identity document, not self-reported.';

create index if not exists agents_last_seen_idx on agents (last_seen desc);

-- ---------------------------------------------------------------- metrics

create table if not exists metrics (
    agent_id    uuid        not null references agents (id) on delete cascade,
    ts          timestamptz not null,
    cpu_pct     real,
    mem_pct     real,
    disk_pct    real,
    load1       real,
    uptime_s    bigint,
    proc_count  integer,
    primary key (agent_id, ts)
);

-- BRIN is the right index for append-only time series: tiny, and the
-- physical order of rows already correlates with ts.
create index if not exists metrics_ts_brin on metrics using brin (ts);
create index if not exists metrics_agent_ts_idx on metrics (agent_id, ts desc);

-- ---------------------------------------------------------------- auth events

-- Postgres has no 'create type if not exists', so guard it manually.
do $$
begin
    create type auth_kind as enum (
        'login_success',
        'login_failed',
        'session_opened',
        'session_closed',
        'logout'
    );
exception
    when duplicate_object then null;
end $$;

create table if not exists auth_events (
    id         bigserial primary key,
    agent_id   uuid        not null references agents (id) on delete cascade,
    ts         timestamptz not null,
    kind       auth_kind   not null,
    username   text,
    source_ip  inet,
    raw        text
);

-- The agent may re-send a batch if the response is lost after the write
-- lands. This makes ingest idempotent: ON CONFLICT DO NOTHING on insert.
-- Done as an expression index rather than a generated column because
-- timestamptz -> text is not immutable in Postgres.
create unique index if not exists auth_events_dedup
    on auth_events (agent_id, ts, md5(coalesce(raw, '')));

create index if not exists auth_ts_brin       on auth_events using brin (ts);
create index if not exists auth_agent_ts_idx  on auth_events (agent_id, ts desc);
create index if not exists auth_kind_ts_idx   on auth_events (kind, ts desc);
create index if not exists auth_source_ip_idx on auth_events (source_ip)
    where source_ip is not null;

-- ---------------------------------------------------------------- ports

-- Current state: what is listening right now.
create table if not exists port_state (
    agent_id   uuid        not null references agents (id) on delete cascade,
    port       integer     not null,
    proto      text        not null check (proto in ('tcp', 'udp')),
    bind_addr  text        not null,
    external   boolean     not null default false,
    pid        integer,
    process    text,
    first_seen timestamptz not null default now(),
    last_seen  timestamptz not null default now(),
    primary key (agent_id, port, proto, bind_addr)
);

comment on column port_state.external is
    'True when bound to 0.0.0.0 or ::, i.e. reachable off-host. This is the column that matters.';

create index if not exists port_state_external_idx on port_state (agent_id)
    where external;

-- Change log: the interesting artifact. A port opening is an event;
-- a port merely being open is not.
create table if not exists port_events (
    id        bigserial primary key,
    agent_id  uuid        not null references agents (id) on delete cascade,
    ts        timestamptz not null default now(),
    port      integer     not null,
    proto     text        not null,
    bind_addr text        not null,
    external  boolean     not null default false,
    process   text,
    action    text        not null check (action in ('opened', 'closed'))
);

create index if not exists port_events_ts_brin      on port_events using brin (ts);
create index if not exists port_events_agent_ts_idx on port_events (agent_id, ts desc);

-- ---------------------------------------------------------------- derived health

-- Status is NEVER stored. A dead agent cannot leave a stale 'healthy'
-- behind, because nothing writes status at all.
create or replace view agent_health as
select
    a.id,
    a.instance_id,
    a.hostname,
    a.os,
    a.agent_version,
    a.region,
    a.last_seen,
    extract(epoch from (now() - a.last_seen))::int as seconds_since_seen,
    case
        when a.last_seen > now() - interval '45 seconds' then 'healthy'
        when a.last_seen > now() - interval '3 minutes'  then 'degraded'
        else 'down'
    end as status,
    (select count(*) from port_state p
      where p.agent_id = a.id and p.external)              as external_ports,
    (select count(*) from auth_events e
      where e.agent_id = a.id
        and e.kind = 'login_failed'
        and e.ts > now() - interval '1 hour')              as failed_logins_1h
from agents a;

-- Latest metric sample per agent, for the dashboard grid.
create or replace view agent_latest_metrics as
select distinct on (agent_id)
    agent_id, ts, cpu_pct, mem_pct, disk_pct, load1, uptime_s, proc_count
from metrics
order by agent_id, ts desc;

-- ---------------------------------------------------------------- RLS

alter table agents      enable row level security;
alter table metrics     enable row level security;
alter table auth_events enable row level security;
alter table port_state  enable row level security;
alter table port_events enable row level security;

-- service_role bypasses RLS entirely, so the ingest API needs no policy.
-- These grant read-only access to signed-in dashboard users.
do $$
declare t text;
begin
    foreach t in array array['agents','metrics','auth_events','port_state','port_events']
    loop
        execute format(
            'create policy %I on %I for select to authenticated using (true)',
            t || '_read', t
        );
    end loop;
end $$;

-- The anon key must not be able to read telemetry before login.
revoke all on agents, metrics, auth_events, port_state, port_events from anon;

-- ---------------------------------------------------------------- retention

-- Metrics are the only table with real volume: ~5.7k rows/agent/day.
-- Auth and port events are low-volume and worth keeping longer.
create extension if not exists pg_cron;

select cron.schedule(
    'nodewatch-retention',
    '17 3 * * *',
    $$
    delete from metrics     where ts < now() - interval '30 days';
    delete from port_events where ts < now() - interval '90 days';
    delete from auth_events where ts < now() - interval '90 days';
    $$
);
