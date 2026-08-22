-- 031: Proxmox VE monitoring.
--
-- A Proxmox check differs from the database checks in the same family:
-- one poll of /cluster/resources returns every node, VM and container in
-- the cluster, plus every storage pool, in a single request - there is no
-- per-guest connection to open the way there is for postgres or mysql.
-- Backup outcomes come from a second call, /cluster/tasks filtered to
-- vzdump, because they are events rather than current state.
--
-- Auth is an API token (user@realm!tokenid + secret), not a password, so it
-- reuses the existing username/password fields in probe_secrets rather than
-- adding new ones: user holds the full token id, password holds the secret.

alter table probes drop constraint if exists probes_kind_check;
alter table probes add constraint probes_kind_check
    check (kind in ('ping','port','url','postgres','mysql','mssql','oracle',
                     'prometheus','nginx','tomcat','jboss','proxmox'));

-- ---------------------------------------------------------------- guests

-- Current inventory. Upserted every poll like port_state and host_packages -
-- the agentless equivalent of a snapshot the server keeps current rather
-- than a full history of every sample.
create table if not exists proxmox_guests (
    probe_id      uuid    not null references probes (id) on delete cascade,
    vmid          integer not null,
    node          text    not null,
    name          text,
    kind          text    not null check (kind in ('qemu','lxc')),
    status        text    not null,          -- running, stopped, paused
    cpu_pct       real,
    mem_bytes     bigint,
    mem_max_bytes bigint,
    disk_bytes    bigint,
    disk_max_bytes bigint,
    uptime_s      bigint,
    last_seen     timestamptz not null default now(),
    primary key (probe_id, vmid)
);

create index if not exists proxmox_guests_probe_idx on proxmox_guests (probe_id);

alter table proxmox_guests enable row level security;
drop policy if exists proxmox_guests_read on proxmox_guests;
create policy proxmox_guests_read on proxmox_guests for select to authenticated using (true);
grant select on proxmox_guests to authenticated;
revoke all on proxmox_guests from anon;

-- ---------------------------------------------------------------- storage

create table if not exists proxmox_storage (
    probe_id    uuid not null references probes (id) on delete cascade,
    node        text not null,
    storage     text not null,
    kind        text,                        -- dir, lvm, zfspool, nfs, ...
    used_bytes  bigint,
    total_bytes bigint,
    last_seen   timestamptz not null default now(),
    primary key (probe_id, node, storage)
);

alter table proxmox_storage enable row level security;
drop policy if exists proxmox_storage_read on proxmox_storage;
create policy proxmox_storage_read on proxmox_storage for select to authenticated using (true);
grant select on proxmox_storage to authenticated;
revoke all on proxmox_storage from anon;

-- ---------------------------------------------------------------- backups

-- Append-only, like port_events: a backup outcome is an event, not state.
-- Keyed on Proxmox's own task id (UPID) rather than (probe_id, ts), because
-- a resync after a gap must not re-derive duplicates from overlapping polls.
create table if not exists proxmox_backups (
    probe_id  uuid    not null references probes (id) on delete cascade,
    upid      text    not null,
    vmid      integer,
    node      text,
    ts        timestamptz not null,
    ok        boolean not null,
    duration_s integer,
    detail    text,
    primary key (probe_id, upid)
);

create index if not exists proxmox_backups_ts_brin      on proxmox_backups using brin (ts);
create index if not exists proxmox_backups_probe_ts_idx on proxmox_backups (probe_id, ts desc);

alter table proxmox_backups enable row level security;
drop policy if exists proxmox_backups_read on proxmox_backups;
create policy proxmox_backups_read on proxmox_backups for select to authenticated using (true);
grant select on proxmox_backups to authenticated;
revoke all on proxmox_backups from anon;

-- ---------------------------------------------------------------- cluster metrics

-- One row per poll: the fleet-level rollup, same shape as db_metrics/
-- app_metrics so the dashboard's polling and history code stays uniform.
create table if not exists proxmox_metrics (
    probe_id     uuid        not null references probes (id) on delete cascade,
    ts           timestamptz not null,
    nodes_total  integer,
    nodes_online integer,
    guests_total integer,
    guests_running integer,
    cpu_pct      real,
    mem_pct      real,
    storage_pct_worst real,
    backups_failed_24h integer,
    extra        jsonb,
    primary key (probe_id, ts)
);

create index if not exists proxmox_metrics_ts_brin on proxmox_metrics using brin (ts);
create index if not exists proxmox_metrics_recent  on proxmox_metrics (probe_id, ts desc);

alter table proxmox_metrics enable row level security;
drop policy if exists proxmox_metrics_read on proxmox_metrics;
create policy proxmox_metrics_read on proxmox_metrics for select to authenticated using (true);
grant select on proxmox_metrics to authenticated;
revoke all on proxmox_metrics from anon;

-- ---------------------------------------------------------------- views

create or replace view proxmox_overview as
with latest as (
    select distinct on (probe_id) * from proxmox_metrics order by probe_id, ts desc
)
select p.id, p.name, p.category, p.site, p.enabled, p.interval_s,
       s.host, s.configured,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       l.ts as measured_at,
       l.nodes_total, l.nodes_online, l.guests_total, l.guests_running,
       l.cpu_pct, l.mem_pct, l.storage_pct_worst, l.backups_failed_24h, l.extra
  from probes p
  join probe_state st on st.id = p.id
  left join probe_secret_status s on s.probe_id = p.id
  left join latest l on l.probe_id = p.id
 where p.kind = 'proxmox';

alter view proxmox_overview set (security_invoker = on);
grant select on proxmox_overview to authenticated;
revoke all on proxmox_overview from anon;

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
  from probe_state where enabled group by kind
union all
select 'PROXMOX GUESTS', upper(g.status), count(*), count(*) filter (where g.status='running'),
       round(100.0*count(*) filter (where g.status='running')/nullif(count(*),0))
  from proxmox_guests g join proxmox_overview o on o.id = g.probe_id
 where o.enabled group by g.status;

alter view health_matrix set (security_invoker = on);
grant select on health_matrix to authenticated;
revoke all on health_matrix from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('proxmox_backup_failed', 'warning', interval '6 hours',
     'A Proxmox guest backup job failed'),
    ('proxmox_storage_full', 'critical', interval '1 hour',
     'A Proxmox storage pool is nearly full')
on conflict (rule) do nothing;

create or replace function sweep_proxmox() returns integer
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

    -- Backups that failed in the last poll cycle's worth of lookback. The
    -- table is a log, so this checks for anything new rather than a status.
    for r in
        select b.probe_id, b.vmid, b.node, b.detail, o.name as cluster
          from proxmox_backups b
          join proxmox_overview o on o.id = b.probe_id
         where not b.ok and b.ts > now() - interval '10 minutes'
    loop
        select cooldown into cd from alert_rules where rule='proxmox_backup_failed' and enabled;
        select last_sent into last from alert_state
         where agent_id is null and rule = 'proxmox_backup_failed:' || r.probe_id::text || ':' || r.vmid::text;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients)
            values (null, 'proxmox_backup_failed', 'warning',
                    format('[warning] backup failed for guest %s on %s', r.vmid, r.cluster),
                    format(E'Cluster: %s\nNode: %s\nGuest: %s\n\n%s',
                           r.cluster, r.node, r.vmid, coalesce(r.detail, 'no detail reported')),
                    coalesce(people, '{}'));
            update alert_state set last_sent = now()
             where agent_id is null and rule = 'proxmox_backup_failed:' || r.probe_id::text || ':' || r.vmid::text;
            if not found then
                insert into alert_state (agent_id, rule, last_sent)
                values (null, 'proxmox_backup_failed:' || r.probe_id::text || ':' || r.vmid::text, now());
            end if;
            n := n + 1;
        end if;
    end loop;

    -- Storage pools close to full.
    for r in
        select s.probe_id, s.node, s.storage, o.name as cluster,
               round(100.0 * s.used_bytes / nullif(s.total_bytes, 0), 1) as pct
          from proxmox_storage s
          join proxmox_overview o on o.id = s.probe_id
         where o.enabled and s.total_bytes > 0
    loop
        continue when r.pct is null or r.pct < 90;
        select cooldown into cd from alert_rules where rule='proxmox_storage_full' and enabled;
        select last_sent into last from alert_state
         where agent_id is null and rule = 'proxmox_storage_full:' || r.probe_id::text || ':' || r.node || ':' || r.storage;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients)
            values (null, 'proxmox_storage_full', 'critical',
                    format('[critical] %s on %s is %s%% full', r.storage, r.node, r.pct),
                    format(E'Cluster: %s\nNode: %s\nStorage: %s\nUsed: %s%%\n\n'
                           'New disk allocations and backups will start failing at 100%%.',
                           r.cluster, r.node, r.storage, r.pct),
                    coalesce(people, '{}'));
            update alert_state set last_sent = now()
             where agent_id is null and rule = 'proxmox_storage_full:' || r.probe_id::text || ':' || r.node || ':' || r.storage;
            if not found then
                insert into alert_state (agent_id, rule, last_sent)
                values (null, 'proxmox_storage_full:' || r.probe_id::text || ':' || r.node || ':' || r.storage, now());
            end if;
            n := n + 1;
        end if;
    end loop;

    return n;
end $$;

select cron.unschedule('nodewatch-proxmox-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-proxmox-sweep');
select cron.schedule('nodewatch-proxmox-sweep', '* * * * *', $$select sweep_proxmox();$$);

select cron.unschedule('nodewatch-proxmox-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-proxmox-retention');
select cron.schedule('nodewatch-proxmox-retention', '59 4 * * *',
    $$delete from proxmox_metrics where ts < now() - interval '30 days';
      delete from proxmox_backups where ts < now() - interval '90 days';$$);
