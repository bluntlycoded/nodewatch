-- 021: network interfaces.
--
-- Agent-reported rather than SNMP. That covers every host running the agent
-- without needing community strings or a route to management VLANs, and it
-- gives the Network and Link overviews something real to show. SNMP remains
-- the way to reach switches and appliances, and is still unbuilt.

create table if not exists net_interfaces (
    agent_id    uuid        not null references agents (id) on delete cascade,
    name        text        not null,
    is_up       boolean     not null default false,
    speed_mbps  integer,
    mtu         integer,
    ipv4        inet,
    mac         text,
    first_seen  timestamptz not null default now(),
    last_seen   timestamptz not null default now(),
    primary key (agent_id, name)
);

comment on column net_interfaces.speed_mbps is
    'Null when the driver does not report a speed, which is normal on virtual NICs. That is different from a 0 Mbps link and is kept distinguishable.';

create index if not exists net_if_up_idx on net_interfaces (agent_id) where is_up;

-- Cumulative counters, sampled. Throughput is the difference between
-- consecutive samples, computed on read: storing a rate would bake in
-- whatever interval happened to apply, and a restart would look like a
-- spike rather than a gap.
create table if not exists net_traffic (
    agent_id     uuid        not null references agents (id) on delete cascade,
    name         text        not null,
    ts           timestamptz not null,
    bytes_sent   bigint,
    bytes_recv   bigint,
    packets_sent bigint,
    packets_recv bigint,
    errin        bigint,
    errout       bigint,
    dropin       bigint,
    dropout      bigint,
    primary key (agent_id, name, ts)
);

create index if not exists net_traffic_ts_brin on net_traffic using brin (ts);
create index if not exists net_traffic_recent  on net_traffic (agent_id, name, ts desc);

alter table net_interfaces enable row level security;
alter table net_traffic    enable row level security;
drop policy if exists net_if_read on net_interfaces;
drop policy if exists net_traffic_read on net_traffic;
create policy net_if_read      on net_interfaces for select to authenticated using (true);
create policy net_traffic_read on net_traffic    for select to authenticated using (true);
grant select on net_interfaces, net_traffic to authenticated;
revoke all on net_interfaces, net_traffic from anon;

-- ---------------------------------------------------------------- rates

create or replace view net_rates as
with paired as (
    select agent_id, name, ts,
           bytes_sent, bytes_recv, errin, errout, dropin, dropout,
           lag(bytes_sent)   over w as p_sent,
           lag(bytes_recv)   over w as p_recv,
           lag(errin)        over w as p_errin,
           lag(errout)       over w as p_errout,
           lag(dropin)       over w as p_dropin,
           lag(dropout)      over w as p_dropout,
           extract(epoch from (ts - lag(ts) over w)) as dt
      from net_traffic
     where ts > now() - interval '2 hours'
    window w as (partition by agent_id, name order by ts)
)
select agent_id, name, ts, dt,
       -- A negative delta means the counter reset (reboot, or a 32-bit
       -- wrap on some drivers). Discard rather than report a huge spike.
       case when dt > 0 and bytes_sent >= p_sent
            then (bytes_sent - p_sent) / dt end as tx_bps,
       case when dt > 0 and bytes_recv >= p_recv
            then (bytes_recv - p_recv) / dt end as rx_bps,
       case when bytes_sent >= p_sent then bytes_sent - p_sent end as tx_delta,
       case when bytes_recv >= p_recv then bytes_recv - p_recv end as rx_delta,
       case when errin  >= p_errin  then errin  - p_errin  end as errin_delta,
       case when errout >= p_errout then errout - p_errout end as errout_delta,
       case when dropin >= p_dropin then dropin - p_dropin end as dropin_delta,
       case when dropout >= p_dropout then dropout - p_dropout end as dropout_delta
  from paired
 where p_sent is not null;

alter view net_rates set (security_invoker = on);
grant select on net_rates to authenticated;
revoke all on net_rates from anon;

-- ---------------------------------------------------------------- overviews

-- One row per interface: current state, latest throughput, and utilisation
-- against link speed where the driver reports one.
create or replace view network_overview as
with latest as (
    select distinct on (agent_id, name) *
      from net_rates order by agent_id, name, ts desc
),
errs as (
    select agent_id, name,
           sum(coalesce(errin_delta,0) + coalesce(errout_delta,0))   as errors_1h,
           sum(coalesce(dropin_delta,0) + coalesce(dropout_delta,0)) as drops_1h,
           sum(coalesce(tx_delta,0))                                 as tx_1h,
           sum(coalesce(rx_delta,0))                                 as rx_1h
      from net_rates where ts > now() - interval '1 hour'
     group by agent_id, name
)
select i.agent_id,
       o.label        as host,
       o.platform,
       o.status       as host_status,
       o.site,
       i.name,
       i.is_up,
       i.speed_mbps,
       i.mtu,
       i.ipv4,
       i.mac,
       i.last_seen,
       round(l.tx_bps)::bigint as tx_bps,
       round(l.rx_bps)::bigint as rx_bps,
       coalesce(e.errors_1h, 0) as errors_1h,
       coalesce(e.drops_1h, 0)  as drops_1h,
       coalesce(e.tx_1h, 0)     as tx_1h,
       coalesce(e.rx_1h, 0)     as rx_1h,
       -- Utilisation only means something when the link speed is known.
       case when i.speed_mbps > 0 and l.tx_bps is not null
            then round(100.0 * ((l.tx_bps + l.rx_bps) * 8)
                       / (i.speed_mbps * 1000000.0), 2) end as util_pct
  from net_interfaces i
  join agent_overview o on o.id = i.agent_id
  left join latest l on l.agent_id = i.agent_id and l.name = i.name
  left join errs   e on e.agent_id = i.agent_id and e.name = i.name;

alter view network_overview set (security_invoker = on);
grant select on network_overview to authenticated;
revoke all on network_overview from anon;

-- Busiest links, which is what the Link Overview answers.
create or replace view link_overview as
select host, platform, name, is_up, speed_mbps, ipv4,
       tx_bps, rx_bps, (coalesce(tx_bps,0) + coalesce(rx_bps,0)) as total_bps,
       util_pct, errors_1h, drops_1h, tx_1h, rx_1h
  from network_overview
 where is_up
 order by total_bps desc nulls last;

alter view link_overview set (security_invoker = on);
grant select on link_overview to authenticated;
revoke all on link_overview from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('link_errors', 'warning', interval '2 hours',
     'A network interface is accumulating errors or drops')
on conflict (rule) do nothing;

create or replace function sweep_links() returns integer
language plpgsql security definer set search_path = public as $$
declare r record; n integer := 0;
begin
    for r in select * from network_overview
              where errors_1h > 100 or drops_1h > 1000
    loop
        if queue_alert(r.agent_id, 'link_errors',
            format('[warning] %s on %s is dropping traffic', r.name, r.host),
            format(E'Interface: %s\nErrors (1h): %s\nDrops (1h): %s\n\n'
                   'Usually a cable, duplex mismatch, or a saturated link.',
                   r.name, r.errors_1h, r.drops_1h))
        then n := n + 1; end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-link-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-link-sweep');
select cron.schedule('nodewatch-link-sweep', '*/5 * * * *', $$select sweep_links();$$);

select cron.unschedule('nodewatch-net-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-net-retention');
select cron.schedule('nodewatch-net-retention', '5 5 * * *',
    $$delete from net_traffic where ts < now() - interval '7 days';$$);
