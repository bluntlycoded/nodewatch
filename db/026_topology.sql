-- 026: topology.
--
-- This is a reachability and dependency map, not a wiring diagram. Switch
-- port mapping and VLAN adjacency need LLDP or CDP neighbour tables, which
-- need SNMP, which is not built. What can be known without it:
--
--   route     L3 path between the probe host and a target, from traceroute
--   subnet    which declared subnet an address belongs to
--   monitors  which check watches which target
--   runs      which host an application or database lives on
--
-- Every edge is derived from data already collected except route, which is
-- the one thing that needs an active measurement.

create table if not exists route_hops (
    probe_id   uuid        not null references probes (id) on delete cascade,
    traced_at  timestamptz not null,
    hop        integer     not null,
    ip         inet,
    rtt_ms     real,
    primary key (probe_id, traced_at, hop)
);

create index if not exists route_hops_recent on route_hops (probe_id, traced_at desc);

alter table route_hops enable row level security;
drop policy if exists route_hops_read on route_hops;
create policy route_hops_read on route_hops for select to authenticated using (true);
grant select on route_hops to authenticated;
revoke all on route_hops from anon;

-- Only the most recent trace per target matters; the history is noise.
select cron.unschedule('nodewatch-route-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-route-retention');
select cron.schedule('nodewatch-route-retention', '20 5 * * *',
    $$delete from route_hops where traced_at < now() - interval '2 days';$$);

-- ---------------------------------------------------------------- nodes

create or replace view topology_nodes as
-- Monitored hosts.
select 'host:' || o.id::text        as id,
       'host'::text                 as kind,
       o.label                      as name,
       o.status,
       o.trust,
       o.site,
       coalesce(o.platform, 'linux') as detail,
       (select i.ipv4::text from net_interfaces i
         where i.agent_id = o.id and i.ipv4 is not null
         order by i.last_seen desc limit 1) as ip
  from agent_overview o
 where o.agent_version is not null
union all
-- Declared subnets, which are what group everything else visually.
select 'subnet:' || s.id::text, 'subnet', s.name,
       case when u.used_pct >= 90 then 'degraded' else 'healthy' end,
       null::integer, s.site, s.cidr::text, null::text
  from subnets s join subnet_usage u on u.id = s.id
union all
-- Agentless targets: a check is the only evidence some of these exist.
select 'probe:' || p.id::text, p.kind, p.name, st.status, null::integer, p.site,
       p.target, nullif(regexp_replace(p.target, '^https?://([^:/]+).*$', '\1'), p.target)
  from probes p join probe_state st on st.id = p.id
 where p.enabled
union all
-- Intermediate routers discovered by tracing. They run nothing we manage,
-- but an outage at one explains several targets going dark at once.
select distinct 'hop:' || host(h.ip), 'router', host(h.ip), 'healthy',
       null::integer, null::text, 'discovered by traceroute', host(h.ip)
  from route_hops h
 where h.ip is not null
   and h.traced_at > now() - interval '1 day'
   and not exists (select 1 from net_interfaces n where n.ipv4 = h.ip);

alter view topology_nodes set (security_invoker = on);
grant select on topology_nodes to authenticated;
revoke all on topology_nodes from anon;

-- ---------------------------------------------------------------- edges

create or replace view topology_edges as
-- A host sits in a subnet.
select 'host:' || i.agent_id::text as src,
       'subnet:' || s.id::text     as dst,
       'subnet'::text              as kind,
       null::real                  as rtt_ms,
       host(i.ipv4)                as label
  from net_interfaces i
  join subnets s on i.ipv4 << s.cidr
 where i.ipv4 is not null
union all
-- A check watches a target. Where that target is a host we already manage,
-- the edge lands on the host rather than creating a duplicate node.
select 'probe:' || p.id::text,
       coalesce('host:' || (select n.agent_id::text from net_interfaces n
                             where n.ipv4::text = p.target limit 1),
                'subnet:' || (select s.id::text from subnets s
                               where p.target ~ '^\d+\.\d+\.\d+\.\d+$'
                                 and p.target::inet << s.cidr limit 1)),
       'monitors', null, p.kind
  from probes p
 where p.enabled
   and (exists (select 1 from net_interfaces n where n.ipv4::text = p.target)
        or (p.target ~ '^\d+\.\d+\.\d+\.\d+$'
            and exists (select 1 from subnets s where p.target::inet << s.cidr)))
union all
-- Consecutive hops on the most recent trace to each target.
select case when prev.ip is null then 'probe:' || cur.probe_id::text
            else 'hop:' || host(prev.ip) end,
       'hop:' || host(cur.ip),
       'route', cur.rtt_ms, cur.hop::text
  from (
    select h.*, lag(h.ip) over (partition by h.probe_id order by h.hop) as prev_ip,
           row_number() over (partition by h.probe_id order by h.traced_at desc, h.hop) as rn
      from route_hops h
     where h.traced_at = (select max(t.traced_at) from route_hops t
                           where t.probe_id = h.probe_id)
  ) cur
  left join lateral (select cur.prev_ip as ip) prev on true
 where cur.ip is not null;

alter view topology_edges set (security_invoker = on);
grant select on topology_edges to authenticated;
revoke all on topology_edges from anon;

-- What the map can and cannot show, kept next to the data rather than only
-- in the interface, so anyone querying directly sees the same caveat.
comment on view topology_edges is
    'Reachability and dependency edges derived from collected telemetry plus traceroute. Physical adjacency - which switch port a device occupies, which links join two switches - is not represented, because that needs LLDP or CDP over SNMP.';
