-- 047: restore the views 030 dropped and never recreated.
--
-- 030_virtualization.sql rebuilds agent_overview with
-- `drop view if exists agent_overview cascade`. The cascade also removes
-- every view built on top of it, directly or through another view - eleven
-- of them, from 021 to 029 - and 030 recreates none of them. On a database
-- built from these migrations in order, the network, IPAM, topology,
-- business-service, application and automation pages have no data and
-- sweep_applications() / sweep_services() fail every minute.
-- db/diagnostics/*_retry.sql were hand-run repairs of the same symptom on
-- the live database.
--
-- Each view below is its latest definition, verbatim, with the grants and
-- security_invoker setting that followed it, in dependency order (checked
-- against a database built from 001-046). `create or replace` keeps this
-- harmless on a database that was already repaired by hand.
--
-- Any future migration that drops agent_overview (or another view) with
-- cascade must recreate its dependents in the same file.

-- alerts_awaiting: as last defined in 027_escalation.sql
create or replace view alerts_awaiting as
select l.id, l.rule, l.severity, l.subject, l.created_at,
       coalesce(o.label, 'fleet') as host,
       extract(epoch from (now() - l.created_at))::int as waiting_s,
       (select count(*) from alert_escalations e where e.alert_id = l.id) as escalated
  from alert_log l
  left join agent_overview o on o.id = l.agent_id
 where l.status = 'sent' and l.acknowledged_at is null and l.resolved_at is null
 order by l.created_at;
alter view alerts_awaiting set (security_invoker = on);
grant select on alerts_awaiting to authenticated;
revoke all on alerts_awaiting from anon;

-- application_overview: as last defined in 024_iis.sql
create or replace view application_overview as
with latest as (
    select distinct on (probe_id, agent_id, app_name) *
      from app_rates order by probe_id, agent_id, app_name, ts desc
),
hour as (
    select probe_id, agent_id, app_name,
           sum(coalesce(req_delta, 0)) as req_1h,
           sum(coalesce(err_delta, 0)) as err_1h,
           avg(p95_latency_s)          as p95_1h,
           max(p95_latency_s)          as p95_max_1h
      from app_rates where ts > now() - interval '1 hour'
     group by probe_id, agent_id, app_name
)
select p.id, p.kind, p.name, p.target, p.category, p.site, p.enabled, p.interval_s,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       null::uuid as agent_id, null::text as host,
       l.ts as measured_at,
       round(l.rps::numeric, 2) as rps, round(l.cpu_pct::numeric, 1) as cpu_pct,
       l.active_conns, l.p95_latency_s, l.avg_latency_s, l.memory_bytes,
       l.uptime_s, l.extra,
       coalesce(h.req_1h, 0) as requests_1h,
       coalesce(h.err_1h, 0) as errors_1h,
       case when coalesce(h.req_1h, 0) > 0
            then round(100.0 * h.err_1h / h.req_1h, 2) end as error_rate,
       round(h.p95_1h::numeric, 4)     as p95_avg_1h,
       round(h.p95_max_1h::numeric, 4) as p95_max_1h
  from probes p
  join probe_state st on st.id = p.id
  left join latest l on l.probe_id = p.id
  left join hour   h on h.probe_id = p.id
 where p.kind in ('prometheus', 'nginx', 'tomcat', 'jboss')

union all

select
       
       
       md5(l.agent_id::text || coalesce(l.app_name, ''))::uuid as id,
       'iis'::text as kind,
       coalesce(l.app_name, 'IIS') as name,
       o.label as target,
       'application'::text as category,
       o.site,
       true as enabled,
       60 as interval_s,
       
       case when o.status = 'down' then 'down' else 'up' end as status,
       l.ts as last_check,
       null::integer as latency_ms,
       case when o.status = 'down' then 'host is offline' end as detail,
       0 as consecutive,
       l.agent_id, o.label as host,
       l.ts as measured_at,
       round(l.rps::numeric, 2), round(l.cpu_pct::numeric, 1),
       l.active_conns, l.p95_latency_s, l.avg_latency_s, l.memory_bytes,
       l.uptime_s, l.extra,
       coalesce(h.req_1h, 0), coalesce(h.err_1h, 0),
       case when coalesce(h.req_1h, 0) > 0
            then round(100.0 * h.err_1h / h.req_1h, 2) end,
       round(h.p95_1h::numeric, 4), round(h.p95_max_1h::numeric, 4)
  from latest l
  join agent_overview o on o.id = l.agent_id
  left join hour h on h.agent_id = l.agent_id
                  and coalesce(h.app_name, '') = coalesce(l.app_name, '')
 where l.agent_id is not null;
alter view application_overview set (security_invoker = on);
grant select on application_overview to authenticated;
revoke all on application_overview from anon;

-- automation_queue: as last defined in 029_automation.sql
create or replace view automation_queue as
select x.id, x.rule_id, r.name as rule_name, r.action_url, r.dry_run,
       x.status, x.reason, x.request, x.response, x.http_status,
       x.approved_by, x.approved_at, x.created_at, x.finished_at,
       coalesce(o.label, s.name, 'fleet') as target
  from automation_runs x
  join automation_rules r on r.id = x.rule_id
  left join alert_log l   on l.id = x.alert_id
  left join agent_overview o on o.id = l.agent_id
  left join services s    on s.id = x.service_id
 order by x.created_at desc;
alter view automation_queue set (security_invoker = on);
grant select on automation_queue to authenticated;
revoke all on automation_queue from anon;

-- ip_conflicts: as last defined in 023_ipam.sql
create or replace view ip_conflicts as
select i.ipv4 as ip,
       count(distinct i.mac) as mac_count,
       array_agg(distinct i.mac) as macs,
       array_agg(distinct o.label) as hosts
  from net_interfaces i
  join agent_overview o on o.id = i.agent_id
 where i.ipv4 is not null and i.mac is not null
   and i.last_seen > now() - interval '24 hours'
 group by i.ipv4
having count(distinct i.mac) > 1;
alter view ip_conflicts set (security_invoker = on);
grant select on ip_conflicts to authenticated;
revoke all on ip_conflicts from anon;

-- ip_inventory: as last defined in 023_ipam.sql
create or replace view ip_inventory as
select a.ip, a.hostname, a.mac, a.source, a.agent_id, a.note,
       a.first_seen, a.last_seen,
       s.name as subnet_name, s.cidr as subnet,
       o.label as host, o.platform, o.status as host_status,
       
       
       
       (s.id is null) as unclaimed
  from ip_addresses a
  left join subnets s on a.ip << s.cidr
  left join agent_overview o on o.id = a.agent_id;
alter view ip_inventory set (security_invoker = on);
grant select on ip_inventory to authenticated;
revoke all on ip_inventory from anon;

-- network_overview: as last defined in 021_network.sql
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

-- service_component_state: as last defined in 028_bsm.sql
create or replace view service_component_state as
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

-- service_health: as last defined in 028_bsm.sql
create or replace view service_health as
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

-- service_impact: as last defined in 028_bsm.sql
create or replace view service_impact as
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

-- topology_nodes: as last defined in 026_topology.sql
create or replace view topology_nodes as

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

select 'subnet:' || s.id::text, 'subnet', s.name,
       case when u.used_pct >= 90 then 'degraded' else 'healthy' end,
       null::integer, s.site, s.cidr::text, null::text
  from subnets s join subnet_usage u on u.id = s.id
union all

select 'probe:' || p.id::text, p.kind, p.name, st.status, null::integer, p.site,
       p.target, nullif(regexp_replace(p.target, '^https?://([^:/]+).*$', '\1'), p.target)
  from probes p join probe_state st on st.id = p.id
 where p.enabled
union all


select distinct 'hop:' || host(h.ip), 'router', host(h.ip), 'healthy',
       null::integer, null::text, 'discovered by traceroute', host(h.ip)
  from route_hops h
 where h.ip is not null
   and h.traced_at > now() - interval '1 day'
   and not exists (select 1 from net_interfaces n where n.ipv4 = h.ip);
alter view topology_nodes set (security_invoker = on);
grant select on topology_nodes to authenticated;
revoke all on topology_nodes from anon;

-- link_overview: as last defined in 021_network.sql
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

