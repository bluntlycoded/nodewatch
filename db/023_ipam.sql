-- 023: IP address management, and two more application kinds.
--
-- IPAM here is mostly derivation rather than new collection. Addresses are
-- already visible in four places: agent interfaces, probe targets, sign-in
-- source IPs and enrolment records. Correlating those gives a real inventory
-- without a discovery protocol; a ping sweep fills the gaps for addresses
-- nothing has spoken to yet.

alter table probes drop constraint if exists probes_kind_check;
alter table probes add constraint probes_kind_check
    check (kind in ('ping','port','url','postgres','mysql',
                    'prometheus','nginx','tomcat','jboss'));

-- ---------------------------------------------------------------- subnets

create table if not exists subnets (
    id          uuid primary key default gen_random_uuid(),
    cidr        cidr        not null unique,
    name        text        not null,
    site        text,
    vlan        integer,
    gateway     inet,
    dhcp_range  text,
    notes       text,
    created_at  timestamptz not null default now()
);

comment on table subnets is
    'Declared by an operator. A subnet nobody declared is not an error - the discovered view shows addresses outside any declared range so they can be claimed or investigated.';

alter table subnets enable row level security;
drop policy if exists subnets_read on subnets;
drop policy if exists subnets_admin on subnets;
create policy subnets_read  on subnets for select to authenticated using (true);
create policy subnets_admin on subnets for all to authenticated
    using (is_admin()) with check (is_admin());
grant select, insert, update, delete on subnets to authenticated;
revoke all on subnets from anon;

-- ---------------------------------------------------------------- addresses

create table if not exists ip_addresses (
    ip          inet        primary key,
    hostname    text,
    mac         text,
    source      text        not null
                check (source in ('agent','probe','signin','sweep','manual')),
    agent_id    uuid references agents (id) on delete set null,
    note        text,
    first_seen  timestamptz not null default now(),
    last_seen   timestamptz not null default now()
);

create index if not exists ip_addresses_seen_idx on ip_addresses (last_seen desc);

alter table ip_addresses enable row level security;
drop policy if exists ip_read on ip_addresses;
drop policy if exists ip_admin on ip_addresses;
create policy ip_read  on ip_addresses for select to authenticated using (true);
create policy ip_admin on ip_addresses for all to authenticated
    using (is_admin()) with check (is_admin());
grant select, insert, update, delete on ip_addresses to authenticated;
revoke all on ip_addresses from anon;

-- Refresh the inventory from everything already collected. Ordered so that
-- the most authoritative source wins: an address we have an agent on beats
-- one we merely saw a login from.
create or replace function refresh_ip_inventory() returns integer
language plpgsql security definer set search_path = public as $$
declare n integer := 0;
begin
    -- Agent-reported interfaces: strongest evidence, and the only source
    -- that carries a MAC address.
    insert into ip_addresses (ip, hostname, mac, source, agent_id, last_seen)
    select distinct on (i.ipv4)
           i.ipv4, o.label, i.mac, 'agent', i.agent_id, i.last_seen
      from net_interfaces i
      join agent_overview o on o.id = i.agent_id
     where i.ipv4 is not null
       and not (i.ipv4 << inet '127.0.0.0/8')
     order by i.ipv4, i.last_seen desc
    on conflict (ip) do update set
        hostname = excluded.hostname,
        mac = coalesce(excluded.mac, ip_addresses.mac),
        source = 'agent',
        agent_id = excluded.agent_id,
        last_seen = excluded.last_seen;
    get diagnostics n = row_count;

    -- Probe targets that are literal addresses rather than hostnames.
    insert into ip_addresses (ip, hostname, source, last_seen)
    select distinct on (p.target::inet) p.target::inet, p.name, 'probe', now()
      from probes p
     where p.target ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
     order by p.target::inet, p.name
    on conflict (ip) do update set
        last_seen = excluded.last_seen,
        hostname = coalesce(ip_addresses.hostname, excluded.hostname);

    -- Sign-in sources: weakest evidence, and often external, but a login
    -- from an address nobody has claimed is exactly what IPAM is for.
    insert into ip_addresses (ip, source, last_seen)
    select e.source_ip, 'signin', max(e.ts)
      from auth_events e
     where e.source_ip is not null and e.ts > now() - interval '30 days'
     group by e.source_ip
    on conflict (ip) do update set last_seen = greatest(ip_addresses.last_seen, excluded.last_seen);

    return n;
end $$;

grant execute on function refresh_ip_inventory() to authenticated;

-- ---------------------------------------------------------------- views

create or replace view subnet_usage as
select s.id, s.cidr, s.name, s.site, s.vlan, s.gateway, s.dhcp_range, s.notes,
       -- Usable host addresses: the whole block minus network and broadcast,
       -- except for /31 and /32 where that convention does not apply.
       case when masklen(s.cidr) >= 31 then 2 ^ (32 - masklen(s.cidr))
            else 2 ^ (32 - masklen(s.cidr)) - 2 end::bigint as capacity,
       count(a.ip)                                          as used,
       count(a.ip) filter (where a.source = 'agent')        as managed,
       count(a.ip) filter (where a.last_seen > now() - interval '24 hours') as active_24h,
       -- The exponent returns double precision, which round(x, n) does not
       -- accept; cast before rounding.
       round((100.0 * count(a.ip) /
             nullif(case when masklen(s.cidr) >= 31 then 2 ^ (32 - masklen(s.cidr))
                         else 2 ^ (32 - masklen(s.cidr)) - 2 end, 0))::numeric, 2) as used_pct
  from subnets s
  left join ip_addresses a on a.ip << s.cidr
 group by s.id, s.cidr, s.name, s.site, s.vlan, s.gateway, s.dhcp_range, s.notes;

alter view subnet_usage set (security_invoker = on);
grant select on subnet_usage to authenticated;
revoke all on subnet_usage from anon;

create or replace view ip_inventory as
select a.ip, a.hostname, a.mac, a.source, a.agent_id, a.note,
       a.first_seen, a.last_seen,
       s.name as subnet_name, s.cidr as subnet,
       o.label as host, o.platform, o.status as host_status,
       -- An address outside every declared subnet is worth surfacing rather
       -- than hiding: either the range was never documented, or something is
       -- on the network that should not be.
       (s.id is null) as unclaimed
  from ip_addresses a
  left join subnets s on a.ip << s.cidr
  left join agent_overview o on o.id = a.agent_id;

alter view ip_inventory set (security_invoker = on);
grant select on ip_inventory to authenticated;
revoke all on ip_inventory from anon;

-- Same address, two MACs, seen recently: either a duplicate assignment or
-- something impersonating a host.
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

-- Keep the inventory current without an operator having to ask.
select cron.unschedule('nodewatch-ipam-refresh')
 where exists (select 1 from cron.job where jobname = 'nodewatch-ipam-refresh');
select cron.schedule('nodewatch-ipam-refresh', '*/10 * * * *',
    $$select refresh_ip_inventory();$$);
