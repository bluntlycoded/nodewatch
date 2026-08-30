-- 028: business service mapping.
--
-- Infrastructure grouped into the services it supports, so an outage reads
-- as "payments degraded" rather than as a list of hosts. The hard part is
-- not the grouping but the rollup: deciding what a service's health is when
-- three of its five components are unhappy in different ways.
--
-- The rule here is explicit rather than clever. A component is either
-- required or redundant. Any required component down takes the service down;
-- redundant components degrade it until all of them are gone.

create table if not exists services (
    id          uuid primary key default gen_random_uuid(),
    name        text not null unique,
    description text,
    owner       text,
    -- Tier drives nothing automatically. It exists so the list can be sorted
    -- by what matters when several things break at once.
    tier        integer not null default 2 check (tier between 1 and 3),
    created_at  timestamptz not null default now()
);

comment on column services.tier is
    '1 = the institution notices within minutes, 2 = within a day, 3 = eventually. Sorting only; no rule reads it.';

create table if not exists service_components (
    id         uuid primary key default gen_random_uuid(),
    service_id uuid not null references services (id) on delete cascade,
    -- Exactly one of these identifies the component.
    agent_id   uuid references agents (id) on delete cascade,
    probe_id   uuid references probes (id) on delete cascade,
    -- Required components take the service down; redundant ones degrade it
    -- until every sibling in the same group is also down.
    required   boolean not null default true,
    group_name text,
    note       text,
    constraint one_component check ((agent_id is not null) <> (probe_id is not null))
);

create index if not exists svc_comp_service on service_components (service_id);

create table if not exists service_dependencies (
    service_id uuid not null references services (id) on delete cascade,
    depends_on uuid not null references services (id) on delete cascade,
    primary key (service_id, depends_on),
    -- A service depending on itself would make the rollup recurse forever.
    constraint no_self_dependency check (service_id <> depends_on)
);

alter table services             enable row level security;
alter table service_components   enable row level security;
alter table service_dependencies enable row level security;

drop policy if exists svc_read  on services;
drop policy if exists svc_admin on services;
drop policy if exists comp_read  on service_components;
drop policy if exists comp_admin on service_components;
drop policy if exists dep_read  on service_dependencies;
drop policy if exists dep_admin on service_dependencies;
create policy svc_read   on services for select to authenticated using (true);
create policy svc_admin  on services for all to authenticated
    using (is_admin()) with check (is_admin());
create policy comp_read  on service_components for select to authenticated using (true);
create policy comp_admin on service_components for all to authenticated
    using (is_admin()) with check (is_admin());
create policy dep_read   on service_dependencies for select to authenticated using (true);
create policy dep_admin  on service_dependencies for all to authenticated
    using (is_admin()) with check (is_admin());

grant select, insert, update, delete
    on services, service_components, service_dependencies to authenticated;
revoke all on services, service_components, service_dependencies from anon;

-- ---------------------------------------------------------------- rollup

-- One row per component with its current state resolved, whichever kind of
-- thing it is.
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
           -- A redundant group is only lost when every member of it is down.
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
       -- What actually caused the state, so the list explains itself without
       -- anyone having to open each service.
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

-- A service can also be dragged down by something it depends on, which is
-- worth separating from its own components failing.
create or replace view service_impact as
select h.id, h.name, h.tier, h.status, h.reason,
       array_remove(array_agg(d.depends_on), null)  as depends_on,
       array_remove(array_agg(dh.name) filter (where dh.status in ('down','degraded')),
                    null)                            as failing_dependencies,
       -- The worst of the service's own state and anything it depends on.
       -- Taking the dependency's state outright would let a degraded
       -- dependency mask the service being down on its own account.
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

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('service_down', 'critical', interval '30 minutes',
     'A mapped business service has lost a required component')
on conflict (rule) do nothing;

create or replace function sweep_services() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
begin
    select cooldown into cd from alert_rules where rule = 'service_down' and enabled;
    if cd is null then return 0; end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from service_health where status = 'down' loop
        select last_sent into last from alert_state
         where agent_id is null and rule = 'service_down:' || r.id::text;
        continue when last is not null and now() - last < cd;

        insert into alert_log (agent_id, rule, severity, subject, body, recipients)
        values (null, 'service_down', 'critical',
                format('[critical] %s is down', r.name),
                format(E'Service: %s (tier %s)\nCause: %s\nComponents: %s, %s down\n\n%s',
                       r.name, r.tier, r.reason, r.components, r.down,
                       coalesce(r.description, '')),
                coalesce(people, '{}'));

        update alert_state set last_sent = now()
         where agent_id is null and rule = 'service_down:' || r.id::text;
        if not found then
            insert into alert_state (agent_id, rule, last_sent)
            values (null, 'service_down:' || r.id::text, now());
        end if;
        n := n + 1;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-services')
 where exists (select 1 from cron.job where jobname = 'nodewatch-services');
select cron.schedule('nodewatch-services', '* * * * *', $$select sweep_services();$$);
