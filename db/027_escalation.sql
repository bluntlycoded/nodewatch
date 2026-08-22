-- 027: escalation policies.
--
-- An alert that nobody acknowledges should get louder, not sit unread. The
-- alert log already records acknowledgement, so escalation is a matter of
-- noticing what has not been acknowledged and after how long.
--
-- Escalated notifications are written back into alert_log as new rows, so
-- they travel the delivery pipeline that already exists rather than getting
-- a parallel one.

create table if not exists escalation_policies (
    id          uuid primary key default gen_random_uuid(),
    name        text not null unique,
    -- Which alerts this policy governs. Empty severity list means any.
    severities  text[] not null default '{critical}',
    rules       text[] not null default '{}',    -- empty means any rule
    -- Outside these hours only critical alerts escalate. Someone woken at
    -- 3am for a warning stops reading alerts entirely, which is worse than
    -- not sending it.
    quiet_start time,
    quiet_end   time,
    quiet_timezone text not null default 'UTC',
    enabled     boolean not null default true,
    created_at  timestamptz not null default now()
);

create table if not exists escalation_steps (
    id          uuid primary key default gen_random_uuid(),
    policy_id   uuid not null references escalation_policies (id) on delete cascade,
    step        integer not null,
    -- Minutes after the alert was raised, not after the previous step, so
    -- reordering steps cannot silently change the whole timeline.
    after_min   integer not null check (after_min >= 0),
    recipients  text[] not null default '{}',
    channel_ids uuid[] not null default '{}',
    note        text,
    unique (policy_id, step)
);

create table if not exists alert_escalations (
    alert_id   bigint  not null references alert_log (id) on delete cascade,
    step_id    uuid    not null references escalation_steps (id) on delete cascade,
    fired_at   timestamptz not null default now(),
    primary key (alert_id, step_id)
);

alter table escalation_policies enable row level security;
alter table escalation_steps    enable row level security;
alter table alert_escalations   enable row level security;

drop policy if exists esc_pol_read  on escalation_policies;
drop policy if exists esc_pol_admin on escalation_policies;
drop policy if exists esc_step_read  on escalation_steps;
drop policy if exists esc_step_admin on escalation_steps;
drop policy if exists esc_fire_read on alert_escalations;
create policy esc_pol_read   on escalation_policies for select to authenticated using (true);
create policy esc_pol_admin  on escalation_policies for all to authenticated
    using (is_admin()) with check (is_admin());
create policy esc_step_read  on escalation_steps for select to authenticated using (true);
create policy esc_step_admin on escalation_steps for all to authenticated
    using (is_admin()) with check (is_admin());
create policy esc_fire_read  on alert_escalations for select to authenticated using (true);

grant select, insert, update, delete on escalation_policies, escalation_steps to authenticated;
grant select on alert_escalations to authenticated;
revoke all on escalation_policies, escalation_steps, alert_escalations from anon;

-- ---------------------------------------------------------------- engine

create or replace function in_quiet_hours(p escalation_policies) returns boolean
language sql stable as $$
    select case
      when p.quiet_start is null or p.quiet_end is null then false
      -- A window that wraps midnight (22:00 to 07:00) needs the opposite
      -- comparison to one that does not.
      when p.quiet_start <= p.quiet_end then
           (now() at time zone p.quiet_timezone)::time between p.quiet_start and p.quiet_end
      else (now() at time zone p.quiet_timezone)::time >= p.quiet_start
        or (now() at time zone p.quiet_timezone)::time <= p.quiet_end
    end;
$$;

create or replace function sweep_escalations() returns integer
language plpgsql security definer set search_path = public as $$
declare
    a      record;
    p      escalation_policies%rowtype;
    st     record;
    n      integer := 0;
    people text[];
begin
    -- Only alerts that were actually delivered, are still unacknowledged and
    -- unresolved. Escalating something already suppressed or failed would be
    -- shouting about a message nobody received in the first place.
    for a in select * from alert_log
              where status = 'sent'
                and acknowledged_at is null
                and resolved_at is null
                and created_at > now() - interval '24 hours'
    loop
        for p in select * from escalation_policies where enabled
                  and (cardinality(severities) = 0 or a.severity = any(severities))
                  and (cardinality(rules) = 0 or a.rule = any(rules))
        loop
            if in_quiet_hours(p) and a.severity <> 'critical' then
                continue;
            end if;

            for st in select * from escalation_steps
                       where policy_id = p.id
                         and now() >= a.created_at + make_interval(mins => after_min)
                       order by step
            loop
                continue when exists (select 1 from alert_escalations
                                       where alert_id = a.id and step_id = st.id);

                select array_agg(distinct lower(x)) into people
                  from unnest(st.recipients) x;

                insert into alert_log (agent_id, rule, severity, subject, body, recipients)
                values (a.agent_id, a.rule, a.severity,
                        format('[escalation %s] %s', st.step, a.subject),
                        format(E'Not acknowledged after %s minutes.\n\n%s\n\n'
                               '--\nEscalation policy: %s, step %s%s',
                               st.after_min, coalesce(a.body, ''), p.name, st.step,
                               case when st.note is null then '' else E'\n' || st.note end),
                        coalesce(people, '{}'));

                insert into alert_escalations (alert_id, step_id) values (a.id, st.id);
                n := n + 1;
            end loop;
        end loop;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-escalations')
 where exists (select 1 from cron.job where jobname = 'nodewatch-escalations');
select cron.schedule('nodewatch-escalations', '* * * * *', $$select sweep_escalations();$$);

-- ---------------------------------------------------------------- views

create or replace view escalation_overview as
select p.id, p.name, p.severities, p.rules, p.enabled,
       p.quiet_start, p.quiet_end, p.quiet_timezone,
       in_quiet_hours(p.*) as quiet_now,
       (select count(*) from escalation_steps s where s.policy_id = p.id) as steps,
       (select min(after_min) from escalation_steps s where s.policy_id = p.id) as first_after,
       (select max(after_min) from escalation_steps s where s.policy_id = p.id) as last_after,
       (select count(*) from alert_escalations e
          join escalation_steps s on s.id = e.step_id
         where s.policy_id = p.id and e.fired_at > now() - interval '7 days') as fired_7d
  from escalation_policies p;

alter view escalation_overview set (security_invoker = on);
grant select on escalation_overview to authenticated;
revoke all on escalation_overview from anon;

-- Alerts currently waiting on someone, and how long they have waited. This
-- is the number that says whether the alerting is working at all.
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
