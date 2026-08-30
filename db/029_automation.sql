-- 029: automation.
--
-- This is the first feature that changes things rather than observing them,
-- so the design is deliberately conservative.
--
-- What it does NOT do, on purpose: it does not execute commands on monitored
-- hosts. The agent only ever pushes; giving it the ability to receive and run
-- commands would turn every agent into a remote shell reachable from the
-- monitoring server, which is a much larger security surface than anything
-- else here and is not something to add casually.
--
-- What it does instead: decides WHEN something should happen, and hands the
-- WHAT to a system built for it - Ansible AWX, Rundeck, a CI pipeline, a
-- webhook receiver. nodewatch knows the state of the estate; those tools
-- know how to change it safely, with their own audit trail and rollback.
--
-- Every run is recorded, every rule can require approval, and a dry run is
-- the default until someone deliberately turns it off.

create table if not exists automation_rules (
    id            uuid primary key default gen_random_uuid(),
    name          text not null unique,
    description   text,
    -- What starts it: an alert rule firing, or a service going down.
    trigger_type  text not null check (trigger_type in ('alert', 'service')),
    trigger_rules text[] not null default '{}',   -- empty means any
    severities    text[] not null default '{critical}',
    -- The only action kind for now. Named rather than assumed so adding
    -- others later is an explicit decision.
    action_type   text not null default 'webhook' check (action_type in ('webhook')),
    action_url    text,
    action_method text not null default 'POST' check (action_method in ('POST','PUT')),
    action_headers jsonb not null default '{}',
    action_body   jsonb not null default '{}',
    -- Safety rails.
    requires_approval boolean not null default true,
    dry_run       boolean not null default true,
    max_per_day   integer not null default 5 check (max_per_day between 1 and 100),
    enabled       boolean not null default false,
    created_at    timestamptz not null default now()
);

comment on table automation_rules is
    'Rules default to disabled, dry-run and approval-required. Turning all three off is three deliberate acts, not an oversight.';

comment on column automation_rules.max_per_day is
    'A rule that fires in response to a condition it fails to fix would otherwise run forever. This is the stop.';

create table if not exists automation_runs (
    id          uuid primary key default gen_random_uuid(),
    rule_id     uuid not null references automation_rules (id) on delete cascade,
    alert_id    bigint references alert_log (id) on delete set null,
    service_id  uuid references services (id) on delete set null,
    status      text not null default 'pending'
                check (status in ('pending','approved','rejected','running',
                                  'done','failed','skipped','dry_run')),
    reason      text,
    request     jsonb,
    response    text,
    http_status integer,
    approved_by text,
    approved_at timestamptz,
    created_at  timestamptz not null default now(),
    finished_at timestamptz
);

create index if not exists auto_runs_pending on automation_runs (created_at)
    where status in ('pending','approved');
create index if not exists auto_runs_recent on automation_runs (rule_id, created_at desc);

alter table automation_rules enable row level security;
alter table automation_runs  enable row level security;

drop policy if exists auto_rule_read  on automation_rules;
drop policy if exists auto_rule_admin on automation_rules;
drop policy if exists auto_run_read   on automation_runs;
drop policy if exists auto_run_admin  on automation_runs;
create policy auto_rule_read  on automation_rules for select to authenticated using (true);
create policy auto_rule_admin on automation_rules for all to authenticated
    using (is_admin()) with check (is_admin());
create policy auto_run_read   on automation_runs for select to authenticated using (true);
-- Approving a run is an admin act: it is the moment something actually happens.
create policy auto_run_admin  on automation_runs for update to authenticated
    using (is_admin()) with check (is_admin());

grant select, insert, update, delete on automation_rules to authenticated;
grant select, update on automation_runs to authenticated;
revoke all on automation_rules, automation_runs from anon;

-- ---------------------------------------------------------------- trigger

create or replace function queue_automation() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r     automation_rules%rowtype;
    a     record;
    s     record;
    n     integer := 0;
    today integer;
begin
    for r in select * from automation_rules where enabled loop
        select count(*) into today from automation_runs
         where rule_id = r.id and created_at > now() - interval '24 hours'
           and status <> 'skipped';
        continue when today >= r.max_per_day;

        if r.trigger_type = 'alert' then
            for a in select * from alert_log
                      where status = 'sent'
                        and created_at > now() - interval '1 hour'
                        and (cardinality(r.trigger_rules) = 0 or rule = any(r.trigger_rules))
                        and (cardinality(r.severities) = 0 or severity = any(r.severities))
                        and not exists (select 1 from automation_runs ar
                                         where ar.rule_id = r.id and ar.alert_id = alert_log.id)
                      limit greatest(0, r.max_per_day - today)
            loop
                insert into automation_runs (rule_id, alert_id, status, reason, request)
                values (r.id, a.id,
                        case when r.dry_run then 'dry_run'
                             when r.requires_approval then 'pending'
                             else 'approved' end,
                        format('alert %s: %s', a.rule, a.subject),
                        jsonb_build_object(
                          'url', r.action_url, 'method', r.action_method,
                          'headers', r.action_headers,
                          'body', r.action_body ||
                                  jsonb_build_object('alert_id', a.id, 'rule', a.rule,
                                                     'severity', a.severity,
                                                     'subject', a.subject,
                                                     'agent_id', a.agent_id)));
                n := n + 1;
                today := today + 1;
            end loop;

        else
            for s in select * from service_health
                      where status = 'down'
                        and (cardinality(r.trigger_rules) = 0 or name = any(r.trigger_rules))
                        and not exists (select 1 from automation_runs ar
                                         where ar.rule_id = r.id and ar.service_id = service_health.id
                                           and ar.created_at > now() - interval '1 hour')
                      limit greatest(0, r.max_per_day - today)
            loop
                insert into automation_runs (rule_id, service_id, status, reason, request)
                values (r.id, s.id,
                        case when r.dry_run then 'dry_run'
                             when r.requires_approval then 'pending'
                             else 'approved' end,
                        format('service down: %s (%s)', s.name, s.reason),
                        jsonb_build_object(
                          'url', r.action_url, 'method', r.action_method,
                          'headers', r.action_headers,
                          'body', r.action_body ||
                                  jsonb_build_object('service', s.name,
                                                     'tier', s.tier,
                                                     'reason', s.reason)));
                n := n + 1;
                today := today + 1;
            end loop;
        end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-automation')
 where exists (select 1 from cron.job where jobname = 'nodewatch-automation');
select cron.schedule('nodewatch-automation', '* * * * *', $$select queue_automation();$$);

select cron.unschedule('nodewatch-automation-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-automation-retention');
select cron.schedule('nodewatch-automation-retention', '30 5 * * *',
    $$delete from automation_runs where created_at < now() - interval '90 days';$$);

-- ---------------------------------------------------------------- views

create or replace view automation_overview as
select r.id, r.name, r.description, r.trigger_type, r.trigger_rules, r.severities,
       r.action_type, r.action_url, r.requires_approval, r.dry_run,
       r.max_per_day, r.enabled,
       (select count(*) from automation_runs x
         where x.rule_id = r.id and x.created_at > now() - interval '24 hours'
           and x.status <> 'skipped')                            as runs_today,
       (select count(*) from automation_runs x
         where x.rule_id = r.id and x.status = 'pending')         as awaiting_approval,
       (select count(*) from automation_runs x
         where x.rule_id = r.id and x.status = 'failed'
           and x.created_at > now() - interval '7 days')          as failed_7d,
       (select max(created_at) from automation_runs x where x.rule_id = r.id) as last_run,
       -- Spelled out because "enabled" alone does not tell you whether this
       -- rule can actually change anything.
       case when not r.enabled          then 'disabled'
            when r.dry_run              then 'dry run only'
            when r.requires_approval    then 'waits for approval'
            else 'runs automatically' end                         as posture
  from automation_rules r;

alter view automation_overview set (security_invoker = on);
grant select on automation_overview to authenticated;
revoke all on automation_overview from anon;

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
