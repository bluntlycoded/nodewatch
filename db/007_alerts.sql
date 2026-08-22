-- 007: alerting.
--
-- Detection lives in Postgres triggers so an alert cannot be missed by a
-- polling gap. Delivery lives in an Edge Function so no credential is ever
-- in the browser. The two are joined by alert_log, which is a queue:
-- triggers write 'pending', the sender marks 'sent' or 'failed'.
--
-- Nothing here touches the ingest API.

create extension if not exists pg_net;

-- The sender claims rows by moving them to 'sending' before calling Resend,
-- so two overlapping cron ticks cannot double-send. That state has to exist
-- in the constraint.
alter table alert_log drop constraint if exists alert_log_status_check;
alter table alert_log add constraint alert_log_status_check
    check (status in ('pending','sending','sent','failed','suppressed'));

-- If the function dies mid-batch a row can be stranded in 'sending'.
-- Return anything stuck for more than five minutes to the queue.
create or replace function requeue_stuck_alerts() returns integer as $$
declare n integer;
begin
    update alert_log set status = 'pending'
     where status = 'sending' and created_at < now() - interval '5 minutes';
    get diagnostics n = row_count;
    return n;
end $$ language plpgsql security definer;

-- ---------------------------------------------------------------- cooldowns

-- Per-rule, per-node. Without this one flapping host emails on every cycle.
create table if not exists alert_rules (
    rule        text primary key,
    severity    text not null check (severity in ('critical','warning','info')),
    cooldown    interval not null,
    enabled     boolean not null default true,
    description text
);

insert into alert_rules (rule, severity, cooldown, description) values
    ('node_down',        'critical', interval '30 minutes', 'Node stopped reporting for more than 3 minutes'),
    ('trust_collapsed',  'critical', interval '1 hour',     'Trust score fell below 50'),
    ('priv_account',     'critical', interval '0 minutes',  'Account added with, or granted, sudo'),
    ('account_removed',  'warning',  interval '10 minutes', 'Local account deleted'),
    ('new_exposure',     'warning',  interval '15 minutes', 'New externally reachable port'),
    ('high_check_fail',  'warning',  interval '1 hour',     'High-severity posture check started failing')
on conflict (rule) do nothing;

alter table alert_rules enable row level security;
drop policy if exists alert_rules_rw on alert_rules;
create policy alert_rules_rw on alert_rules for all to authenticated using (true) with check (true);
grant select, update on alert_rules to authenticated;
revoke all on alert_rules from anon;

-- ---------------------------------------------------------------- queueing

-- Single entry point for every alert. Applies the rule's cooldown, honours
-- the node's mute flag, and refuses to queue anything with no recipients.
create or replace function queue_alert(
    p_agent uuid, p_rule text, p_subject text, p_body text
) returns boolean as $$
declare
    r       alert_rules%rowtype;
    last    timestamptz;
    muted_  boolean;
    people  text[];
begin
    select * into r from alert_rules where rule = p_rule and enabled;
    if not found then return false; end if;

    select muted into muted_ from agents where id = p_agent;
    if coalesce(muted_, false) then
        insert into alert_log (agent_id, rule, severity, subject, body, status)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed');
        return false;
    end if;

    select last_sent into last from alert_state where agent_id = p_agent and rule = p_rule;
    if last is not null and now() - last < r.cooldown then
        return false;
    end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients
     where (agent_id = p_agent or agent_id is null) and instant;

    if people is null or cardinality(people) = 0 then
        insert into alert_log (agent_id, rule, severity, subject, body, status, error)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed',
                'no recipients configured');
        return false;
    end if;

    insert into alert_log (agent_id, rule, severity, subject, body, recipients)
    values (p_agent, p_rule, r.severity, p_subject, p_body, people);

    insert into alert_state (agent_id, rule, last_sent) values (p_agent, p_rule, now())
    on conflict (agent_id, rule) do update set last_sent = now();

    return true;
end $$ language plpgsql security definer;

-- ---------------------------------------------------------------- triggers

-- Account changes. A new sudo account is the strongest single signal here,
-- so it has no cooldown: every occurrence sends.
create or replace function alert_on_user_event() returns trigger as $$
declare label text;
begin
    select coalesce(display_name, hostname, instance_id) into label
      from agents where id = new.agent_id;

    if new.sudoer and new.action in ('added','modified') then
        perform queue_alert(new.agent_id, 'priv_account',
            format('[critical] Privileged account %s on %s', new.action, label),
            format(E'Account: %s\nAction: %s\nDetail: %s\n\nThis account has sudo. '
                   'If you did not make this change, treat the host as compromised.',
                   new.username, new.action, coalesce(new.detail, '')));
    elsif new.action = 'removed' then
        perform queue_alert(new.agent_id, 'account_removed',
            format('[warning] Account removed on %s', label),
            format(E'Account: %s\nDetail: %s', new.username, coalesce(new.detail, '')));
    end if;
    return new;
end $$ language plpgsql security definer;

drop trigger if exists user_event_alert on user_events;
create trigger user_event_alert after insert on user_events
    for each row execute function alert_on_user_event();

-- New externally reachable port.
create or replace function alert_on_port_event() returns trigger as $$
declare label text;
begin
    if new.action = 'opened' and new.external then
        select coalesce(display_name, hostname, instance_id) into label
          from agents where id = new.agent_id;
        perform queue_alert(new.agent_id, 'new_exposure',
            format('[warning] New external port %s/%s on %s', new.port, new.proto, label),
            format(E'Port: %s/%s\nBound: %s\nProcess: %s\n\nThis port is reachable from '
                   'outside the host.', new.port, new.proto, new.bind_addr,
                   coalesce(new.process, 'unknown')));
    end if;
    return new;
end $$ language plpgsql security definer;

drop trigger if exists port_event_alert on port_events;
create trigger port_event_alert after insert on port_events
    for each row execute function alert_on_port_event();

-- Posture check flipping to failing at high severity.
create or replace function alert_on_check_fail() returns trigger as $$
declare label text;
begin
    if new.status = 'fail' and new.severity = 'high'
       and (tg_op = 'INSERT' or old.status <> 'fail') then
        select coalesce(display_name, hostname, instance_id) into label
          from agents where id = new.agent_id;
        perform queue_alert(new.agent_id, 'high_check_fail',
            format('[warning] %s failing on %s', new.title, label),
            format(E'Check: %s\nDetail: %s', new.title, coalesce(new.detail, '')));
    end if;
    return new;
end $$ language plpgsql security definer;

drop trigger if exists check_fail_alert on host_checks;
create trigger check_fail_alert after insert or update on host_checks
    for each row execute function alert_on_check_fail();

-- ---------------------------------------------------------------- sweeps

-- Down and low-trust are states, not events, so nothing inserts a row to
-- hang a trigger on. A sweep catches them; cooldowns stop repetition.
create or replace function sweep_node_health() returns integer as $$
declare a record; n integer := 0;
begin
    for a in
        select o.id, o.label, o.status, o.trust, o.seconds_since_seen
          from agent_overview o
         where o.status in ('down','degraded') or o.trust < 50
    loop
        if a.status = 'down' then
            if queue_alert(a.id, 'node_down',
                format('[critical] %s has stopped reporting', a.label),
                format(E'No telemetry for %s seconds.\n\nThe agent may have stopped, '
                       'the host may be down, or it may have lost network access to '
                       'the ingest API.', a.seconds_since_seen)) then n := n + 1; end if;
        elsif a.trust is not null and a.trust < 50 then
            if queue_alert(a.id, 'trust_collapsed',
                format('[critical] Trust on %s fell to %s', a.label, a.trust),
                format(E'Trust score: %s\nStatus: %s\n\nOpen the dashboard to see which '
                       'factor dropped.', a.trust, a.status)) then n := n + 1; end if;
        end if;
    end loop;
    return n;
end $$ language plpgsql security definer;

-- ---------------------------------------------------------------- digest

create or replace function build_digest() returns integer as $$
declare a record; people text[]; body text; n integer := 0;
begin
    for a in select * from agent_overview loop
        select array_agg(distinct lower(email)) into people
          from alert_recipients
         where (agent_id = a.id or agent_id is null) and digest;
        continue when people is null or cardinality(people) = 0;
        continue when a.muted;

        body := format(
            E'Node: %s (%s)\nStatus: %s\nTrust: %s\n\n'
            'Last 6 hours\n'
            '  Failed sign-ins (1h): %s\n'
            '  Posture checks failing: %s (%s high severity)\n'
            '  Account changes (24h): %s, of which privileged: %s\n'
            '  New external ports (24h): %s\n'
            '  Externally reachable ports now: %s\n',
            a.label, a.instance_id, a.status, coalesce(a.trust::text, 'n/a'),
            a.failed_logins_1h, a.checks_failed, a.checks_failed_high,
            a.account_changes_24h, a.priv_changes_24h,
            a.new_exposure_24h, a.external_ports);

        insert into alert_log (agent_id, rule, severity, subject, body, recipients)
        values (a.id, 'digest', 'info',
                format('[nodewatch] 6-hour digest: %s (trust %s)',
                       a.label, coalesce(a.trust::text, 'n/a')),
                body, people);
        n := n + 1;
    end loop;
    return n;
end $$ language plpgsql security definer;

-- ---------------------------------------------------------------- scheduling

-- Reads the function URL and service key from Vault, so no secret is ever
-- written into a migration or a cron definition.
create or replace function drain_alert_queue() returns bigint as $$
declare url text; key text; req bigint;
begin
    perform requeue_stuck_alerts();
    if not exists (select 1 from alert_log where status = 'pending') then
        return null;
    end if;
    select decrypted_secret into url from vault.decrypted_secrets where name = 'project_url';
    select decrypted_secret into key from vault.decrypted_secrets where name = 'service_role_key';
    if url is null or key is null then
        raise warning 'vault secrets project_url / service_role_key are not set';
        return null;
    end if;
    select net.http_post(
        url  := url || '/functions/v1/send-alerts',
        headers := jsonb_build_object(
            'Content-Type',  'application/json',
            'Authorization', 'Bearer ' || key),
        body := '{}'::jsonb
    ) into req;
    return req;
end $$ language plpgsql security definer;

select cron.unschedule('nodewatch-drain')  where exists (select 1 from cron.job where jobname='nodewatch-drain');
select cron.unschedule('nodewatch-sweep')  where exists (select 1 from cron.job where jobname='nodewatch-sweep');
select cron.unschedule('nodewatch-digest') where exists (select 1 from cron.job where jobname='nodewatch-digest');

select cron.schedule('nodewatch-sweep',  '* * * * *',       $$select sweep_node_health();$$);
select cron.schedule('nodewatch-drain',  '* * * * *',       $$select drain_alert_queue();$$);
select cron.schedule('nodewatch-digest', '0 */6 * * *',     $$select build_digest();$$);

-- Keep the log readable.
select cron.schedule('nodewatch-alert-retention', '25 4 * * *',
    $$delete from alert_log where created_at < now() - interval '30 days';$$);
