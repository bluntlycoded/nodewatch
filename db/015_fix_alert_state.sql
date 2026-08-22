-- 015: repair alert cooldowns, broken by 014.
--
-- 014 dropped alert_state's primary key so probes could hold a fleet-level
-- row with a null agent_id, and replaced it with a unique index over a
-- coalesced expression. But ON CONFLICT cannot infer an expression index,
-- so queue_alert's `on conflict (agent_id, rule)` no longer matched
-- anything and raised. Since queue_alert runs inside the ingest
-- transaction, every event that would have triggered an alert - a new
-- external port, a critical file change, a privileged account - returned
-- 500 instead.
--
-- The fix is to stop relying on conflict inference and do the upsert
-- explicitly, the same way sweep_probes already does.

create or replace function queue_alert(
    p_agent uuid, p_rule text, p_subject text, p_body text
) returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
    r       alert_rules%rowtype;
    last    timestamptz;
    muted_  boolean;
    people  text[];
    chans   integer;
begin
    select * into r from alert_rules where rule = p_rule and enabled;
    if not found then return false; end if;

    select muted into muted_ from agents where id = p_agent;
    if coalesce(muted_, false) then
        insert into alert_log (agent_id, rule, severity, subject, body, status)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed');
        return false;
    end if;

    select last_sent into last from alert_state
     where agent_id is not distinct from p_agent and rule = p_rule;
    if last is not null and now() - last < r.cooldown then
        return false;
    end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients
     where (agent_id = p_agent or agent_id is null) and instant;

    select count(*) into chans
      from alert_channels
     where enabled and (agent_id = p_agent or agent_id is null);

    if coalesce(cardinality(people), 0) = 0 and chans = 0 then
        insert into alert_log (agent_id, rule, severity, subject, body, status, error)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed',
                'no destinations configured');
        return false;
    end if;

    insert into alert_log (agent_id, rule, severity, subject, body, recipients)
    values (p_agent, p_rule, r.severity, p_subject, p_body, coalesce(people, '{}'));

    -- Explicit upsert: ON CONFLICT cannot infer the expression index that
    -- 014 put on (coalesce(agent_id, ...), rule).
    update alert_state set last_sent = now()
     where agent_id is not distinct from p_agent and rule = p_rule;
    if not found then
        insert into alert_state (agent_id, rule, last_sent)
        values (p_agent, p_rule, now());
    end if;

    return true;
end $$;

-- Same reasoning for the trust snapshot job: its conflict target is a real
-- primary key, so it is fine, but pin its search_path for the same reason
-- 013 pinned the others.
create or replace function snapshot_trust() returns integer
language plpgsql
security definer
set search_path = public
as $$
declare n integer;
begin
    insert into trust_history (agent_id, ts, trust, status,
                               f_recency, f_exposure, f_auth, f_churn, f_posture, f_integrity)
    select id, date_trunc('minute', now()), trust, status,
           f_recency, f_exposure, f_auth, f_churn, f_posture, f_integrity
      from agent_overview
     where agent_version is not null
    on conflict (agent_id, ts) do nothing;
    get diagnostics n = row_count;
    return n;
end $$;

-- A permanently unreachable target should report once, not four times an
-- hour forever. The dashboard is where ongoing state belongs.
update alert_rules set cooldown = interval '6 hours' where rule = 'probe_down';
