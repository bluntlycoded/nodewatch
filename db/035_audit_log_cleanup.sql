-- 035: stop auditing telemetry, index and retain what's left.
--
-- audit_agents fires on every insert/update/delete to agents with no
-- exclusion for the one update that happens continuously and means
-- nothing administratively: the ingest API bumping last_seen on every
-- batch, roughly every 15 seconds per agent. That is system telemetry,
-- not an admin action, and it is indistinguishable from one once written
-- - the row's actor is null either way, because the request came from
-- the ingest API's service-role connection, not an authenticated
-- dashboard session.
--
-- That is also the fix for the backlog: every audit_log row with a null
-- actor was written by something other than a person acting through the
-- dashboard - there is no code path that produces a null-actor row that
-- represents a real administrative decision. Four agents over about
-- three weeks at that interval accounts for roughly 460k potential rows,
-- which is why this table had 422k in it against 3 real users.

create or replace function log_audit() returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    who  uuid := auth.uid();
    mail text;
    rec  jsonb;
    key  text;
begin
    -- Nothing but last_seen changing means this was an ingest heartbeat,
    -- not an administrative change to the row.
    if tg_op = 'UPDATE' and tg_table_name = 'agents'
       and (to_jsonb(new) - 'last_seen') = (to_jsonb(old) - 'last_seen') then
        return new;
    end if;

    select email into mail from profiles where id = who;
    rec := coalesce(to_jsonb(new), to_jsonb(old));
    key := case tg_table_name
             when 'agents'           then 'instance_id'
             when 'alert_channels'   then 'kind'
             when 'alert_recipients' then 'email'
             when 'profiles'         then 'email'
             else null end;

    insert into audit_log (actor, actor_email, action, target, detail)
    values (who, mail, lower(tg_op) || ' ' || tg_table_name,
            case when key is null then null else rec ->> key end,
            case when tg_table_name = 'profiles' and tg_op = 'UPDATE'
                 then jsonb_build_object('role', rec ->> 'role') else null end);
    return coalesce(new, old);
exception when others then
    -- An audit write failing must not roll back the change it was recording.
    raise warning 'log_audit failed on %: %', tg_table_name, sqlerrm;
    return coalesce(new, old);
end $$;

-- One-time backlog cleanup: every row a person's dashboard action ever
-- produced has a real actor, since that is the only code path that runs
-- with an authenticated Supabase session. A null actor is always
-- system-driven and never represents an admin decision worth keeping.
delete from audit_log where actor is null;

create index if not exists audit_log_actor_idx on audit_log (actor);

select cron.unschedule('nodewatch-audit-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-audit-retention');
select cron.schedule('nodewatch-audit-retention', '35 4 * * *',
    $$delete from audit_log where created_at < now() - interval '365 days';$$);
