-- 012: roles.
--
--   admin   manages servers, credentials, recipients, channels, tokens, users
--   viewer  reads everything except credentials, and can acknowledge alerts
--
-- Enforced in Postgres, not in the dashboard. Hiding a button does not stop
-- anyone from calling the API with the anon key, so every restriction here is
-- a policy the database applies regardless of client.

create table if not exists profiles (
    id         uuid primary key references auth.users (id) on delete cascade,
    email      text,
    role       text not null default 'viewer' check (role in ('admin','viewer')),
    full_name  text,
    created_at timestamptz not null default now(),
    last_seen  timestamptz
);

comment on table profiles is
    'One row per auth user. Role drives every write policy in the schema.';

-- ---------------------------------------------------------------- bootstrap

-- New sign-ups become viewers, except the very first account, which becomes
-- admin so the system is not locked out of its own administration.
create or replace function handle_new_user() returns trigger as $$
declare n integer;
begin
    select count(*) into n from profiles;
    insert into profiles (id, email, role)
    values (new.id, new.email, case when n = 0 then 'admin' else 'viewer' end)
    on conflict (id) do nothing;
    return new;
end $$ language plpgsql security definer;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
    for each row execute function handle_new_user();

-- Back-fill anyone who signed up before this migration. The earliest account
-- becomes admin; that is you.
insert into profiles (id, email, role)
select u.id, u.email,
       case when u.created_at = (select min(created_at) from auth.users)
            then 'admin' else 'viewer' end
  from auth.users u
 where not exists (select 1 from profiles p where p.id = u.id);

-- ---------------------------------------------------------------- helpers

-- security definer so the check itself is not subject to the policies it
-- gates, which would recurse.
create or replace function is_admin() returns boolean as $$
    select exists (
        select 1 from profiles where id = auth.uid() and role = 'admin'
    );
$$ language sql stable security definer;

create or replace function my_role() returns text as $$
    select coalesce((select role from profiles where id = auth.uid()), 'viewer');
$$ language sql stable security definer;

grant execute on function is_admin() to authenticated;
grant execute on function my_role() to authenticated;

alter table profiles enable row level security;

drop policy if exists profiles_read on profiles;
drop policy if exists profiles_admin_write on profiles;
drop policy if exists profiles_self_update on profiles;

-- Everyone can see who has access; that is not sensitive and it makes the
-- team list useful.
create policy profiles_read on profiles for select to authenticated using (true);
create policy profiles_admin_write on profiles for all to authenticated
    using (is_admin()) with check (is_admin());

grant select on profiles to authenticated;
grant insert, update, delete on profiles to authenticated;
revoke all on profiles from anon;

-- ---------------------------------------------------------------- servers

-- Reads stay open to any signed-in user. Writes become admin-only.
drop policy if exists agents_write on agents;
drop policy if exists agents_insert on agents;
drop policy if exists agents_delete on agents;

create policy agents_write  on agents for update to authenticated
    using (is_admin()) with check (is_admin());
create policy agents_insert on agents for insert to authenticated
    with check (is_admin());
create policy agents_delete on agents for delete to authenticated
    using (is_admin());

-- ---------------------------------------------------------------- credentials

-- alert_channels.config holds bot tokens and webhook URLs. A viewer must not
-- be able to read them, so the table itself becomes admin-only and everyone
-- else sees a view with the config column omitted.
drop policy if exists alert_channels_rw on alert_channels;
drop policy if exists alert_channels_admin on alert_channels;
create policy alert_channels_admin on alert_channels for all to authenticated
    using (is_admin()) with check (is_admin());

-- Deliberately NOT security_invoker: this view runs with the owner's rights
-- so viewers can read channel health without the table grant, and it simply
-- does not select the config column. The secret is unreachable rather than
-- merely unrendered.
drop view if exists alert_channel_status;
create view alert_channel_status as
select c.id, c.agent_id, c.kind, c.label, c.min_severity, c.enabled,
       c.last_ok_at, c.last_error, c.last_error_at, c.created_at,
       coalesce(a.display_name, a.hostname, a.instance_id) as node_label,
       -- Enough to tell a configured channel from a blank one, without
       -- revealing anything.
       (c.config ? 'bot_token') or (c.config ? 'token') or (c.config ? 'url') as configured,
       (select count(*) from alert_deliveries d
         where d.channel_id = c.id and d.status = 'sent'
           and d.created_at > now() - interval '7 days') as sent_7d,
       (select count(*) from alert_deliveries d
         where d.channel_id = c.id and d.status = 'failed'
           and d.created_at > now() - interval '7 days') as failed_7d
from alert_channels c
left join agents a on a.id = c.agent_id;

alter view alert_channel_status set (security_invoker = off);
grant select on alert_channel_status to authenticated;
revoke all on alert_channel_status from anon;

-- Same reasoning for enrolment tokens: a token is a credential.
drop policy if exists enroll_tokens_rw on enroll_tokens;
drop policy if exists enroll_tokens_admin on enroll_tokens;
create policy enroll_tokens_admin on enroll_tokens for all to authenticated
    using (is_admin()) with check (is_admin());

drop view if exists enroll_token_status;
create view enroll_token_status as
select token, label, created_at, expires_at, used_at, used_by, revoked,
       case when revoked            then 'revoked'
            when used_at is not null then 'used'
            when expires_at < now()  then 'expired'
            else 'open' end as status
from enroll_tokens;

-- Admin-only: the token value itself is the secret.
alter view enroll_token_status set (security_invoker = on);
grant select on enroll_token_status to authenticated;
revoke all on enroll_token_status from anon;

revoke execute on function new_enroll_token(text, integer) from authenticated;
create or replace function new_enroll_token(p_label text default null,
                                            p_hours integer default 24)
returns text as $$
declare t text;
begin
    if not is_admin() then
        raise exception 'only an admin can issue enrolment tokens';
    end if;
    t := encode(gen_random_bytes(24), 'hex');
    insert into enroll_tokens (token, label, expires_at)
    values (t, p_label, now() + make_interval(hours => p_hours));
    return t;
end $$ language plpgsql security definer;
grant execute on function new_enroll_token(text, integer) to authenticated;

-- ---------------------------------------------------------------- recipients

drop policy if exists alert_recipients_all on alert_recipients;
drop policy if exists alert_recipients_read on alert_recipients;
create policy alert_recipients_read on alert_recipients
    for select to authenticated using (true);
drop policy if exists alert_recipients_admin on alert_recipients;
create policy alert_recipients_admin on alert_recipients
    for all to authenticated using (is_admin()) with check (is_admin());

-- ---------------------------------------------------------------- alert rules

drop policy if exists alert_rules_rw on alert_rules;
drop policy if exists alert_rules_read on alert_rules;
create policy alert_rules_read on alert_rules for select to authenticated using (true);
drop policy if exists alert_rules_admin on alert_rules;
create policy alert_rules_admin on alert_rules for all to authenticated
    using (is_admin()) with check (is_admin());

-- ---------------------------------------------------------------- workflow

-- Acknowledging and resolving is triage, not configuration, so a viewer can
-- do it. That is the "see and report" part of their job, and the audit trail
-- records who did it.
drop policy if exists alert_log_update on alert_log;
create policy alert_log_update on alert_log for update to authenticated
    using (true) with check (true);

-- ---------------------------------------------------------------- audit

-- Who changed what. Without this, "admin can manage" has no accountability.
create table if not exists audit_log (
    id         bigserial   primary key,
    actor      uuid references auth.users (id) on delete set null,
    actor_email text,
    action     text        not null,
    target     text,
    detail     jsonb,
    created_at timestamptz not null default now()
);

create index if not exists audit_log_ts_idx on audit_log (created_at desc);

alter table audit_log enable row level security;
drop policy if exists audit_log_read on audit_log;
drop policy if exists audit_log_insert on audit_log;
create policy audit_log_read on audit_log for select to authenticated using (true);
create policy audit_log_insert on audit_log for insert to authenticated with check (true);
grant select, insert on audit_log to authenticated;
grant usage, select on sequence audit_log_id_seq to authenticated;
revoke all on audit_log from anon;

create or replace function log_audit() returns trigger as $$
declare
    who  uuid := auth.uid();
    mail text;
    rec  jsonb;
    key  text;
begin
    select email into mail from profiles where id = who;

    -- to_jsonb rather than old.<column>: PL/pgSQL resolves record fields
    -- across every branch of a CASE, not only the branch taken, so naming a
    -- column that does not exist on some of the audited tables fails at
    -- runtime even when that branch is never reached.
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
end $$ language plpgsql security definer;

do $$
declare t text;
begin
    foreach t in array array['agents','alert_channels','alert_recipients','profiles']
    loop
        execute format('drop trigger if exists %I on %I', 'audit_' || t, t);
        execute format(
            'create trigger %I after insert or update or delete on %I
             for each row execute function log_audit()', 'audit_' || t, t);
    end loop;
end $$;
