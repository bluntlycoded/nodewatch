-- 013: fix "Database error creating new user".
--
-- The trigger on auth.users is SECURITY DEFINER but did not pin search_path.
-- The auth service runs with its own search_path, so `profiles` could not be
-- resolved, the trigger raised, and because a trigger failure aborts the
-- statement, creating any user failed outright.
--
-- Every SECURITY DEFINER function here gets an explicit search_path. Leaving
-- it unset is also a privilege-escalation footgun: anyone able to create a
-- table in a schema earlier on the path could shadow the one the function
-- meant to use.

-- ---------------------------------------------------------------- profile trigger

create or replace function handle_new_user() returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare n integer;
begin
    select count(*) into n from profiles;
    insert into profiles (id, email, role)
    values (new.id, new.email, case when n = 0 then 'admin' else 'viewer' end)
    on conflict (id) do nothing;
    return new;
exception when others then
    -- Never block account creation on profile bookkeeping. A user without a
    -- profile defaults to viewer via my_role(), and the back-fill below
    -- repairs it. Failing closed here would lock everyone out instead.
    raise warning 'handle_new_user failed for %: %', new.id, sqlerrm;
    return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
    for each row execute function handle_new_user();

-- The auth service executes the trigger as supabase_auth_admin, so it needs
-- to reach the function and the table it writes.
do $$
begin
    if exists (select 1 from pg_roles where rolname = 'supabase_auth_admin') then
        grant usage on schema public to supabase_auth_admin;
        grant select, insert on public.profiles to supabase_auth_admin;
        grant execute on function public.handle_new_user() to supabase_auth_admin;
    end if;
end $$;

-- ---------------------------------------------------------------- role helpers

create or replace function is_admin() returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function my_role() returns text
language sql
stable
security definer
set search_path = public
as $$
    select coalesce((select role from profiles where id = auth.uid()), 'viewer');
$$;

grant execute on function is_admin() to authenticated;
grant execute on function my_role() to authenticated;

-- ---------------------------------------------------------------- audit

create or replace function log_audit() returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    who  uuid;
    mail text;
    rec  jsonb;
    key  text;
begin
    begin
        who := auth.uid();
    exception when others then
        who := null;   -- no request context, e.g. a cron job or the auth service
    end;

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
    -- Losing one audit row is bad; losing the ability to create a user or
    -- delete a server because logging broke is worse.
    raise warning 'log_audit failed on %: %', tg_table_name, sqlerrm;
    return coalesce(new, old);
end $$;

-- ---------------------------------------------------------------- token issuer

create or replace function new_enroll_token(p_label text default null,
                                            p_hours integer default 24)
returns text
language plpgsql
security definer
set search_path = public
as $$
declare t text;
begin
    if not is_admin() then
        raise exception 'only an admin can issue enrolment tokens';
    end if;
    t := encode(gen_random_bytes(24), 'hex');
    insert into enroll_tokens (token, label, expires_at)
    values (t, p_label, now() + make_interval(hours => p_hours));
    return t;
end $$;
grant execute on function new_enroll_token(text, integer) to authenticated;

-- ---------------------------------------------------------------- repair

-- Anyone created while the trigger was broken has no profile. Give them one.
-- If no admin exists at all, the earliest account becomes admin so the
-- system is not locked out of its own administration.
insert into profiles (id, email, role)
select u.id, u.email, 'viewer'
  from auth.users u
 where not exists (select 1 from profiles p where p.id = u.id);

update profiles set role = 'admin'
 where id = (select id from profiles order by created_at limit 1)
   and not exists (select 1 from profiles where role = 'admin');

-- Confirm afterwards:
--   select email, role, created_at from profiles order by created_at;
