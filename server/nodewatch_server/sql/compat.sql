-- Self-hosted compatibility layer.
--
-- The migrations in db/ were written for Supabase and call a handful of
-- things stock PostgreSQL does not have: the auth schema, the anon /
-- authenticated / service_role roles, pg_cron, Vault and pg_net. This file
-- provides each of them with the same names and signatures, so the master
-- applies db/*.sql unchanged and the hosted and self-hosted schemas cannot
-- drift apart.
--
-- Applied by the master only, before db/001. Never run this on Supabase:
-- it would collide with the real auth and cron schemas.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- roles
-- The migrations grant to these and write RLS policies against them. The
-- master connects as the database owner, which bypasses RLS the same way
-- service_role does on Supabase.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'anon') then
        create role anon nologin;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'authenticated') then
        create role authenticated nologin;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'service_role') then
        create role service_role nologin bypassrls;
    end if;
end $$;

-- ---------------------------------------------------------------- default grants
-- Supabase grants every new table, view and sequence in public to its API
-- roles, and leaves the filtering to row-level security; the migrations
-- rely on that (agent_overview reads views that are never granted
-- explicitly). Reproduced here, but stricter: nothing is granted to anon by
-- default, since the dashboard reads no data before sign-in. Must run
-- before db/001 so it covers every object the migrations create.
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to authenticated, service_role;
alter default privileges in schema public grant all on sequences to authenticated, service_role;
alter default privileges in schema public grant execute on functions to anon, authenticated, service_role;

-- ---------------------------------------------------------------- auth
-- Accounts live here so the existing triggers on auth.users (profile
-- creation, first user becomes admin) keep working. The master owns the
-- password hash; nothing else reads it.
create schema if not exists auth;

create table if not exists auth.users (
    id                 uuid primary key default gen_random_uuid(),
    email              text unique,
    encrypted_password text,
    raw_user_meta_data jsonb not null default '{}'::jsonb,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),
    last_sign_in_at    timestamptz
);

-- Same contract as Supabase: the caller's user id from the request's JWT
-- claims, set per transaction with set_config('request.jwt.claims', ...).
-- Null outside a user request (scheduler, ingest), which the migrations
-- already treat as "no user".
create or replace function auth.jwt() returns jsonb
language sql stable as $$
    select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;

create or replace function auth.uid() returns uuid
language sql stable as $$
    select nullif(auth.jwt() ->> 'sub', '')::uuid
$$;

create or replace function auth.role() returns text
language sql stable as $$
    select auth.jwt() ->> 'role'
$$;

grant usage on schema auth to anon, authenticated, service_role;
grant execute on all functions in schema auth to anon, authenticated, service_role;

-- ---------------------------------------------------------------- cron
-- cron.schedule() records the job; the master's scheduler runs it. Same
-- table and column names pg_cron uses, because migrations query cron.job
-- directly to unschedule idempotently.
create schema if not exists cron;

create table if not exists cron.job (
    jobid    bigserial primary key,
    jobname  text unique,
    schedule text not null,
    command  text not null,
    active   boolean not null default true
);

create table if not exists cron.job_run_details (
    runid          bigserial primary key,
    jobid          bigint,
    status         text,
    return_message text,
    start_time     timestamptz,
    end_time       timestamptz
);

create or replace function cron.schedule(job_name text, schedule text, command text)
returns bigint language sql as $$
    insert into cron.job (jobname, schedule, command)
    values (job_name, schedule, command)
    on conflict (jobname) do update
       set schedule = excluded.schedule,
           command  = excluded.command,
           active   = true
    returning jobid
$$;

create or replace function cron.unschedule(job_name text)
returns boolean language sql as $$
    with gone as (delete from cron.job where jobname = job_name returning 1)
    select exists (select 1 from gone)
$$;

-- ---------------------------------------------------------------- vault, net
-- Only drain_alert_queue() and run_vuln_scan() use these, to call Supabase
-- Edge Functions. The master delivers alerts itself, so those two jobs are
-- unscheduled after migrating and these exist only so the functions compile.
create schema if not exists vault;

create table if not exists vault.secrets (
    name   text primary key,
    secret text
);

create or replace view vault.decrypted_secrets as
    select name, secret as decrypted_secret from vault.secrets;

create schema if not exists net;

create or replace function net.http_post(
    url text,
    body jsonb default '{}'::jsonb,
    params jsonb default '{}'::jsonb,
    headers jsonb default '{}'::jsonb,
    timeout_milliseconds integer default 5000
) returns bigint language sql as $$
    select null::bigint
$$;

-- ---------------------------------------------------------------- sessions
-- Refresh tokens for the master's sign-in endpoints (auth.py). Stored as
-- SHA-256 hashes: a copy of this table does not let anyone sign in.
create table if not exists auth.refresh_tokens (
    token_hash text primary key,
    user_id    uuid not null references auth.users (id) on delete cascade,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked    boolean not null default false
);
create index if not exists refresh_tokens_user_idx on auth.refresh_tokens (user_id);
revoke all on auth.refresh_tokens from anon, authenticated;
revoke all on auth.users from anon, authenticated;
