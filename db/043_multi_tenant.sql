-- 043: multi-tenancy, phase 1 (data model + RLS retrofit + self-serve
-- signup). See the approved plan for the full three-phase design; this
-- migration is phase 1 only. Phase 2 (the probe runner becoming a
-- tenant-scoped API client instead of holding a direct service-role DB
-- credential - required before "master node" can mean something a
-- customer runs on their own infrastructure) and phase 3 (signup UI,
-- master-node token issuance UI) are separate, later work.
--
-- Every policy this migration touches was individually verified against
-- the live migration history first (every redefinition across db/*.sql
-- properly drops its predecessor - no hidden permissive policy was found
-- still active underneath a later, stricter one). This migration follows
-- the same drop-then-create idiom throughout.
--
-- Design choice, a deliberate deviation from a strict read of the
-- approved plan: every tenant-scoped table gets its OWN tenant_id column
-- (denormalized), not just the "high-volume" ones the plan called out -
-- a single uniform enforcement pattern is far easier to verify correct
-- for a security-critical retrofit than two different patterns (direct
-- column vs. join-to-parent) depending on row count. The storage cost of
-- one extra UUID column on a small table is negligible; a second, harder-
-- to-audit RLS pattern is not a cost worth taking here.

-- ================================================================
-- 1. core tenant infrastructure
-- ================================================================

create table if not exists tenants (
    id         uuid primary key default gen_random_uuid(),
    name       text not null,
    plan       text not null default 'trial',
    created_at timestamptz not null default now()
);

-- Every table below belongs to exactly one tenant, backfilled here to a
-- single "tenant zero" holding whatever nodewatch already had before
-- this migration - a real customer, not a placeholder, so its data must
-- not move or reset.
insert into tenants (id, name)
values ('00000000-0000-0000-0000-000000000001', 'Cipherium')
on conflict (id) do nothing;

-- profiles.tenant_id and current_tenant() both have to exist before any
-- RLS policy anywhere can reference either - added first, deliberately,
-- rather than interleaved with the tenants table's own RLS below (an
-- earlier draft of this migration had that backwards and would have
-- failed on "column profiles.tenant_id does not exist").
--
-- Deliberately left NULLABLE, unlike every other table in section 2: a
-- caught-and-discarded bug in an earlier draft made this NOT NULL, which
-- made handle_new_user() fail its own insert (silently - it has its own
-- exception handler) on every signup, since a brand new profile is
-- supposed to have no tenant yet until provision_tenant() runs. Caught by
-- actually replaying this migration and exercising the signup trigger
-- against a live Postgres, not by re-reading the file.
alter table profiles add column if not exists tenant_id uuid references tenants(id);
update profiles set tenant_id = '00000000-0000-0000-0000-000000000001' where tenant_id is null;
create index if not exists profiles_tenant_idx on profiles (tenant_id);

create or replace function current_tenant() returns uuid
language sql stable security definer set search_path = public as $$
    select tenant_id from profiles where id = auth.uid();
$$;
grant execute on function current_tenant() to authenticated;

alter table tenants enable row level security;
-- A user can see their own tenant's row (name/plan), never another's.
drop policy if exists tenants_read on tenants;
create policy tenants_read on tenants for select to authenticated
    using (id = current_tenant());
grant select on tenants to authenticated;
revoke all on tenants from anon;

-- profiles_read used to mean "every signed-in user, any tenant" - now
-- scoped, since it directly answers "who else can sign in here", and a
-- customer's user directory (names, emails, roles) is exactly the kind
-- of thing another customer must never see.
drop policy if exists profiles_read on profiles;
create policy profiles_read on profiles for select to authenticated
    using (tenant_id = current_tenant());
-- An admin manages only their own tenant's users - is_admin() alone was
-- never enough once a second tenant's admin exists.
drop policy if exists profiles_admin_write on profiles;
create policy profiles_admin_write on profiles for all to authenticated
    using (is_admin() and tenant_id = current_tenant())
    with check (is_admin() and tenant_id = current_tenant());

-- handle_new_user() used to make the first-ever signup an admin and
-- everyone after a viewer - a single-tenant assumption. A brand new
-- auth.users row now gets a profile with no tenant yet (tenant_id null,
-- role viewer as a harmless default); the dashboard treats a null
-- tenant_id as "finish signup" and calls provision_tenant() next. An
-- admin-invited teammate (via manage-users, unchanged) already has a
-- caller with a tenant, so that path sets tenant_id directly rather than
-- going through this trigger's default.
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    insert into profiles (id, email, role)
    values (new.id, new.email, 'viewer')
    on conflict (id) do nothing;
    return new;
exception when others then
    raise warning 'handle_new_user failed for %: %', new.id, sqlerrm;
    return new;
end $$;

-- Runs in the new user's own authenticated session right after signUp -
-- auth.uid() resolves to them. Creates their tenant and promotes them to
-- its admin in one transaction; a profile that already has a tenant
-- (invited teammate, or calling this twice) is refused rather than
-- silently reassigned.
create or replace function provision_tenant(p_name text) returns uuid
language plpgsql security definer set search_path = public as $$
declare
    new_tenant uuid;
    already    uuid;
begin
    select tenant_id into already from profiles where id = auth.uid();
    if already is not null then
        raise exception 'this account already belongs to a tenant';
    end if;
    if p_name is null or length(trim(p_name)) = 0 then
        raise exception 'a tenant name is required';
    end if;

    insert into tenants (name) values (trim(p_name)) returning id into new_tenant;
    update profiles set tenant_id = new_tenant, role = 'admin' where id = auth.uid();
    return new_tenant;
end $$;
grant execute on function provision_tenant(text) to authenticated;

-- ================================================================
-- 2. tenant_id on every tenant-scoped table, backfilled to tenant zero
-- ================================================================
--
-- alert_rules is deliberately excluded - it is a shared catalog of rule
-- *types* ("db_connections", "link_errors", ...), one row per type, not
-- per-tenant data; every tenant sees the same catalog, same as today.
-- teams_oauth_pending is also excluded - it has no RLS policies at all
-- (never read via an authenticated client, only written by
-- api/teams_app.py's own connection) and gets tenant-scoped when the
-- OAuth flows themselves are revisited for multi-tenancy.

do $$
declare
    t text;
    tables text[] := array[
        'agents','alert_channels','probe_secrets','enroll_tokens',
        'probes','services','service_components','service_dependencies',
        'escalation_policies','escalation_steps','automation_rules',
        'subnets','ip_addresses','github_installations','alert_recipients',
        'metrics','auth_events','port_state','port_events','host_checks',
        'alert_state','alert_log','user_state','user_events','fim_state',
        'fim_events','host_packages','package_vulns','package_scan_state',
        'trust_history','probe_results','db_metrics','app_metrics',
        'net_interfaces','net_traffic','route_hops','alert_escalations',
        'proxmox_guests','proxmox_storage','proxmox_backups','proxmox_metrics',
        'supply_chain_scans','supply_chain_findings','tls_cert_scans',
        'alert_deliveries','audit_log','automation_runs','nettool_jobs'
    ];
begin
    foreach t in array tables loop
        execute format('alter table %I add column if not exists tenant_id uuid references tenants(id)', t);
        execute format(
            'update %I set tenant_id = %L where tenant_id is null',
            t, '00000000-0000-0000-0000-000000000001'
        );
        execute format('alter table %I alter column tenant_id set not null', t);
        execute format('create index if not exists %I on %I (tenant_id)', t || '_tenant_idx', t);
    end loop;
end $$;

-- agents.instance_id was only ever globally unique by accident (AWS
-- instance IDs happen to be; GCP/Azure/on-premise machine fingerprints
-- are not guaranteed to be). Scoping the uniqueness to a tenant was
-- already the correct fix independent of multi-tenancy.
alter table agents drop constraint if exists agents_instance_id_key;
create unique index if not exists agents_tenant_instance_idx on agents (tenant_id, instance_id);

-- ================================================================
-- 3. RLS: the read(true)+admin(is_admin) pattern, tenant-scoped
-- ================================================================
--
-- Every table here previously had a "<x>_read for select using(true)"
-- policy plus a "<x>_admin for all using(is_admin())" policy - same
-- shape, different table each time. Named explicitly per table (not
-- derived from a naming convention) so nothing here depends on guessing
-- at an unverified pattern.

do $$
declare
    r record;
begin
    for r in select * from (values
        ('probes','probes_read','probes_admin'),
        ('services','svc_read','svc_admin'),
        ('service_components','comp_read','comp_admin'),
        ('service_dependencies','dep_read','dep_admin'),
        ('escalation_policies','esc_pol_read','esc_pol_admin'),
        ('escalation_steps','esc_step_read','esc_step_admin'),
        ('automation_rules','auto_rule_read','auto_rule_admin'),
        ('subnets','subnets_read','subnets_admin'),
        ('ip_addresses','ip_read','ip_admin'),
        ('github_installations','github_installations_read','github_installations_admin'),
        ('alert_recipients','alert_recipients_read','alert_recipients_admin')
    ) as t(tbl, read_pol, admin_pol)
    loop
        execute format('drop policy if exists %I on %I', r.read_pol, r.tbl);
        execute format(
            'create policy %I on %I for select to authenticated using (tenant_id = current_tenant())',
            r.read_pol, r.tbl
        );
        execute format('drop policy if exists %I on %I', r.admin_pol, r.tbl);
        execute format(
            'create policy %I on %I for all to authenticated
                 using (is_admin() and tenant_id = current_tenant())
                 with check (is_admin() and tenant_id = current_tenant())',
            r.admin_pol, r.tbl
        );
    end loop;
end $$;

-- ================================================================
-- 4. RLS: read-only(true) tables, tenant-scoped
-- ================================================================
--
-- No admin/write policy existed for any of these - writes come from the
-- ingest API's service-role connection, which bypasses RLS entirely, not
-- from an authenticated dashboard session.

do $$
declare
    r record;
begin
    for r in select * from (values
        ('metrics','metrics_read'), ('auth_events','auth_events_read'),
        ('port_state','port_state_read'), ('port_events','port_events_read'),
        ('host_checks','host_checks_read'), ('alert_state','alert_state_read'),
        ('user_state','user_state_read'), ('user_events','user_events_read'),
        ('fim_state','fim_state_read'), ('fim_events','fim_events_read'),
        ('host_packages','host_packages_read'), ('package_vulns','package_vulns_read'),
        ('package_scan_state','package_scan_state_read'), ('trust_history','trust_history_read'),
        ('probe_results','probe_results_read'), ('db_metrics','db_metrics_read'),
        ('app_metrics','app_metrics_read'), ('net_interfaces','net_if_read'),
        ('net_traffic','net_traffic_read'), ('route_hops','route_hops_read'),
        ('alert_escalations','esc_fire_read'), ('proxmox_guests','proxmox_guests_read'),
        ('proxmox_storage','proxmox_storage_read'), ('proxmox_backups','proxmox_backups_read'),
        ('proxmox_metrics','proxmox_metrics_read'), ('supply_chain_scans','supply_chain_scans_read'),
        ('supply_chain_findings','supply_chain_findings_read'), ('tls_cert_scans','tls_cert_scans_read'),
        ('alert_deliveries','alert_deliveries_read'), ('audit_log','audit_log_read')
    ) as t(tbl, read_pol)
    loop
        execute format('drop policy if exists %I on %I', r.read_pol, r.tbl);
        execute format(
            'create policy %I on %I for select to authenticated using (tenant_id = current_tenant())',
            r.read_pol, r.tbl
        );
    end loop;
end $$;

-- ================================================================
-- 5. RLS: hand-written exceptions - every one has a shape that doesn't
--    fit the two generic loops above, so each gets its exact policy
--    rewritten explicitly.
-- ================================================================

-- agents: read=any tenant member, write/insert/delete=admin of that tenant.
drop policy if exists agents_read on agents;
create policy agents_read on agents for select to authenticated
    using (tenant_id = current_tenant());
drop policy if exists agents_write on agents;
create policy agents_write on agents for update to authenticated
    using (is_admin() and tenant_id = current_tenant())
    with check (is_admin() and tenant_id = current_tenant());
drop policy if exists agents_insert on agents;
create policy agents_insert on agents for insert to authenticated
    with check (is_admin() and tenant_id = current_tenant());
drop policy if exists agents_delete on agents;
create policy agents_delete on agents for delete to authenticated
    using (is_admin() and tenant_id = current_tenant());

-- Credential tables: admin-only for every operation including read, same
-- as before - only the tenant boundary is new.
drop policy if exists alert_channels_admin on alert_channels;
create policy alert_channels_admin on alert_channels for all to authenticated
    using (is_admin() and tenant_id = current_tenant())
    with check (is_admin() and tenant_id = current_tenant());

drop policy if exists probe_secrets_admin on probe_secrets;
create policy probe_secrets_admin on probe_secrets for all to authenticated
    using (is_admin() and tenant_id = current_tenant())
    with check (is_admin() and tenant_id = current_tenant());

drop policy if exists enroll_tokens_admin on enroll_tokens;
create policy enroll_tokens_admin on enroll_tokens for all to authenticated
    using (is_admin() and tenant_id = current_tenant())
    with check (is_admin() and tenant_id = current_tenant());

-- alert_log: any tenant member can read; any tenant member can also
-- acknowledge/resolve (triage, not configuration - unchanged from before).
drop policy if exists alert_log_read on alert_log;
create policy alert_log_read on alert_log for select to authenticated
    using (tenant_id = current_tenant());
drop policy if exists alert_log_update on alert_log;
create policy alert_log_update on alert_log for update to authenticated
    using (tenant_id = current_tenant()) with check (tenant_id = current_tenant());

-- audit_log's insert policy is vestigial defense-in-depth - real writes
-- come from the log_audit() SECURITY DEFINER trigger, which bypasses RLS
-- - but tenant-scoping it anyway costs nothing and leaves no stray hole.
drop policy if exists audit_log_insert on audit_log;
create policy audit_log_insert on audit_log for insert to authenticated
    with check (tenant_id = current_tenant());

-- automation_runs: read=any tenant member; only an admin may approve a
-- pending run (UPDATE only, not full CRUD - unchanged from before).
drop policy if exists auto_run_read on automation_runs;
create policy auto_run_read on automation_runs for select to authenticated
    using (tenant_id = current_tenant());
drop policy if exists auto_run_admin on automation_runs;
create policy auto_run_admin on automation_runs for update to authenticated
    using (is_admin() and tenant_id = current_tenant())
    with check (is_admin() and tenant_id = current_tenant());

-- nettool_jobs: any tenant member reads results; only an admin may run a
-- tool (INSERT only, not full CRUD - unchanged from before).
drop policy if exists nettool_read on nettool_jobs;
create policy nettool_read on nettool_jobs for select to authenticated
    using (tenant_id = current_tenant());
drop policy if exists nettool_write on nettool_jobs;
create policy nettool_write on nettool_jobs for insert to authenticated
    with check (is_admin() and tenant_id = current_tenant());

-- ================================================================
-- 6. log_audit() must set tenant_id too, now that audit_log.tenant_id
--    is NOT NULL like every other table here.
-- ================================================================
--
-- This is not cosmetic: log_audit() (db/035_audit_log_cleanup.sql) has
-- its own catch-all "exception when others" that swallows any error
-- during the audit insert and only raises a warning, specifically so an
-- audit write failing never rolls back the change it was recording.
-- Without this fix that safety net would fire on every single admin
-- action from now on (the insert into audit_log would violate the new
-- NOT NULL tenant_id) - the underlying operation would still succeed,
-- but the audit trail would go silently dark, which defeats the point
-- of having one. agents/alert_channels/alert_recipients/profiles - the
-- four tables this trigger is attached to - all already have tenant_id
-- from section 2/section 1 above, so it reads straight off the row
-- being audited rather than needing a lookup.

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
    tid  uuid;
begin
    if tg_op = 'UPDATE' and tg_table_name = 'agents'
       and (to_jsonb(new) - 'last_seen') = (to_jsonb(old) - 'last_seen') then
        return new;
    end if;

    rec := coalesce(to_jsonb(new), to_jsonb(old));
    tid := (rec ->> 'tenant_id')::uuid;
    -- A profiles row between signup and provision_tenant() has no tenant
    -- yet (deliberately, see section 1) - nothing to attribute this event
    -- to under any tenant's audit trail, so there is nothing to log, not
    -- an error to warn about.
    if tid is null then
        return coalesce(new, old);
    end if;

    select email into mail from profiles where id = who;
    key := case tg_table_name
             when 'agents'           then 'instance_id'
             when 'alert_channels'   then 'kind'
             when 'alert_recipients' then 'email'
             when 'profiles'         then 'email'
             else null end;

    insert into audit_log (actor, actor_email, action, target, detail, tenant_id)
    values (who, mail, lower(tg_op) || ' ' || tg_table_name,
            case when key is null then null else rec ->> key end,
            case when tg_table_name = 'profiles' and tg_op = 'UPDATE'
                 then jsonb_build_object('role', rec ->> 'role') else null end,
            tid);
    return coalesce(new, old);
exception when others then
    raise warning 'log_audit failed on %: %', tg_table_name, sqlerrm;
    return coalesce(new, old);
end $$;

-- ================================================================
-- 7. Three more insert sites that need tenant_id threaded through now
--    that their target tables are NOT NULL on it: queue_alert()
--    (db/007_alerts.sql - the shared helper sweep_node_health() uses,
--    agent-scoped so tenant_id is one lookup away), new_enroll_token()
--    (db/013_fix_user_creation.sql - called from an authenticated admin
--    session, so current_tenant() is directly available, no lookup
--    needed), and snapshot_trust() (db/008/db/015 - agent-scoped,
--    joined in from agents rather than added to agent_overview's own
--    column list, since that view is read from a lot more places than
--    this one function).
--
-- Every other direct writer to a table that gained NOT NULL tenant_id
-- in section 2 is fixed further down: the nine fleet-level sweep
-- functions and queue_automation() in section 8/9, sweep_probes() and
-- build_digest() in section 11/12 (neither goes through queue_alert(),
-- despite build_digest sharing its file with it), refresh_ip_inventory()
-- in section 10, and log_audit() in section 6. Confirmed by grepping
-- every `insert into` against the section 2 table list, not assumed.
-- ================================================================

-- Based on db/015_fix_alert_state.sql's body - the actual current
-- definition, verified by reading the file rather than assumed. An
-- earlier draft of this section was built on the older db/007 version
-- (plain ON CONFLICT, recipients-only "no destination" check) and would
-- have reintroduced the exact 500-on-every-alert bug 015 already fixed,
-- plus regressed the alert_channels destination check 015 added. Only
-- change from 015's version: tenant_id threaded through every insert,
-- looked up once from the agent the alert is about.
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
    tid     uuid;
begin
    select * into r from alert_rules where rule = p_rule and enabled;
    if not found then return false; end if;

    select muted, tenant_id into muted_, tid from agents where id = p_agent;
    if coalesce(muted_, false) then
        insert into alert_log (agent_id, rule, severity, subject, body, status, tenant_id)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed', tid);
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
        insert into alert_log (agent_id, rule, severity, subject, body, status, error, tenant_id)
        values (p_agent, p_rule, r.severity, p_subject, p_body, 'suppressed',
                'no destinations configured', tid);
        return false;
    end if;

    insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
    values (p_agent, p_rule, r.severity, p_subject, p_body, coalesce(people, '{}'), tid);

    -- Explicit upsert: ON CONFLICT cannot infer the expression index
    -- (coalesce(agent_id, ...), rule) that migration 014 put on alert_state.
    update alert_state set last_sent = now()
     where agent_id is not distinct from p_agent and rule = p_rule;
    if not found then
        insert into alert_state (agent_id, rule, last_sent, tenant_id)
        values (p_agent, p_rule, now(), tid);
    end if;

    return true;
end $$;

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
    insert into enroll_tokens (token, label, expires_at, tenant_id)
    values (t, p_label, now() + make_interval(hours => p_hours), current_tenant());
    return t;
end $$;

-- db/015_fix_alert_state.sql's version, tenant_id joined in from agents
-- rather than added to agent_overview's own column list - agent_overview
-- is read from a lot of places and changing its shape is a bigger, more
-- cascading risk than one extra join here.
create or replace function snapshot_trust() returns integer
language plpgsql
security definer
set search_path = public
as $$
declare n integer;
begin
    insert into trust_history (agent_id, ts, trust, status,
                               f_recency, f_exposure, f_auth, f_churn, f_posture, f_integrity,
                               tenant_id)
    select o.id, date_trunc('minute', now()), o.trust, o.status,
           o.f_recency, o.f_exposure, o.f_auth, o.f_churn, o.f_posture, o.f_integrity,
           a.tenant_id
      from agent_overview o
      join agents a on a.id = o.id
     where o.agent_version is not null
    on conflict (agent_id, ts) do nothing;
    get diagnostics n = row_count;
    return n;
end $$;

-- ================================================================
-- 8. Fleet-level sweep functions (db/022, db/025, db/020, db/028,
--    db/037, db/038, db/031 x2, db/027) - each inserts into alert_log/
--    alert_state directly with agent_id null (a fleet-level condition,
--    not tied to one host), so there is no agent to join tenant_id from.
--    Each one's r.id is the id of whatever it's iterating - a probe for
--    the ones built on a *_overview view (from probes p ...), a service
--    for service_health. tenant_id is looked up from that row's actual
--    owning table once per alert, same cost as the cooldown/recipients
--    lookups already there.
-- ================================================================

-- db/022_applications.sql's sweep_applications(), unchanged except
-- tenant_id looked up from probes (application_overview is built from
-- probes p ..., so r.id is a probe id) and threaded into both inserts.
create or replace function sweep_applications() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from application_overview where status = 'up' loop
        select tenant_id into tid from probes where id = r.id;

        if r.error_rate is not null and r.error_rate >= 5 and r.requests_1h >= 100 then
            select cooldown into cd from alert_rules where rule = 'app_errors' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'app_errors:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (null, 'app_errors', 'warning',
                        format('[warning] %s is returning %s%% errors', r.name, r.error_rate),
                        format(E'Application: %s\nErrors: %s of %s requests in the last hour\n'
                               'Current rate: %s req/s',
                               r.name, r.errors_1h, r.requests_1h, coalesce(r.rps, 0)),
                        coalesce(people, '{}'), tid);
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'app_errors:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent, tenant_id)
                    values (null, 'app_errors:' || r.id::text, now(), tid);
                end if;
                n := n + 1;
            end if;
        end if;

        if r.p95_avg_1h is not null and r.p95_avg_1h >= 2 then
            select cooldown into cd from alert_rules where rule = 'app_latency' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'app_latency:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (null, 'app_latency', 'warning',
                        format('[warning] %s p95 response time is %ss', r.name, r.p95_avg_1h),
                        format(E'Application: %s\np95 over the last hour: %ss\nWorst: %ss',
                               r.name, r.p95_avg_1h, r.p95_max_1h),
                        coalesce(people, '{}'), tid);
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'app_latency:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent, tenant_id)
                    values (null, 'app_latency:' || r.id::text, now(), tid);
                end if;
                n := n + 1;
            end if;
        end if;
    end loop;
    return n;
end $$;

-- db/020_databases.sql's sweep_databases() - same treatment, r.id is a
-- probes.id (database_overview is also built from probes p ...).
create or replace function sweep_databases() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from database_overview where status = 'up' loop
        select tenant_id into tid from probes where id = r.id;

        if r.conn_pct is not null and r.conn_pct >= 85 then
            select cooldown into cd from alert_rules where rule='db_connections' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_connections:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (null, 'db_connections', 'warning',
                        format('[warning] %s is at %s%% of its connection limit',
                               r.name, round(r.conn_pct)),
                        format(E'Database: %s (%s)\nConnections: %s of %s\n\n'
                               'New connections will be refused at the limit.',
                               r.name, r.kind, r.connections, r.max_connections),
                        coalesce(people, '{}'), tid);
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_connections:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent, tenant_id)
                    values (null, 'db_connections:' || r.id::text, now(), tid);
                end if;
                n := n + 1;
            end if;
        end if;

        if r.replication_lag_s is not null and r.replication_lag_s >= 60 then
            select cooldown into cd from alert_rules where rule='db_replication' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_replication:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (null, 'db_replication', 'critical',
                        format('[critical] %s replication is %s seconds behind',
                               r.name, round(r.replication_lag_s)),
                        format(E'Database: %s (%s)\nLag: %s seconds\n\n'
                               'A failover now would lose everything written in that window.',
                               r.name, r.kind, round(r.replication_lag_s)),
                        coalesce(people, '{}'), tid);
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_replication:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent, tenant_id)
                    values (null, 'db_replication:' || r.id::text, now(), tid);
                end if;
                n := n + 1;
            end if;
        end if;
    end loop;
    return n;
end $$;

-- db/025_mssql_oracle.sql's sweep_db_extras() - same treatment, also
-- built on database_overview.
create or replace function sweep_db_extras() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from database_overview where status = 'up' loop
        select tenant_id into tid from probes where id = r.id;

        if coalesce((r.extra ->> 'blocked_sessions')::int, 0) >= 5 then
            select cooldown into cd from alert_rules where rule = 'db_blocked' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_blocked:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (null, 'db_blocked', 'warning',
                        format('[warning] %s has %s blocked sessions',
                               r.name, r.extra ->> 'blocked_sessions'),
                        format(E'Database: %s (%s)\nBlocked sessions: %s\n\n'
                               'Something is holding a lock other work is waiting on.',
                               r.name, r.kind, r.extra ->> 'blocked_sessions'),
                        coalesce(people, '{}'), tid);
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_blocked:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent, tenant_id)
                    values (null, 'db_blocked:' || r.id::text, now(), tid);
                end if;
                n := n + 1;
            end if;
        end if;

        if coalesce((r.extra ->> 'tablespace_worst_pct')::numeric, 0) >= 90 then
            select cooldown into cd from alert_rules where rule = 'db_tablespace' and enabled;
            select last_sent into last from alert_state
             where agent_id is null and rule = 'db_tablespace:' || r.id::text;
            if cd is not null and (last is null or now() - last >= cd) then
                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (null, 'db_tablespace', 'critical',
                        format('[critical] %s tablespace is %s%% full',
                               r.name, round((r.extra ->> 'tablespace_worst_pct')::numeric)),
                        format(E'Database: %s\nWorst tablespace: %s%%\nOver 90%%: %s\n\n'
                               'Writes stop when a tablespace fills.',
                               r.name, r.extra ->> 'tablespace_worst_pct',
                               r.extra ->> 'tablespaces_over_90'),
                        coalesce(people, '{}'), tid);
                update alert_state set last_sent = now()
                 where agent_id is null and rule = 'db_tablespace:' || r.id::text;
                if not found then
                    insert into alert_state (agent_id, rule, last_sent, tenant_id)
                    values (null, 'db_tablespace:' || r.id::text, now(), tid);
                end if;
                n := n + 1;
            end if;
        end if;
    end loop;
    return n;
end $$;

-- db/028_bsm.sql's sweep_services() - r.id is services.id here (built
-- from services s ...), not probes.
create or replace function sweep_services() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select cooldown into cd from alert_rules where rule = 'service_down' and enabled;
    if cd is null then return 0; end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from service_health where status = 'down' loop
        select tenant_id into tid from services where id = r.id;

        select last_sent into last from alert_state
         where agent_id is null and rule = 'service_down:' || r.id::text;
        continue when last is not null and now() - last < cd;

        insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
        values (null, 'service_down', 'critical',
                format('[critical] %s is down', r.name),
                format(E'Service: %s (tier %s)\nCause: %s\nComponents: %s, %s down\n\n%s',
                       r.name, r.tier, r.reason, r.components, r.down,
                       coalesce(r.description, '')),
                coalesce(people, '{}'), tid);

        update alert_state set last_sent = now()
         where agent_id is null and rule = 'service_down:' || r.id::text;
        if not found then
            insert into alert_state (agent_id, rule, last_sent, tenant_id)
            values (null, 'service_down:' || r.id::text, now(), tid);
        end if;
        n := n + 1;
    end loop;
    return n;
end $$;

-- db/037_supply_chain.sql's sweep_supply_chain() - r.id is a probes.id
-- (supply_chain_overview is built from probes p ...).
create or replace function sweep_supply_chain() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from supply_chain_overview
              where recommendation = 'DO_NOT_INSTALL'
    loop
        select tenant_id into tid from probes where id = r.id;

        select cooldown into cd from alert_rules where rule='supply_chain_risk' and enabled;
        select last_sent into last from alert_state
         where agent_id is null and rule = 'supply_chain_risk:' || r.id::text;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
            values (null, 'supply_chain_risk', 'critical',
                    format('[critical] %s scored %s for supply-chain risk', r.name, r.risk_score),
                    format(E'Repository: %s\nScore: %s/100 (%s)\nFindings: %s\n\n'
                           'Reviewed via ForgeGuardian. See the Supply Chain page for detail.',
                           r.target, r.risk_score, r.severity, r.finding_count),
                    coalesce(people, '{}'), tid);
            update alert_state set last_sent = now()
             where agent_id is null and rule = 'supply_chain_risk:' || r.id::text;
            if not found then
                insert into alert_state (agent_id, rule, last_sent, tenant_id)
                values (null, 'supply_chain_risk:' || r.id::text, now(), tid);
            end if;
            n := n + 1;
        end if;
    end loop;
    return n;
end $$;

-- db/038_tls_certs.sql's sweep_tls_certs() - r.id is a probes.id
-- (tls_cert_overview is built from probes p ...).
create or replace function sweep_tls_certs() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    rule   text;
    sev    text;
    msg    text;
    tid    uuid;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from tls_cert_overview
              where checked_at is not null
                and (chain_valid is false or days_remaining <= 14)
    loop
        select tenant_id into tid from probes where id = r.id;

        if r.chain_valid is false then
            rule := 'tls_cert_invalid'; sev := 'critical';
            msg := format('Chain error: %s', r.chain_error);
        else
            rule := 'tls_cert_expiring'; sev := 'warning';
            msg := format('Expires in %s day(s) (%s)', r.days_remaining, r.not_after);
        end if;

        select cooldown into cd from alert_rules where alert_rules.rule = rule and enabled;
        select last_sent into last from alert_state
         where agent_id is null and alert_state.rule = rule || ':' || r.id::text;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
            values (null, rule, sev,
                    format('[%s] %s - certificate problem', sev, r.name),
                    format(E'Target: %s\nSubject: %s\nIssuer: %s\n%s',
                           r.target, r.subject, r.issuer, msg),
                    coalesce(people, '{}'), tid);
            update alert_state set last_sent = now()
             where agent_id is null and alert_state.rule = rule || ':' || r.id::text;
            if not found then
                insert into alert_state (agent_id, rule, last_sent, tenant_id)
                values (null, rule || ':' || r.id::text, now(), tid);
            end if;
            n := n + 1;
        end if;
    end loop;
    return n;
end $$;

-- db/031_proxmox.sql's sweep_proxmox() - both loops already select
-- probe_id explicitly, so tenant_id is a direct lookup, no view-shape
-- assumption needed.
create or replace function sweep_proxmox() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in
        select b.probe_id, b.vmid, b.node, b.detail, o.name as cluster
          from proxmox_backups b
          join proxmox_overview o on o.id = b.probe_id
         where not b.ok and b.ts > now() - interval '10 minutes'
    loop
        select tenant_id into tid from probes where id = r.probe_id;

        select cooldown into cd from alert_rules where rule='proxmox_backup_failed' and enabled;
        select last_sent into last from alert_state
         where agent_id is null and rule = 'proxmox_backup_failed:' || r.probe_id::text || ':' || r.vmid::text;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
            values (null, 'proxmox_backup_failed', 'warning',
                    format('[warning] backup failed for guest %s on %s', r.vmid, r.cluster),
                    format(E'Cluster: %s\nNode: %s\nGuest: %s\n\n%s',
                           r.cluster, r.node, r.vmid, coalesce(r.detail, 'no detail reported')),
                    coalesce(people, '{}'), tid);
            update alert_state set last_sent = now()
             where agent_id is null and rule = 'proxmox_backup_failed:' || r.probe_id::text || ':' || r.vmid::text;
            if not found then
                insert into alert_state (agent_id, rule, last_sent, tenant_id)
                values (null, 'proxmox_backup_failed:' || r.probe_id::text || ':' || r.vmid::text, now(), tid);
            end if;
            n := n + 1;
        end if;
    end loop;

    for r in
        select s.probe_id, s.node, s.storage, o.name as cluster,
               round(100.0 * s.used_bytes / nullif(s.total_bytes, 0), 1) as pct
          from proxmox_storage s
          join proxmox_overview o on o.id = s.probe_id
         where o.enabled and s.total_bytes > 0
    loop
        continue when r.pct is null or r.pct < 90;
        select tenant_id into tid from probes where id = r.probe_id;

        select cooldown into cd from alert_rules where rule='proxmox_storage_full' and enabled;
        select last_sent into last from alert_state
         where agent_id is null and rule = 'proxmox_storage_full:' || r.probe_id::text || ':' || r.node || ':' || r.storage;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
            values (null, 'proxmox_storage_full', 'critical',
                    format('[critical] %s on %s is %s%% full', r.storage, r.node, r.pct),
                    format(E'Cluster: %s\nNode: %s\nStorage: %s\nUsed: %s%%\n\n'
                           'New disk allocations and backups will start failing at 100%%.',
                           r.cluster, r.node, r.storage, r.pct),
                    coalesce(people, '{}'), tid);
            update alert_state set last_sent = now()
             where agent_id is null and rule = 'proxmox_storage_full:' || r.probe_id::text || ':' || r.node || ':' || r.storage;
            if not found then
                insert into alert_state (agent_id, rule, last_sent, tenant_id)
                values (null, 'proxmox_storage_full:' || r.probe_id::text || ':' || r.node || ':' || r.storage, now(), tid);
            end if;
            n := n + 1;
        end if;
    end loop;

    return n;
end $$;

-- db/027_escalation.sql's sweep_escalations() - a is already a row from
-- alert_log, which now carries tenant_id directly (section 2 above), so
-- no lookup is needed here at all - just threaded through to both the
-- escalation's own alert_log row and alert_escalations.
create or replace function sweep_escalations() returns integer
language plpgsql security definer set search_path = public as $$
declare
    a      record;
    p      escalation_policies%rowtype;
    st     record;
    n      integer := 0;
    people text[];
begin
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

                insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
                values (a.agent_id, a.rule, a.severity,
                        format('[escalation %s] %s', st.step, a.subject),
                        format(E'Not acknowledged after %s minutes.\n\n%s\n\n'
                               '--\nEscalation policy: %s, step %s%s',
                               st.after_min, coalesce(a.body, ''), p.name, st.step,
                               case when st.note is null then '' else E'\n' || st.note end),
                        coalesce(people, '{}'), a.tenant_id);

                insert into alert_escalations (alert_id, step_id, tenant_id) values (a.id, st.id, a.tenant_id);
                n := n + 1;
            end loop;
        end loop;
    end loop;
    return n;
end $$;

-- ================================================================
-- 9. queue_automation() - a real cross-tenant correctness fix, not
--     just a null-constraint one. This function runs as SECURITY
--     DEFINER and iterates alert_log/service_health with no tenant
--     filter at all, matched only by rule name/severity - without an
--     explicit tenant check, a tenant's automation rule could fire
--     against a completely different tenant's alert if the conditions
--     happened to line up. Both loops now require the matched alert/
--     service to belong to the same tenant as the rule being evaluated.
-- ================================================================

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
                        and tenant_id = r.tenant_id
                        and (cardinality(r.trigger_rules) = 0 or rule = any(r.trigger_rules))
                        and (cardinality(r.severities) = 0 or severity = any(r.severities))
                        and not exists (select 1 from automation_runs ar
                                         where ar.rule_id = r.id and ar.alert_id = alert_log.id)
                      limit greatest(0, r.max_per_day - today)
            loop
                insert into automation_runs (rule_id, alert_id, status, reason, request, tenant_id)
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
                                                     'agent_id', a.agent_id)),
                        r.tenant_id);
                n := n + 1;
                today := today + 1;
            end loop;

        else
            for s in select sh.* from service_health sh
                      join services sv on sv.id = sh.id
                      where sh.status = 'down'
                        and sv.tenant_id = r.tenant_id
                        and (cardinality(r.trigger_rules) = 0 or sh.name = any(r.trigger_rules))
                        and not exists (select 1 from automation_runs ar
                                         where ar.rule_id = r.id and ar.service_id = sh.id
                                           and ar.created_at > now() - interval '1 hour')
                      limit greatest(0, r.max_per_day - today)
            loop
                insert into automation_runs (rule_id, service_id, status, reason, request, tenant_id)
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
                                                     'reason', s.reason)),
                        r.tenant_id);
                n := n + 1;
                today := today + 1;
            end loop;
        end if;
    end loop;
    return n;
end $$;

-- ================================================================
-- 10. ip_addresses: its primary key is the bare IP, which was already
--     wrong the moment a second tenant exists - two unrelated
--     customers very plausibly both have a host at 10.0.0.5 on their
--     own private network, and a global PK on ip would let one
--     tenant's inventory refresh silently overwrite the other's row
--     (a data-correctness bug and a leak - tenant B would see tenant
--     A's hostname/agent association under "their" address). Same fix
--     shape as agents.instance_id in section 2: PK becomes
--     (tenant_id, ip). All three sources refresh_ip_inventory() reads
--     from (net_interfaces, probes, auth_events) already carry their
--     own tenant_id directly from section 2, so no extra joins needed.
-- ================================================================

alter table ip_addresses drop constraint if exists ip_addresses_pkey;
alter table ip_addresses add primary key (tenant_id, ip);

create or replace function refresh_ip_inventory() returns integer
language plpgsql security definer set search_path = public as $$
declare n integer := 0;
begin
    insert into ip_addresses (ip, hostname, mac, source, agent_id, last_seen, tenant_id)
    select distinct on (i.tenant_id, i.ipv4)
           i.ipv4, o.label, i.mac, 'agent', i.agent_id, i.last_seen, i.tenant_id
      from net_interfaces i
      join agent_overview o on o.id = i.agent_id
     where i.ipv4 is not null
       and not (i.ipv4 << inet '127.0.0.0/8')
     order by i.tenant_id, i.ipv4, i.last_seen desc
    on conflict (tenant_id, ip) do update set
        hostname = excluded.hostname,
        mac = coalesce(excluded.mac, ip_addresses.mac),
        source = 'agent',
        agent_id = excluded.agent_id,
        last_seen = excluded.last_seen;
    get diagnostics n = row_count;

    insert into ip_addresses (ip, hostname, source, last_seen, tenant_id)
    select distinct on (p.tenant_id, p.target::inet) p.target::inet, p.name, 'probe', now(), p.tenant_id
      from probes p
     where p.target ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
     order by p.tenant_id, p.target::inet, p.name
    on conflict (tenant_id, ip) do update set
        last_seen = excluded.last_seen,
        hostname = coalesce(ip_addresses.hostname, excluded.hostname);

    insert into ip_addresses (ip, source, last_seen, tenant_id)
    select e.source_ip, 'signin', max(e.ts), e.tenant_id
      from auth_events e
     where e.source_ip is not null and e.ts > now() - interval '30 days'
     group by e.source_ip, e.tenant_id
    on conflict (tenant_id, ip) do update set last_seen = greatest(ip_addresses.last_seen, excluded.last_seen);

    return n;
end $$;

-- ================================================================
-- 11. sweep_probes() (db/014_probes.sql) - writes to alert_log/
--     alert_state directly for probe_down, the same shape as the
--     section 8 sweep functions (agent_id null, fleet-level), not
--     through queue_alert() despite section 7's comment above
--     suggesting otherwise. r.id here is probe_state.id = probes.id,
--     so tenant_id is one lookup away, same as sweep_applications().
-- ================================================================

create or replace function sweep_probes() returns integer as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
    tid    uuid;
begin
    select cooldown into cd from alert_rules where rule = 'probe_down' and enabled;
    if cd is null then return 0; end if;

    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from probe_state
              where status = 'down' and enabled
                and consecutive >= 2      -- one bad sample is noise, two is a fault
    loop
        select last_sent into last from alert_state
         where agent_id is null and rule = 'probe_down:' || r.id::text;

        continue when last is not null and now() - last < cd;

        select tenant_id into tid from probes where id = r.id;

        insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
        values (null, 'probe_down', 'critical',
                format('[critical] %s is unreachable', r.name),
                format(E'Check: %s (%s)\nTarget: %s%s\nFailing for %s consecutive checks.\nLast detail: %s',
                       r.name, r.kind, r.target,
                       case when r.port is null then '' else ':' || r.port end,
                       r.consecutive, coalesce(r.detail, 'no detail')),
                coalesce(people, '{}'), tid);

        -- ON CONFLICT cannot infer an expression index, so do it explicitly.
        update alert_state set last_sent = now()
         where agent_id is null and rule = 'probe_down:' || r.id::text;
        if not found then
            insert into alert_state (agent_id, rule, last_sent, tenant_id)
            values (null, 'probe_down:' || r.id::text, now(), tid);
        end if;

        n := n + 1;
    end loop;
    return n;
end $$ language plpgsql security definer set search_path = public;

-- ================================================================
-- 12. build_digest() (db/007_alerts.sql) - inserts into alert_log
--     directly with a real agent_id (not through queue_alert()), so
--     it was missed by section 7's queue_alert()-only sweep. Same
--     lookup shape as snapshot_trust() in section 7: a join to
--     agents by id, rather than adding tenant_id to agent_overview's
--     own column list, which is read from in many more places than
--     this one function.
-- ================================================================

create or replace function build_digest() returns integer as $$
declare a record; people text[]; body text; n integer := 0; tid uuid;
begin
    for a in select * from agent_overview loop
        select array_agg(distinct lower(email)) into people
          from alert_recipients
         where (agent_id = a.id or agent_id is null) and digest;
        continue when people is null or cardinality(people) = 0;
        continue when a.muted;

        select tenant_id into tid from agents where id = a.id;

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

        insert into alert_log (agent_id, rule, severity, subject, body, recipients, tenant_id)
        values (a.id, 'digest', 'info',
                format('[nodewatch] 6-hour digest: %s (trust %s)',
                       a.label, coalesce(a.trust::text, 'n/a')),
                body, people, tid);
        n := n + 1;
    end loop;
    return n;
end $$ language plpgsql security definer;

-- ================================================================
-- 13. probes.probes_unique_target (db/014_probes.sql) is the same class
--     of bug as agents.instance_id (section 2) and ip_addresses.ip
--     (section 10), found only by actually inserting two tenants' probes
--     against a live database rather than by re-reading the file: a
--     bare (kind, target, port) uniqueness check is global, and a target
--     like a private IP (10.0.0.5) or an internal hostname is exactly
--     the kind of value two unrelated customers' own networks very
--     plausibly both use. Without this fix, whichever tenant creates a
--     probe for that target first would silently block every other
--     tenant from ever monitoring "their" 10.0.0.5.
-- ================================================================

drop index if exists probes_unique_target;
create unique index if not exists probes_tenant_unique_target
    on probes (tenant_id, kind, target, coalesce(port, -1));
