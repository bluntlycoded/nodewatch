-- 045: tenant admin tools - self-service delete and data export, the
-- basic "danger zone" a multi-tenant product needs before its first
-- real, unrelated customer: a way for a tenant's own admin to leave
-- entirely (with their data), without needing to ask us to do it by hand
-- against production.

-- ---------------------------------------------------------------- delete

-- Irreversible, so gated the same way GitHub gates repo deletion: the
-- caller must type the tenant's exact current name, not just click a
-- button. session_replication_role=replica (rather than 48 hand-ordered
-- deletes, or adding ON DELETE CASCADE to every tenant_id FK, which would
-- also change ordinary non-delete-tenant behaviour) suppresses both FK
-- trigger checks and normal triggers for this transaction only, so the
-- 48 tables below - which have a real, multi-level dependency graph
-- between them (e.g. alert_escalations references both alert_log and
-- escalation_steps) - can be cleared in one flat pass without a
-- topological sort, and without this one-time bulk delete generating
-- audit_log noise for a tenant that is being removed anyway. Verified
-- against a live Postgres with real cross-referencing rows in several of
-- these tables, not just read for syntax.
create or replace function delete_tenant(p_confirm_name text) returns void
language plpgsql security definer set search_path = public as $$
declare
    tid         uuid := current_tenant();
    actual_name text;
    t           text;
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
    if not is_admin() then
        raise exception 'only an admin can delete a tenant';
    end if;
    if tid is null then
        raise exception 'this account does not belong to a tenant';
    end if;

    select name into actual_name from tenants where id = tid;
    if p_confirm_name is null or p_confirm_name <> actual_name then
        raise exception 'confirmation name does not match - type the tenant name exactly to delete it';
    end if;

    set local session_replication_role = replica;

    foreach t in array tables loop
        execute format('delete from %I where tenant_id = %L', t, tid);
    end loop;

    -- profiles is tenant-scoped from db/043 section 1, not section 2, so
    -- it is not in the array above. The auth.users row itself is left
    -- alone - deleting it is a GoTrue admin-API operation (it also has to
    -- invalidate sessions/refresh tokens), not a plain SQL delete, and
    -- belongs to the existing manage-users flow, not this function.
    delete from profiles where tenant_id = tid;
    delete from tenants where id = tid;
end $$;
grant execute on function delete_tenant(text) to authenticated;

-- ---------------------------------------------------------------- export

-- One JSON blob covering every tenant-scoped table, keyed by table name,
-- plus the tenant row itself. Deliberately not paginated or streamed -
-- fine for a v1 "admin clicks export, downloads a file" feature; a
-- tenant large enough for this to matter is a later problem, not a
-- reason to withhold the feature now.
--
-- Two deliberate omissions from the table list: probe_secrets holds
-- connection credentials and must never leave the database in a data
-- export, and the raw high-volume time series (metrics, probe_results,
-- db_metrics, app_metrics, net_traffic, trust_history, proxmox_metrics)
-- and internal bookkeeping (alert_state, alert_escalations,
-- alert_deliveries) are left out to keep a v1 export a reasonable size -
-- inventory, config, events, alerts and the audit trail, not a full
-- metrics dump a customer can already query live.
create or replace function export_tenant_data() returns jsonb
language plpgsql security definer set search_path = public as $$
declare
    tid    uuid := current_tenant();
    result jsonb := '{}'::jsonb;
    part   jsonb;
    t      text;
    tables text[] := array[
        'agents','alert_channels','enroll_tokens',
        'probes','services','service_components','service_dependencies',
        'escalation_policies','escalation_steps','automation_rules',
        'subnets','ip_addresses','github_installations','alert_recipients',
        'auth_events','port_state','port_events','host_checks',
        'alert_log','user_state','user_events','fim_state',
        'fim_events','host_packages','package_vulns','package_scan_state',
        'net_interfaces','route_hops',
        'proxmox_guests','proxmox_storage','proxmox_backups',
        'supply_chain_scans','supply_chain_findings','tls_cert_scans',
        'audit_log','automation_runs','nettool_jobs'
    ];
begin
    if not is_admin() then
        raise exception 'only an admin can export tenant data';
    end if;
    if tid is null then
        raise exception 'this account does not belong to a tenant';
    end if;

    foreach t in array tables loop
        execute format(
            'select coalesce(jsonb_agg(to_jsonb(x)), ''[]''::jsonb) from %I x where x.tenant_id = %L',
            t, tid
        ) into part;
        result := result || jsonb_build_object(t, part);
    end loop;

    result := jsonb_build_object('exported_at', now(), 'tenant',
        (select to_jsonb(x) - 'id' from tenants x where x.id = tid)) || result;
    return result;
end $$;
grant execute on function export_tenant_data() to authenticated;
