-- 048: two multi-tenancy gaps left by 043.
--
-- 1. tenant_id has no default.
--
--    043 made tenant_id NOT NULL on every tenant-scoped table and every
--    write policy checks tenant_id = current_tenant(), but nothing fills
--    the column in, and the dashboard never sends it. So since 043 every
--    insert the dashboard makes - a probe, a recipient, an alert channel,
--    a subnet, a service - is rejected by row-level security. Defaulting
--    the column to current_tenant() makes a signed-in user's insert land
--    in their own tenant, which the policy then accepts. Server-side
--    inserts (ingest API, OAuth callbacks) have no signed-in user and keep
--    setting tenant_id explicitly; for them the default is null and the
--    NOT NULL constraint still catches a missed one.
--
-- 2. Alerts reached other tenants' recipients.
--
--    queue_alert() and the probe/database/application/service/Proxmox/
--    supply-chain/TLS sweeps resolve recipients with
--        from alert_recipients where agent_id is null and instant
--    with no tenant filter, so a fleet-wide recipient in one tenant was
--    copied onto every other tenant's alerts. Rather than rewrite each of
--    those functions, one trigger on alert_log keeps only the recipients
--    that belong to the alert's own tenant - which also covers any future
--    function that queues alerts - and suppresses the alert, with the
--    reason, when that leaves the tenant with no destination at all.

do $$
declare
    t text;
begin
    foreach t in array array[
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
    ] loop
        execute format('alter table %I alter column tenant_id set default current_tenant()', t);
    end loop;
end $$;

create or replace function alert_log_tenant_scope() returns trigger
language plpgsql security definer set search_path = public as $$
begin
    if new.status is distinct from 'pending' then
        return new;
    end if;

    if coalesce(cardinality(new.recipients), 0) > 0 then
        select coalesce(array_agg(distinct lower(r.email)), '{}')
          into new.recipients
          from alert_recipients r
         where r.tenant_id = new.tenant_id
           and (r.agent_id is null or r.agent_id is not distinct from new.agent_id)
           and lower(r.email) = any (new.recipients);
    end if;

    if coalesce(cardinality(new.recipients), 0) = 0
       and not exists (select 1 from alert_channels c
                        where c.enabled
                          and c.tenant_id = new.tenant_id
                          and (c.agent_id is null or c.agent_id is not distinct from new.agent_id)) then
        new.status := 'suppressed';
        new.error  := coalesce(new.error, 'no destinations configured');
    end if;

    return new;
end $$;

drop trigger if exists alert_log_tenant_scope on alert_log;
create trigger alert_log_tenant_scope before insert on alert_log
    for each row execute function alert_log_tenant_scope();
