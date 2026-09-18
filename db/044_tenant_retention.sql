-- 044: per-tenant data retention. Every retention cron job introduced
-- across db/001-041 deletes rows older than a single hardcoded interval,
-- the same for every tenant. This makes that interval a per-tenant
-- setting instead, surfaced in the dashboard as one "keep my data for N
-- days" control rather than N separate per-table sliders - the existing
-- per-table defaults already varied by data category (2 days for route
-- traces, 180 for TLS scans, 365 for the audit log) for good operational
-- reasons, and this migration keeps that shape: retention_days scales
-- each job's window relative to its own previous default rather than
-- replacing every table with one flat number, and audit_log additionally
-- enforces a 365-day floor no tenant setting can shorten, since an audit
-- trail existing precisely to reconstruct what happened during an
-- incident is not something a self-service setting should be able to
-- shrink out from under a security investigation.

alter table tenants add column if not exists retention_days integer not null default 90
    check (retention_days between 7 and 3650);
comment on column tenants.retention_days is
    'Multiplier baseline for every per-tenant retention job in this file - see db/044_tenant_retention.sql. Default 90 preserves existing single-tenant behaviour for tenant zero at the day this migration lands, since 90 / 90 = 1x every table''s pre-multi-tenancy default.';

-- Every job below scales its table's original hardcoded window by
-- (t.retention_days / 90.0) - tenant zero's default of 90 makes every
-- ratio exactly 1, so applying this migration changes nothing for
-- existing data until a tenant actually changes their own setting.

select cron.unschedule('nodewatch-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-retention');
select cron.schedule('nodewatch-retention', '17 3 * * *', $$
    delete from metrics m using tenants t
     where m.tenant_id = t.id
       and m.ts < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
    delete from port_events e using tenants t
     where e.tenant_id = t.id
       and e.ts < now() - (t.retention_days / 90.0 * 90) * interval '1 day';
    delete from auth_events a using tenants t
     where a.tenant_id = t.id
       and a.ts < now() - (t.retention_days / 90.0 * 90) * interval '1 day';
$$);

select cron.unschedule('nodewatch-alert-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-alert-retention');
select cron.schedule('nodewatch-alert-retention', '25 4 * * *', $$
    delete from alert_log l using tenants t
     where l.tenant_id = t.id
       and l.created_at < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
$$);

select cron.unschedule('nodewatch-history-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-history-retention');
select cron.schedule('nodewatch-history-retention', '40 4 * * *', $$
    delete from trust_history h using tenants t
     where h.tenant_id = t.id
       and h.ts < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
    delete from fim_events f using tenants t
     where f.tenant_id = t.id
       and f.ts < now() - (t.retention_days / 90.0 * 90) * interval '1 day';
$$);

select cron.unschedule('nodewatch-probe-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-probe-retention');
select cron.schedule('nodewatch-probe-retention', '50 4 * * *', $$
    delete from probe_results r using tenants t
     where r.tenant_id = t.id
       and r.ts < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
$$);

select cron.unschedule('nodewatch-app-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-app-retention');
select cron.schedule('nodewatch-app-retention', '10 5 * * *', $$
    delete from app_metrics m using tenants t
     where m.tenant_id = t.id
       and m.ts < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
$$);

select cron.unschedule('nodewatch-db-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-db-retention');
select cron.schedule('nodewatch-db-retention', '58 4 * * *', $$
    delete from db_metrics m using tenants t
     where m.tenant_id = t.id
       and m.ts < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
$$);

select cron.unschedule('nodewatch-net-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-net-retention');
select cron.schedule('nodewatch-net-retention', '5 5 * * *', $$
    delete from net_traffic n using tenants t
     where n.tenant_id = t.id
       and n.ts < now() - (t.retention_days / 90.0 * 7) * interval '1 day';
$$);

select cron.unschedule('nodewatch-nettool-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-nettool-retention');
select cron.schedule('nodewatch-nettool-retention', '55 4 * * *', $$
    delete from nettool_jobs j using tenants t
     where j.tenant_id = t.id
       and j.created_at < now() - (t.retention_days / 90.0 * 7) * interval '1 day';
$$);

select cron.unschedule('nodewatch-route-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-route-retention');
select cron.schedule('nodewatch-route-retention', '20 5 * * *', $$
    delete from route_hops h using tenants t
     where h.tenant_id = t.id
       and h.traced_at < now() - (t.retention_days / 90.0 * 2) * interval '1 day';
$$);

select cron.unschedule('nodewatch-automation-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-automation-retention');
select cron.schedule('nodewatch-automation-retention', '30 5 * * *', $$
    delete from automation_runs r using tenants t
     where r.tenant_id = t.id
       and r.created_at < now() - (t.retention_days / 90.0 * 90) * interval '1 day';
$$);

select cron.unschedule('nodewatch-proxmox-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-proxmox-retention');
select cron.schedule('nodewatch-proxmox-retention', '59 4 * * *', $$
    delete from proxmox_metrics m using tenants t
     where m.tenant_id = t.id
       and m.ts < now() - (t.retention_days / 90.0 * 30) * interval '1 day';
    delete from proxmox_backups b using tenants t
     where b.tenant_id = t.id
       and b.ts < now() - (t.retention_days / 90.0 * 90) * interval '1 day';
$$);

select cron.unschedule('nodewatch-tls-cert-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-tls-cert-retention');
select cron.schedule('nodewatch-tls-cert-retention', '20 5 * * *', $$
    delete from tls_cert_scans s using tenants t
     where s.tenant_id = t.id
       and s.ts < now() - (t.retention_days / 90.0 * 180) * interval '1 day';
$$);

select cron.unschedule('nodewatch-supply-chain-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-supply-chain-retention');
select cron.schedule('nodewatch-supply-chain-retention', '15 5 * * *', $$
    delete from supply_chain_scans s using tenants t
     where s.tenant_id = t.id
       and s.ts < now() - (t.retention_days / 90.0 * 180) * interval '1 day';
$$);

-- Floor, not a scale: whatever a tenant sets retention_days to, the audit
-- log never drops below its original 365-day default - see the file
-- header comment.
select cron.unschedule('nodewatch-audit-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-audit-retention');
select cron.schedule('nodewatch-audit-retention', '35 4 * * *', $$
    delete from audit_log l using tenants t
     where l.tenant_id = t.id
       and l.created_at < now() - greatest(t.retention_days, 365) * interval '1 day';
$$);

-- nodewatch-cron-log-retention (cron.job_run_details) and
-- nodewatch-teams-pending-retention (teams_oauth_pending) are
-- deliberately untouched: neither is tenant data - the first is pg_cron's
-- own execution log, the second has no tenant_id as of db/043 (see that
-- migration's section 2 header).

-- The one field of tenants a self-serve admin should be able to change
-- right now. A dedicated RPC rather than an RLS UPDATE policy on tenants
-- itself, since a broad admin-write policy would also let an admin edit
-- plan directly, and plan is meant to stay controlled by billing (not
-- built yet), not by whoever is admin on the account.
create or replace function update_tenant_retention(p_retention_days integer) returns void
language plpgsql security definer set search_path = public as $$
begin
    if not is_admin() then
        raise exception 'only an admin can change retention settings';
    end if;
    if p_retention_days is null or p_retention_days < 7 or p_retention_days > 3650 then
        raise exception 'retention_days must be between 7 and 3650';
    end if;
    update tenants set retention_days = p_retention_days where id = current_tenant();
end $$;
grant execute on function update_tenant_retention(integer) to authenticated;
