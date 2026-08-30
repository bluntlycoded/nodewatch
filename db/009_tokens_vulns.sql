-- 009: enrolment tokens, alert acknowledgement, vulnerability scan queue.

-- ---------------------------------------------------------------- enrolment tokens

-- Today any instance in the account carrying the agent role can enrol.
-- A token makes enrolment an explicit invitation: single use, expiring,
-- and issued from the dashboard. It layers on top of the AWS identity
-- check rather than replacing it - the token says "this node is invited",
-- the identity document says "this node is who it claims to be".
create table if not exists enroll_tokens (
    token        text        primary key,
    label        text,
    created_at   timestamptz not null default now(),
    expires_at   timestamptz not null default now() + interval '24 hours',
    used_at      timestamptz,
    used_by      text,
    revoked      boolean     not null default false
);

create index if not exists enroll_tokens_open_idx on enroll_tokens (expires_at)
    where used_at is null and not revoked;

create or replace function new_enroll_token(p_label text default null,
                                            p_hours integer default 24)
returns text as $$
declare t text;
begin
    t := encode(gen_random_bytes(24), 'hex');
    insert into enroll_tokens (token, label, expires_at)
    values (t, p_label, now() + make_interval(hours => p_hours));
    return t;
end $$ language plpgsql security definer;

create or replace view enroll_token_status as
select token, label, created_at, expires_at, used_at, used_by, revoked,
       case when revoked          then 'revoked'
            when used_at is not null then 'used'
            when expires_at < now()  then 'expired'
            else 'open' end as status
from enroll_tokens;

alter table enroll_tokens enable row level security;
drop policy if exists enroll_tokens_rw on enroll_tokens;
create policy enroll_tokens_rw on enroll_tokens for all to authenticated using (true) with check (true);
grant select, insert, update, delete on enroll_tokens to authenticated;
alter view enroll_token_status set (security_invoker = on);
grant select on enroll_token_status to authenticated;
revoke all on enroll_tokens, enroll_token_status from anon;
grant execute on function new_enroll_token(text, integer) to authenticated;

-- ---------------------------------------------------------------- alert workflow

alter table alert_log add column if not exists acknowledged_at timestamptz;
alter table alert_log add column if not exists acknowledged_by text;
alter table alert_log add column if not exists resolved_at     timestamptz;
alter table alert_log add column if not exists note            text;

comment on column alert_log.acknowledged_at is
    'Someone has seen it. Distinct from resolved: acknowledging stops it nagging, resolving asserts the underlying problem is gone.';

create index if not exists alert_log_open_idx on alert_log (created_at desc)
    where acknowledged_at is null and resolved_at is null;

drop policy if exists alert_log_update on alert_log;
create policy alert_log_update on alert_log for update to authenticated
    using (true) with check (true);
grant update (acknowledged_at, acknowledged_by, resolved_at, note) on alert_log to authenticated;

create or replace view alert_open as
select l.*, coalesce(a.display_name, a.hostname, a.instance_id) as label,
       case when l.resolved_at is not null     then 'resolved'
            when l.acknowledged_at is not null then 'acknowledged'
            else 'open' end as workflow
from alert_log l
left join agents a on a.id = l.agent_id;

alter view alert_open set (security_invoker = on);
grant select on alert_open to authenticated;
revoke all on alert_open from anon;

-- ---------------------------------------------------------------- vuln scan queue

-- Every (name, version) pair a host reports that has not been looked up
-- recently. Deduplicated across the fleet: one OSV query covers every
-- node running that package.
create or replace view package_scan_queue as
select distinct p.name, p.version
  from host_packages p
  left join package_scan_state s on s.name = p.name and s.version = p.version
 where s.name is null
    or s.checked_at < now() - interval '7 days';

alter view package_scan_queue set (security_invoker = on);
grant select on package_scan_queue to authenticated;
revoke all on package_scan_queue from anon;

create or replace function pending_vuln_scans() returns integer as $$
declare n integer;
begin
    select count(*) into n from package_scan_queue;
    return n;
end $$ language plpgsql security definer;

-- Calls the scanner Edge Function, same Vault pattern as the alert drain.
create or replace function run_vuln_scan() returns bigint as $$
declare url text; key text; req bigint;
begin
    if pending_vuln_scans() = 0 then return null; end if;
    select decrypted_secret into url from vault.decrypted_secrets where name = 'project_url';
    select decrypted_secret into key from vault.decrypted_secrets where name = 'service_role_key';
    if url is null or key is null then
        raise warning 'vault secrets not set';
        return null;
    end if;
    select net.http_post(
        url := url || '/functions/v1/scan-vulns',
        headers := jsonb_build_object('Content-Type','application/json',
                                      'Authorization','Bearer ' || key),
        body := '{}'::jsonb
    ) into req;
    return req;
end $$ language plpgsql security definer;

select cron.unschedule('nodewatch-vuln-scan')
 where exists (select 1 from cron.job where jobname='nodewatch-vuln-scan');
select cron.schedule('nodewatch-vuln-scan', '*/10 * * * *', $$select run_vuln_scan();$$);

-- ---------------------------------------------------------------- vuln alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('severe_vuln', 'warning', interval '12 hours',
     'A critical or high severity vulnerability was found in an installed package')
on conflict (rule) do nothing;

-- Fires per host once new severe findings appear, rather than per package -
-- one email listing five CVEs is useful, five emails is not.
create or replace function sweep_vulnerabilities() returns integer as $$
declare a record; n integer := 0;
begin
    for a in
        select o.id, o.label, o.vulns_severe, o.vulns_total
          from agent_overview o
         where o.vulns_severe > 0
    loop
        if queue_alert(a.id, 'severe_vuln',
            format('[warning] %s severe vulnerabilit%s on %s',
                   a.vulns_severe, case when a.vulns_severe = 1 then 'y' else 'ies' end, a.label),
            format(E'Severe (critical or high): %s\nTotal known: %s\n\n'
                   'Open the node in nodewatch to see the affected packages.',
                   a.vulns_severe, a.vulns_total))
        then n := n + 1; end if;
    end loop;
    return n;
end $$ language plpgsql security definer;

select cron.unschedule('nodewatch-vuln-sweep')
 where exists (select 1 from cron.job where jobname='nodewatch-vuln-sweep');
select cron.schedule('nodewatch-vuln-sweep', '15 */6 * * *', $$select sweep_vulnerabilities();$$);
