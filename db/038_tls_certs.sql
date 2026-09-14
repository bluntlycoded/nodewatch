-- 038: TLS certificate expiry and chain validity on https:// url checks.
--
-- Not a new probe kind - it's a property of the same connection an https
-- url check already makes (probe/prober.py's check_url calls
-- _check_tls_cert alongside the HTTP request, not on a separate schedule),
-- attached the same way Proxmox attaches guests/storage/backups and
-- supply-chain attaches findings.

-- ---------------------------------------------------------------- scans

create table if not exists tls_cert_scans (
    probe_id       uuid        not null references probes (id) on delete cascade,
    ts             timestamptz not null,
    subject        text,
    issuer         text,
    not_before     timestamptz,
    not_after      timestamptz,
    days_remaining integer,
    chain_valid    boolean,
    chain_error    text,
    primary key (probe_id, ts)
);

create index if not exists tls_cert_scans_ts_brin on tls_cert_scans using brin (ts);
create index if not exists tls_cert_scans_recent  on tls_cert_scans (probe_id, ts desc);

alter table tls_cert_scans enable row level security;
drop policy if exists tls_cert_scans_read on tls_cert_scans;
create policy tls_cert_scans_read on tls_cert_scans for select to authenticated using (true);
grant select on tls_cert_scans to authenticated;
revoke all on tls_cert_scans from anon;

-- ---------------------------------------------------------------- view

create or replace view tls_cert_overview as
with latest as (
    select distinct on (probe_id) * from tls_cert_scans order by probe_id, ts desc
)
select p.id, p.name, p.target, p.category, p.site, p.enabled, p.interval_s,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       l.ts as checked_at, l.subject, l.issuer, l.not_before, l.not_after,
       l.days_remaining, l.chain_valid, l.chain_error
  from probes p
  join probe_state st on st.id = p.id
  left join latest l on l.probe_id = p.id
 where p.kind = 'url' and p.target like 'https://%';

alter view tls_cert_overview set (security_invoker = on);
grant select on tls_cert_overview to authenticated;
revoke all on tls_cert_overview from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('tls_cert_expiring', 'warning',  interval '24 hours',
     'A monitored certificate expires within 14 days'),
    ('tls_cert_invalid',  'critical', interval '6 hours',
     'A monitored certificate is expired or its chain does not validate')
on conflict (rule) do nothing;

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
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from tls_cert_overview
              where checked_at is not null
                and (chain_valid is false or days_remaining <= 14)
    loop
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
            insert into alert_log (agent_id, rule, severity, subject, body, recipients)
            values (null, rule, sev,
                    format('[%s] %s - certificate problem', sev, r.name),
                    format(E'Target: %s\nSubject: %s\nIssuer: %s\n%s',
                           r.target, r.subject, r.issuer, msg),
                    coalesce(people, '{}'));
            update alert_state set last_sent = now()
             where agent_id is null and alert_state.rule = rule || ':' || r.id::text;
            if not found then
                insert into alert_state (agent_id, rule, last_sent)
                values (null, rule || ':' || r.id::text, now());
            end if;
            n := n + 1;
        end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-tls-cert-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-tls-cert-sweep');
select cron.schedule('nodewatch-tls-cert-sweep', '*/5 * * * *', $$select sweep_tls_certs();$$);

select cron.unschedule('nodewatch-tls-cert-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-tls-cert-retention');
select cron.schedule('nodewatch-tls-cert-retention', '20 5 * * *',
    $$delete from tls_cert_scans where ts < now() - interval '180 days';$$);
