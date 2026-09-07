-- 037: supply-chain scanning as a probe kind.
--
-- ForgeGuardian (github.com/Mah3Sec/ForgeGuardian) already does the actual
-- scanning - dependency parsing across nine ecosystems, OSV lookups,
-- malware pattern matching. Reimplementing that would be its own product.
-- What nodewatch adds is the same thing it adds for Postgres or Proxmox:
-- scheduling, history, a dashboard, and alerting on top of a scanner it
-- doesn't own. The probe runner clones the target repo and shells out to
-- fgctl the same way it queries Proxmox's API or a database's DMVs -
-- expected to already be on the probe host, not installed by nodewatch.

alter table probes drop constraint if exists probes_kind_check;
alter table probes add constraint probes_kind_check
    check (kind in ('ping','port','url','postgres','mysql','mssql','oracle',
                     'prometheus','nginx','tomcat','jboss','proxmox','supply_chain'));

-- ---------------------------------------------------------------- scans

-- One row per scan: the rollup a dashboard card reads at a glance.
create table if not exists supply_chain_scans (
    probe_id       uuid        not null references probes (id) on delete cascade,
    ts             timestamptz not null,
    risk_score     integer,
    severity       text check (severity in ('LOW','MEDIUM','HIGH','CRITICAL')),
    recommendation text check (recommendation in ('SAFE','CAUTION','DO_NOT_INSTALL')),
    finding_count  integer not null default 0,
    scan_mode      text,                        -- e.g. "static" (no LLM) vs "full"
    extra          jsonb,
    primary key (probe_id, ts)
);

create index if not exists supply_chain_scans_ts_brin on supply_chain_scans using brin (ts);
create index if not exists supply_chain_scans_recent  on supply_chain_scans (probe_id, ts desc);

alter table supply_chain_scans enable row level security;
drop policy if exists supply_chain_scans_read on supply_chain_scans;
create policy supply_chain_scans_read on supply_chain_scans for select to authenticated using (true);
grant select on supply_chain_scans to authenticated;
revoke all on supply_chain_scans from anon;

-- ---------------------------------------------------------------- findings

-- Current findings, upserted like host_checks - the interesting artifact
-- is what's wrong right now, not a growing log of the same finding
-- reappearing on every scan.
create table if not exists supply_chain_findings (
    probe_id   uuid    not null references probes (id) on delete cascade,
    rule_id    text    not null,
    category   text,
    severity   text,
    message    text,
    location   text,
    confidence real,
    first_seen timestamptz not null default now(),
    last_seen  timestamptz not null default now(),
    primary key (probe_id, rule_id)
);

create index if not exists supply_chain_findings_probe_idx on supply_chain_findings (probe_id);

alter table supply_chain_findings enable row level security;
drop policy if exists supply_chain_findings_read on supply_chain_findings;
create policy supply_chain_findings_read on supply_chain_findings for select to authenticated using (true);
grant select on supply_chain_findings to authenticated;
revoke all on supply_chain_findings from anon;

-- ---------------------------------------------------------------- views

create or replace view supply_chain_overview as
with latest as (
    select distinct on (probe_id) * from supply_chain_scans order by probe_id, ts desc
)
select p.id, p.name, p.target, p.category, p.site, p.enabled, p.interval_s,
       s.host, s.configured,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       l.ts as scanned_at, l.risk_score, l.severity, l.recommendation,
       l.finding_count, l.scan_mode, l.extra
  from probes p
  join probe_state st on st.id = p.id
  left join probe_secret_status s on s.probe_id = p.id
  left join latest l on l.probe_id = p.id
 where p.kind = 'supply_chain';

alter view supply_chain_overview set (security_invoker = on);
grant select on supply_chain_overview to authenticated;
revoke all on supply_chain_overview from anon;

-- ---------------------------------------------------------------- alerting

insert into alert_rules (rule, severity, cooldown, description) values
    ('supply_chain_risk', 'critical', interval '6 hours',
     'A monitored repository scored DO_NOT_INSTALL for supply-chain risk')
on conflict (rule) do nothing;

create or replace function sweep_supply_chain() returns integer
language plpgsql security definer set search_path = public as $$
declare
    r      record;
    people text[];
    n      integer := 0;
    last   timestamptz;
    cd     interval;
begin
    select array_agg(distinct lower(email)) into people
      from alert_recipients where agent_id is null and instant;

    for r in select * from supply_chain_overview
              where recommendation = 'DO_NOT_INSTALL'
    loop
        select cooldown into cd from alert_rules where rule='supply_chain_risk' and enabled;
        select last_sent into last from alert_state
         where agent_id is null and rule = 'supply_chain_risk:' || r.id::text;
        if cd is not null and (last is null or now() - last >= cd) then
            insert into alert_log (agent_id, rule, severity, subject, body, recipients)
            values (null, 'supply_chain_risk', 'critical',
                    format('[critical] %s scored %s for supply-chain risk', r.name, r.risk_score),
                    format(E'Repository: %s\nScore: %s/100 (%s)\nFindings: %s\n\n'
                           'Reviewed via ForgeGuardian. See the Supply Chain page for detail.',
                           r.target, r.risk_score, r.severity, r.finding_count),
                    coalesce(people, '{}'));
            update alert_state set last_sent = now()
             where agent_id is null and rule = 'supply_chain_risk:' || r.id::text;
            if not found then
                insert into alert_state (agent_id, rule, last_sent)
                values (null, 'supply_chain_risk:' || r.id::text, now());
            end if;
            n := n + 1;
        end if;
    end loop;
    return n;
end $$;

select cron.unschedule('nodewatch-supply-chain-sweep')
 where exists (select 1 from cron.job where jobname = 'nodewatch-supply-chain-sweep');
select cron.schedule('nodewatch-supply-chain-sweep', '* * * * *', $$select sweep_supply_chain();$$);

select cron.unschedule('nodewatch-supply-chain-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-supply-chain-retention');
select cron.schedule('nodewatch-supply-chain-retention', '15 5 * * *',
    $$delete from supply_chain_scans where ts < now() - interval '180 days';$$);
