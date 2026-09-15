-- 039: container/registry image scanning as a second supply_chain scan
-- target, alongside the existing git-repo mode.
--
-- Same tables, same view, same alert rule as 037 - a scan is a scan
-- regardless of whether the target was a git URL cloned and handed to
-- fgctl, or a container image reference handed to grype directly. Only
-- the probe-side logic differs (see probe/prober.py); the schema just
-- needs to say which kind of target produced a given row, since a repo
-- and an image aren't comparable "the same finding recurring" for the
-- upsert-by-rule_id logic in supply_chain_findings to make sense across.

alter table supply_chain_scans
    add column if not exists target_kind text not null default 'repo'
        check (target_kind in ('repo', 'image'));

comment on column supply_chain_scans.target_kind is
    'repo: probes.target is a git clone URL, scanned with fgctl. image: probes.target is a container image reference, scanned with grype.';

-- create or replace view only allows appending columns, not reordering or
-- removing - target_kind goes at the end, same constraint that applies to
-- every other view already using create or replace in this codebase.
create or replace view supply_chain_overview as
with latest as (
    select distinct on (probe_id) * from supply_chain_scans order by probe_id, ts desc
)
select p.id, p.name, p.target, p.category, p.site, p.enabled, p.interval_s,
       s.host, s.configured,
       st.status, st.last_check, st.latency_ms, st.detail, st.consecutive,
       l.ts as scanned_at, l.risk_score, l.severity, l.recommendation,
       l.finding_count, l.scan_mode, l.extra, l.target_kind
  from probes p
  join probe_state st on st.id = p.id
  left join probe_secret_status s on s.probe_id = p.id
  left join latest l on l.probe_id = p.id
 where p.kind = 'supply_chain';

alter view supply_chain_overview set (security_invoker = on);
grant select on supply_chain_overview to authenticated;
revoke all on supply_chain_overview from anon;
