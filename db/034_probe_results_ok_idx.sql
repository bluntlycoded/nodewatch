-- 034: index probe_results for filtering by ok.
--
-- 033 rewrote probe_state's consecutive-streak calculation to avoid a
-- correlated subquery filtered on ok, which is what made it quadratic in
-- the first place. This index isn't needed for that query any more, but
-- probe_results had nothing covering ok at all - anything else that ever
-- needs "this probe's rows where ok = X" (a manual query, a future
-- report, the old query pattern if it's ever reintroduced) would hit the
-- same class of full-scan-per-lookup problem. Cheap to have now rather
-- than rediscovering the same bug from a different angle later.

create index if not exists probe_results_probe_ok_ts_idx
    on probe_results (probe_id, ok, ts);
