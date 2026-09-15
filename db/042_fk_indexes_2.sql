-- 042: two more FK columns with no covering index, found by
-- db/diagnostics/db_health_check.sql - same bug class migration 036
-- fixed, on tables added after that pass (027, 028). Both are the
-- second column of a composite primary key, so the PK's own index
-- doesn't cover a lookup on this column alone: deleting a row from
-- escalation_steps or services currently forces a full scan of the
-- referencing table to check for orphans.

create index if not exists alert_escalations_step_idx
    on alert_escalations (step_id);

create index if not exists service_dependencies_depends_on_idx
    on service_dependencies (depends_on);
