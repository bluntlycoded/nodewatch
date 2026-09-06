-- 036: remaining unindexed foreign keys, and retention for pg_cron's own log.
--
-- None of these tables are large yet, but an unindexed foreign key means
-- every join against it and every ON DELETE CASCADE check is a
-- sequential scan - cheap to fix now, expensive to rediscover later once
-- one of them has grown the way audit_log did.

create index if not exists alert_recipients_agent_idx on alert_recipients (agent_id);
create index if not exists alert_state_agent_idx       on alert_state (agent_id);
create index if not exists alert_channels_agent_idx    on alert_channels (agent_id);
create index if not exists alert_deliveries_channel_idx on alert_deliveries (channel_id);
create index if not exists service_components_agent_idx on service_components (agent_id);
create index if not exists service_components_probe_idx on service_components (probe_id);
create index if not exists ip_addresses_agent_idx      on ip_addresses (agent_id);
create index if not exists automation_runs_alert_idx   on automation_runs (alert_id);
create index if not exists automation_runs_service_idx on automation_runs (service_id);

-- pg_cron logs every run of every job to cron.job_run_details and never
-- prunes it itself. With roughly ten jobs firing every minute, that is
-- on the order of 14,000 rows a day - already 64MB with no retention at
-- all. This is execution history for diagnosing a stuck job, not data
-- anyone needs long-term, so a short window is enough.
select cron.unschedule('nodewatch-cron-log-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-cron-log-retention');
select cron.schedule('nodewatch-cron-log-retention', '45 5 * * *',
    $$delete from cron.job_run_details where end_time < now() - interval '7 days';$$);
