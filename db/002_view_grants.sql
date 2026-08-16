-- 002: expose the derived views to the dashboard.
-- Postgres views default to the *owner's* privileges, which would bypass the
-- RLS we set up in 001. security_invoker forces the caller's own policies.

alter view agent_health          set (security_invoker = on);
alter view agent_latest_metrics  set (security_invoker = on);

grant select on agent_health         to authenticated;
grant select on agent_latest_metrics to authenticated;

revoke all on agent_health         from anon;
revoke all on agent_latest_metrics from anon;
