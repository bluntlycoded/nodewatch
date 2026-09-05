-- 032: end-user computing posture.
--
-- Desktops already get the same posture checks as servers, reported
-- through the existing host_checks pipeline - this migration adds no new
-- check_ids server-side because it doesn't need to: screen lock, EDR/AV
-- presence, remote-access software, Secure Boot and TPM, and USB storage
-- policy are all new check_ids the agent now reports (agent/os_linux.py,
-- os_windows.py, os_darwin.py), and host_checks is already generic enough
-- to hold them without a schema change.
--
-- What host_checks cannot answer is a fleet-wide question: how many
-- end-user machines have a local admin account. "only root has uid 0" is
-- a per-server pass/fail; "how many of our laptops have one" is a count
-- across the fleet, which needs its own rollup.

create or replace view desktop_admin_summary as
select a.id, a.instance_id,
       coalesce(a.display_name, a.hostname, a.instance_id) as label,
       a.platform, a.site,
       array_agg(u.username order by u.username) filter (where u.sudoer) as admins,
       count(*) filter (where u.sudoer) as admin_count
  from agents a
  join user_state u on u.agent_id = a.id
 where a.role = 'desktop' and a.agent_version is not null
 group by a.id, a.instance_id, a.display_name, a.hostname, a.platform, a.site;

alter view desktop_admin_summary set (security_invoker = on);
grant select on desktop_admin_summary to authenticated;
revoke all on desktop_admin_summary from anon;
