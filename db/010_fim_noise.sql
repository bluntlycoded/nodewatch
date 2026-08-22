-- 010: retire the snapd unit-file false positives.
--
-- snapd rewrites its generated mount units on every refresh, with the
-- snap revision in the filename. /etc/systemd/system is a critical path
-- because that is where persistence is installed, so ordinary snap
-- churn was being reported as tampering. The agent now excludes the
-- machine-generated naming pattern; this cleans up what already landed.

-- Reclassify historical events so the trust factor stops counting them.
update fim_events
   set critical = false
 where critical
   and (path ~ '^/etc/systemd/system/(.*\.wants/)?snap[-.].*-\d+\.mount$'
     or path ~ '^/etc/systemd/system/snapd\.mounts(-pre)?\.target\.wants/.*\.mount$'
     or path ~ '^/etc/ssl/certs/[0-9a-f]{8}\.\d+$');

-- Close the alerts they raised. Resolved rather than deleted: the record
-- of what fired and why is the point of the log.
update alert_log
   set resolved_at     = coalesce(resolved_at, now()),
       acknowledged_at = coalesce(acknowledged_at, now()),
       note            = coalesce(note, 'False positive: snapd regenerates these unit files on every snap refresh. Agent updated to exclude the generated naming pattern.')
 where rule = 'critical_file'
   and resolved_at is null
   and (subject like '%snap-%' or subject like '%snapd.mounts%');

-- A burst of file changes should produce one email, not one per file.
-- Ten minutes still alerts immediately on the first change; the rest are
-- in the dashboard and the digest.
update alert_rules set cooldown = interval '10 minutes' where rule = 'critical_file';
