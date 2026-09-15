-- One-shot DB health check. Paste the whole thing into the Supabase SQL
-- editor and paste the JSON result back. Read-only - nothing here writes.
--
-- Covers what a schema review alone can't: live table/index bloat, actual
-- index usage (are the indexes migrations 033-041 added even being used),
-- FK columns still missing a covering index anywhere in the schema (not
-- just the tables touched recently), cron job health, and slow-query
-- candidates via pg_stat_statements if it's enabled.

with fk_missing_index as (
    -- Every FK column, and whether a btree/brin index actually leads with
    -- it. A FK with no covering index means every delete/update on the
    -- referenced table does a sequential scan of the referencing table to
    -- check for orphans - this is exactly the bug class migration 036
    -- fixed; this re-checks the whole schema, not just what 036 touched.
    select
        con.conrelid::regclass::text as table_name,
        att.attname as fk_column,
        confrelid::regclass::text as references_table
    from pg_constraint con
    join pg_attribute att
      on att.attrelid = con.conrelid and att.attnum = con.conkey[1]
    where con.contype = 'f'
      and array_length(con.conkey, 1) = 1
      and not exists (
          select 1 from pg_index idx
          where idx.indrelid = con.conrelid
            and idx.indkey[0] = con.conkey[1]
      )
),
table_bloat as (
    select
        schemaname || '.' || relname as table_name,
        n_live_tup, n_dead_tup,
        round(100.0 * n_dead_tup / nullif(n_live_tup + n_dead_tup, 0), 1) as dead_pct,
        last_autovacuum, last_vacuum,
        pg_size_pretty(pg_total_relation_size(schemaname || '.' || relname)) as total_size
    from pg_stat_user_tables
    where n_live_tup + n_dead_tup > 1000
    order by n_dead_tup desc
    limit 15
),
unused_indexes as (
    -- Indexes that have never been used for a read. Each one still costs
    -- write overhead on every insert/update to the table it's on -
    -- worth knowing about even if none turn out to be worth dropping.
    select
        schemaname || '.' || relname as table_name,
        indexrelname as index_name,
        pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
        idx_scan as times_used
    from pg_stat_user_indexes
    where idx_scan = 0
      and indexrelname not like '%_pkey'
    order by pg_relation_size(indexrelid) desc
    limit 15
),
largest_tables as (
    select
        schemaname || '.' || relname as table_name,
        pg_size_pretty(pg_total_relation_size(schemaname || '.' || relname)) as total_size,
        pg_size_pretty(pg_relation_size(schemaname || '.' || relname)) as table_size,
        pg_size_pretty(pg_indexes_size(schemaname || '.' || relname)) as index_size,
        n_live_tup as row_estimate
    from pg_stat_user_tables
    order by pg_total_relation_size(schemaname || '.' || relname) desc
    limit 15
),
cron_health as (
    select
        j.jobname,
        j.schedule,
        j.active,
        max(d.start_time) as last_run,
        count(*) filter (where d.status = 'failed' and d.start_time > now() - interval '7 days') as failures_7d,
        round(avg(extract(epoch from (d.end_time - d.start_time)))
              filter (where d.start_time > now() - interval '7 days'), 2) as avg_seconds_7d
    from cron.job j
    left join cron.job_run_details d on d.jobid = j.jobid
    group by j.jobname, j.schedule, j.active
    order by failures_7d desc, j.jobname
),
long_running_now as (
    select pid, now() - query_start as running_for, state,
           left(query, 200) as query_snippet
    from pg_stat_activity
    where state != 'idle'
      and query_start < now() - interval '5 seconds'
      and pid != pg_backend_pid()
    order by running_for desc
),
top_slow_queries as (
    -- Requires the pg_stat_statements extension (Supabase enables it by
    -- default on most projects). If this errors with "relation
    -- pg_stat_statements does not exist", delete this CTE and its entry
    -- in the final json_build_object below and rerun - the rest of the
    -- check does not depend on it.
    select
        left(query, 200) as query_snippet,
        calls,
        round(total_exec_time::numeric, 1) as total_ms,
        round(mean_exec_time::numeric, 1) as avg_ms,
        round((100 * total_exec_time / sum(total_exec_time) over ())::numeric, 1) as pct_of_total
    from pg_stat_statements
    where query not ilike '%pg_stat_statements%'
    order by total_exec_time desc
    limit 15
)
select json_build_object(
    'fk_missing_index',  (select json_agg(fk_missing_index)  from fk_missing_index),
    'table_bloat',       (select json_agg(table_bloat)       from table_bloat),
    'unused_indexes',    (select json_agg(unused_indexes)    from unused_indexes),
    'largest_tables',    (select json_agg(largest_tables)    from largest_tables),
    'cron_health',       (select json_agg(cron_health)       from cron_health),
    'long_running_now',  (select json_agg(long_running_now)  from long_running_now),
    'top_slow_queries',  (select coalesce(json_agg(top_slow_queries), '[]'::json)
                            from top_slow_queries)
) as health_check;
