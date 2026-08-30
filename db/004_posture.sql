-- 004: host posture checks (SCA-style config hardening + account anomalies)
-- and their integration into the trust score as a fifth factor.

create table if not exists host_checks (
    agent_id     uuid        not null references agents (id) on delete cascade,
    check_id     text        not null,
    title        text        not null,
    category     text        not null,
    severity     text        not null check (severity in ('high','medium','low')),
    status       text        not null check (status in ('pass','fail','error')),
    detail       text,
    first_seen   timestamptz not null default now(),
    last_seen    timestamptz not null default now(),
    last_changed timestamptz not null default now(),
    primary key (agent_id, check_id)
);

comment on column host_checks.last_changed is
    'Updated only when status flips, so "this host started failing 10 minutes ago" is answerable.';

create index if not exists host_checks_failing_idx
    on host_checks (agent_id, severity) where status = 'fail';

alter table host_checks enable row level security;
drop policy if exists host_checks_read on host_checks;
create policy host_checks_read on host_checks
    for select to authenticated using (true);
revoke all on host_checks from anon;

-- ---------------------------------------------------------------- posture

-- Weighted pass rate. A failing high-severity check costs three times a
-- failing low one. Checks that errored are excluded from the denominator
-- rather than counted as failures: "could not evaluate" is not "insecure".
create or replace view agent_posture as
select
    a.id as agent_id,
    count(*) filter (where c.status <> 'error')                  as evaluated,
    count(*) filter (where c.status = 'pass')                    as passed,
    count(*) filter (where c.status = 'fail')                    as failed,
    count(*) filter (where c.status = 'fail' and c.severity = 'high') as failed_high,
    count(*) filter (where c.status = 'error')                   as errored,
    coalesce(
        sum(case when c.status = 'pass' then
            case c.severity when 'high' then 3 when 'medium' then 2 else 1 end
        else 0 end)::numeric
        / nullif(sum(case when c.status <> 'error' then
            case c.severity when 'high' then 3 when 'medium' then 2 else 1 end
        else 0 end), 0),
    1.0)                                                          as score
from agents a
left join host_checks c on c.agent_id = a.id
group by a.id;

alter view agent_posture set (security_invoker = on);
grant select on agent_posture to authenticated;
revoke all on agent_posture from anon;

-- ---------------------------------------------------------------- trust v2

-- create-or-replace cannot change a view's column list, so drop first.
drop view if exists agent_trust;
create view agent_trust as
with base as (
    select
        a.id, a.instance_id, a.hostname, a.os, a.region, a.agent_version, a.last_seen,
        extract(epoch from (now() - a.last_seen)) as age_s,
        (select count(*) from port_state p
          where p.agent_id = a.id and p.external)                as external_ports,
        (select count(*) from auth_events e
          where e.agent_id = a.id and e.kind = 'login_failed'
            and e.ts > now() - interval '1 hour')                as failed_1h,
        (select count(*) from port_events v
          where v.agent_id = a.id and v.action = 'opened' and v.external
            and v.ts > now() - interval '24 hours')              as new_exposure_24h,
        coalesce((select score from agent_posture q where q.agent_id = a.id), 1.0)::float as posture,
        coalesce((select failed from agent_posture q where q.agent_id = a.id), 0)      as checks_failed,
        coalesce((select failed_high from agent_posture q where q.agent_id = a.id), 0) as checks_failed_high
    from agents a
),
factors as (
    select *,
        greatest(0, least(1, (300 - age_s) / 255.0))       as f_recency,
        1.0 / (1 + 0.25 * greatest(0, external_ports - 1)) as f_exposure,
        1.0 / (1 + 0.5 * failed_1h)                        as f_auth,
        1.0 / (1 + 0.5 * new_exposure_24h)                 as f_churn,
        posture                                            as f_posture
    from base
)
select
    id, instance_id, hostname, os, region, agent_version, last_seen,
    age_s::int      as seconds_since_seen,
    external_ports,
    failed_1h       as failed_logins_1h,
    new_exposure_24h,
    checks_failed,
    checks_failed_high,

    case
        when age_s < 45  then 'healthy'
        when age_s < 180 then 'degraded'
        else 'down'
    end as status,

    round(f_recency::numeric,  3) as f_recency,
    round(f_exposure::numeric, 3) as f_exposure,
    round(f_auth::numeric,     3) as f_auth,
    round(f_churn::numeric,    3) as f_churn,
    round(f_posture::numeric,  3) as f_posture,

    -- Recency multiplies rather than adds: posture only counts if the host
    -- is still reporting. A clean configuration seen four minutes ago is
    -- not evidence about the host now.
    round(100 * f_recency * (
        0.22 * f_exposure +
        0.33 * f_auth +
        0.15 * f_churn +
        0.30 * f_posture
    )::numeric)::int as trust,

    case
        when 100 * f_recency * (0.22*f_exposure + 0.33*f_auth
                              + 0.15*f_churn + 0.30*f_posture) < 70
        then true else false
    end as needs_reverification
from factors;

comment on view agent_trust is
    'Continuous trust per agent from recency, port exposure, authentication pressure, exposure churn and configuration posture. Components are exposed alongside the total so any score is explainable.';

alter view agent_trust set (security_invoker = on);
grant select on agent_trust to authenticated;
revoke all on agent_trust from anon;
