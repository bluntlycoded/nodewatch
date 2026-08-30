-- 003: continuous trust scoring.
--
-- Every input is already collected; nothing new ships from the agent.
-- The score is a view, not a column: it is recomputed on read, so it can
-- never go stale and there is no path by which a dead agent keeps a good
-- score.
--
-- Four factors, each normalised to 0..1 and reported alongside the total
-- so the score is explainable rather than a black box. A host does not
-- just score 61 — it scores 61 *because* auth pressure is 0.33.

create or replace view agent_trust as
with base as (
    select
        a.id,
        a.instance_id,
        a.hostname,
        a.os,
        a.region,
        a.agent_version,
        a.last_seen,
        extract(epoch from (now() - a.last_seen)) as age_s,

        (select count(*) from port_state p
          where p.agent_id = a.id and p.external)                as external_ports,

        (select count(*) from auth_events e
          where e.agent_id = a.id and e.kind = 'login_failed'
            and e.ts > now() - interval '1 hour')                as failed_1h,

        (select count(*) from port_events v
          where v.agent_id = a.id and v.action = 'opened'
            and v.external
            and v.ts > now() - interval '24 hours')              as new_exposure_24h
    from agents a
),
factors as (
    select *,
        -- Recency: full marks inside one heartbeat interval, decaying to
        -- zero at five minutes. This is the trust-decay term.
        greatest(0, least(1, (300 - age_s) / 255.0))              as f_recency,

        -- Exposure: one externally-bound port (sshd) is expected. Each
        -- additional one erodes trust with diminishing weight.
        1.0 / (1 + 0.25 * greatest(0, external_ports - 1))         as f_exposure,

        -- Auth pressure: failed sign-ins in the last hour.
        1.0 / (1 + 0.5 * failed_1h)                                as f_auth,

        -- Churn: newly exposed ports are more suspicious than long-standing
        -- ones, so recent openings are penalised separately from the count.
        1.0 / (1 + 0.5 * new_exposure_24h)                         as f_churn
    from base
)
select
    id, instance_id, hostname, os, region, agent_version, last_seen,
    age_s::int                                       as seconds_since_seen,
    external_ports, failed_1h                        as failed_logins_1h,
    new_exposure_24h,

    case
        when age_s < 45  then 'healthy'
        when age_s < 180 then 'degraded'
        else 'down'
    end                                              as status,

    round(f_recency::numeric,  3) as f_recency,
    round(f_exposure::numeric, 3) as f_exposure,
    round(f_auth::numeric,     3) as f_auth,
    round(f_churn::numeric,    3) as f_churn,

    -- Recency multiplies rather than adds. Posture only counts if the host
    -- is still talking to us: a clean configuration reported four minutes
    -- ago is not evidence about the host now. This is the decay term, and
    -- making it a gate is what stops a silent host from coasting on an old
    -- good score.
    round(100 * f_recency * (
        0.30 * f_exposure +
        0.45 * f_auth +
        0.25 * f_churn
    )::numeric)::int                                 as trust,

    -- Below 70 the host should be challenged rather than trusted on the
    -- strength of its last handshake.
    case
        when 100 * f_recency * (0.30*f_exposure + 0.45*f_auth
                              + 0.25*f_churn) < 70
        then true else false
    end                                              as needs_reverification
from factors;

comment on view agent_trust is
    'Continuous trust score per agent. Derived on read from recency, port exposure, authentication pressure and exposure churn. Components are exposed alongside the total so any score can be explained.';

alter view agent_trust set (security_invoker = on);
grant select on agent_trust to authenticated;
revoke all on agent_trust from anon;
