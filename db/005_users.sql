-- 005: local account inventory and add/remove/modify events.
--
-- Same shape as ports: the agent ships a full snapshot, the server derives
-- the change log. An account merely existing is inventory; an account
-- appearing, disappearing, or gaining sudo is an event.

create table if not exists user_state (
    agent_id   uuid        not null references agents (id) on delete cascade,
    username   text        not null,
    uid        integer,
    gid        integer,
    shell      text,
    home       text,
    groups     text[]      not null default '{}',
    sudoer     boolean     not null default false,
    can_login  boolean     not null default false,
    password   text,
    first_seen timestamptz not null default now(),
    last_seen  timestamptz not null default now(),
    primary key (agent_id, username)
);

comment on column user_state.password is
    'State only - none / locked / set / unknown. No hash is ever collected or transmitted.';

create index if not exists user_state_priv_idx on user_state (agent_id)
    where sudoer or uid = 0;

create table if not exists user_events (
    id       bigserial   primary key,
    agent_id uuid        not null references agents (id) on delete cascade,
    ts       timestamptz not null default now(),
    username text        not null,
    action   text        not null check (action in ('added','removed','modified')),
    uid      integer,
    sudoer   boolean     not null default false,
    detail   text
);

create index if not exists user_events_ts_brin      on user_events using brin (ts);
create index if not exists user_events_agent_ts_idx on user_events (agent_id, ts desc);

alter table user_state  enable row level security;
alter table user_events enable row level security;

drop policy if exists user_state_read  on user_state;
drop policy if exists user_events_read on user_events;
create policy user_state_read  on user_state  for select to authenticated using (true);
create policy user_events_read on user_events for select to authenticated using (true);

revoke all on user_state, user_events from anon;

-- ---------------------------------------------------------------- trust v3

-- Churn now covers account change as well as port exposure. A host that
-- gained a new sudo account in the last day is less trustworthy than one
-- whose account set has been stable, independent of whether any
-- configuration check failed.
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
        (select count(*) from user_events u
          where u.agent_id = a.id
            and u.ts > now() - interval '24 hours')              as account_changes_24h,
        (select count(*) from user_events u
          where u.agent_id = a.id and u.sudoer
            and u.action in ('added','modified')
            and u.ts > now() - interval '24 hours')              as priv_changes_24h,
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
        -- A privileged account change weighs double a port opening.
        1.0 / (1 + 0.5 * new_exposure_24h
                 + 0.3 * account_changes_24h
                 + 1.0 * priv_changes_24h)                 as f_churn,
        posture                                            as f_posture
    from base
)
select
    id, instance_id, hostname, os, region, agent_version, last_seen,
    age_s::int as seconds_since_seen,
    external_ports,
    failed_1h  as failed_logins_1h,
    new_exposure_24h,
    account_changes_24h,
    priv_changes_24h,
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

alter view agent_trust set (security_invoker = on);
grant select on agent_trust to authenticated;
revoke all on agent_trust from anon;
