-- 008: file integrity monitoring, package inventory, and trust history.

-- ---------------------------------------------------------------- fim

create table if not exists fim_state (
    agent_id       uuid        not null references agents (id) on delete cascade,
    files_watched  integer     not null default 0,
    digest         text,
    paths          text[]      not null default '{}',
    last_scan      timestamptz not null default now(),
    primary key (agent_id)
);

comment on column fim_state.digest is
    'Fingerprint of the agent''s whole manifest. Lets the server notice divergence and request a full resync.';

create table if not exists fim_events (
    id       bigserial   primary key,
    agent_id uuid        not null references agents (id) on delete cascade,
    ts       timestamptz not null default now(),
    path     text        not null,
    action   text        not null check (action in ('added','modified','deleted')),
    critical boolean     not null default false,
    sha256   text,
    mode     text,
    size     bigint,
    detail   text
);

comment on column fim_events.critical is
    'Set for files an attacker would edit - sudoers, shadow, sshd_config, cron, pam. Weighted far above ordinary /etc churn.';

create index if not exists fim_events_ts_brin      on fim_events using brin (ts);
create index if not exists fim_events_agent_ts_idx on fim_events (agent_id, ts desc);
create index if not exists fim_events_critical_idx on fim_events (agent_id, ts desc) where critical;

-- ---------------------------------------------------------------- packages

create table if not exists host_packages (
    agent_id   uuid        not null references agents (id) on delete cascade,
    name       text        not null,
    version    text        not null,
    arch       text,
    first_seen timestamptz not null default now(),
    last_seen  timestamptz not null default now(),
    primary key (agent_id, name)
);

create index if not exists host_packages_nv_idx on host_packages (name, version);

-- Vulnerability findings, resolved server-side against OSV. Cached by
-- (name, version) so one lookup covers every host running that package.
create table if not exists package_vulns (
    name        text        not null,
    version     text        not null,
    vuln_id     text        not null,
    aliases     text[]      not null default '{}',
    severity    text        not null default 'unknown'
                check (severity in ('critical','high','medium','low','unknown')),
    summary     text,
    fixed_in    text,
    checked_at  timestamptz not null default now(),
    primary key (name, version, vuln_id)
);

-- Records that a (name, version) pair has been looked up, including when
-- the answer was "nothing known". Without this the server would re-query
-- OSV forever for clean packages.
create table if not exists package_scan_state (
    name       text not null,
    version    text not null,
    checked_at timestamptz not null default now(),
    vuln_count integer not null default 0,
    primary key (name, version)
);

create or replace view agent_vulns as
select
    p.agent_id,
    count(*)                                                  as total,
    count(*) filter (where v.severity = 'critical')           as critical,
    count(*) filter (where v.severity = 'high')               as high,
    count(*) filter (where v.severity in ('critical','high')) as severe
from host_packages p
join package_vulns v on v.name = p.name and v.version = p.version
group by p.agent_id;

-- ---------------------------------------------------------------- trust history

-- Trust is computed on read, so it leaves no trace over time. Sampling it
-- on a schedule is what makes the decay model visible rather than a
-- momentary number.
create table if not exists trust_history (
    agent_id   uuid        not null references agents (id) on delete cascade,
    ts         timestamptz not null default now(),
    trust      integer,
    status     text,
    f_recency  real,
    f_exposure real,
    f_auth     real,
    f_churn    real,
    f_posture  real,
    f_integrity real,
    primary key (agent_id, ts)
);

create index if not exists trust_history_ts_brin on trust_history using brin (ts);

-- ---------------------------------------------------------------- rls

alter table fim_state          enable row level security;
alter table fim_events         enable row level security;
alter table host_packages      enable row level security;
alter table package_vulns      enable row level security;
alter table package_scan_state enable row level security;
alter table trust_history      enable row level security;

do $$
declare t text;
begin
    foreach t in array array['fim_state','fim_events','host_packages',
                             'package_vulns','package_scan_state','trust_history']
    loop
        execute format('drop policy if exists %I on %I', t || '_read', t);
        execute format('create policy %I on %I for select to authenticated using (true)', t || '_read', t);
        execute format('grant select on %I to authenticated', t);
        execute format('revoke all on %I from anon', t);
    end loop;
end $$;

-- ---------------------------------------------------------------- trust v4

drop view if exists agent_overview;
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
        (select count(*) from fim_events f
          where f.agent_id = a.id
            and f.ts > now() - interval '24 hours')              as file_changes_24h,
        (select count(*) from fim_events f
          where f.agent_id = a.id and f.critical
            and f.ts > now() - interval '24 hours')              as critical_file_changes_24h,
        coalesce((select score from agent_posture q where q.agent_id = a.id), 1.0)::float as posture,
        coalesce((select failed from agent_posture q where q.agent_id = a.id), 0)      as checks_failed,
        coalesce((select failed_high from agent_posture q where q.agent_id = a.id), 0) as checks_failed_high,
        coalesce((select severe from agent_vulns v where v.agent_id = a.id), 0)        as vulns_severe,
        coalesce((select total  from agent_vulns v where v.agent_id = a.id), 0)        as vulns_total
    from agents a
),
factors as (
    select *,
        greatest(0, least(1, (300 - age_s) / 255.0))       as f_recency,
        1.0 / (1 + 0.25 * greatest(0, external_ports - 1)) as f_exposure,
        1.0 / (1 + 0.5 * failed_1h)                        as f_auth,
        1.0 / (1 + 0.5 * new_exposure_24h
                 + 0.3 * account_changes_24h
                 + 1.0 * priv_changes_24h)                 as f_churn,
        posture                                            as f_posture,
        -- A change under /etc/sudoers.d or to sshd_config weighs ten times
        -- an ordinary /etc edit. Routine config churn should barely move
        -- the score; an edit to the files an attacker targets should.
        1.0 / (1 + 0.05 * file_changes_24h
                 + 0.50 * critical_file_changes_24h
                 + 0.10 * vulns_severe)                    as f_integrity
    from base
)
select
    id, instance_id, hostname, os, region, agent_version, last_seen,
    age_s::int as seconds_since_seen,
    external_ports, failed_1h as failed_logins_1h, new_exposure_24h,
    account_changes_24h, priv_changes_24h,
    file_changes_24h, critical_file_changes_24h,
    checks_failed, checks_failed_high, vulns_total, vulns_severe,

    case when age_s < 45 then 'healthy'
         when age_s < 180 then 'degraded'
         else 'down' end as status,

    round(f_recency::numeric,3)   as f_recency,
    round(f_exposure::numeric,3)  as f_exposure,
    round(f_auth::numeric,3)      as f_auth,
    round(f_churn::numeric,3)     as f_churn,
    round(f_posture::numeric,3)   as f_posture,
    round(f_integrity::numeric,3) as f_integrity,

    round(100 * f_recency * (
        0.18 * f_exposure +
        0.26 * f_auth +
        0.13 * f_churn +
        0.23 * f_posture +
        0.20 * f_integrity
    )::numeric)::int as trust,

    case when 100 * f_recency * (0.18*f_exposure + 0.26*f_auth + 0.13*f_churn
                               + 0.23*f_posture + 0.20*f_integrity) < 70
         then true else false end as needs_reverification
from factors;

alter view agent_trust set (security_invoker = on);
grant select on agent_trust to authenticated;
revoke all on agent_trust from anon;

-- Pending nodes have no telemetry; reporting them as down or scoring them
-- would both be wrong.
create view agent_overview as
select
    o.id, o.instance_id, o.hostname, o.os, o.region, o.agent_version, o.last_seen,
    o.seconds_since_seen, o.external_ports, o.failed_logins_1h, o.new_exposure_24h,
    o.account_changes_24h, o.priv_changes_24h, o.file_changes_24h,
    o.critical_file_changes_24h, o.checks_failed, o.checks_failed_high,
    o.vulns_total, o.vulns_severe,
    o.f_recency, o.f_exposure, o.f_auth, o.f_churn, o.f_posture, o.f_integrity,
    case when o.agent_version is null then 'pending' else o.status end as status,
    case when o.agent_version is null then null      else o.trust  end as trust,
    case when o.agent_version is null then false else o.needs_reverification end as needs_reverification,
    o.display_name, o.notes, o.muted, o.label, o.recipient_count, o.last_alert_at,
    o.files_watched, o.package_count
from (
    select t.*, a.display_name, a.notes, a.muted,
           coalesce(a.display_name, t.hostname, t.instance_id) as label,
           (select count(*) from alert_recipients r
             where r.agent_id = t.id or r.agent_id is null)    as recipient_count,
           (select max(created_at) from alert_log l where l.agent_id = t.id) as last_alert_at,
           (select files_watched from fim_state f where f.agent_id = t.id)   as files_watched,
           (select count(*) from host_packages p where p.agent_id = t.id)    as package_count
      from agent_trust t join agents a on a.id = t.id
) o;

alter view agent_overview set (security_invoker = on);
grant select on agent_overview to authenticated;
revoke all on agent_overview from anon;

-- ---------------------------------------------------------------- alerts

insert into alert_rules (rule, severity, cooldown, description) values
    ('critical_file', 'critical', interval '0 minutes',
     'A security-critical file was added, modified or deleted'),
    ('file_churn',    'warning',  interval '1 hour',
     'Unusual volume of file changes under a watched path')
on conflict (rule) do nothing;

create or replace function alert_on_fim_event() returns trigger as $$
declare label text;
begin
    if new.critical then
        select coalesce(display_name, hostname, instance_id) into label
          from agents where id = new.agent_id;
        perform queue_alert(new.agent_id, 'critical_file',
            format('[critical] %s was %s on %s', new.path, new.action, label),
            format(E'Path: %s\nAction: %s\nDetail: %s\nSHA-256: %s\n\n'
                   'This file governs authentication, privilege or scheduled '
                   'execution. If you did not make this change, treat the host '
                   'as compromised.',
                   new.path, new.action, coalesce(new.detail,''),
                   coalesce(new.sha256,'n/a')));
    end if;
    return new;
end $$ language plpgsql security definer;

drop trigger if exists fim_event_alert on fim_events;
create trigger fim_event_alert after insert on fim_events
    for each row execute function alert_on_fim_event();

-- ---------------------------------------------------------------- history job

create or replace function snapshot_trust() returns integer as $$
declare n integer;
begin
    insert into trust_history (agent_id, ts, trust, status,
                               f_recency, f_exposure, f_auth, f_churn, f_posture, f_integrity)
    select id, date_trunc('minute', now()), trust, status,
           f_recency, f_exposure, f_auth, f_churn, f_posture, f_integrity
      from agent_overview
     where agent_version is not null
    on conflict (agent_id, ts) do nothing;
    get diagnostics n = row_count;
    return n;
end $$ language plpgsql security definer;

select cron.unschedule('nodewatch-trust-history')
 where exists (select 1 from cron.job where jobname='nodewatch-trust-history');
select cron.schedule('nodewatch-trust-history', '*/5 * * * *', $$select snapshot_trust();$$);

select cron.unschedule('nodewatch-history-retention')
 where exists (select 1 from cron.job where jobname='nodewatch-history-retention');
select cron.schedule('nodewatch-history-retention', '40 4 * * *',
    $$delete from trust_history where ts < now() - interval '30 days';
      delete from fim_events    where ts < now() - interval '90 days';$$);
