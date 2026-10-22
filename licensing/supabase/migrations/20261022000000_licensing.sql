-- The vendor's licence server: which licences exist, which machine each is
-- active on, and everything that happened to them.
--
-- Everything lives in the private schema "licensing". It is not exposed
-- through the Supabase REST API; only the licensing Edge Function reaches
-- it, over a direct database connection. The rules that must hold under
-- concurrent requests (one active machine per licence, the yearly move
-- limit) are enforced here, in single transactions.

create schema if not exists licensing;
revoke all on schema licensing from public;
do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    execute 'revoke all on schema licensing from anon, authenticated';
  end if;
end $$;

create table licensing.licences (
  id             uuid primary key,              -- the key's "lid"
  customer       text not null,
  email          text not null default '',
  nodes          int  not null check (nodes > 0),
  features       text[] not null default '{}',
  issued         date not null,
  expires        date not null,
  key            text not null,                 -- the current signed key; replaced on renewal
  moves_per_year int  not null default 3 check (moves_per_year >= 0),
  notes          text not null default '',
  -- 'admin': issued from the admin page. 'external': issued offline with
  -- tools/license_tool.py and first seen when a master activated it.
  source         text not null default 'admin' check (source in ('admin', 'external')),
  revoked_at     timestamptz,
  revoked_reason text not null default '',
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);

create table licensing.activations (
  id              uuid primary key default gen_random_uuid(),
  lid             uuid not null references licensing.licences(id) on delete cascade,
  machine_id      text not null,
  machine_name    text not null default '',
  version         text not null default '',
  method          text not null check (method in ('online', 'offline')),
  activated_at    timestamptz not null default now(),
  last_seen_at    timestamptz,
  released_at     timestamptz,
  released_reason text check (released_reason in ('moved', 'admin'))
);
-- A licence is active on at most one machine at a time.
create unique index activations_one_active on licensing.activations (lid) where released_at is null;
create index activations_by_lid on licensing.activations (lid, activated_at desc);

create table licensing.events (
  id     bigint generated always as identity primary key,
  lid    uuid references licensing.licences(id) on delete cascade,
  at     timestamptz not null default now(),
  actor  text not null,                         -- 'master', 'offline page', or an admin's email
  kind   text not null,
  detail jsonb not null default '{}'
);
create index events_by_lid on licensing.events (lid, at desc);

-- Who may use the admin page: Supabase Auth users with these emails.
create table licensing.admins (
  email    text primary key check (email = lower(email)),
  added_at timestamptz not null default now()
);


-- Activate a licence on a machine. The Edge Function has already checked
-- the key's signature and passes its payload; a key issued offline with
-- license_tool.py is registered here the first time it is seen.
--
-- Same machine again: succeeds and changes nothing. Another machine while
-- the licence is active elsewhere: moves it there if p_allow_move and the
-- yearly limit allows, releasing the old machine (which learns at its next
-- check-in). Returns {ok, code, message, ...} - never raises for a
-- customer-facing refusal.
create or replace function licensing.activate(
  p_lid uuid, p_customer text, p_nodes int, p_features text[], p_issued date, p_expires date,
  p_key text, p_machine text, p_name text, p_version text, p_method text, p_allow_move boolean,
  p_actor text
) returns jsonb
language plpgsql as $$
declare
  l     licensing.licences;
  cur   licensing.activations;
  moved int;
  moved_from text;
begin
  -- First sight of a key issued offline: register it. "on conflict do
  -- nothing" so two masters activating the same new key at once cannot
  -- both try to insert it.
  insert into licensing.licences (id, customer, nodes, features, issued, expires, key, source)
  values (p_lid, p_customer, p_nodes, coalesce(p_features, '{}'), p_issued, p_expires, p_key, 'external')
  on conflict (id) do nothing;
  if found then
    insert into licensing.events (lid, actor, kind, detail)
    values (p_lid, p_actor, 'registered', jsonb_build_object('customer', p_customer));
  end if;
  select * into l from licensing.licences where id = p_lid for update;

  if l.revoked_at is not null then
    return jsonb_build_object('ok', false, 'code', 'revoked',
      'message', 'This licence has been revoked' || coalesce(nullif(': ' || l.revoked_reason, ': '), '')
                 || '. Contact your supplier.');
  end if;

  select * into cur from licensing.activations where lid = p_lid and released_at is null;
  if found and cur.machine_id = p_machine then
    update licensing.activations
       set last_seen_at = now(), machine_name = coalesce(nullif(p_name, ''), machine_name),
           version = coalesce(nullif(p_version, ''), version)
     where id = cur.id;
    return jsonb_build_object('ok', true, 'activated_at', cur.activated_at, 'key', l.key,
                              'method', cur.method, 'already', true);
  end if;

  if found then
    select count(*) into moved from licensing.activations
     where lid = p_lid and released_reason = 'moved' and released_at > now() - interval '365 days';
    if not p_allow_move then
      return jsonb_build_object('ok', false, 'code', 'in_use',
        'message', format('This licence is active on another machine ("%s"). Activate it from this '
                          'master''s setup or with "nodewatch-server activate" to move it here.',
                          cur.machine_name));
    end if;
    if moved >= l.moves_per_year then
      return jsonb_build_object('ok', false, 'code', 'move_limit',
        'message', format('This licence is active on another machine ("%s") and has already been moved '
                          '%s time(s) in the last 12 months, the most allowed. Contact your supplier '
                          'to move it again.', cur.machine_name, moved));
    end if;
    update licensing.activations set released_at = now(), released_reason = 'moved' where id = cur.id;
    moved_from := cur.machine_name;
  end if;

  insert into licensing.activations (lid, machine_id, machine_name, version, method, last_seen_at)
  values (p_lid, p_machine, coalesce(p_name, ''), coalesce(p_version, ''), p_method, now())
  returning * into cur;
  insert into licensing.events (lid, actor, kind, detail)
  values (p_lid, p_actor, case when moved_from is null then 'activated' else 'moved' end,
          jsonb_strip_nulls(jsonb_build_object('machine', p_name, 'method', p_method,
                                               'from', moved_from, 'version', nullif(p_version, ''))));
  return jsonb_build_object('ok', true, 'activated_at', cur.activated_at, 'key', l.key,
                            'method', p_method, 'moved_from', moved_from);
end $$;


-- A master's daily check-in. status:
--   active    still the licence's machine; key is the current key (a
--             renewal shows up here as a different key)
--   released  moved to another machine, or released by the vendor
--   revoked   the vendor revoked the licence
--   unknown   the server has no record of this activation (the master
--             changes nothing)
create or replace function licensing.checkin(p_lid uuid, p_machine text, p_version text)
returns jsonb
language plpgsql as $$
declare
  l   licensing.licences;
  act licensing.activations;
  cur licensing.activations;
begin
  select * into l from licensing.licences where id = p_lid;
  if not found then
    return jsonb_build_object('status', 'unknown');
  end if;
  if l.revoked_at is not null then
    return jsonb_build_object('status', 'revoked',
      'message', 'This licence has been revoked' || coalesce(nullif(': ' || l.revoked_reason, ': '), '') || '.');
  end if;
  select * into act from licensing.activations
   where lid = p_lid and machine_id = p_machine order by activated_at desc limit 1;
  if not found then
    return jsonb_build_object('status', 'unknown');
  end if;
  if act.released_at is null then
    update licensing.activations set last_seen_at = now(),
           version = coalesce(nullif(p_version, ''), version) where id = act.id;
    return jsonb_build_object('status', 'active', 'key', l.key);
  end if;
  select * into cur from licensing.activations where lid = p_lid and released_at is null;
  return jsonb_build_object('status', 'released',
    'message', case act.released_reason
      when 'moved' then format('This licence was moved to another machine ("%s") on %s.',
                               coalesce(cur.machine_name, '?'), to_char(act.released_at, 'YYYY-MM-DD'))
      else format('Your supplier released this licence from this machine on %s.',
                  to_char(act.released_at, 'YYYY-MM-DD')) end);
end $$;

revoke all on all functions in schema licensing from public;
