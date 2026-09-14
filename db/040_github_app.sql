-- 040: GitHub App installations, for connecting private repositories to
-- Supply Chain checks without pasting a personal access token.
--
-- A GitHub App installation grants access to a chosen set of repositories
-- (or all of an account's) and is exchanged for a short-lived (1 hour)
-- installation access token at clone time - api/github_app.py handles the
-- interactive "connect" flow and records which installations exist;
-- probe/prober.py mints its own fresh token per scan directly against
-- GitHub's API using the same App private key, rather than storing a
-- long-lived credential the way a PAT-based check still does.

create table if not exists github_installations (
    installation_id bigint primary key,
    account_login   text not null,
    account_type    text,                -- 'User' or 'Organization'
    installed_by    text,                -- dashboard admin's email, for the audit trail
    installed_at    timestamptz not null default now()
);

alter table github_installations enable row level security;
drop policy if exists github_installations_read on github_installations;
create policy github_installations_read on github_installations for select to authenticated using (true);
drop policy if exists github_installations_admin on github_installations;
create policy github_installations_admin on github_installations for all to authenticated
    using (is_admin()) with check (is_admin());
grant select on github_installations to authenticated;
grant insert, update, delete on github_installations to authenticated;
revoke all on github_installations from anon;

comment on table github_installations is
    'Written by api/github_app.py''s OAuth callback using its own DB connection (not RLS-bound) - the RLS policies above govern the dashboard''s own direct reads/writes, same as every other admin-only table.';
