-- 041: Microsoft Teams as an alert channel kind.
--
-- Unlike Slack's incoming-webhook grant, Teams has no OAuth scope that
-- just hands back a post-to-this-URL webhook - Microsoft deprecated that
-- model (Office 365 Connectors). Posting into a Teams channel today needs
-- a Microsoft Graph access token and knows which team/channel to post
-- into, so a 'teams' channel's config carries a refresh token plus
-- tenant/team/channel ids rather than a single static url the way
-- 'slack'/'webhook' do.

alter table alert_channels drop constraint if exists alert_channels_kind_check;
alter table alert_channels add constraint alert_channels_kind_check
    check (kind in ('telegram', 'webhook', 'botim', 'slack', 'teams'));

-- ---------------------------------------------------------------- OAuth handoff
--
-- The Teams OAuth callback (api/teams_app.py) gets a refresh token back
-- before it knows which team/channel to post into - Microsoft's grant
-- isn't scoped to one channel the way Slack's incoming-webhook is, so the
-- admin picks a team and then a channel in a second step. The refresh
-- token is real, long-lived credential material, so it stays server-side
-- for that entire handoff: the browser only ever sees this row's random
-- id, never the token itself, the same discipline every other credential
-- in this schema already gets.
create table if not exists teams_oauth_pending (
    id            uuid primary key default gen_random_uuid(),
    refresh_token text not null,
    tenant_id     text not null,
    created_at    timestamptz not null default now()
);

-- No RLS: never read or written via the dashboard's own Supabase session,
-- only from api/teams_app.py's own database connection - same reasoning
-- as github_installations's insert path, just with no read side at all.
revoke all on teams_oauth_pending from authenticated, anon;

select cron.unschedule('nodewatch-teams-pending-retention')
 where exists (select 1 from cron.job where jobname = 'nodewatch-teams-pending-retention');
select cron.schedule('nodewatch-teams-pending-retention', '*/15 * * * *',
    $$delete from teams_oauth_pending where created_at < now() - interval '1 hour';$$);
