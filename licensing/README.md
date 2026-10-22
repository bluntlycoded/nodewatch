# Licence server

The vendor side of nodewatch licensing. Masters activate their licence key
here once, and check in every six hours. The vendor issues and manages
licences from an admin page.

| Piece | Where |
|---|---|
| Database: licences, activations, history, admins | `supabase/migrations/` - private schema `licensing`, not exposed through the REST API |
| API: one Edge Function | `supabase/functions/licensing/` |
| Admin page | `docs/licensing/` - https://bluntlycoded.github.io/nodewatch/licensing/ |
| Offline activation page | `docs/activate/` - https://bluntlycoded.github.io/nodewatch/activate/ |
| Master side | `server/nodewatch_server/activation.py` |

## How it works

- **Activation.** At setup the master sends its licence key and a machine
  ID (a hash of the OS's own machine identifier) to `activate`. It gets back
  an activation code signed with the vendor key and saves it as
  `activation.key`.
- **One machine per licence.** Activating on a new machine moves the
  licence there, up to *moves per year* times (default 3) in any 12 months.
  The old master learns at its next check-in and becomes read-only.
  Monitoring and alerts never stop.
- **Check-in** (`checkin`, every 6 hours). It delivers a renewed key
  automatically, and reports a move or a revocation. If the server cannot
  be reached, nothing changes.
- **Offline.** A master with no internet shows a request code. The
  customer enters the request code and the licence key on the offline
  page, then pastes the activation code it returns back into the master.
- **Masters set up before activation existed** have 14 days to activate.
  They try on their own, but never take a licence that is active on
  another machine.
- **Keys issued with `tools/license_tool.py`** still work. The server
  registers them the first time a master activates them; they are marked
  "offline-issued" on the admin page.

Admin actions: issue, renew (new expiry or node count, same licence ID),
release a machine (does not use a move), revoke or lift a revocation, and
edit the move limit, contact email and notes.

## Deploy

From `licensing/`, with the Supabase CLI:

```bash
supabase link --project-ref <project-ref>
supabase db push
supabase secrets set LICENCE_SIGNING_KEY="$(cat ~/.nodewatch-vendor/license-signing.key)"
supabase functions deploy licensing --no-verify-jwt
```

Then:

1. In the Supabase dashboard, open **Authentication > Sign In / Providers**
   and turn off **Allow new users to sign up**. Add your admin user under
   **Authentication > Users**.
2. Make that user an admin, in the SQL editor:
   `insert into licensing.admins (email) values ('you@example.com');`
3. Put the project URL and anon key in `docs/licensing/config.js`, and
   the function URL in `LICENSING_URL` in
   `server/nodewatch_server/activation.py`. Rebuild the master.

Until step 3, masters do not ask for activation at all: a build whose
`LICENSING_URL` is still the placeholder treats every valid licence key
as enough, so nothing goes read-only waiting for a server that does not
exist yet.

The signing key in Supabase can issue licences. Anyone with access to
the Supabase project's secrets can therefore create licences, so protect
the account with two-factor authentication.

## Test

```bash
python licensing/test_licensing.py
```

The test runs a local Postgres, the function under Deno, and a stand-in for
Supabase Auth, then drives the master's own activation code through
activation, moves, the move limit, release, renewal, revocation, offline
activation and forgery attempts. It does not need Docker or a Supabase
project.
