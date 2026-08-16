# nodewatch

Agent-based host telemetry for EC2 fleets: agent health, SSH authentication
events, and listening-port changes.

    agents (EC2) --HTTPS--> ingest API (EC2) --> Supabase Postgres
                                                      ^
                            dashboard (browser) ------+
                                     anon key + RLS

## Design notes

**Enrolment is not self-asserted.** An agent presents its IMDSv2 instance
identity document. The API calls `ec2:DescribeInstances` on the claimed
instance and rejects the request unless the source address matches one of
that instance's own addresses. No shared secret exists on any host, so
there is no registration password to steal. Verifying the PKCS7 signature
directly against the AWS regional certificate is the next step; the agent
already ships the signed blob.

**Health is derived, never stored.** No table has a status column. The
`agent_health` view computes healthy/degraded/down from `last_seen` at
query time, so a crashed agent cannot leave a stale "healthy" behind.

**Port diffing happens server-side.** The agent ships a full snapshot of
listening sockets each cycle; the API compares it against `port_state` and
writes only transitions to `port_events`. A restarted agent cannot desync
the change log. `external` marks binds to 0.0.0.0 or :: — the distinction
between a loopback listener and an externally reachable one.

**The agent buffers locally.** A SQLite queue survives restarts and network
outages, capped at 10k rows. Without it a brief outage would look identical
to a dead host. Journald reads use a persisted `__CURSOR`, so restarts
neither replay nor skip auth events.

## Layout

    agent/      Python daemon for each monitored host
    api/        FastAPI ingest service
    db/         Supabase migrations (run 001 then 002)
    dashboard/  Single-file HTML dashboard

## Setup

1. Run `db/001_init.sql` then `db/002_view_grants.sql` in the Supabase SQL editor.
2. Create a dashboard user under Authentication → Users (auto-confirm on).
3. Deploy the API — see `api/deploy/install-api.sh`. Requires
   `/etc/nodewatch/api.env`; template in `api/deploy/api.env.example`.
   The instance role needs `ec2:DescribeInstances` plus
   `AmazonSSMManagedInstanceCore`.
4. Install agents — see `api/deploy/install-agent.sh`. Point
   `NW_INGEST_URL` at the API's **private** IP; over loopback the source
   address is 127.0.0.1 and enrolment will be rejected.
5. Open `dashboard/index.html`.

## Not yet built

SCA config checks, file integrity monitoring, package inventory with CVE
lookup, and users/groups inventory. In that order.
