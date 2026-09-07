# nodewatch

Host and infrastructure monitoring with a continuous, explainable trust score
per machine.

Most monitoring tells you whether a host is up and what it is doing. nodewatch
also answers a question those tools do not ask: **how much should you trust
this machine right now, and why?** Every host carries a live score derived from
six signals, and the components are shown alongside the number so any score can
be explained rather than taken on faith.

```
agents (any OS, any cloud) ──HTTPS──▶ ingest API ──▶ Supabase (Postgres)
                                          ▲                  ▲
probe runner (agentless checks) ──────────┘                  │
                                                             │
                              dashboard (static) ──anon key + RLS
```

---

## What it monitors

**Hosts, via an agent** — Linux, Windows and macOS. CPU, memory, disk, uptime,
listening ports, sign-in events, local accounts and privilege changes,
installed packages, file integrity, network interfaces, and virtualisation
role — physical, a type 1 or type 2 hypervisor host, or a guest, inferred
from direct detection plus hardware evidence (fan/temperature sensors, NIC
link speed) rather than asserted.

**Configuration posture** runs unconditionally on every host, but covers two
different things: server hardening (SSH, sysctl, firewall, pending updates)
and end-user machines specifically (screen lock, third-party EDR/AV
presence via each OS's own security-product registry — not just the
platform's built-in one, remote-access tooling, Secure Boot and TPM, USB
storage policy, and the risk of any installed AI-agent skill — Claude Code
skills and similar — via [NVIDIA's SkillSpector](https://github.com/NVIDIA/skillspector)
if it happens to be present on the host). A host is classified as a server
or a desktop from the dashboard, but every check still runs on every host
regardless — a check that only ran sometimes could not be trusted to have
run at all.

**Anything else, via agentless probes** — ping, TCP port, HTTP/URL, PostgreSQL,
MySQL, SQL Server, Oracle, Prometheus, nginx, Tomcat, JBoss/WildFly,
Proxmox VE clusters (node status, VM/container inventory, storage pool
capacity, backup outcomes), and supply-chain risk in a git repository (risk
score, severity and current findings, via [ForgeGuardian](https://github.com/Mah3Sec/ForgeGuardian) —
the probe host clones the repo and calls `fgctl`, the same way it calls
Proxmox's API or a database's DMVs, rather than nodewatch reimplementing a
dependency scanner). The probe runner polls on a schedule from a host with
a route to the target, which is also how BMC and SNMP support will work.

**Enrolment covers** AWS, GCP, Azure and on-premise, each verified as strongly
as the platform allows.

---

## The trust model

Trust is a view, not a column. It is recomputed on read, so it can never go
stale and no code path can leave a dead host reporting healthy.

```
trust = 100 × recency × ( 0.18·exposure + 0.26·auth + 0.13·churn
                        + 0.23·posture  + 0.20·integrity )
```

| Factor | Falls when |
|---|---|
| `recency` | the agent stops reporting |
| `exposure` | more ports are bound to all interfaces |
| `auth` | failed sign-ins accumulate |
| `churn` | ports open or accounts change, privileged changes weighing double |
| `posture` | configuration checks fail, weighted by severity |
| `integrity` | watched files change, security-critical paths weighing ten times |

**Recency multiplies rather than adds.** Posture only counts if the host is
still talking to us: a clean configuration reported four minutes ago is not
evidence about the host now. A host that stops reporting scores **zero**, not a
decayed remainder — everything known about a silent host is stale by
definition, so there is nothing to be partly confident about.

Below 70 a host is flagged for re-verification rather than trusted on the
strength of its last handshake.

**Honest limitation:** the weights are judgement calls, not empirical results.
They have not been validated against compromised hosts. Treat the score as a
well-reasoned heuristic until a sensitivity analysis says otherwise.

---

## Enrolment identity

A node's identity is verified, not asserted. How strongly depends on what the
platform can prove, and the difference is recorded per node rather than
smoothed over.

| Provider | Evidence | Recorded as |
|---|---|---|
| AWS | IMDSv2 signed identity document, verified against the regional certificate | `signed` |
| GCP | Google-signed identity JWT, verified against Google's JWKS | `signed` |
| Azure | IMDS attested document | `signed` or `token` |
| On-premise | machine ID plus a single-use invitation token | `token` |

No shared registration secret exists on any host, so there is nothing to steal
and replay. The AWS path additionally confirms with EC2 that the instance
exists in the account and that the request came from its own address.

A token invites a host **once**. Agents re-enrol whenever their short-lived JWT
expires, so requiring a fresh token every time would lock a host out on its
first renewal; afterwards the machine ID and hardware fingerprint carry
continuity, and a fingerprint change is refused.

---

## Repository layout

```
agent/     the agent, one module per OS behind a shared interface
api/       FastAPI ingest service
probe/     agentless probe runner
db/        migrations, applied in order
docs/      the dashboard (single HTML file, served by GitHub Pages)
```

**The agent** is pure Python: `psutil` and `requests`, nothing compiled.
`osdetect.py` defines one interface; `os_linux`, `os_windows` and `os_darwin`
implement it. The agent itself contains no platform conditionals, so adding an
OS means adding a module rather than editing the collectors. `virt.py` is the
one exception with its own file rather than living in each OS module,
since virtualisation-role detection shares logic (classification, hardware
evidence) across all three.

**Edge Functions** (`send-alerts`, `scan-vulns`, `manage-users`) run on
Supabase but are not yet tracked in this repository — they are deployed
directly from the Supabase dashboard/CLI. Referenced in
[Deploying the stack](#deploying-the-stack) below for what each does and
how it must be configured.

---

## Installing an agent

Generate an invitation from **Servers → Add server**, pick the operating
system, and run the command it gives you.

```bash
# Linux
sudo NW_INGEST_URL=https://ingest.example.com NW_ENROLL_TOKEN=<token> \
     bash install.sh

# macOS
sudo NW_INGEST_URL=... NW_ENROLL_TOKEN=<token> bash install-macos.sh
```

```powershell
# Windows, elevated
$env:NW_INGEST_URL='https://ingest.example.com'
$env:NW_ENROLL_TOKEN='<token>'
irm .../agent/install.ps1 | iex
```

Linux and macOS run under systemd and launchd. **Windows runs as a scheduled
task, not a service** — a plain Python script is not a Windows service, and the
Service Control Manager kills one that does not report back. Making it a real
service would need `pywin32`, and a compiled dependency would cost more than it
buys.

**The agent does not self-update.** It runs whatever was on disk at install
time, so a host enrolled before a code change stays on the old code until
updated. `update.sh` / `update-macos.sh` / `update.ps1` pull the latest
`agent/*.py` from `main` and restart the service or task in place — they
never touch enrolment state, the venv, or the ingest URL/token, so no
credentials are needed to run one.

```bash
# Linux / macOS, on the host, as root
sudo bash update.sh          # or: sudo bash update-macos.sh
```

```powershell
# Windows, elevated
irm .../agent/update.ps1 | iex
```

---

## Deploying the stack

Migrations are applied in order in the Supabase SQL editor. After each batch:

```sql
-- smoke test: if these three run clean, the core paths survived
select queue_alert((select id from agents where agent_version is not null limit 1),
                   'node_down', '[smoke] alerting works', 'delete me');
select count(*) from agent_overview;
select snapshot_trust();
```

Then the API host, then the agents, then the dashboard. Order matters: the API
writes columns the migrations create, and the dashboard asks the database what
role you have.

Three Edge Functions deploy with **Verify JWT off** — `send-alerts`,
`scan-vulns`, and `manage-users`. The last one is stricter than the built-in
check: it verifies the caller's session *and* requires the admin role.

---

## Roles

Two roles, enforced in Postgres rather than in the dashboard, because hiding a
button does not stop anyone calling the API with the anon key.

An **admin** manages servers, credentials, recipients, channels, tokens and
users. A **viewer** sees everything except credentials and can acknowledge or
resolve alerts.

Credentials are unreachable rather than unrendered: `alert_channels` and
`probe_secrets` are admin-only under RLS, and viewers read views that omit the
secret column entirely. Postgres has no column-level RLS, so splitting the
table is the only way to let one role read the name of a thing while another
reads its password.

---

## Alerting

Each rule has its own cooldown — from account changes and new exposure to
database replication lag, a hypervisor going down, and a Proxmox backup
failing. Delivery by email (Resend), Telegram, Slack, Botim or a plain
webhook, configured per server or fleet-wide, each destination with a
minimum severity.

Detection lives in database triggers so nothing can slip through a polling gap;
delivery lives in an Edge Function so no credential ever reaches a browser. The
two meet at `alert_log`, which is a queue: triggers write `pending`, the sender
claims rows before sending so overlapping runs cannot double-send, and anything
stranded for five minutes is requeued.

An alert that is deliberately **not** sent is recorded as `suppressed` with the
reason — a muted node, or no destination configured. An alerting system that
silently drops what it cannot deliver is worse than one that does not alert.

`priv_account` has a **zero cooldown**. Every other rule throttles; an account
gaining sudo sends every single time.

---

## Design decisions worth knowing

**Derived state, never stored.** No table holds a status column. Health,
trust and outage state are computed at query time.

**Server-side diffing.** Agents ship full snapshots of ports, accounts and
posture; the server derives the change log. A crashed or restarted agent cannot
desync it. File integrity is the exception — `/etc` is thousands of files, so
the agent diffs locally and ships deltas, with a manifest digest so drift is
detectable.

**Local buffering.** A SQLite queue survives restarts and outages, capped at
10k rows. Without it a brief network problem would look identical to a dead
host.

**Raw counters, derived rates.** Network throughput and database statistics
ship cumulatively and are differenced on read. Storing a rate would bake in
whatever interval applied, and a restart would look like a spike rather than a
gap.

**Baselines seed silently.** First contact records the existing state without
raising events. Otherwise every new host would report every file in `/etc` and
every stock system account as newly added.

---

## Security disclosure

The agent reads configuration state — the Security event log, BitLocker
status, `/etc/shadow`, registry keys — that looks alarming out of context
and is exactly what an EDR or antivirus product has good reason to be
suspicious of. [SECURITY.md](SECURITY.md) documents exactly what each
platform's collectors read and why, and — just as importantly — what the
agent categorically never does: it never transmits a password or its hash,
never writes to the monitored host, opens no listening port, and persists
nowhere beyond the one service or scheduled task the installer creates.
Written for a security vendor disputing a detection, or an admin writing an
allowlist rule, sourced directly from the collectors rather than a separate
marketing description of them.

---

## Not built

BMC telemetry (iDRAC, iLO, XCC, Supermicro — one Redfish module would cover
all four), Nutanix, and SNMP — which is also what a physical, LLDP/CDP-based
topology map would need. The topology page that exists today shows L3
reachability derived from traceroute, which is a different and narrower
thing than switch-port-level adjacency.

The dashboard lists what isn't built with a page describing what it would
collect and how it would work, rather than a dead link.


