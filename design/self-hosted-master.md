# Self-hosted master node

Status: phases 1-4 built. The licence server (`licensing/`) is tested
locally and not yet deployed. Tested end to end on macOS (arm64): setup, sign-in,
dashboard, join codes, signed enrolment, licence limit, alerts, crash
recovery. Linux and Windows masters - including the Windows service - build
and are tested only in CI.

Still open:

- Deploy the licence server to its Supabase project and put its address
  into the master (`licensing/README.md`).
- MSI / pkg / deb installers and code signing (phase 5).
- The agent window's administrator prompt (UAC, macOS password dialog,
  pkexec) has not been exercised outside CI.

## The product, from the customer's side

1. Download `nodewatch-server` and run it.
2. A setup page opens in the browser: enter the licence key, create the
   admin account. The master installs itself as a service, generates its
   own certificate authority, and serves the dashboard on
   `https://<this machine>:8443`.
3. **Add node** in the dashboard gives a one-time join code and a download
   link served by the master itself.
4. On the machine to monitor: download the agent from the master, run it,
   paste the code. It installs as a service and appears in the dashboard.

No scripts, no Python on any host, and nothing needs internet access
after licence activation.

One master serves one customer. Several people use the same master with
admin or viewer roles. A second network the master cannot route to gets a
**relay** (the existing probe runner, attached to the same master), not a
second master.

```
  vendor                           customer network
 ┌──────────────┐  activate once  ┌──────────────────────────────┐
 │ licence      │◀────────────────│  nodewatch-server (master)   │
 │ server       │  (offline file  │  dashboard · API · Postgres  │
 └──────────────┘   also works)   │  scheduler · alerts · probes │
                                  │  agent downloads · own CA    │
                                  └──────▲──────────▲────────────┘
                                         │ mTLS     │ mTLS
                                     ┌───┴────┐ ┌───┴────┐
                                     │ agent  │ │ agent  │  … up to the licensed count
                                     └────────┘ └────────┘
```

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Database | PostgreSQL shipped inside the master and run by it as a child process | The trust model, sweeps and alert triggers are ~7,600 lines of Postgres SQL. Bundling Postgres keeps all of it; SQLite would mean rewriting the core. |
| Supabase-only SQL | A compatibility layer (`server/nodewatch_server/sql/compat.sql`, applied only by the master) provides the `auth`, `cron`, `vault` and `net` pieces the existing migrations call, on stock Postgres | The 46 existing migrations run unchanged, so the hosted and self-hosted schemas cannot drift apart. |
| `pg_cron` | `cron.schedule()` records the job in a table; the master's scheduler runs it | No extension to compile per OS. |
| Edge Functions | Replaced by Python inside the master (alert delivery first) | Their source was never in this repository. |
| Executables | `nodewatch-server` (master) and `nodewatch-agent` (~10 MB) | The agent goes on every machine and stays small. |
| Master GUI | Setup wizard and dashboard in the browser, served by the master | Most masters are headless servers. |
| Agent GUI | Small native window plus `nodewatch-agent join <code>` for scripted rollout | Desktops get a window, GPO/Ansible/MDM get a command. |
| Agent identity | Client certificate from the master's CA, issued at join, mTLS on every request | A machine ID is readable by any local user and was enough to impersonate a host. |
| Transport | HTTPS only; the join code carries the master's CA fingerprint | Agents verify the master without a public certificate. |
| Licence | Ed25519-signed key verified offline against a public key built into the master; one online activation binds it to the machine, with an offline activation file for air-gapped sites | Works without internet; one key cannot run many sites. |
| Licence expiry | Grace period, then the dashboard is read-only and no new nodes join. Monitoring never stops. | A monitoring tool that silently stops is worse than none. |
| Master OS | Linux and Windows first, macOS later | That is where servers run. |
| Multi-tenancy | One tenant per master. The `tenant_id` schema stays, so an MSP licence can enable several workspaces later. | Customers are isolated by having separate masters. |

## Phases

| Phase | Delivers |
|---|---|
| 1 | Master as one executable: bundled Postgres, existing API, scheduler, alert delivery, built-in probe runner, setup wizard, own CA, offline licence verification |
| 2 | Dashboard served by the master: PostgREST for data, the master's own sign-in and user management |
| 3 | Join codes, mTLS, agent GUI and `join` command, agent downloads served by the master, agent auto-update |
| 4 | Licence server, online activation, node limits enforced |
| 5 | MSI / pkg / deb installers, code signing |

## Master layout on disk

| | Linux | Windows |
|---|---|---|
| Data | `/var/lib/nodewatch-server` | `%ProgramData%\nodewatch-server` |
| Contents | `config.json`, `licence.key`, `pki/` (CA, server cert), `pg/` (binaries), `pgdata/` | same |

Postgres refuses to run as root, so on Linux the master runs as a
dedicated `nodewatch` system user.
