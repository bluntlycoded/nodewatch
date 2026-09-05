# Security & telemetry disclosure

nodewatch ships a monitoring agent that reads host state an EDR or antivirus
product may reasonably want to know about before allowing it to run
unattended, at scale, on production and end-user machines. This document
exists so a security team can evaluate the agent from its actual behaviour
rather than from what reading `/etc/shadow` or shelling out to PowerShell
looks like in isolation.

**If you are a security vendor evaluating a detection against this agent, or
an admin who needs to write an allowlist rule, this is the page to read
first.** Everything below is derived directly from the source in this
repository, not from a separate marketing description of it.

---

## What this is

nodewatch is a host and infrastructure monitoring product. The agent
(`agent/`) is a single Python process, installed as a systemd service
(Linux), a launchd job (macOS), or a Scheduled Task running as SYSTEM
(Windows). It reads configuration state, sends a summary to a server the
operator controls, and does nothing else. It is not obfuscated: the full
source, including every command it runs, is in this repository.

**[nodewatch/README.md](README.md)** — product overview and architecture.
**[nodewatch/CHANGES.md](CHANGES.md)** — user-facing change history.

---

## What it never does

- **Never reads or transmits a password, password hash, or private key.**
  Where account state is collected (Linux `/etc/shadow`, macOS
  `AuthenticationAuthority`, Windows `Get-LocalUser`), only a coarse
  classification is derived — `set`, `none`, or `locked` — and only that
  word is sent. The hash itself, or anything derived from it, never leaves
  the field it was read from.
- **Never writes to, modifies, or deletes anything on the monitored host.**
  Every collector is read-only. There is no remote command execution
  capability on the agent side of the product at all.
- **Never opens a listening port or accepts inbound connections.** The
  agent is a pure outbound HTTPS client.
- **Never contacts anything but the one ingest URL an admin configured**
  (`NW_INGEST_URL`) plus, where applicable, the host's own cloud metadata
  service (`169.254.169.254`, link-local, used only to prove instance
  identity at enrolment — see below).
- **Never persists beyond the one service/task the installer creates.** No
  additional scheduled tasks, registry Run keys, cron entries, or startup
  items are created.
- **Never disables, tampers with, or queries the state of security
  controls in order to weaken them** — Defender/BitLocker/firewall/SIP
  status are *read* (to report posture), never changed.

The one feature that executes anything outside the monitored host's own
state is **automation** (`probe/prober.py: run_automation`), and it is
scoped deliberately narrowly: it runs on the probe/API host, not the
monitored endpoint, only fires a plain outbound HTTP request to a URL an
admin configured on a rule, and only after a human has approved that
specific run from the dashboard. It cannot execute anything on an agent
host.

---

## What it reads, per platform, and why

### Linux

| Reads | Purpose |
|---|---|
| `/etc/passwd`, `/etc/group`, `/etc/shadow` (state only, see above) | account inventory, privilege changes |
| `/etc/ssh/sshd_config` (via `sshd -T`) | SSH hardening posture |
| `/proc/sys/net/*`, `/proc/sys/kernel/*` | kernel hardening posture (ASLR, SYN cookies, etc.) |
| `/etc` (file list + SHA-256 of watched files) | file integrity monitoring — see [file integrity](#file-integrity-monitoring-detail) below |
| journald, via `journalctl -u ssh -u sshd -o json` | sign-in/auth events |
| `dpkg-query` | installed package inventory (name/version only, for CVE matching against public OSV data — no code is executed from package metadata) |
| `find /etc -perm -0002`, `ufw status` / `nft list ruleset`, `/usr/lib/update-notifier/apt-check` | world-writable file check, firewall state, pending security update count |
| `psutil` (CPU, memory, disk, network interfaces, listening sockets) | standard host metrics |

No binary is invoked with elevated arguments beyond what a read-only status
query needs. Nothing is invoked via a shell string — every subprocess call
in this codebase uses an argument list, never `shell=True`.

### Windows

Every Windows collector runs a scoped `powershell -NoProfile -NonInteractive
-Command "<literal script>"` — the exact script text is committed in
[`agent/os_windows.py`](agent/os_windows.py), never assembled at runtime,
never base64-encoded, never downloaded. This is the same shape of
invocation used by many legitimate management tools, and it is worth an
EDR's PowerShell logging/AMSI inspection specifically because the script
text is fully static and auditable — there is nothing dynamic to hide.

| Cmdlet | Purpose |
|---|---|
| `Get-WinEvent` (Security log, IDs 4624/4625/4634 only) | sign-in events |
| `Get-LocalUser`, `Get-LocalGroupMember` | account inventory, admin group membership |
| `Get-NetFirewallProfile`, `Get-ItemProperty` (RDP/UAC/LmCompat registry values), `Get-SmbServerConfiguration`, `Get-MpComputerStatus`, `Get-BitLockerVolume` | posture: firewall, RDP, UAC, SMBv1, Defender, BitLocker |
| `New-Object -ComObject Microsoft.Update.Session` | pending Windows Update count |
| `Get-ItemProperty` (registry, `HKLM:\SOFTWARE\...\Uninstall\*`) | installed package inventory (name/version only) — deliberately *not* `Win32_Product`, since enumerating that WMI class can trigger MSI reconfiguration as a side effect |
| `Get-CimInstance Win32_ComputerSystemProduct`, `Win32_BaseBoard` | hardware fingerprint (UUID, board serial) used only to detect a machine ID being reused on different hardware |
| `Get-Counter`, `Get-Website`, `IIS:\AppPools` (only if IIS/`W3SVC` is present) | IIS metrics |

### macOS

`dscl`, `csrutil status`, `fdesetup status`, `spctl --status`,
`socketfilterfw --getglobalstate`/`--getstealthmode`, `systemsetup
-getremotelogin`, `softwareupdate -l`, `pkgutil --pkgs`, `ioreg` — all
read-only status queries against Apple's own CLI tools, no `sudo`
escalation beyond what the launchd job already runs as.

### File integrity monitoring detail

The agent hashes a narrow, explicit set of paths (`/etc` and equivalents —
see `WATCH_PATHS` per platform module), never the whole filesystem. A
manifest of `{path: sha256}` is kept locally in the agent's own SQLite
buffer; only the *diff* between scans (added/modified/deleted paths, never
file contents) is sent to the server.

---

## Network behaviour

- **Outbound only**, HTTPS, to a single URL the operator supplies at
  install time (`NW_INGEST_URL`). No hardcoded vendor endpoint, no
  telemetry to any address the customer did not configure.
- Every request now identifies itself with `User-Agent: nodewatch-agent/<version>`
  rather than a generic HTTP client string, so network-layer inspection
  does not have to guess what made the request.
- Identity at enrolment is proven, not asserted, using each cloud
  provider's own signed attestation (AWS IMDSv2 signed document, GCP
  metadata identity JWT, Azure IMDS attested document) or, for anything
  without one, a single-use invitation token issued from the operator's own
  dashboard. See [README.md § Enrolment identity](README.md#enrolment-identity)
  for the full mechanism.
- A short-lived JWT (15 minutes by default) authorises each batch; there is
  no long-lived shared secret on disk.

---

## Verifying what actually shipped

Every collector referenced above is plain, unminified Python (or the
literal PowerShell text shown inline in `os_windows.py`) in this public
repository. A reviewer does not need to take this document's word for it:

```bash
grep -rn "subprocess.run\|_run(\|requests\." agent/
```

surfaces every external process the agent can start and every network call
it can make — there is nothing else.

**Release integrity.** Until signed releases are in place (see below), a
security team can pin against a specific commit hash rather than a moving
`main` branch, and diff subsequent installs against it:

```bash
git clone https://github.com/bluntlycoded/nodewatch
git log -1 --format=%H              # the commit an install was built from
sha256sum agent/*.py                # per-file hashes to compare across installs
```

---

## Status: code signing

The Windows installer and agent are **not yet Authenticode-signed**, and
the macOS installer is **not yet notarized**. This is the single biggest
remaining lever for reducing false-positive detections and is the
recommended next step before wide deployment — it requires acquiring an EV
code-signing certificate (Windows) and an Apple Developer ID (macOS), which
is a procurement step rather than a code change. Once in place, `install.ps1`
and the agent's `.py` sources (or a compiled distribution, if one is
introduced later) should be signed as part of the release process, and this
document updated with the publisher identity and certificate thumbprint so
it can be pinned directly.

---

## Reporting a false-positive detection, or a real vulnerability

- **False-positive / allowlisting request** (you are a security vendor and
  your product flagged this agent): open an issue at
  `https://github.com/bluntlycoded/nodewatch/issues` with the detection
  name, the exact behaviour that triggered it, and the platform. This
  document is the reference for that discussion.
- **Vulnerability report**: `<security contact email — add before publishing>`.

<!--
  TODO before this goes external:
    - Add a real security contact address above.
    - Add the legal entity name / publisher name that will appear on a
      code-signing certificate, once one is acquired.
    - Once signed releases exist, replace the "Status: code signing"
      section with the actual certificate thumbprint and publisher name.
-->
