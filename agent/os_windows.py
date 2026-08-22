"""
Windows collectors.

Everything goes through PowerShell rather than pywin32, so the agent stays a
pure-Python install with no compiled dependencies and no vendored wheels -
the same `pip install psutil requests` works on every platform.

Output is requested as JSON and parsed structurally. Scraping the text
rendering of Windows commands is brittle across locales; ConvertTo-Json is
stable.
"""

import json
import os
import re
import subprocess

SEV_HIGH, SEV_MED, SEV_LOW = "high", "medium", "low"

# Config that governs authentication, privilege or startup on Windows. The
# registry equivalents (Run keys, services) are not files, so they are
# covered by posture checks rather than file hashing.
WATCH_PATHS = [
    os.path.expandvars(r"%SystemRoot%\System32\drivers\etc"),
    os.path.expandvars(r"%SystemRoot%\System32\GroupPolicy"),
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp"),
]

CRITICAL_PATHS = {
    os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\hosts").lower(),
    os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\lmhosts.sam").lower(),
}
CRITICAL_DIRS = (
    os.path.expandvars(r"%SystemRoot%\System32\GroupPolicy").lower(),
    os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp").lower(),
)

NOISE_PATTERNS = [
    re.compile(r".*\\Temp\\.*", re.I),
    re.compile(r".*\.log$", re.I),
    re.compile(r".*\.etl$", re.I),
]

PS_TIMEOUT = 45


def ps(script: str, timeout: int = PS_TIMEOUT):
    """
    Run PowerShell and parse JSON output. -Depth 4 because the default of 2
    silently truncates nested objects into type names.
    """
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    out = (res.stdout or "").strip()
    if not out:
        return None
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None
    # ConvertTo-Json emits a bare object when there is exactly one result.
    return data if isinstance(data, list) else [data]


def _check(cid, title, cat, sev, ok, detail):
    return {"check_id": cid, "title": title, "category": cat, "severity": sev,
            "status": "pass" if ok else "fail", "detail": detail}


def _error(cid, title, cat, sev, detail):
    return {"check_id": cid, "title": title, "category": cat, "severity": sev,
            "status": "error", "detail": detail}


# ---------------------------------------------------------------- sign-in events

# 4624 logon, 4625 failed logon, 4634 logoff, 4720 account created,
# 4732 added to a privileged group.
AUTH_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4624,4625,4634); StartTime=(Get-Date).AddMinutes(-%d)} -MaxEvents 200 |
  ForEach-Object {
    $x=[xml]$_.ToXml()
    $d=@{}
    $x.Event.EventData.Data | ForEach-Object { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{
      Id=$_.Id
      Time=$_.TimeCreated.ToUniversalTime().ToString('o')
      User=$d['TargetUserName']
      Domain=$d['TargetDomainName']
      Ip=$d['IpAddress']
      LogonType=$d['LogonType']
      Status=$d['Status']
    }
  } | ConvertTo-Json -Depth 4
"""

# Machine and service logons are constant background noise on Windows; only
# interactive, network, remote-interactive and unlock are worth reporting.
INTERESTING_LOGON_TYPES = {"2", "3", "7", "10", "11"}


def collect_auth_events(buf):
    """
    Reads the Security event log. Uses a stored high-water mark rather than
    a cursor - Windows has no journald cursor equivalent - so events are
    filtered by timestamp against the last one already shipped.
    """
    last = buf.get_meta("win_auth_high_water")
    window = 15 if last else 60          # minutes to look back
    rows = ps(AUTH_QUERY % window)
    if rows is None:
        return []

    out, newest = [], last or ""
    for r in rows:
        ts_iso = r.get("Time") or ""
        if last and ts_iso <= last:
            continue
        if str(r.get("LogonType") or "") not in INTERESTING_LOGON_TYPES:
            continue

        eid = int(r.get("Id") or 0)
        kind = {4624: "login_success", 4625: "login_failed",
                4634: "session_closed"}.get(eid)
        if not kind:
            continue

        user = r.get("User") or ""
        # Machine accounts end in $ and are not people signing in.
        if user.endswith("$") or user.upper() in ("SYSTEM", "ANONYMOUS LOGON"):
            continue

        ip = (r.get("Ip") or "").strip()
        if ip in ("-", "::1", "127.0.0.1"):
            ip = None

        try:
            import datetime
            ts = datetime.datetime.fromisoformat(ts_iso.replace("Z", "+00:00")).timestamp()
        except Exception:
            continue

        out.append({
            "kind": kind, "ts": ts,
            "username": (f"{r.get('Domain')}\\{user}" if r.get("Domain") else user),
            "source_ip": ip,
            "raw": f"EventID {eid} logon type {r.get('LogonType')} for {user}"
                   + (f" from {ip}" if ip else ""),
        })
        newest = max(newest, ts_iso)

    if newest:
        buf.set_meta("win_auth_high_water", newest)
    return out


# ---------------------------------------------------------------- accounts

USERS_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
$admins = @(Get-LocalGroupMember -Group 'Administrators' | ForEach-Object { $_.Name })
Get-LocalUser | ForEach-Object {
  $n=$_.Name
  [pscustomobject]@{
    Name=$n
    Sid=$_.SID.Value
    Enabled=$_.Enabled
    PasswordRequired=$_.PasswordRequired
    LastLogon=$(if($_.LastLogon){$_.LastLogon.ToUniversalTime().ToString('o')}else{$null})
    IsAdmin=[bool]($admins | Where-Object { $_ -match "\\$([regex]::Escape($n))$" })
  }
} | ConvertTo-Json -Depth 4
"""


def collect_users():
    rows = ps(USERS_QUERY)
    if rows is None:
        return []
    out = []
    for r in rows:
        sid = r.get("Sid") or ""
        # The RID is the trailing component of the SID; 500 is the built-in
        # Administrator. Reporting it as uid keeps the schema shared with Unix.
        rid = None
        if "-" in sid:
            tail = sid.rsplit("-", 1)[-1]
            rid = int(tail) if tail.isdigit() else None
        out.append({
            "username": r.get("Name"),
            "uid": rid,
            "gid": None,
            "shell": None,
            "home": None,
            "groups": ["Administrators"] if r.get("IsAdmin") else [],
            "sudoer": bool(r.get("IsAdmin")),
            "can_login": bool(r.get("Enabled")),
            "password": "none" if r.get("PasswordRequired") is False else "set",
        })
    return out


# ---------------------------------------------------------------- posture

POSTURE_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
$fw = Get-NetFirewallProfile | Select-Object Name,Enabled
$rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections).fDenyTSConnections
$uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA
$smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
$guest = (Get-LocalUser -Name 'Guest').Enabled
$bl = @(Get-BitLockerVolume | Where-Object { $_.MountPoint -eq $env:SystemDrive } | Select-Object -First 1)
$def = Get-MpComputerStatus
$au = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name AUOptions).AUOptions
$secure = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel).LmCompatibilityLevel
[pscustomobject]@{
  FirewallDomain = ($fw | Where-Object Name -eq 'Domain').Enabled
  FirewallPrivate= ($fw | Where-Object Name -eq 'Private').Enabled
  FirewallPublic = ($fw | Where-Object Name -eq 'Public').Enabled
  RdpDenied      = $rdp
  Uac            = $uac
  Smb1           = $smb1
  GuestEnabled   = $guest
  BitLocker      = $(if($bl){$bl[0].ProtectionStatus.ToString()}else{'Unknown'})
  DefenderRealTime = $def.RealTimeProtectionEnabled
  DefenderSigAge   = $def.AntivirusSignatureAge
  AutoUpdate     = $au
  LmCompat       = $secure
} | ConvertTo-Json -Depth 4
"""

PENDING_UPDATES = r"""
$ErrorActionPreference='SilentlyContinue'
$s=New-Object -ComObject Microsoft.Update.Session
$r=$s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
$sec=@($r.Updates | Where-Object { $_.Categories | Where-Object { $_.Name -match 'Security' } }).Count
[pscustomobject]@{ Total=$r.Updates.Count; Security=$sec } | ConvertTo-Json
"""


def collect_checks():
    results = []
    d = ps(POSTURE_QUERY)
    if not d:
        return [_error("win-posture", "Windows posture is readable", "system",
                       SEV_MED, "PowerShell query failed or returned nothing")]
    d = d[0]

    for prof in ("Domain", "Private", "Public"):
        v = d.get(f"Firewall{prof}")
        results.append(_check(f"win-firewall-{prof.lower()}",
                              f"Windows Firewall is on for the {prof} profile",
                              "system", SEV_HIGH, v is True,
                              f"{prof} profile: {'enabled' if v else 'disabled'}"))

    rdp = d.get("RdpDenied")
    results.append(_check("win-rdp", "Remote Desktop is disabled", "network",
                          SEV_MED, rdp == 1,
                          "RDP enabled" if rdp == 0 else "RDP disabled"))

    results.append(_check("win-uac", "User Account Control is enabled", "system",
                          SEV_HIGH, d.get("Uac") == 1,
                          f"EnableLUA = {d.get('Uac')}"))

    results.append(_check("win-smb1", "SMBv1 is disabled", "network", SEV_HIGH,
                          d.get("Smb1") is False,
                          "SMBv1 enabled" if d.get("Smb1") else "SMBv1 disabled"))

    results.append(_check("win-guest", "The Guest account is disabled", "accounts",
                          SEV_HIGH, d.get("GuestEnabled") is False,
                          "Guest enabled" if d.get("GuestEnabled") else "Guest disabled"))

    bl = str(d.get("BitLocker") or "Unknown")
    results.append(_check("win-bitlocker", "System drive is encrypted", "filesystem",
                          SEV_HIGH, bl == "On", f"BitLocker: {bl}"))

    results.append(_check("win-defender-rt", "Defender real-time protection is on",
                          "system", SEV_HIGH, d.get("DefenderRealTime") is True,
                          "real-time protection " + ("on" if d.get("DefenderRealTime") else "off")))

    age = d.get("DefenderSigAge")
    results.append(_check("win-defender-sig", "Antivirus signatures are current",
                          "system", SEV_MED,
                          isinstance(age, int) and age <= 3,
                          f"signatures {age} day(s) old"))

    # LmCompatibilityLevel 5 refuses LM and NTLMv1 outright.
    lm = d.get("LmCompat")
    results.append(_check("win-ntlm", "NTLMv1 and LM are refused", "network", SEV_MED,
                          lm == 5, f"LmCompatibilityLevel = {lm}"))

    au = d.get("AutoUpdate")
    results.append(_check("win-autoupdate", "Automatic updates are configured",
                          "system", SEV_MED, au in (3, 4),
                          f"AUOptions = {au}"))

    upd = ps(PENDING_UPDATES, timeout=120)
    if upd:
        sec = upd[0].get("Security") or 0
        results.append(_check("win-security-updates", "No pending security updates",
                              "system", SEV_HIGH if sec > 5 else SEV_MED, sec == 0,
                              f"{sec} security update(s) pending, "
                              f"{upd[0].get('Total')} total"))
    else:
        results.append(_error("win-security-updates", "No pending security updates",
                              "system", SEV_MED, "Windows Update search unavailable"))

    return results


# ---------------------------------------------------------------- packages

# Reads both registry uninstall hives. WMI Win32_Product is avoided on
# purpose: enumerating it triggers a consistency check that can reconfigure
# installed MSIs, which is not something a monitoring agent should do.
PACKAGES_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
$paths=@(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
Get-ItemProperty $paths |
  Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
  Select-Object @{n='name';e={$_.DisplayName}},
                @{n='version';e={$_.DisplayVersion}},
                @{n='arch';e={ if($_.PSPath -match 'WOW6432Node'){'x86'}else{'x64'} }} |
  Sort-Object name -Unique | ConvertTo-Json -Depth 3
"""


def collect_packages():
    rows = ps(PACKAGES_QUERY, timeout=90)
    if rows is None:
        return []
    out = []
    for r in rows:
        name, ver = r.get("name"), r.get("version")
        if name and ver:
            out.append({"name": str(name)[:200], "version": str(ver)[:100],
                        "arch": r.get("arch")})
    return out


# ---------------------------------------------------------------- iis

# Per-site counters plus application pool state. Get-Counter is present on
# every Windows Server with IIS; WebAdministration is only present when the
# management tools feature is installed, so pool state degrades to unknown
# rather than failing the whole collection.
IIS_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
if (-not (Get-Service W3SVC -ErrorAction SilentlyContinue)) { '[]'; exit }

$paths = @(
  '\web service(*)\total method requests',
  '\web service(*)\total not found errors',
  '\web service(*)\total server errors',
  '\web service(*)\current connections',
  '\web service(*)\bytes sent/sec',
  '\web service(*)\bytes received/sec'
)
$samples = (Get-Counter -Counter $paths -ErrorAction SilentlyContinue).CounterSamples

$sites = @{}
foreach ($s in $samples) {
  # InstanceName is the site name; _Total is the rollup and is skipped.
  $name = $s.InstanceName
  if (-not $name -or $name -eq '_total') { continue }
  if (-not $sites.ContainsKey($name)) { $sites[$name] = @{} }
  $metric = ($s.Path -split '\\')[-1]
  $sites[$name][$metric] = $s.CookedValue
}

$pools = @{}
if (Get-Module -ListAvailable -Name WebAdministration) {
  Import-Module WebAdministration -ErrorAction SilentlyContinue
  foreach ($p in (Get-ChildItem IIS:\AppPools -ErrorAction SilentlyContinue)) {
    $pools[$p.Name] = $p.State.ToString()
  }
}

$out = foreach ($k in $sites.Keys) {
  $m = $sites[$k]
  $siteState = 'Unknown'
  if (Get-Module -ListAvailable -Name WebAdministration) {
    $site = Get-Website -Name $k -ErrorAction SilentlyContinue
    if ($site) { $siteState = $site.State.ToString() }
  }
  [pscustomobject]@{
    site        = $k
    requests    = [int64]$m['total method requests']
    notfound    = [int64]$m['total not found errors']
    server_err  = [int64]$m['total server errors']
    connections = [int]$m['current connections']
    bytes_sent  = [int64]$m['bytes sent/sec']
    bytes_recv  = [int64]$m['bytes received/sec']
    state       = $siteState
  }
}
if (-not $out) { '[]' } else { $out | ConvertTo-Json -Depth 4 }
"""

POOL_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'
if (-not (Get-Module -ListAvailable -Name WebAdministration)) { '[]'; exit }
Import-Module WebAdministration
$r = Get-ChildItem IIS:\AppPools | ForEach-Object {
  [pscustomobject]@{ name=$_.Name; state=$_.State.ToString();
                     runtime=$_.managedRuntimeVersion; pipeline=$_.managedPipelineMode }
}
if (-not $r) { '[]' } else { $r | ConvertTo-Json -Depth 3 }
"""


def collect_iis():
    """
    One entry per IIS site. Returns [] when IIS is not installed, which is
    the common case and must not look like an error.
    """
    rows = ps(IIS_QUERY, timeout=60)
    if not rows:
        return []

    pools = {p.get("name"): p for p in (ps(POOL_QUERY, timeout=30) or [])}
    stopped = [n for n, p in pools.items() if str(p.get("state")) != "Started"]

    out = []
    for r in rows:
        site = r.get("site")
        if not site:
            continue
        # "Total server errors" is the 5xx count. 404s are counted separately
        # and deliberately excluded: a missing page is usually the caller's
        # problem, not the server's.
        out.append({
            "app_name": f"IIS: {site}",
            "requests_total": int(r.get("requests") or 0),
            "errors_total": int(r.get("server_err") or 0),
            "active_conns": int(r.get("connections") or 0),
            "extra": {
                "site_state": r.get("state"),
                "not_found": int(r.get("notfound") or 0),
                "bytes_sent_sec": int(r.get("bytes_sent") or 0),
                "bytes_recv_sec": int(r.get("bytes_recv") or 0),
                "pools_total": len(pools),
                "pools_stopped": stopped,
            },
        })
    return out


# ---------------------------------------------------------------- identity

def machine_id():
    """
    MachineGuid is written at install time and is stable across reboots and
    hardware changes, which is what makes it the right continuity anchor.
    """
    rows = ps(r"[pscustomobject]@{ Id=(Get-ItemProperty "
              r"'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid } "
              r"| ConvertTo-Json")
    if rows and rows[0].get("Id"):
        return str(rows[0]["Id"]).replace("-", "").lower()
    return None


def hardware_fingerprint():
    rows = ps(r"""
$cs = Get-CimInstance Win32_ComputerSystemProduct
$bb = Get-CimInstance Win32_BaseBoard
[pscustomobject]@{
  hostname=$env:COMPUTERNAME
  product_uuid=$cs.UUID
  board_serial=$bb.SerialNumber
  kernel=[System.Environment]::OSVersion.Version.ToString()
} | ConvertTo-Json""")
    if not rows:
        return {"hostname": os.environ.get("COMPUTERNAME")}
    r = rows[0]
    return {k: (str(v) if v is not None else None) for k, v in r.items()}
