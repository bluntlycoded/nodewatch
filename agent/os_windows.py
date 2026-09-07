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
import shutil
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

# End-user-computing posture: screen lock, third-party AV/EDR presence,
# remote-access tooling, Secure Boot, TPM, USB mass storage policy. A
# server has no screen to lock and no business running TeamViewer, but
# this runs unconditionally regardless of the agent's role classification
# - a check that only ran sometimes could not be trusted to have run at all.
EUC_QUERY = r"""
$ErrorActionPreference='SilentlyContinue'

# Screen lock lives in HKCU, which a SYSTEM service cannot read for a user
# it is not running as. Machine policy (GPO) is authoritative when set and
# lives in HKLM, so check that first; otherwise read the hive of whichever
# interactive user is actually logged in, from HKEY_USERS.
$policy = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop' -ErrorAction SilentlyContinue
$lockSource = $null; $lockActive = $null; $lockSecure = $null; $lockUser = $null
if ($policy -and $null -ne $policy.ScreenSaveActive) {
  $lockSource = 'policy'; $lockActive = $policy.ScreenSaveActive; $lockSecure = $policy.ScreenSaverIsSecure
} else {
  $sids = Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' }
  foreach ($sid in $sids) {
    $u = Get-ItemProperty "Registry::HKEY_USERS\$($sid.PSChildName)\Control Panel\Desktop" -ErrorAction SilentlyContinue
    if ($u -and $null -ne $u.ScreenSaveActive) {
      $lockSource = 'user'; $lockActive = $u.ScreenSaveActive; $lockSecure = $u.ScreenSaverIsSecure
      try { $lockUser = (New-Object System.Security.Principal.SecurityIdentifier($sid.PSChildName)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
      break
    }
  }
}

# SecurityCenter2 lists every AV/EDR product registered with Windows
# Security Center, not only Defender - a third-party agent registers here
# and Windows disables Defender's own real-time scanning in response,
# which is expected behaviour, not a posture failure.
$avs = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction SilentlyContinue |
         Select-Object -ExpandProperty displayName)

$procs = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessName)

$sb = $null
try { $sb = [bool](Confirm-SecureBootUEFI) } catch {}
$tpm = Get-Tpm -ErrorAction SilentlyContinue

# 3 = enabled (default), 4 = disabled by policy.
$usb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR' -Name Start -ErrorAction SilentlyContinue).Start

[pscustomobject]@{
  LockSource=$lockSource; LockActive=$lockActive; LockSecure=$lockSecure; LockUser=$lockUser
  AntivirusProducts=$avs
  Processes=$procs
  SecureBoot=$sb
  TpmPresent=$tpm.TpmPresent; TpmReady=$tpm.TpmReady
  UsbStorageStart=$usb
} | ConvertTo-Json -Depth 4
"""

# A visibility check, not a policy one: presence fails at low severity so
# it surfaces for review, since only a person knows whether a given
# install is IT-sanctioned.
REMOTE_ACCESS_PROCESS_NAMES = {
    "TeamViewer": "TeamViewer", "TeamViewer_Service": "TeamViewer",
    "AnyDesk": "AnyDesk", "vncserver": "VNC", "tvnserver": "VNC", "winvnc": "VNC",
    "ScreenConnect.ClientService": "ScreenConnect", "LMIGuardianSvc": "LogMeIn",
    "SRService": "Splashtop",
}


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

    euc = ps(EUC_QUERY)
    euc = euc[0] if euc else {}
    avs = [a for a in (euc.get("AntivirusProducts") or []) if a]
    third_party_av = [a for a in avs if "defender" not in a.lower()]

    # Windows disables Defender's own real-time scanning the moment a
    # compatible third-party AV registers as active - that is correct
    # behaviour, not a posture gap, so it only fails when nothing else is
    # covering the host either.
    rt = d.get("DefenderRealTime") is True
    results.append(_check("win-defender-rt", "Real-time antivirus protection is on",
                          "system", SEV_HIGH, rt or bool(third_party_av),
                          "real-time protection on" if rt
                          else (f"off, but {', '.join(third_party_av)} is registered" if third_party_av
                                else "off, and no other antivirus product is registered")))

    age = d.get("DefenderSigAge")
    if third_party_av:
        results.append(_check("win-defender-sig", "Antivirus signatures are current",
                              "system", SEV_LOW, True,
                              f"managed by {', '.join(third_party_av)}, not Defender"))
    else:
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

    # ------------------------------------------------------ end-user computing

    if euc.get("LockSource"):
        active, secure = euc.get("LockActive"), euc.get("LockSecure")
        # ScreenSaveActive/ScreenSaverIsSecure are historically REG_SZ, not
        # REG_DWORD, so PowerShell can hand back either "1" or 1 depending
        # on how a given machine's value was written; compare as strings
        # rather than gambling on which.
        src = "policy" if euc["LockSource"] == "policy" else f"user {euc.get('LockUser') or '?'}"
        results.append(_check("win-screen-lock", "Screen lock is enabled", "system",
                              SEV_MED, str(active) == "1" and str(secure) == "1",
                              f"ScreenSaveActive={active}, ScreenSaverIsSecure={secure} ({src})"))
    else:
        results.append(_error("win-screen-lock", "Screen lock is enabled", "system",
                              SEV_MED, "no policy set and no interactive user session found"))

    results.append(_check("win-edr", "A recognised security agent is running", "system",
                          SEV_MED, bool(avs), ", ".join(avs) if avs else
                          "none of the known agents were found"))

    procs = euc.get("Processes") or []
    found_ra = sorted({label for needle, label in REMOTE_ACCESS_PROCESS_NAMES.items()
                       if needle in procs})
    results.append(_check("win-remote-access", "No remote-access software is running",
                          "system", SEV_LOW, not found_ra,
                          "none found" if not found_ra else "running: " + ", ".join(found_ra)))

    sb = euc.get("SecureBoot")
    if sb is None:
        results.append(_error("win-secureboot", "Secure Boot is enabled", "system",
                              SEV_MED, "not UEFI, or Secure Boot state unavailable"))
    else:
        results.append(_check("win-secureboot", "Secure Boot is enabled", "system",
                              SEV_MED, sb is True, f"Secure Boot: {'on' if sb else 'off'}"))

    tpm_present, tpm_ready = euc.get("TpmPresent"), euc.get("TpmReady")
    if tpm_present is None:
        results.append(_error("win-tpm", "A TPM is present and ready", "system",
                              SEV_MED, "TPM state unavailable (module not present or accessible)"))
    else:
        results.append(_check("win-tpm", "A TPM is present and ready", "system", SEV_MED,
                              bool(tpm_present) and bool(tpm_ready),
                              f"present={bool(tpm_present)}, ready={bool(tpm_ready)}"))

    usb = euc.get("UsbStorageStart")
    results.append(_check("win-usb-storage", "USB mass storage is restricted", "system",
                          SEV_LOW, usb == 4,
                          f"USBSTOR start = {usb}" if usb is not None else "USBSTOR service not found"))

    results.append(check_ai_skills())

    return results


# Known AI-CLI skill directories, relative to a user's profile. Claude
# Code's convention is well documented and stable; others get added here
# once confirmed rather than guessed at.
AI_SKILL_DIRS = {"Claude Code": r".claude\skills"}
AI_SKILLS_SCAN_MAX = 15   # bounded like every other unbounded-input check here


def _find_ai_skills():
    """[(tool, skill_dir, [skill_name, ...])] for every populated skill
    directory found across every real user profile under C:\\Users."""
    found = []
    try:
        homes = [os.path.join(r"C:\Users", d) for d in os.listdir(r"C:\Users")
                 if d not in ("Public", "Default", "Default User", "All Users")
                 and os.path.isdir(os.path.join(r"C:\Users", d))]
    except OSError:
        homes = []
    for home in homes:
        for tool, rel in AI_SKILL_DIRS.items():
            base = os.path.join(home, rel)
            if not os.path.isdir(base):
                continue
            try:
                skills = [d for d in os.listdir(base)
                         if os.path.isfile(os.path.join(base, d, "SKILL.md"))]
            except OSError:
                continue
            if skills:
                found.append((tool, base, skills))
    return found


def check_ai_skills():
    """
    Installed AI-agent skills (Claude Code, etc.) run with implicit trust
    and minimal vetting - this doesn't install or execute anything, it
    only reports whether skillspector (github.com/NVIDIA/skillspector),
    if present on the host, considers what's already installed safe.
    """
    dirs = _find_ai_skills()
    if not dirs:
        return _check("win-ai-skills", "Installed AI-agent skills carry no unreviewed risk",
                      "system", SEV_MED, True, "no AI-agent skills found")

    total = sum(len(skills) for _, _, skills in dirs)
    scanner = shutil.which("skillspector") or shutil.which("skillspector.exe")
    if not scanner:
        return _error("win-ai-skills", "Installed AI-agent skills carry no unreviewed risk",
                      "system", SEV_MED,
                      f"{total} skill(s) found but skillspector is not installed to assess them")

    order = {"SAFE": 0, "CAUTION": 1, "DO_NOT_INSTALL": 2}
    worst, flagged, scanned = "SAFE", [], 0
    for tool, base, skills in dirs:
        for name in skills:
            if scanned >= AI_SKILLS_SCAN_MAX:
                break
            scanned += 1
            try:
                # --no-llm: static analysis only, nothing about the
                # skill's contents leaves this host.
                res = subprocess.run(
                    [scanner, "scan", os.path.join(base, name), "--no-llm", "--format", "json"],
                    capture_output=True, text=True, timeout=20,
                )
                verdict = json.loads(res.stdout)["risk_assessment"]
                rec = verdict.get("recommendation", "SAFE")
            except Exception:
                continue
            if order.get(rec, 0) > order.get(worst, 0):
                worst = rec
            if rec != "SAFE":
                flagged.append(f"{name} ({rec}, score {verdict.get('score', '?')})")

    sev = SEV_HIGH if worst == "DO_NOT_INSTALL" else SEV_MED
    detail = f"{scanned} of {total} skill(s) scanned"
    detail += f", flagged: {', '.join(flagged)}" if flagged else ", none flagged"
    return _check("win-ai-skills", "Installed AI-agent skills carry no unreviewed risk",
                  "system", sev, worst == "SAFE", detail)


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
