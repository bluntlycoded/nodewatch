# nodewatch agent installer for Windows. Run in an elevated PowerShell.
#
#   $env:NW_INGEST_URL   = 'https://ingest.example.com'
#   $env:NW_ENROLL_TOKEN = '<token from the dashboard>'
#   $env:NW_SITE         = 'VIT-AP Lab'
#   irm https://raw.githubusercontent.com/bluntlycoded/nodewatch/main/agent/install.ps1 | iex
#
# Administrator rights are required: the Security event log, BitLocker state
# and Defender status are not readable otherwise, and the agent must run as
# SYSTEM to keep reading them.
#
# The agent runs as a scheduled task rather than a Windows service. A plain
# Python script is not a service - the Service Control Manager expects the
# process to report back within about thirty seconds and kills it when it
# does not, which is why a New-Service install starts and immediately dies.
# Making it a real service would need pywin32, and the point of this agent is
# that it installs with nothing but psutil and requests on every platform.

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- admin check

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {

  throw 'Run this in an elevated PowerShell (Run as administrator).'
}

# ---------------------------------------------------------------- environment

if (-not $env:NW_INGEST_URL) {
  throw 'Set NW_INGEST_URL first.'
}

if (-not $env:NW_ENROLL_TOKEN) {
  throw 'Set NW_ENROLL_TOKEN first - Windows hosts have no cloud identity, so an invitation is required.'
}

$Root = 'C:\Program Files\nodewatch'

$Repo = if ($env:NW_REPO) {
  $env:NW_REPO
}
else {
  'https://github.com/bluntlycoded/nodewatch'
}

$Task = 'nodewatch-agent'

Write-Host '== nodewatch agent install'


# ---------------------------------------------------------------- python
#
# Windows ships "App execution aliases" that make `python` a Microsoft Store
# stub. Detect a real interpreter rather than trusting the name to resolve.

function Find-Python {

  $candidates = @()

  # Python launcher
  if (Get-Command py -ErrorAction SilentlyContinue) {

    $candidates += ,@(
      'py',
      @('-3')
    )
  }

  # Normal python/python3 commands
  foreach ($c in @('python', 'python3')) {

    $cmd = Get-Command $c -ErrorAction SilentlyContinue

    if (
      $cmd -and
      $cmd.Source -notlike '*WindowsApps*'
    ) {

      $candidates += ,@(
        $cmd.Source,
        @()
      )
    }
  }

  # Common installation paths
  foreach ($p in @(
      "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
      "$env:ProgramFiles\Python3*\python.exe",
      'C:\Python3*\python.exe'
  )) {

    Get-ChildItem $p -ErrorAction SilentlyContinue |
      Sort-Object FullName -Descending |
      ForEach-Object {

        $candidates += ,@(
          $_.FullName,
          @()
        )
      }
  }

  foreach ($cand in $candidates) {

    $exe = $cand[0]
    $pre = $cand[1]

    try {

      $out = & $exe @pre -c `
        "import sys;print('%d.%d' % sys.version_info[:2])" `
        2>$null

    }
    catch {

      continue
    }

    if (-not $out) {
      continue
    }

    $v = (
      $out |
      Select-Object -First 1
    ).ToString().Trim()

    if (
      $v -match '^\d+\.\d+$' -and
      [version]$v -ge [version]'3.10'
    ) {

      return ,@(
        $exe,
        $pre,
        $v
      )
    }
  }

  return $null
}


$py = Find-Python

if (-not $py) {

  Write-Host '   No usable Python 3.10+ found. Installing via winget...'

  if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {

    throw 'Python 3.10+ is required and winget is unavailable. Install Python from python.org with "Add python.exe to PATH" ticked, then re-run.'
  }

  winget install `
    --id Python.Python.3.12 `
    --scope machine `
    --silent `
    --accept-source-agreements `
    --accept-package-agreements

  $env:Path =
    [Environment]::GetEnvironmentVariable(
      'Path',
      'Machine'
    ) +
    ';' +
    [Environment]::GetEnvironmentVariable(
      'Path',
      'User'
    )

  $py = Find-Python

  if (-not $py) {

    throw 'Python still not usable. Open Settings > Apps > Advanced app settings > App execution aliases and turn off the python.exe alias, then re-run.'
  }
}

$PyExe = $py[0]
$PyPre = $py[1]
$PyVer = $py[2]

Write-Host "   Python $PyVer at $PyExe"


# ---------------------------------------------------------------- files

New-Item `
  -ItemType Directory `
  -Force `
  -Path $Root, "$Root\state" |
  Out-Null

$zip = Join-Path `
  $env:TEMP `
  'nodewatch.zip'

$ext = Join-Path `
  $env:TEMP `
  'nodewatch-src'

Remove-Item `
  $ext `
  -Recurse `
  -Force `
  -ErrorAction SilentlyContinue

Write-Host '   Downloading nodewatch...'

Invoke-WebRequest `
  "$Repo/archive/refs/heads/main.zip" `
  -OutFile $zip `
  -UseBasicParsing

Expand-Archive `
  $zip `
  $ext `
  -Force

$sourceAgent = Join-Path `
  $ext `
  'nodewatch-main\agent'

if (-not (Test-Path $sourceAgent)) {

  throw "Agent source directory was not found at $sourceAgent"
}

Copy-Item `
  (Join-Path $sourceAgent '*.py') `
  $Root `
  -Force

Remove-Item `
  $zip `
  -Force

Remove-Item `
  $ext `
  -Recurse `
  -Force


# ---------------------------------------------------------------- verify files

foreach ($f in @(
  'agent.py',
  'osdetect.py',
  'os_windows.py',
  'inventory.py',
  'checks.py',
  'identity.py'
)) {

  $file = Join-Path `
    $Root `
    $f

  if (-not (Test-Path $file)) {

    throw "$f is missing after download. Check that the repository contains agent/$f."
  }
}

Write-Host '   Agent files downloaded successfully.'


# ---------------------------------------------------------------- virtualenv

Write-Host '   Creating Python virtual environment...'

& $PyExe @PyPre `
  -m venv `
  "$Root\venv"

$VenvPy = "$Root\venv\Scripts\python.exe"

if (-not (Test-Path $VenvPy)) {

  throw "Virtualenv creation failed at $Root\venv"
}


# ---------------------------------------------------------------- dependencies

Write-Host '   Installing Python dependencies...'

& $VenvPy `
  -m pip `
  install `
  -q `
  --upgrade `
  pip

& $VenvPy `
  -m pip `
  install `
  -q `
  psutil `
  requests


# ---------------------------------------------------------------- launcher
#
# A scheduled task cannot carry environment variables directly, so a small
# wrapper sets them and runs the agent.
#
# The enrolment token is stored in this file, so its ACL is reduced to
# SYSTEM and Administrators only.

$runner = Join-Path `
  $Root `
  'run-agent.cmd'


$lines = @(
  '@echo off',

  "set NW_INGEST_URL=$env:NW_INGEST_URL",

  "set NW_ENROLL_TOKEN=$env:NW_ENROLL_TOKEN",

  "set NW_STATE_DIR=$Root\state",

  'set NW_PROVIDER=generic'
)


if ($env:NW_SITE) {

  $lines += `
    "set NW_SITE=$env:NW_SITE"
}


$lines += (
  '"' +
  $VenvPy +
  '" "' +
  $Root +
  '\agent.py" >> "' +
  $Root +
  '\state\agent.log" 2>&1'
)


Set-Content `
  -Path $runner `
  -Value $lines `
  -Encoding ASCII


# Well-known SIDs rather than names:
# "Administrators" is localised and the grant would silently fail
# on a non-English installation.

icacls `
  $runner `
  /inheritance:r `
  /grant:r `
  '*S-1-5-18:(F)' `
  '*S-1-5-32-544:(F)' |
  Out-Null


# ---------------------------------------------------------------- smoke test
#
# IMPORTANT:
#
# The old installer only imported agent.py:
#
#     import agent
#
# That does NOT execute collect_metrics().
#
# The Windows agent was therefore reported as "clean" even though it later
# crashed at:
#
#     os.getloadavg()
#
# This smoke test now actually executes the important Windows collectors
# before the Scheduled Task is created.

Write-Host '   Running Windows agent smoke test...'


$probeCode = @"
import sys

sys.path.insert(0, r'$Root')

import agent
import osdetect

print("Platform:", osdetect.PLATFORM)
print("Agent version:", agent.AGENT_VERSION)

print("Testing collect_metrics()...")
metrics = agent.collect_metrics()
print("Metrics:", metrics)

if not isinstance(metrics, dict):
    raise RuntimeError("collect_metrics() did not return a dictionary")

required = [
    "cpu_pct",
    "mem_pct",
    "disk_pct",
    "load1",
    "uptime_s",
    "proc_count"
]

for key in required:

    if key not in metrics:
        raise RuntimeError(
            "collect_metrics() missing key: " + key
        )

print("Testing collect_ports()...")
ports = agent.collect_ports()
print("Listening ports:", len(ports))

print("Windows agent smoke test: OK")
"@


$probe = & $VenvPy `
  -c $probeCode `
  2>&1


if ($LASTEXITCODE -ne 0) {

  Write-Host ''
  Write-Host '============================================' `
    -ForegroundColor Red

  Write-Host ' WINDOWS AGENT SMOKE TEST FAILED' `
    -ForegroundColor Red

  Write-Host '============================================' `
    -ForegroundColor Red

  Write-Host ''

  $probe |
    ForEach-Object {
      Write-Host $_ -ForegroundColor Red
    }

  Write-Host ''

  throw 'The Windows agent failed its smoke test. The Scheduled Task was NOT created.'
}


Write-Host ''

$probe |
  ForEach-Object {
    Write-Host "   $_"
  }

Write-Host ''
Write-Host '   Windows agent smoke test passed.' `
  -ForegroundColor Green


# ---------------------------------------------------------------- task

Write-Host '   Registering Scheduled Task...'


Unregister-ScheduledTask `
  -TaskName $Task `
  -Confirm:$false `
  -ErrorAction SilentlyContinue


$action = New-ScheduledTaskAction `
  -Execute $runner


$trigger = New-ScheduledTaskTrigger `
  -AtStartup


$principal = New-ScheduledTaskPrincipal `
  -UserId 'SYSTEM' `
  -LogonType ServiceAccount `
  -RunLevel Highest


# No execution time limit:
# this is a long-running loop, not a batch job, and the
# three-day default would silently kill it.

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -RestartCount 999 `
  -RestartInterval (
    New-TimeSpan -Minutes 1
  ) `
  -ExecutionTimeLimit (
    New-TimeSpan -Seconds 0
  )


Register-ScheduledTask `
  -TaskName $Task `
  -Action $action `
  -Trigger $trigger `
  -Principal $principal `
  -Settings $settings `
  -Description 'nodewatch host telemetry and trust verification agent' |
  Out-Null


# ---------------------------------------------------------------- start

Write-Host '   Starting nodewatch agent...'

Start-ScheduledTask `
  -TaskName $Task

Start-Sleep `
  -Seconds 10


# ---------------------------------------------------------------- status

$taskInfo = Get-ScheduledTask `
  -TaskName $Task

$info = $taskInfo |
  Get-ScheduledTaskInfo


Write-Host ''

Write-Host (
  "   Task state:  " +
  $taskInfo.State
)

Write-Host (
  "   Last result: " +
  $info.LastTaskResult +
  "  (0 or 267009 means running)"
)


# ---------------------------------------------------------------- process check

$running = Get-Process `
  -Name python `
  -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Path -eq $VenvPy
  }


if ($running) {

  Write-Host `
    '   Agent process is running.' `
    -ForegroundColor Green

}
else {

  Write-Warning `
    'Agent process not detected. Recent log:'

  $log = Join-Path `
    $Root `
    'state\agent.log'


  if (Test-Path $log) {

    Get-Content `
      $log `
      -Tail 30 |
      ForEach-Object {

        Write-Host `
          "     $_"
      }

  }
  else {

    Write-Host `
      '     (no log yet - run the launcher by hand)'
  }


  Write-Host ''

  Write-Host (
    "     & '" +
    $runner +
    "'"
  )
}


# ---------------------------------------------------------------- done

Write-Host ''

Write-Host `
  'Installed. The host appears in the dashboard within about two minutes.' `
  -ForegroundColor Green

Write-Host (
  "Logs:    Get-Content '" +
  $Root +
  "\state\agent.log' -Tail 20 -Wait"
)

Write-Host (
  "Stop:    Stop-ScheduledTask -TaskName " +
  $Task
)

Write-Host (
  "Start:   Start-ScheduledTask -TaskName " +
  $Task
)

Write-Host (
  "Remove:  Unregister-ScheduledTask -TaskName " +
  $Task +
  " -Confirm:`$false"
)
