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

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an elevated PowerShell (Run as administrator).'
}

if (-not $env:NW_INGEST_URL) { throw 'Set NW_INGEST_URL first.' }
if (-not $env:NW_ENROLL_TOKEN) {
  throw 'Set NW_ENROLL_TOKEN first - Windows hosts have no cloud identity, so an invitation is required.'
}

$Root = 'C:\Program Files\nodewatch'
$Repo = if ($env:NW_REPO) { $env:NW_REPO } else { 'https://github.com/bluntlycoded/nodewatch' }
$Task = 'nodewatch-agent'

Write-Host '== nodewatch agent install'

# ---------------------------------------------------------------- python
# Windows ships "App execution aliases" that make `python` a Microsoft Store
# stub: it produces no output and opens the Store instead. Detect a real
# interpreter rather than trusting the name to resolve.
function Find-Python {
  $candidates = @()

  if (Get-Command py -ErrorAction SilentlyContinue) {
    $candidates += ,@('py', @('-3'))
  }
  foreach ($c in @('python', 'python3')) {
    $cmd = Get-Command $c -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notlike '*WindowsApps*') {
      $candidates += ,@($cmd.Source, @())
    }
  }
  foreach ($p in @(
      "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
      "$env:ProgramFiles\Python3*\python.exe",
      'C:\Python3*\python.exe')) {
    Get-ChildItem $p -ErrorAction SilentlyContinue |
      Sort-Object FullName -Descending |
      ForEach-Object { $candidates += ,@($_.FullName, @()) }
  }

  foreach ($cand in $candidates) {
    $exe = $cand[0]
    $pre = $cand[1]
    try {
      $out = & $exe @pre -c "import sys;print('%d.%d' % sys.version_info[:2])" 2>$null
    } catch { continue }
    if (-not $out) { continue }
    $v = ($out | Select-Object -First 1).ToString().Trim()
    if ($v -match '^\d+\.\d+$' -and [version]$v -ge [version]'3.10') {
      return ,@($exe, $pre, $v)
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
  winget install --id Python.Python.3.12 --scope machine --silent `
    --accept-source-agreements --accept-package-agreements
  $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
              [Environment]::GetEnvironmentVariable('Path', 'User')
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
New-Item -ItemType Directory -Force -Path $Root, "$Root\state" | Out-Null
$zip = Join-Path $env:TEMP 'nodewatch.zip'
$ext = Join-Path $env:TEMP 'nodewatch-src'
Remove-Item $ext -Recurse -Force -ErrorAction SilentlyContinue
Invoke-WebRequest "$Repo/archive/refs/heads/main.zip" -OutFile $zip -UseBasicParsing
Expand-Archive $zip $ext -Force
Copy-Item (Join-Path $ext 'nodewatch-main\agent\*.py') $Root -Force
Remove-Item $zip -Force
Remove-Item $ext -Recurse -Force

& $PyExe @PyPre -m venv "$Root\venv"
$VenvPy = "$Root\venv\Scripts\python.exe"
if (-not (Test-Path $VenvPy)) { throw "Virtualenv creation failed at $Root\venv" }
& $VenvPy -m pip install -q --upgrade pip
& $VenvPy -m pip install -q psutil requests

# ---------------------------------------------------------------- launcher
# A scheduled task cannot carry environment variables directly, so a small
# wrapper sets them and runs the agent. It holds the enrolment token, so its
# ACL is reduced to SYSTEM and Administrators only.
$runner = Join-Path $Root 'run-agent.cmd'
$lines = @(
  '@echo off',
  "set NW_INGEST_URL=$env:NW_INGEST_URL",
  "set NW_ENROLL_TOKEN=$env:NW_ENROLL_TOKEN",
  "set NW_STATE_DIR=$Root\state",
  'set NW_PROVIDER=generic'
)
if ($env:NW_SITE) { $lines += "set NW_SITE=$env:NW_SITE" }
$lines += ('"' + $VenvPy + '" "' + $Root + '\agent.py"')
Set-Content -Path $runner -Value $lines -Encoding ASCII

icacls $runner /inheritance:r /grant:r 'SYSTEM:(F)' 'Administrators:(F)' | Out-Null

# ---------------------------------------------------------------- task
Unregister-ScheduledTask -TaskName $Task -Confirm:$false -ErrorAction SilentlyContinue

$action    = New-ScheduledTaskAction -Execute $runner
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' `
             -LogonType ServiceAccount -RunLevel Highest
# No execution time limit: this is a long-running loop, not a batch job, and
# the three-day default would silently kill it.
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
             -DontStopIfGoingOnBatteries -StartWhenAvailable `
             -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
             -ExecutionTimeLimit (New-TimeSpan -Seconds 0)

Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger `
  -Principal $principal -Settings $settings `
  -Description 'nodewatch host telemetry and trust verification agent' | Out-Null

Start-ScheduledTask -TaskName $Task
Start-Sleep -Seconds 10

$info = Get-ScheduledTask -TaskName $Task | Get-ScheduledTaskInfo
Write-Host ''
Write-Host ("   Task state:  " + (Get-ScheduledTask -TaskName $Task).State)
Write-Host ("   Last result: " + $info.LastTaskResult + "  (0 or 267009 means running)")

$running = Get-Process -Name python -ErrorAction SilentlyContinue |
           Where-Object { $_.Path -eq $VenvPy }
if ($running) {
  Write-Host '   Agent process is running.'
} else {
  Write-Warning 'Agent process not detected. Run the launcher by hand to see the error:'
  Write-Host ("     & '" + $runner + "'")
}

Write-Host ''
Write-Host 'Installed. The host appears in the dashboard within about two minutes.'
Write-Host ("Stop:    Stop-ScheduledTask -TaskName " + $Task)
Write-Host ("Start:   Start-ScheduledTask -TaskName " + $Task)
Write-Host ("Remove:  Unregister-ScheduledTask -TaskName " + $Task + " -Confirm:`$false")
