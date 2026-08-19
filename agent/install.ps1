# nodewatch agent installer for Windows. Run in an elevated PowerShell.
#
#   $env:NW_INGEST_URL   = 'https://ingest.example.com'
#   $env:NW_ENROLL_TOKEN = '<token from the dashboard>'
#   $env:NW_SITE         = 'VIT-AP Lab'
#   irm https://raw.githubusercontent.com/bluntlycoded/nodewatch/main/agent/install.ps1 | iex
#
# Administrator rights are required: the Security event log, BitLocker state
# and Defender status are not readable otherwise, and the service must run
# as SYSTEM to keep reading them.

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this in an elevated PowerShell (Run as administrator).'
}

if (-not $env:NW_INGEST_URL)   { throw 'Set NW_INGEST_URL first.' }
if (-not $env:NW_ENROLL_TOKEN) { throw 'Set NW_ENROLL_TOKEN first - Windows hosts have no cloud identity, so an invitation is required.' }

$Root = 'C:\Program Files\nodewatch'
$Repo = if ($env:NW_REPO) { $env:NW_REPO } else { 'https://github.com/bluntlycoded/nodewatch' }

Write-Host '== nodewatch agent install'

# ── Python ──
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) {
  Write-Host 'Installing Python via winget...'
  winget install --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements
  $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
              [System.Environment]::GetEnvironmentVariable('Path','User')
  $py = Get-Command python -ErrorAction SilentlyContinue
  if (-not $py) { throw 'Python install failed. Install Python 3.10+ and re-run.' }
}
$ver = (& python -c "import sys;print('%d.%d'%sys.version_info[:2])")
if ([version]$ver -lt [version]'3.10') { throw "Python $ver found; 3.10 or newer is required." }

# ── files ──
New-Item -ItemType Directory -Force -Path $Root, "$Root\state" | Out-Null
$zip = "$env:TEMP\nodewatch.zip"
Invoke-WebRequest "$Repo/archive/refs/heads/main.zip" -OutFile $zip
Expand-Archive $zip "$env:TEMP\nw" -Force
Copy-Item "$env:TEMP\nw\nodewatch-main\agent\*.py" $Root -Force
Remove-Item $zip, "$env:TEMP\nw" -Recurse -Force

& python -m venv "$Root\venv"
& "$Root\venv\Scripts\python.exe" -m pip install -q --upgrade pip
& "$Root\venv\Scripts\python.exe" -m pip install -q psutil requests

# ── service ──
# Environment goes in the registry rather than the command line so the token
# is not visible in the process list.
$svc = 'nodewatch-agent'
if (Get-Service $svc -ErrorAction SilentlyContinue) {
  Stop-Service $svc -Force -ErrorAction SilentlyContinue
  sc.exe delete $svc | Out-Null
  Start-Sleep -Seconds 2
}

$envBlock = @(
  "NW_INGEST_URL=$($env:NW_INGEST_URL)",
  "NW_ENROLL_TOKEN=$($env:NW_ENROLL_TOKEN)",
  "NW_STATE_DIR=$Root\state",
  "NW_PROVIDER=generic"
)
if ($env:NW_SITE) { $envBlock += "NW_SITE=$($env:NW_SITE)" }

New-Service -Name $svc -DisplayName 'nodewatch agent' -StartupType Automatic `
  -BinaryPathName "`"$Root\venv\Scripts\python.exe`" `"$Root\agent.py`"" | Out-Null

$key = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
New-ItemProperty -Path $key -Name Environment -PropertyType MultiString -Value $envBlock -Force | Out-Null
New-ItemProperty -Path $key -Name Description -PropertyType String `
  -Value 'Host telemetry and trust verification agent' -Force | Out-Null

# Restart on failure rather than staying dead after a transient error.
sc.exe failure $svc reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null

Start-Service $svc
Start-Sleep -Seconds 8
Get-Service $svc | Format-List Name, Status, StartType

Write-Host ''
Write-Host 'Installed. The host appears in the dashboard within about two minutes.'
Write-Host "Logs: Get-Content '$Root\state\agent.log' -Tail 20 -Wait"
