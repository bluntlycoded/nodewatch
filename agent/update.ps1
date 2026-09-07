# Update an already-installed nodewatch Windows agent to the latest code
# on main, including its pinned dependencies. Enrolment state and the
# Scheduled Task (which holds the ingest URL and token as environment
# variables) are untouched, so this does not re-enrol or need any
# credentials. Run in an elevated PowerShell.
#
#   irm https://raw.githubusercontent.com/bluntlycoded/nodewatch/main/agent/update.ps1 | iex

$ErrorActionPreference = 'Stop'

$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this in an elevated PowerShell (Run as administrator).'
}

$Root = 'C:\Program Files\nodewatch'
$Task = 'nodewatch-agent'
$Repo = if ($env:NW_REPO) { $env:NW_REPO } else { 'https://github.com/bluntlycoded/nodewatch' }

if (-not (Test-Path $Root)) {
    throw "$Root does not exist - this host has no nodewatch agent to update."
}

Write-Host '== updating nodewatch agent'

$zip = Join-Path $env:TEMP 'nodewatch-update.zip'
$ext = Join-Path $env:TEMP 'nodewatch-update-src'
Remove-Item $ext -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $zip -Force -ErrorAction SilentlyContinue

Invoke-WebRequest "$Repo/archive/refs/heads/main.zip" -OutFile $zip -UseBasicParsing
Expand-Archive $zip $ext -Force

$sourceAgent = Join-Path $ext 'nodewatch-main\agent'
if (-not (Test-Path $sourceAgent)) {
    throw "Agent directory was not found. Expected: $sourceAgent"
}

Stop-ScheduledTask -TaskName $Task -ErrorAction SilentlyContinue
Copy-Item (Join-Path $sourceAgent '*.py') $Root -Force

# A code-only refresh would silently leave a known-vulnerable dependency
# in place, since the venv is otherwise never touched after install.
$VenvPy = "$Root\venv\Scripts\python.exe"
$reqs = Join-Path $sourceAgent 'requirements.txt'
if ((Test-Path $VenvPy) -and (Test-Path $reqs)) {
    & $VenvPy -m pip install -q --upgrade -r $reqs
}

Remove-Item $zip -Force
Remove-Item $ext -Recurse -Force

Start-ScheduledTask -TaskName $Task
Start-Sleep -Seconds 5

Write-Host ''
Write-Host 'Updated.' -ForegroundColor Green
Get-ScheduledTaskInfo -TaskName $Task
