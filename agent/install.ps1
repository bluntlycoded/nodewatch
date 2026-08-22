# nodewatch Windows agent installer
#
# Run this script in an elevated PowerShell.
#
# Example:
#
#   $env:NW_INGEST_URL   = 'https://ingest.example.com'
#   $env:NW_ENROLL_TOKEN = '<token from dashboard>'
#   $env:NW_SITE         = 'VIT-AP Lab'
#
#   irm https://raw.githubusercontent.com/bluntlycoded/nodewatch/main/agent/install.ps1 | iex
#
# The agent runs as a Scheduled Task under SYSTEM.


$ErrorActionPreference = 'Stop'


# ============================================================
# ADMIN CHECK
# ============================================================

$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

$currentPrincipal = New-Object `
    Security.Principal.WindowsPrincipal(
        $currentIdentity
    )

if (-not $currentPrincipal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw 'Run this in an elevated PowerShell (Run as administrator).'
}


# ============================================================
# CONFIGURATION
# ============================================================

if (-not $env:NW_INGEST_URL) {
    throw 'Set NW_INGEST_URL first.'
}

if (-not $env:NW_ENROLL_TOKEN) {
    throw 'Set NW_ENROLL_TOKEN first.'
}


$Root = 'C:\Program Files\nodewatch'

if ($env:NW_REPO) {
    $Repo = $env:NW_REPO
}
else {
    $Repo = 'https://github.com/bluntlycoded/nodewatch'
}

$Task = 'nodewatch-agent'


Write-Host ''
Write-Host '============================================'
Write-Host '       nodewatch Windows Agent Install'
Write-Host '============================================'
Write-Host ''


# ============================================================
# PYTHON DETECTION
# ============================================================

function Find-Python {

    $candidates = @()


    # --------------------------------------------------------
    # Python launcher
    # --------------------------------------------------------

    if (Get-Command py -ErrorAction SilentlyContinue) {

        $candidates += ,@(
            'py',
            @('-3')
        )
    }


    # --------------------------------------------------------
    # python / python3
    # --------------------------------------------------------

    foreach ($c in @('python', 'python3')) {

        $cmd = Get-Command `
            $c `
            -ErrorAction SilentlyContinue

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


    # --------------------------------------------------------
    # Common installation paths
    # --------------------------------------------------------

    foreach ($p in @(
        "$env:LOCALAPPDATA\Programs\Python\Python3*\python.exe",
        "$env:ProgramFiles\Python3*\python.exe",
        'C:\Python3*\python.exe'
    )) {

        Get-ChildItem `
            $p `
            -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            ForEach-Object {

                $candidates += ,@(
                    $_.FullName,
                    @()
                )
            }
    }


    # --------------------------------------------------------
    # Test candidates
    # --------------------------------------------------------

    foreach ($cand in $candidates) {

        $exe = $cand[0]
        $pre = $cand[1]

        try {

            $out = & $exe @pre `
                -c "import sys;print('%d.%d' % sys.version_info[:2])" `
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


Write-Host 'Checking Python...'


$py = Find-Python


# ============================================================
# INSTALL PYTHON IF REQUIRED
# ============================================================

if (-not $py) {

    Write-Host ''
    Write-Host 'No usable Python 3.10+ found.'
    Write-Host 'Attempting to install Python 3.12 using winget...'


    if (-not (
        Get-Command winget `
        -ErrorAction SilentlyContinue
    )) {

        throw @'
Python 3.10+ is required and winget is unavailable.

Install Python from python.org with:
"Add python.exe to PATH"

Then run this installer again.
'@
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

        throw @'
Python was installed but could not be detected.

Open:

Settings
  >
Apps
  >
Advanced app settings
  >
App execution aliases

Turn off the python.exe alias and run the installer again.
'@
    }
}


$PyExe = $py[0]
$PyPre = $py[1]
$PyVer = $py[2]


Write-Host ''
Write-Host "Python $PyVer detected."
Write-Host "Python path: $PyExe"
Write-Host ''


# ============================================================
# CREATE NODEWATCH DIRECTORIES
# ============================================================

Write-Host 'Creating nodewatch directories...'


New-Item `
    -ItemType Directory `
    -Force `
    -Path $Root |
    Out-Null


New-Item `
    -ItemType Directory `
    -Force `
    -Path "$Root\state" |
    Out-Null


Write-Host 'Directories ready.'
Write-Host ''


# ============================================================
# DOWNLOAD NODEWATCH
# ============================================================

Write-Host 'Downloading nodewatch from GitHub...'


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


Remove-Item `
    $zip `
    -Force `
    -ErrorAction SilentlyContinue


$downloadUrl =
    "$Repo/archive/refs/heads/main.zip"


Write-Host "URL: $downloadUrl"


Invoke-WebRequest `
    $downloadUrl `
    -OutFile $zip `
    -UseBasicParsing


if (-not (Test-Path $zip)) {
    throw 'Failed to download nodewatch source.'
}


Write-Host 'Source downloaded.'


# ============================================================
# EXTRACT SOURCE
# ============================================================

Write-Host 'Extracting source...'


Expand-Archive `
    $zip `
    $ext `
    -Force


$sourceAgent =
    Join-Path `
        $ext `
        'nodewatch-main\agent'


if (-not (Test-Path $sourceAgent)) {

    throw @"
Agent directory was not found.

Expected:
$sourceAgent

Check that the GitHub repository contains:
agent/
"@
}


# ============================================================
# COPY AGENT FILES
# ============================================================

Write-Host 'Copying agent files...'


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


Write-Host 'Agent files copied.'
Write-Host ''


# ============================================================
# VERIFY REQUIRED FILES
# ============================================================

Write-Host 'Checking required files...'


$requiredFiles = @(
    'agent.py',
    'osdetect.py',
    'os_windows.py',
    'inventory.py',
    'checks.py',
    'identity.py'
)


foreach ($f in $requiredFiles) {

    $file = Join-Path `
        $Root `
        $f


    if (-not (Test-Path $file)) {

        throw @"
Required file is missing:

$f

Expected location:

$file
"@
    }


    Write-Host "  OK  $f"
}


Write-Host ''
Write-Host 'All required files found.'
Write-Host ''


# ============================================================
# PYTHON VIRTUAL ENVIRONMENT
# ============================================================

Write-Host 'Creating Python virtual environment...'


$VenvDir = "$Root\venv"


if (Test-Path $VenvDir) {

    Write-Host 'Existing virtual environment found.'
    Write-Host 'Reusing existing environment.'
}
else {

    & $PyExe @PyPre `
        -m venv `
        $VenvDir


    if ($LASTEXITCODE -ne 0) {

        throw 'Python virtual environment creation failed.'
    }
}


$VenvPy =
    "$VenvDir\Scripts\python.exe"


if (-not (Test-Path $VenvPy)) {

    throw @"
Virtual environment was not created correctly.

Expected:

$VenvPy
"@
}


Write-Host "Virtual environment: $VenvDir"
Write-Host ''


# ============================================================
# INSTALL PYTHON DEPENDENCIES
# ============================================================

Write-Host 'Installing Python dependencies...'


& $VenvPy `
    -m pip `
    install `
    --upgrade `
    pip


if ($LASTEXITCODE -ne 0) {

    throw 'pip upgrade failed.'
}


& $VenvPy `
    -m pip `
    install `
    psutil `
    requests


if ($LASTEXITCODE -ne 0) {

    throw 'Python dependency installation failed.'
}


Write-Host ''
Write-Host 'Python dependencies installed.'
Write-Host ''


# ============================================================
# CREATE LAUNCHER
# ============================================================

Write-Host 'Creating agent launcher...'


$runner =
    Join-Path `
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


if (-not (Test-Path $runner)) {

    throw 'Failed to create run-agent.cmd.'
}


Write-Host "Launcher created: $runner"
Write-Host ''


# ============================================================
# SECURE LAUNCHER
# ============================================================

Write-Host 'Securing launcher permissions...'


icacls `
    $runner `
    /inheritance:r `
    /grant:r `
    '*S-1-5-18:(F)' `
    '*S-1-5-32-544:(F)' |
    Out-Null


Write-Host 'Launcher permissions configured.'
Write-Host ''


# ============================================================
# WINDOWS AGENT SMOKE TEST
# ============================================================

Write-Host ''
Write-Host '============================================'
Write-Host '      Windows Agent Smoke Test'
Write-Host '============================================'
Write-Host ''


$probeCode = @"
import sys
import platform

sys.path.insert(0, r'$Root')

print("Operating system:", platform.system())
print("Windows version:", platform.version())

import agent
import osdetect

print("agent.py imported successfully")
print("osdetect.py imported successfully")

print("Agent version:", agent.AGENT_VERSION)

print("")
print("Testing platform_string()...")

try:
    p = agent.platform_string()
    print("Platform:", p)
except Exception as e:
    print("WARNING: platform_string() failed:", repr(e))

print("")
print("Testing collect_metrics()...")

metrics = agent.collect_metrics()

print("")
print("Metrics returned:")
print(metrics)

if not isinstance(metrics, dict):
    raise RuntimeError(
        "collect_metrics() did not return a dictionary"
    )

required = [
    "cpu_pct",
    "mem_pct",
    "disk_pct",
    "load1",
    "uptime_s",
    "proc_count"
]

print("")
print("Checking required metrics...")

for key in required:

    if key not in metrics:

        raise RuntimeError(
            "collect_metrics() missing key: " + key
        )

    print(
        "  OK:",
        key,
        "=",
        metrics[key]
    )

print("")
print("Testing collect_ports()...")

ports = agent.collect_ports()

print(
    "collect_ports() returned",
    len(ports),
    "ports"
)

print("")
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

            Write-Host `
                $_ `
                -ForegroundColor Red
        }


    Write-Host ''
    Write-Host 'The Scheduled Task was NOT created.'
    Write-Host ''

    throw 'The Windows agent failed its smoke test.'
}


Write-Host ''

$probe |
    ForEach-Object {

        Write-Host `
            "   $_"
    }


Write-Host ''
Write-Host 'Windows agent smoke test PASSED.' `
    -ForegroundColor Green
Write-Host ''


# ============================================================
# REMOVE OLD SCHEDULED TASK
# ============================================================

Write-Host 'Removing existing nodewatch Scheduled Task...'


Unregister-ScheduledTask `
    -TaskName $Task `
    -Confirm:$false `
    -ErrorAction SilentlyContinue


# ============================================================
# CREATE SCHEDULED TASK
# ============================================================

Write-Host 'Creating Scheduled Task...'


$action =
    New-ScheduledTaskAction `
        -Execute $runner


$trigger =
    New-ScheduledTaskTrigger `
        -AtStartup


$principal =
    New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest


$settings =
    New-ScheduledTaskSettingsSet `
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


Write-Host 'Scheduled Task created successfully.'
Write-Host ''


# ============================================================
# START AGENT
# ============================================================

Write-Host 'Starting nodewatch agent...'


Start-ScheduledTask `
    -TaskName $Task


Start-Sleep `
    -Seconds 10


# ============================================================
# CHECK TASK
# ============================================================

$task =
    Get-ScheduledTask `
        -TaskName $Task


$info =
    $task |
    Get-ScheduledTaskInfo


Write-Host ''
Write-Host '============================================'
Write-Host '          Agent Status'
Write-Host '============================================'
Write-Host ''


Write-Host (
    'Task state:  ' +
    $task.State
)


Write-Host (
    'Last result: ' +
    $info.LastTaskResult
)


# ============================================================
# CHECK PYTHON PROCESS
# ============================================================

$running =
    Get-Process `
        -Name python `
        -ErrorAction SilentlyContinue |
        Where-Object {

            $_.Path -eq $VenvPy
        }


if ($running) {

    Write-Host ''
    Write-Host 'Agent process is RUNNING.' `
        -ForegroundColor Green

    Write-Host ''
    Write-Host (
        'PID: ' +
        $running.Id
    )

}
else {

    Write-Host ''
    Write-Warning 'Agent process was not detected.'


    $log =
        Join-Path `
            $Root `
            'state\agent.log'


    if (Test-Path $log) {

        Write-Host ''
        Write-Host 'Recent agent log:'
        Write-Host ''


        Get-Content `
            $log `
            -Tail 30 |
            ForEach-Object {

                Write-Host "  $_"
            }

    }
    else {

        Write-Host ''
        Write-Host 'No agent log exists yet.'
    }


    Write-Host ''
    Write-Host 'To run the agent manually:'
    Write-Host ''


    Write-Host (
        "& '" +
        $runner +
        "'"
    )
}


# ============================================================
# COMPLETE
# ============================================================

Write-Host ''
Write-Host '============================================'
Write-Host ' nodewatch Windows agent installed'
Write-Host '============================================'
Write-Host ''


Write-Host `
    'The host should appear in the dashboard within about two minutes.'


Write-Host ''
Write-Host 'Useful commands:'
Write-Host ''


Write-Host (
    "Logs:    Get-Content '" +
    $Root +
    "\state\agent.log' -Tail 30 -Wait"
)


Write-Host (
    'Status:  Get-ScheduledTask -TaskName ' +
    $Task
)


Write-Host (
    'Stop:    Stop-ScheduledTask -TaskName ' +
    $Task
)


Write-Host (
    'Start:   Start-ScheduledTask -TaskName ' +
    $Task
)


Write-Host (
    'Remove:  Unregister-ScheduledTask -TaskName ' +
    $Task +
    ' -Confirm:$false'
)


Write-Host ''
