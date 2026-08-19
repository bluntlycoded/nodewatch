#!/usr/bin/env bash
# nodewatch agent installer for macOS. Run with sudo.
#
#   sudo NW_INGEST_URL=https://ingest.example.com \
#        NW_ENROLL_TOKEN=<token from the dashboard> \
#        NW_SITE="VIT-AP Lab" \
#        bash install-macos.sh
#
# Root is required: the Security-relevant checks (FileVault, SIP, firewall)
# and unified-log reads are privileged, and launchd needs to own the daemon.
set -euo pipefail

: "${NW_INGEST_URL:?set NW_INGEST_URL}"
: "${NW_ENROLL_TOKEN:?macOS hosts have no cloud identity, so NW_ENROLL_TOKEN is required}"
NW_SITE="${NW_SITE:-}"
REPO="${NW_REPO:-https://github.com/bluntlycoded/nodewatch}"
ROOT=/usr/local/nodewatch
PLIST=/Library/LaunchDaemons/com.nodewatch.agent.plist

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }

echo "== nodewatch agent install"

PY=$(command -v python3 || true)
[[ -n "$PY" ]] || { echo "Install Python 3.10+ (xcode-select --install, or python.org)." >&2; exit 1; }
"$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)' \
  || { echo "Python 3.10+ required; found $($PY -V)." >&2; exit 1; }

mkdir -p "$ROOT" "$ROOT/state"
TMP=$(mktemp -d)
curl -fsSL "$REPO/archive/refs/heads/main.zip" -o "$TMP/nw.zip"
unzip -q "$TMP/nw.zip" -d "$TMP"
cp "$TMP"/nodewatch-main/agent/*.py "$ROOT/"
rm -rf "$TMP"

"$PY" -m venv "$ROOT/venv"
"$ROOT/venv/bin/pip" install -q --upgrade pip
"$ROOT/venv/bin/pip" install -q psutil requests

# launchd reads the plist as root, so 600 keeps the token off other accounts.
cat > "$PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.nodewatch.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$ROOT/venv/bin/python</string>
    <string>$ROOT/agent.py</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NW_INGEST_URL</key><string>$NW_INGEST_URL</string>
    <key>NW_ENROLL_TOKEN</key><string>$NW_ENROLL_TOKEN</string>
    <key>NW_STATE_DIR</key><string>$ROOT/state</string>
    <key>NW_PROVIDER</key><string>generic</string>
$( [[ -n "$NW_SITE" ]] && printf '    <key>NW_SITE</key><string>%s</string>\n' "$NW_SITE" )
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$ROOT/state/agent.log</string>
  <key>StandardErrorPath</key><string>$ROOT/state/agent.log</string>
</dict>
</plist>
PLIST
chmod 600 "$PLIST"

launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 8
launchctl print system/com.nodewatch.agent | head -8 || true
echo
echo "Installed. Logs: tail -f $ROOT/state/agent.log"
echo "If posture checks report 'needs root', grant Full Disk Access to"
echo "$ROOT/venv/bin/python in System Settings > Privacy & Security."
