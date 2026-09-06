#!/usr/bin/env bash
# Update an already-installed nodewatch macOS agent to the latest code on
# main. Only overwrites the agent's .py files - enrolment state, the venv
# and the launchd plist (which holds the ingest URL and token) are
# untouched, so this does not re-enrol or need any credentials. Run with sudo.
#
#   sudo bash update-macos.sh
set -euo pipefail

REPO="${NW_REPO:-https://github.com/bluntlycoded/nodewatch}"
ROOT=/usr/local/nodewatch
PLIST=/Library/LaunchDaemons/com.nodewatch.agent.plist

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
[[ -d "$ROOT" ]] || { echo "$ROOT does not exist - this host has no nodewatch agent to update." >&2; exit 1; }

echo "== updating nodewatch agent"

TMP=$(mktemp -d)
curl -fsSL "$REPO/archive/refs/heads/main.zip" -o "$TMP/nw.zip"
unzip -q "$TMP/nw.zip" -d "$TMP"
cp "$TMP"/nodewatch-main/agent/*.py "$ROOT/"
rm -rf "$TMP"

launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
sleep 5
launchctl print system/com.nodewatch.agent | head -8
echo
echo "Updated. Logs: tail -f $ROOT/state/agent.log"
