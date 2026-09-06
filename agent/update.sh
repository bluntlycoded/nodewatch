#!/usr/bin/env bash
# Update an already-installed nodewatch Linux agent to the latest code on
# main. Only overwrites the agent's .py files - enrolment state, the venv
# and the systemd unit (which holds the ingest URL and token) are
# untouched, so this does not re-enrol or need any credentials. Run as root.
#
#   bash update.sh
set -euo pipefail

REPO="${NW_REPO:-https://github.com/bluntlycoded/nodewatch.git}"
ROOT=/opt/nodewatch

[[ -d "$ROOT" ]] || { echo "$ROOT does not exist - this host has no nodewatch agent to update." >&2; exit 1; }

echo "== updating nodewatch agent"

rm -rf /tmp/nodewatch-update-src
git clone --depth 1 "$REPO" /tmp/nodewatch-update-src
cp /tmp/nodewatch-update-src/agent/*.py "$ROOT/"
rm -rf /tmp/nodewatch-update-src

systemctl restart nodewatch-agent
sleep 5
systemctl is-active nodewatch-agent
journalctl -u nodewatch-agent -n 15 --no-pager
