#!/usr/bin/env bash
# Update an already-installed nodewatch probe runner to the latest code on
# main, including its pinned dependencies. Like the agent, the probe
# runner does not self-update - it runs whatever was on disk at install
# time. Credentials (/etc/nodewatch/api.env) are untouched. Run as root.
#
#   bash update-probe.sh
set -euo pipefail

REPO="${NW_REPO:-https://github.com/bluntlycoded/nodewatch.git}"
ROOT=/opt/nodewatch-probe
VENV=/opt/nodewatch-api/venv   # the probe runner reuses the API's venv

[[ -d "$ROOT" ]] || { echo "$ROOT does not exist - this host has no nodewatch probe runner to update." >&2; exit 1; }
[[ -d "$VENV" ]] || { echo "$VENV does not exist - run install-api.sh first." >&2; exit 1; }

echo "== updating nodewatch probe runner"

rm -rf /tmp/nodewatch-probe-update-src
git clone --depth 1 "$REPO" /tmp/nodewatch-probe-update-src
cp /tmp/nodewatch-probe-update-src/probe/prober.py "$ROOT/"

# A code-only refresh would silently leave a known-vulnerable dependency
# in place, since the shared venv is otherwise never touched after install.
"$VENV/bin/pip" install -q --upgrade -r /tmp/nodewatch-probe-update-src/probe/requirements.txt

rm -rf /tmp/nodewatch-probe-update-src

systemctl restart nodewatch-probe
sleep 5
systemctl is-active nodewatch-probe
journalctl -u nodewatch-probe -n 15 --no-pager
