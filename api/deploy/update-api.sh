#!/usr/bin/env bash
# Update an already-installed nodewatch ingest API to the latest code on
# main, including its pinned dependencies. Like the agent and the probe
# runner, this service does not self-update - it runs whatever was on
# disk at install time. /etc/nodewatch/api.env (credentials) is untouched.
# Run as root.
#
#   bash update-api.sh
set -euo pipefail

REPO="${NW_REPO:-https://github.com/bluntlycoded/nodewatch.git}"
ROOT=/opt/nodewatch-api

[[ -d "$ROOT" ]] || { echo "$ROOT does not exist - run install-api.sh first." >&2; exit 1; }

echo "== updating nodewatch ingest API"

rm -rf /tmp/nodewatch-api-update-src
git clone --depth 1 "$REPO" /tmp/nodewatch-api-update-src
cp /tmp/nodewatch-api-update-src/api/app.py "$ROOT/"

# A code-only refresh would silently leave a known-vulnerable dependency
# in place, since the venv is otherwise never touched after install.
"$ROOT/venv/bin/pip" install -q --upgrade -r /tmp/nodewatch-api-update-src/api/requirements.txt

rm -rf /tmp/nodewatch-api-update-src

# The service runs as the unprivileged nodewatch user; this script runs
# as root to reach the venv and systemctl, so ownership has to be
# restored or the service can't read what was just written.
chown -R nodewatch:nodewatch "$ROOT"

systemctl restart nodewatch-api
sleep 5
systemctl is-active nodewatch-api
curl -s localhost:8000/health && echo
journalctl -u nodewatch-api -n 15 --no-pager
