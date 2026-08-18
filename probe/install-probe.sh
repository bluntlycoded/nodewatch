#!/usr/bin/env bash
# Install the probe runner on the API host. Reuses the API's virtualenv and
# its database credentials, so there is nothing new to configure.
set -euo pipefail

[[ -f /etc/nodewatch/api.env ]] || { echo "run install-api.sh first" >&2; exit 1; }

apt-get update -q
# Needed for ICMP checks. Without it, ping probes report the binary missing
# and every other probe type still works.
apt-get install -y iputils-ping

mkdir -p /opt/nodewatch-probe
cp "$(dirname "$0")/prober.py" /opt/nodewatch-probe/

install -m644 "$(dirname "$0")/nodewatch-probe.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nodewatch-probe
sleep 6
systemctl --no-pager --lines=15 status nodewatch-probe || true
