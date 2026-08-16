#!/usr/bin/env bash
# Run on each monitored node as root, via SSM Run Command.
# Set NW_INGEST_URL to the API box's PRIVATE ip, not localhost:
# over loopback the source address is 127.0.0.1 and enrolment will 403.
set -euo pipefail
: "${NW_INGEST_URL:?set NW_INGEST_URL=http://<api-private-ip>:8000}"

apt-get update -q
apt-get install -y python3-venv python3-pip

mkdir -p /opt/nodewatch /var/lib/nodewatch
python3 -m venv /opt/nodewatch/venv
/opt/nodewatch/venv/bin/pip install -q --upgrade pip
/opt/nodewatch/venv/bin/pip install -q psutil requests

sed -i "s|^Environment=NW_INGEST_URL=.*|Environment=NW_INGEST_URL=${NW_INGEST_URL}|" \
  /opt/nodewatch/nodewatch-agent.service
install -m644 /opt/nodewatch/nodewatch-agent.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nodewatch-agent
sleep 3
journalctl -u nodewatch-agent --no-pager -n 20
