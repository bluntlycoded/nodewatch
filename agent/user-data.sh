#!/bin/bash
# nodewatch agent bootstrap - paste into the User data field of an EC2
# launch template. Runs once, as root, on first boot.
#
# The node enrols itself and appears in the dashboard within a minute of
# becoming reachable. No SSM step, no manual copy.

set -euxo pipefail
exec > >(tee /var/log/nodewatch-bootstrap.log) 2>&1

INGEST_URL="http://172.31.30.90:8000"
REPO="https://github.com/bluntlycoded/nodewatch.git"

echo "== nodewatch bootstrap starting $(date -Is)"

# Wait for network. cloud-init can run before DNS is usable.
for i in $(seq 30); do
  getent hosts github.com >/dev/null 2>&1 && break
  echo "waiting for DNS ($i)"; sleep 2
done

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y git python3-venv python3-pip

rm -rf /tmp/nodewatch-src
git clone --depth 1 "$REPO" /tmp/nodewatch-src

mkdir -p /opt/nodewatch /var/lib/nodewatch
cp /tmp/nodewatch-src/agent/*.py /opt/nodewatch/

python3 -m venv /opt/nodewatch/venv
/opt/nodewatch/venv/bin/pip install -q --upgrade pip
/opt/nodewatch/venv/bin/pip install -q psutil requests

cat > /etc/systemd/system/nodewatch-agent.service <<EOF
[Unit]
Description=nodewatch agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Environment=NW_INGEST_URL=${INGEST_URL}
Environment=NW_STATE_DIR=/var/lib/nodewatch
ExecStart=/opt/nodewatch/venv/bin/python /opt/nodewatch/agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now nodewatch-agent

sleep 15
systemctl is-active nodewatch-agent
journalctl -u nodewatch-agent -n 20 --no-pager

echo "== nodewatch bootstrap done $(date -Is)"
