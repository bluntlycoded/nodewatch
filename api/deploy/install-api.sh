#!/usr/bin/env bash
# Run on the nw-api instance as root.
set -euo pipefail

apt-get update -q
apt-get install -y python3-venv python3-pip

id -u nodewatch &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin nodewatch

mkdir -p /opt/nodewatch-api /etc/nodewatch
python3 -m venv /opt/nodewatch-api/venv
/opt/nodewatch-api/venv/bin/pip install -q --upgrade pip
/opt/nodewatch-api/venv/bin/pip install -q -r /opt/nodewatch-api/requirements.txt
chown -R nodewatch:nodewatch /opt/nodewatch-api

if [[ ! -f /etc/nodewatch/api.env ]]; then
  echo "FATAL: create /etc/nodewatch/api.env first (see api.env.example)" >&2
  exit 1
fi
chmod 600 /etc/nodewatch/api.env

install -m644 /opt/nodewatch-api/deploy/nodewatch-api.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nodewatch-api
sleep 3
systemctl --no-pager --lines=20 status nodewatch-api || true
curl -s localhost:8000/health && echo
