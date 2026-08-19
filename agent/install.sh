#!/usr/bin/env bash
# nodewatch agent installer for any Linux host: on-premise, GCP, Azure,
# a VPS, or AWS. Run as root.
#
#   NW_INGEST_URL=https://ingest.example.com \
#   NW_ENROLL_TOKEN=<token from the dashboard> \
#   bash install.sh
#
# The token is required on hosts with no cloud metadata service, because
# nothing else can vouch for them. On AWS, GCP and Azure the provider's
# signed identity is used and the token is optional.
set -euo pipefail

: "${NW_INGEST_URL:?set NW_INGEST_URL, e.g. http://10.0.0.5:8000}"
NW_ENROLL_TOKEN="${NW_ENROLL_TOKEN:-}"
NW_PROVIDER="${NW_PROVIDER:-}"
NW_SITE="${NW_SITE:-}"
REPO="${NW_REPO:-https://github.com/bluntlycoded/nodewatch.git}"

echo "== nodewatch agent install"

if command -v apt-get >/dev/null; then
  apt-get update -q && apt-get install -y git python3-venv python3-pip
elif command -v dnf >/dev/null; then
  dnf install -y git python3 python3-pip
elif command -v yum >/dev/null; then
  yum install -y git python3 python3-pip
else
  echo "No supported package manager found. Install git and python3 first." >&2
  exit 1
fi

rm -rf /tmp/nodewatch-src
git clone --depth 1 "$REPO" /tmp/nodewatch-src

mkdir -p /opt/nodewatch /var/lib/nodewatch
cp /tmp/nodewatch-src/agent/*.py /opt/nodewatch/

python3 -m venv /opt/nodewatch/venv
/opt/nodewatch/venv/bin/pip install -q --upgrade pip
/opt/nodewatch/venv/bin/pip install -q psutil requests

{
  echo "[Unit]"
  echo "Description=nodewatch agent"
  echo "After=network-online.target"
  echo "Wants=network-online.target"
  echo
  echo "[Service]"
  echo "Type=simple"
  echo "User=root"
  # Quote every value: systemd splits an unquoted Environment= line on
  # whitespace, so NW_SITE="VIT-AP Lab" silently became two assignments and
  # the second one was discarded as invalid.
  echo "Environment=\"NW_INGEST_URL=${NW_INGEST_URL}\""
  echo "Environment=\"NW_STATE_DIR=/var/lib/nodewatch\""
  [ -n "$NW_ENROLL_TOKEN" ] && echo "Environment=\"NW_ENROLL_TOKEN=${NW_ENROLL_TOKEN}\""
  [ -n "$NW_PROVIDER" ]     && echo "Environment=\"NW_PROVIDER=${NW_PROVIDER}\""
  [ -n "$NW_SITE" ]         && echo "Environment=\"NW_SITE=${NW_SITE}\""
  echo "ExecStart=/opt/nodewatch/venv/bin/python /opt/nodewatch/agent.py"
  echo "Restart=always"
  echo "RestartSec=10"
  echo
  echo "[Install]"
  echo "WantedBy=multi-user.target"
} > /etc/systemd/system/nodewatch-agent.service

# The unit holds the enrolment token, so it must not be world readable.
chmod 600 /etc/systemd/system/nodewatch-agent.service

systemctl daemon-reload
systemctl enable --now nodewatch-agent
sleep 8
systemctl is-active nodewatch-agent
journalctl -u nodewatch-agent -n 15 --no-pager
