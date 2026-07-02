#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/fail2ban-ui}"
CONFIG_DIR="${CONFIG_DIR:-/etc/fail2ban-ui}"
STATE_DIR="${STATE_DIR:-/var/lib/fail2ban-ui}"
SERVICE_NAME="${SERVICE_NAME:-fail2ban-ui}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install.sh" >&2
  exit 1
fi

echo "[1/8] Installing system packages"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    fail2ban ipset iproute2 python3 python3-venv python3-pip curl ca-certificates
else
  echo "Unsupported package manager. Install fail2ban, ipset, iproute2, python3-venv manually." >&2
  exit 1
fi

echo "[2/8] Installing app files"
install -d -m 0755 "${APP_DIR}" "${APP_DIR}/templates" "${APP_DIR}/scripts"
install -m 0644 "${SRC_DIR}/app.py" "${APP_DIR}/app.py"
install -m 0644 "${SRC_DIR}/requirements.txt" "${APP_DIR}/requirements.txt"
install -m 0644 "${SRC_DIR}/templates/"*.html "${APP_DIR}/templates/"
install -m 0755 "${SRC_DIR}/scripts/fail2ban_ui_tick.py" "${APP_DIR}/scripts/fail2ban_ui_tick.py"

echo "[3/8] Creating Python environment"
python3 -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --upgrade pip
"${APP_DIR}/.venv/bin/pip" install -r "${APP_DIR}/requirements.txt"

echo "[4/8] Writing environment"
install -d -m 0700 "${CONFIG_DIR}" "${STATE_DIR}"
ENV_FILE="${CONFIG_DIR}/fail2ban-ui.env"
if [[ ! -f "${ENV_FILE}" ]]; then
  SETUP_TOKEN="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"
  cat > "${ENV_FILE}" <<EOF
FAIL2BAN_UI_APP_DIR=${APP_DIR}
FAIL2BAN_UI_CONFIG_PATH=${CONFIG_DIR}/config.json
FAIL2BAN_UI_STATE_PATH=${STATE_DIR}/state.json
FAIL2BAN_UI_SETUP_TOKEN=${SETUP_TOKEN}
FAIL2BAN_UI_BIND_HOST=127.0.0.1
FAIL2BAN_UI_BIND_PORT=2020
EOF
  chmod 0600 "${ENV_FILE}"
else
  SETUP_TOKEN="$(awk -F= '/^FAIL2BAN_UI_SETUP_TOKEN=/{print $2}' "${ENV_FILE}" | tail -1)"
fi

echo "[5/8] Provisioning fail2ban base jails"
install -d -m 0755 /etc/fail2ban/filter.d /etc/fail2ban/jail.d
cat > /etc/fail2ban/filter.d/fail2ban-ui-portscan.conf <<'EOF'
[Definition]
failregex = ^.*F2B-PORTSCAN:.*SRC=<HOST>.*$
            ^.*F2B-SENSITIVE:.*SRC=<HOST>.*$
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/fail2ban-ui-blacklist.conf <<'EOF'
[Definition]
failregex = ^<HOST>$
ignoreregex =
EOF

touch /var/log/fail2ban-ui-blacklist.log
touch /var/log/fail2ban.log
cat > /etc/fail2ban/jail.d/fail2ban-ui.local <<'EOF'
[sshd]
enabled = true
backend = systemd
bantime = 24h
findtime = 10m
maxretry = 5

[portscan]
enabled = true
filter = fail2ban-ui-portscan
backend = systemd
journalmatch = _TRANSPORT=kernel
bantime = 24h
findtime = 10m
maxretry = 3

[sensible-ports]
enabled = true
filter = fail2ban-ui-portscan
backend = systemd
journalmatch = _TRANSPORT=kernel
bantime = 24h
findtime = 10m
maxretry = 1

[recidive-48h]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 48h
findtime = 1d
maxretry = 3

[blacklist-permanent]
enabled = true
filter = fail2ban-ui-blacklist
logpath = /var/log/fail2ban-ui-blacklist.log
bantime = -1
findtime = 1d
maxretry = 1
EOF

systemctl enable --now fail2ban
systemctl restart fail2ban

echo "[6/8] Installing fail2ban-ui service"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Secure Fail2ban UI
After=network-online.target fail2ban.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > "/etc/systemd/system/${SERVICE_NAME}-tick.service" <<EOF
[Unit]
Description=Fail2ban UI decision and notification tick
After=fail2ban.service

[Service]
Type=oneshot
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/scripts/fail2ban_ui_tick.py
EOF

cat > "/etc/systemd/system/${SERVICE_NAME}-tick.timer" <<EOF
[Unit]
Description=Run Fail2ban UI decisions periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s

[Install]
WantedBy=timers.target
EOF

echo "[7/8] Starting services"
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"
systemctl enable --now "${SERVICE_NAME}-tick.timer"

echo "[8/8] Done"
echo
echo "Open the initial setup through SSH tunnel, Tailscale, or localhost:"
echo "  http://127.0.0.1:2020/setup?token=${SETUP_TOKEN}"
echo
echo "Status:"
systemctl --no-pager --full status "${SERVICE_NAME}.service" | sed -n '1,8p'
