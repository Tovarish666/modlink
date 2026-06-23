#!/usr/bin/env bash
# modlink — deploy script for Linux (Ubuntu/Debian)
# Run: sudo bash deploy-linux.sh
#
# What it does:
#   1. Installs python3, curl, openssl
#   2. Installs sing-box
#   3. Downloads server.py and panel.py
#   4. Creates /etc/modlink/ with configs
#   5. Registers modlink.service       (sing-box, autostart)
#   6. Registers modlink-panel.service (web panel :5000, autostart)

set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "нужен root: sudo bash deploy-linux.sh"; exit 1; }

MODLINK_DIR="/usr/local/bin"
CONF_DIR="/etc/modlink"
PANEL_PORT=5000
REPO_RAW="https://raw.githubusercontent.com/Tovarish666/modlink/main"

info()  { echo "  $*"; }
ok()    { echo "  [OK] $*"; }
warn()  { echo "  [!!] $*"; }
abort() { echo -e "\n  ERROR: $*" >&2; exit 1; }

echo ""
echo "=== modlink deploy (Linux) ==="
echo ""

# ── 1. Python ─────────────────────────────────────────────────────────────────
info "Проверяю Python..."
PY=""
for cmd in python3 python; do
    if command -v "$cmd" >/dev/null 2>&1 && "$cmd" -c "import sys; sys.exit(0 if sys.version_info>=( 3,7) else 1)" 2>/dev/null; then
        PY="$cmd"; break
    fi
done

if [ -z "$PY" ]; then
    warn "Python 3 не найден — устанавливаю..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 >/dev/null
    PY="python3"
fi
ok "Python: $($PY --version 2>&1)"

# ── 2. Зависимости ────────────────────────────────────────────────────────────
info "Устанавливаю системные пакеты..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl wget ca-certificates openssl >/dev/null
ok "пакеты: curl wget openssl"

# ── 3. sing-box ───────────────────────────────────────────────────────────────
SB_BIN=""
if command -v sing-box >/dev/null 2>&1; then
    SB_BIN="$(command -v sing-box)"
    ok "sing-box уже есть: $SB_BIN"
else
    info "Скачиваю sing-box..."
    bash <(curl -fsSL https://sing-box.app/installer.sh)
    SB_BIN="$(command -v sing-box 2>/dev/null || echo "")"
    [ -n "$SB_BIN" ] || abort "sing-box не установился"
    ok "sing-box: $(sing-box version 2>&1 | head -1)"
fi

# Отключаем дефолтный сервис sing-box — используем свой modlink.service
systemctl disable --now sing-box.service >/dev/null 2>&1 || true

# Симлинк чтобы путь был стабильным в юнитах
ln -sf "$SB_BIN" /usr/local/bin/sing-box

# ── 4. Директории и скрипты ───────────────────────────────────────────────────
info "Скачиваю panel.py и server.py..."
curl -fsSL "$REPO_RAW/server.py" -o "$MODLINK_DIR/modlink-server" && chmod +x "$MODLINK_DIR/modlink-server"
curl -fsSL "$REPO_RAW/panel.py"  -o "$MODLINK_DIR/modlink-panel"  && chmod +x "$MODLINK_DIR/modlink-panel"
ok "modlink-server  modlink-panel"

# ── 5. Конфиги ────────────────────────────────────────────────────────────────
info "Создаю директории конфигов..."
mkdir -p "$CONF_DIR/certs" "$CONF_DIR/logs"

if [ ! -f "$CONF_DIR/modems.conf" ]; then
    printf "# N  password\n" > "$CONF_DIR/modems.conf"
    chmod 600 "$CONF_DIR/modems.conf"
    ok "Создан пустой $CONF_DIR/modems.conf"
else
    ok "$CONF_DIR/modems.conf уже есть — не трогаю"
fi

# ── 6. TLS сертификат ─────────────────────────────────────────────────────────
if [ ! -f "$CONF_DIR/certs/cert.pem" ]; then
    info "Генерирую TLS сертификат..."
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$CONF_DIR/certs/key.pem" \
        -out    "$CONF_DIR/certs/cert.pem" \
        -days 3650 -subj "/CN=modlink-server" 2>/dev/null
    chmod 644 "$CONF_DIR/certs/cert.pem"
    chmod 600 "$CONF_DIR/certs/key.pem"
    ok "TLS: $CONF_DIR/certs/cert.pem"
else
    ok "TLS сертификат уже есть"
fi

# ── 7. systemd: modlink (sing-box) ────────────────────────────────────────────
info "Регистрирую сервис modlink (sing-box)..."
cat > /etc/systemd/system/modlink.service <<EOF
[Unit]
Description=modlink — sing-box proxy for modems
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/sing-box run -c $CONF_DIR/singbox.json
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
ok "modlink.service"

# ── 8. systemd: modlink-panel (веб-панель) ────────────────────────────────────
info "Регистрирую сервис modlink-panel (панель :$PANEL_PORT)..."
cat > /etc/systemd/system/modlink-panel.service <<EOF
[Unit]
Description=modlink web panel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$PY $MODLINK_DIR/modlink-panel --host 0.0.0.0 --port $PANEL_PORT --no-browser
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
ok "modlink-panel.service"

# ── 9. Включаем автозапуск ────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable modlink modlink-panel
ok "Автозапуск включён: modlink + modlink-panel"

# ── 10. Запускаем панель ──────────────────────────────────────────────────────
systemctl start modlink-panel
sleep 2
PANEL_STATUS="$(systemctl is-active modlink-panel 2>/dev/null || echo unknown)"
ok "modlink-panel: $PANEL_STATUS"

LOCAL_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || echo "?")"

echo ""
echo "=== Готово ==="
echo "  Директория:   $CONF_DIR"
echo "  Скрипты:      $MODLINK_DIR/modlink-server  $MODLINK_DIR/modlink-panel"
echo "  Автозапуск:   systemd → modlink + modlink-panel"
echo "  Панель:       http://$LOCAL_IP:$PANEL_PORT"
echo ""
echo "  Добавь модемы: nano $CONF_DIR/modems.conf"
echo "  Затем нажми «Применить» в панели."
echo ""
echo "  Управление:"
echo "    systemctl status  modlink modlink-panel"
echo "    systemctl restart modlink"
echo "    journalctl -u modlink         -n 30 --no-pager"
echo "    journalctl -u modlink-panel   -n 30 --no-pager"
echo ""
