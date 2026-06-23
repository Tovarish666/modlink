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
_install_singbox_apt() {
    info "Метод 1: APT-репозиторий SagerNet..."
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc 2>/dev/null || return 1
    chmod a+r /etc/apt/keyrings/sagernet.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/sagernet.asc] https://deb.sagernet.org/ * *" \
        > /etc/apt/sources.list.d/sagernet.list
    apt-get update -qq 2>/dev/null || return 1
    apt-get install -y -qq sing-box 2>/dev/null || return 1
    return 0
}

_install_singbox_github() {
    info "Метод 2: GitHub Releases..."

    MACHINE="$(uname -m)"
    case "$MACHINE" in
        x86_64)        ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7*|armhf)  ARCH="armv7" ;;
        *)             ARCH="amd64" ;;
    esac

    info "  Получаю последний тег..."
    API_JSON="$(curl -fsSL --max-time 15 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null)"
    TAG="$(echo "$API_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'])" 2>/dev/null)"
    [ -n "$TAG" ] || { warn "  GitHub API не ответил"; return 1; }

    VER="${TAG#v}"
    ARCHIVE="sing-box-${VER}-linux-${ARCH}.tar.gz"
    URL="https://github.com/SagerNet/sing-box/releases/download/${TAG}/${ARCHIVE}"
    info "  Качаю $URL"

    TMP_DIR="$(mktemp -d)"
    curl -fsSL --max-time 60 "$URL" -o "$TMP_DIR/$ARCHIVE" 2>/dev/null || { rm -rf "$TMP_DIR"; return 1; }
    tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"
    FOUND="$(find "$TMP_DIR" -name "sing-box" -type f | head -1)"
    [ -n "$FOUND" ] || { rm -rf "$TMP_DIR"; return 1; }
    install -m 0755 "$FOUND" /usr/local/bin/sing-box
    rm -rf "$TMP_DIR"
    return 0
}

SB_BIN=""
if command -v sing-box >/dev/null 2>&1; then
    SB_BIN="$(command -v sing-box)"
    ok "sing-box уже есть: $SB_BIN"
else
    _install_singbox_apt   && SB_BIN="$(command -v sing-box 2>/dev/null)" \
    || _install_singbox_github && SB_BIN="/usr/local/bin/sing-box"
    [ -n "$SB_BIN" ] && command -v sing-box >/dev/null 2>&1 \
        || abort "Не удалось установить sing-box ни одним из методов"
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
