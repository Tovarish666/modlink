#!/usr/bin/env bash
# ProxyVethLab — экспериментальный деплой на ЧИСТУЮ Ubuntu. НЕ для прода.
# Ставит зависимости + sing-box + proxyveth, готовит конфиг и sysctl.
# Запуск:  sudo bash deploy.sh
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "нужен root: sudo bash deploy.sh"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"

echo "[1/6] пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 iproute2 iptables curl wget ca-certificates >/dev/null

echo "[2/6] sing-box"
if ! command -v sing-box >/dev/null 2>&1; then
  curl -fsSL https://sing-box.app/install.sh | sh
fi
SB="$(command -v sing-box || true)"
[ -n "$SB" ] || { echo "ОШИБКА: sing-box не установился"; exit 1; }
ln -sf "$SB" /usr/local/bin/sing-box
# их дефолтный сервис нам не нужен — мы держим свой шаблон per-netns
systemctl disable --now sing-box.service >/dev/null 2>&1 || true
echo "  $(sing-box version | head -1)"

echo "[3/6] proxyveth"
install -m 0755 "$HERE/proxyveth.py" /usr/local/bin/proxyveth.py
ln -sf /usr/local/bin/proxyveth.py /usr/local/bin/proxyveth
mkdir -p /etc/proxyveth/singbox

echo "[4/6] modems.conf"
if [ ! -f /etc/proxyveth/modems.conf ]; then
  cat > /etc/proxyveth/modems.conf <<'EOF'
# По одной проксе на строку:  host:port:login:password
# N модема = номер НЕПУСТОЙ строки (1-based) -> интерфейс ethN, адрес 192.168.N.100
# Впиши свои прокси (пример формата, значения фейковые):
# 203.0.113.10:1080:proxyuser:proxypass
EOF
  chmod 600 /etc/proxyveth/modems.conf
  echo "  создан /etc/proxyveth/modems.conf (впиши прокси!)"
else
  echo "  /etc/proxyveth/modems.conf уже есть — не трогаю"
fi

echo "[5/6] sysctl (loose rp_filter + forwarding)"
cat > /etc/sysctl.d/99-proxyveth.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
EOF
sysctl -p /etc/sysctl.d/99-proxyveth.conf >/dev/null 2>&1 || true

echo "[6/6] systemd-шаблон sing-box"
proxyveth status >/dev/null 2>&1 || true   # прогрев/проверка импорта

cat <<'EOF'

ГОТОВО (experimental). Дальше:
  1) впиши прокси:        nano /etc/proxyveth/modems.conf
  2) план (dry-run):      proxyveth up 1
  3) применить ОДИН:      sudo proxyveth up 1 --apply
  4) проверить:           sudo proxyveth check 1
        - exit IP (.100)  -> должен быть мобильный IP СПб
        - Huawei .1       -> тест управления через тоннель
  5) статус всех:         proxyveth status
  6) снять:               sudo proxyveth down 1 --apply

Если exit IP пустой/таймаут на api.ipify.org — это может быть «мёртвый» тест-сайт
на мобильном IP (см. README), попробуй: curl --interface 192.168.1.100 https://www.google.com -I
EOF
