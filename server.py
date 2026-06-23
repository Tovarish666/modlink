#!/usr/bin/env python3
"""
modlink server — серверная часть (хосты с модемами).

Поднимает sing-box как mixed (HTTP CONNECT + SOCKS5) прокси.
Каждый модем N:
  • слушает на BASE_PORT + sorted_index * 2  (такой же порядок, как в panel.py)
  • auth: username=modem-N  password=из modems.conf
  • outbound: direct, inet4_bind_address=192.168.N.100
  • Huawei .1 доступен через CONNECT 192.168.N.1

modems.conf: одна строка = один модем
    N password
    # или просто N  (пароль автогенерируется)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
CONF_DIR    = Path("/etc/modlink")
MODEMS_CONF = CONF_DIR / "modems.conf"
SB_CONF     = CONF_DIR / "singbox.json"

BASE_PORT   = 10000
HOST_OCTET  = 100      # 192.168.N.100 — адрес интерфейса модема на хосте
SINGBOX_BIN = shutil.which("sing-box") or "/usr/local/bin/sing-box"
SYSTEMD_SVC = "modlink"


# ---------------------------------------------------------------------------
@dataclass
class Modem:
    n: int
    password: str

    @property
    def net(self) -> str:       return f"192.168.{self.n}"
    @property
    def bind_ip(self) -> str:   return f"{self.net}.{HOST_OCTET}"
    @property
    def username(self) -> str:  return f"modem{self.n}"
    @property
    def huawei_ip(self) -> str: return f"{self.net}.1"


def _auto_pass(n: int) -> str:
    return hashlib.sha256(f"proxyveth-modem-{n}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
def load_modems() -> list[Modem]:
    if not MODEMS_CONF.exists():
        sys.exit(f"нет {MODEMS_CONF} — создай его (формат: N [password])")
    result = []
    seen: set[int] = set()
    for ln, raw in enumerate(MODEMS_CONF.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        try:
            n = int(parts[0])
        except ValueError:
            sys.stderr.write(f"  ! строка {ln}: ожидается N [password]\n")
            continue
        if not (1 <= n <= 254):
            sys.stderr.write(f"  ! строка {ln}: N={n} вне 1..254\n")
            continue
        if n in seen:
            sys.stderr.write(f"  ! строка {ln}: N={n} дублируется\n")
            continue
        seen.add(n)
        password = parts[1] if len(parts) > 1 else _auto_pass(n)
        result.append(Modem(n, password))
    if not result:
        sys.exit("modems.conf пустой")
    return result


# ---------------------------------------------------------------------------
def calc_ports(modems: list[Modem]) -> dict[int, int]:
    """Возвращает {modem_n: mixed_port} — тот же алгоритм, что в panel.py."""
    return {m.n: BASE_PORT + i * 2 for i, m in enumerate(sorted(modems, key=lambda x: x.n))}


def gen_singbox_config(modems: list[Modem]) -> dict:
    """
    mixed inbound (HTTP CONNECT + SOCKS5) на канале прокси.
    Порт модема = BASE_PORT + sorted_index * 2  (совпадает с panel.py).
    """
    ports = calc_ports(modems)
    inbounds, outbounds, rules = [], [], []
    for m in sorted(modems, key=lambda x: x.n):
        port = ports[m.n]
        inbounds.append({
            "type": "mixed",
            "tag": f"in-{m.n}",
            "listen": "0.0.0.0",
            "listen_port": port,
            "users": [{"username": m.username, "password": m.password}],
        })
        outbounds.append({
            "type": "direct",
            "tag": f"out-{m.n}",
            "inet4_bind_address": m.bind_ip,
        })
        rules.append({"inbound": [f"in-{m.n}"], "outbound": f"out-{m.n}"})
    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }


# ---------------------------------------------------------------------------
def ensure_systemd_unit() -> None:
    unit = f"""\
[Unit]
Description=modlink — sing-box proxy for modems
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={SINGBOX_BIN} run -c {SB_CONF}
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
"""
    path = Path(f"/etc/systemd/system/{SYSTEMD_SVC}.service")
    path.write_text(unit)
    subprocess.run("systemctl daemon-reload", shell=True, capture_output=True)
    subprocess.run(f"systemctl enable {SYSTEMD_SVC}", shell=True, capture_output=True)


def sh(cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)


# ---------------------------------------------------------------------------
def cmd_apply(modems: list[Modem]) -> None:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    ensure_systemd_unit()

    cfg = gen_singbox_config(modems)
    SB_CONF.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    SB_CONF.chmod(0o600)
    print(f"  конфиг: {SB_CONF}  ({len(modems)} модемов)")

    r = sh(f"{SINGBOX_BIN} check -c {SB_CONF}")
    if r.returncode != 0:
        sys.exit(f"sing-box check failed:\n{r.stdout}\n{r.stderr}")

    r = sh(f"systemctl restart {SYSTEMD_SVC}")
    if r.returncode != 0:
        sys.exit(f"systemctl restart failed:\n{r.stderr}")

    time.sleep(1)
    r = sh(f"systemctl is-active {SYSTEMD_SVC}")
    status = r.stdout.strip()
    print(f"  sing-box: {status}")
    if status != "active":
        print(f"  журнал: journalctl -u {SYSTEMD_SVC} -n 20 --no-pager")


def cmd_status(modems: list[Modem]) -> None:
    r = sh(f"systemctl is-active {SYSTEMD_SVC}")
    print(f"  sing-box ({SYSTEMD_SVC}): {r.stdout.strip() or '—'}")

    ports = calc_ports(modems)
    print(f"\n  {'N':>3}  {'port':<8}  {'bind IP':<18}  {'user':<12}  iface up?")
    for m in sorted(modems, key=lambda x: x.n):
        port = ports[m.n]
        r_port = sh(f"ss -tlnp | grep :{port}")
        port_status = "слушает" if r_port.returncode == 0 else "нет"
        iface_r = sh(f"ip addr show | grep -w '{m.bind_ip}'")
        iface_up = "OK" if iface_r.returncode == 0 else "нет адреса"
        print(f"  {m.n:>3}  {port:<8}  {m.bind_ip:<18}  {m.username:<12}  {iface_up} / порт {port_status}")


def cmd_test(n: int, server_addr: str = "127.0.0.1") -> None:
    modems = load_modems()
    m_list = [m for m in modems if m.n == n]
    if not m_list:
        sys.exit(f"модем {n} не найден в {MODEMS_CONF}")
    m = m_list[0]

    ports = calc_ports(modems)
    port = ports[m.n]
    proxy_url = f"http://{m.username}:{m.password}@{server_addr}:{port}"
    curl_base = f"curl -s --max-time 10 --proxy '{proxy_url}'"

    print(f"  модем {m.n}  bind={m.bind_ip}  порт={port}")
    print(f"  прокси: {server_addr}:{port}  user={m.username}")

    r = sh(f"{curl_base} http://ip.me", timeout=15)
    exit_ip = r.stdout.strip()
    print(f"\n  exit IP:       {exit_ip or '— (таймаут)'}")

    huawei_url = f"http://{m.huawei_ip}/api/webserver/SesTokInfo"
    r = sh(f"{curl_base} '{huawei_url}'", timeout=15)
    ok = "SesInfo" in (r.stdout or "")
    print(f"  Huawei .1 API: {'OK' if ok else '— ' + (r.stderr or r.stdout or 'нет ответа')[:60]}")

    if exit_ip and ok:
        print("\n  [OK] прокся работает, Huawei API доступен")
    elif exit_ip:
        print("\n  [~] прокся работает, Huawei API недоступен (модем не подключён?)")
    else:
        print("\n  [FAIL] нет ответа через прокси")
        print(f"  journalctl -u {SYSTEMD_SVC} -n 30 --no-pager")


def cmd_show_creds(modems: list[Modem]) -> None:
    host = sh("hostname -I | awk '{print $1}'").stdout.strip() or "SERVER_IP"
    ports = calc_ports(modems)
    print("# Строки для /etc/modlink-client/modems.conf на клиенте")
    print("# (заменить SERVER_IP на реальный IP этого сервера)")
    for m in sorted(modems, key=lambda x: x.n):
        port = ports[m.n]
        print(f"{host}:{port}:{m.username}:{m.password}")


# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(prog="modlink-server")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("apply",  help="сгенерировать конфиг и (пере)запустить sing-box")
    sub.add_parser("status", help="состояние sing-box и интерфейсов")
    sub.add_parser("creds",  help="напечатать строки для modems.conf клиента")

    t = sub.add_parser("test", help="тест модема: exit IP + Huawei API")
    t.add_argument("n",      type=int, help="номер модема")
    t.add_argument("--host", default="127.0.0.1",
                   help="адрес сервера (по умолчанию 127.0.0.1 — локальный тест)")

    a = p.parse_args()
    modems = load_modems()

    if a.cmd == "apply":
        cmd_apply(modems)
    elif a.cmd == "status":
        cmd_status(modems)
    elif a.cmd == "creds":
        cmd_show_creds(modems)
    elif a.cmd == "test":
        cmd_test(a.n, a.host)


if __name__ == "__main__":
    main()
