#!/usr/bin/env python3
"""
modlink server — серверная часть (хосты с модемами).

Поднимает sing-box как HTTPS-прокси.  Каждый модем N:
  • слушает на одном порту (PROXY_PORT), TLS
  • auth: username=modem-N  password=из modems.conf
  • outbound: direct, inet4_bind_address=192.168.N.100
  • Huawei .1 доступен через CONNECT 192.168.N.1 (L2 локально)

modems.conf: одна строка = один модем
    N password
    # или просто N  (пароль автогенерируется)
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
CONF_DIR    = Path("/etc/modlink")
MODEMS_CONF = CONF_DIR / "modems.conf"
SB_CONF     = CONF_DIR / "singbox.json"
CERT_FILE   = CONF_DIR / "cert.pem"
KEY_FILE    = CONF_DIR / "key.pem"

BASE_PORT   = 10000    # порт модема N = BASE_PORT + N
HOST_OCTET  = 100      # 192.168.N.100 — адрес интерфейса модема на хосте
SINGBOX_BIN = shutil.which("sing-box") or "/usr/local/bin/sing-box"
SYSTEMD_SVC = "modlink"


# ---------------------------------------------------------------------------
@dataclass
class Modem:
    n: int
    password: str

    @property
    def net(self) -> str:           return f"192.168.{self.n}"
    @property
    def bind_ip(self) -> str:       return f"{self.net}.{HOST_OCTET}"
    @property
    def username(self) -> str:      return f"modem{self.n}"
    @property
    def huawei_ip(self) -> str:     return f"{self.net}.1"
    @property
    def tag(self) -> str:           return f"out-{self.n}"


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
def gen_singbox_config(modems: list[Modem]) -> dict:
    """
    Порт-per-модем: HTTP inbound с TLS на BASE_PORT + N.
    Маршрутизация по inbound тегу — изоляция отказов, удобный мониторинг.
    """
    tls = CERT_FILE.exists() and KEY_FILE.exists()
    inbounds, outbounds, rules = [], [], []
    for m in modems:
        port    = BASE_PORT + m.n
        tag_in  = f"in-{m.n}"
        tag_out = f"out-{m.n}"
        inbound: dict = {
            "type": "http" if tls else "mixed",
            "tag": tag_in,
            "listen": "0.0.0.0",
            "listen_port": port,
            "users": [{"username": m.username, "password": m.password}],
        }
        if tls:
            inbound["tls"] = {
                "enabled": True,
                "certificate_path": str(CERT_FILE),
                "key_path": str(KEY_FILE),
            }
        inbounds.append(inbound)
        outbounds.append({
            "type": "direct",
            "tag": tag_out,
            "inet4_bind_address": m.bind_ip,
        })
        rules.append({"inbound": [tag_in], "outbound": tag_out})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules},
    }


# ---------------------------------------------------------------------------
def ensure_cert() -> None:
    if CERT_FILE.exists() and KEY_FILE.exists():
        return
    print("  генерирую self-signed TLS cert...")
    cmd = (
        f"openssl req -x509 -newkey rsa:2048 -nodes "
        f"-keyout {KEY_FILE} -out {CERT_FILE} "
        f"-days 3650 -subj '/CN=proxyveth-server'"
    )
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"openssl failed:\n{r.stderr}")
    CERT_FILE.chmod(0o644)
    KEY_FILE.chmod(0o600)
    print(f"  cert: {CERT_FILE}")


def ensure_systemd_unit() -> None:
    unit = f"""\
[Unit]
Description=modlink — HTTPS proxy server for modems
After=network-online.target
Wants=network-online.target

[Service]
ExecStart={SINGBOX_BIN} run -c {SB_CONF}
Restart=always
RestartSec=3
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""
    path = Path(f"/etc/systemd/system/{SYSTEMD_SVC}.service")
    path.write_text(unit)
    subprocess.run("systemctl daemon-reload", shell=True)


def sh(cmd: str, timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)


# ---------------------------------------------------------------------------
def cmd_apply(modems: list[Modem]) -> None:
    """Сгенерировать конфиг, (пере)запустить sing-box."""
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    ensure_cert()
    ensure_systemd_unit()

    cfg = gen_singbox_config(modems)
    SB_CONF.write_text(json.dumps(cfg, indent=2, ensure_ascii=False))
    SB_CONF.chmod(0o600)
    print(f"  конфиг: {SB_CONF}  ({len(modems)} модемов)")

    # валидация конфига sing-box
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

    # проверить что порт слушает
    r = sh(f"ss -tlnp | grep :{PROXY_PORT}")
    print(f"  порт {PROXY_PORT}: {'слушает' if r.returncode == 0 else 'не слушает'}")

    print(f"\n  {'N':>3}  {'bind IP':<18}  {'user':<12}  {'iface up?'}")
    for m in modems:
        r = sh(f"ip link show | grep -w '{m.bind_ip}\\|192\\.168\\.{m.n}\\.'")
        iface_r = sh(f"ip addr show | grep -w '{m.bind_ip}'")
        iface_up = "OK" if iface_r.returncode == 0 else "нет адреса"
        print(f"  {m.n:>3}  {m.bind_ip:<18}  {m.username:<12}  {iface_up}")


def cmd_test(n: int, server_addr: str = "127.0.0.1") -> None:
    """Тест конкретного модема: exit IP + Huawei .1 API."""
    modems = load_modems()
    m_list = [m for m in modems if m.n == n]
    if not m_list:
        sys.exit(f"модем {n} не найден в {MODEMS_CONF}")
    m = m_list[0]

    port      = BASE_PORT + m.n
    tls       = CERT_FILE.exists() and KEY_FILE.exists()
    scheme    = "https" if tls else "http"
    proxy_url = f"{scheme}://{m.username}:{m.password}@{server_addr}:{port}"
    insecure  = "--proxy-insecure" if tls else ""
    curl_base = f"curl -s --max-time 10 {insecure} --proxy '{proxy_url}'"

    print(f"  модем {m.n}  bind={m.bind_ip}  порт={port}")
    print(f"  прокси: {server_addr}:{port}  user={m.username}")

    # exit IP
    r = sh(f"{curl_base} http://ip.me", timeout=15)
    exit_ip = r.stdout.strip()
    print(f"\n  exit IP:       {exit_ip or '— (таймаут)'}")

    # Huawei .1
    huawei_url = f"http://{m.huawei_ip}/api/webserver/SesTokInfo"
    r = sh(f"{curl_base} '{huawei_url}'", timeout=15)
    ok = "SesInfo" in (r.stdout or "")
    print(f"  Huawei .1 API: {'OK' if ok else '— ' + (r.stderr or r.stdout or 'нет ответа')[:60]}")

    # итог
    if exit_ip and ok:
        print("\n  [OK] прокся работает, Huawei API доступен")
    elif exit_ip:
        print("\n  [~] прокся работает, Huawei API недоступен (модем не подключён?)")
    else:
        print("\n  [FAIL] нет ответа через прокси")
        print(f"  journalctl -u {SYSTEMD_SVC} -n 30 --no-pager")


def cmd_show_creds(modems: list[Modem]) -> None:
    """Напечатать строки для modems.conf на клиентской стороне."""
    host = sh("hostname -I | awk '{print $1}'").stdout.strip() or "SERVER_IP"
    print(f"# Строки для /etc/proxyveth/modems.conf на клиенте")
    print(f"# (заменить SERVER_IP на реальный IP этого сервера)")
    for m in modems:
        port = BASE_PORT + m.n
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
