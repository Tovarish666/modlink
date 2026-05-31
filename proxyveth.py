#!/usr/bin/env python3
"""
ProxyVethLab — экспериментальный rewrite адаптера proxyveth.  ЭКСПЕРИМЕНТ, не прод.

Удалённый SOCKS5-прокси (модем в СПб) -> локальный "модем" ethN @ 192.168.N.100,
чтобы немодифицированный mobileproxy.space работал как с физическим модемом.

    данные      192.168.N.100  -> прокся -> 3proxy(СПб) -> модем -> интернет
    управление  192.168.N.1    -> та же прокся -> 3proxy connect к своему .1 (веб модема)

Транспорт socks5->tun: sing-box (1 инстанс/netns, супервизия systemd).
Обоснования решений и находки по mproxy — в README.md.

run()/up/down по умолчанию DRY-RUN (печатают план); реально — флаг --apply.
check/status — read-only, выполняются всегда.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Инварианты (см. README). Менять осознанно.
# ---------------------------------------------------------------------------
IFACE_PREFIX = "eth"      # ОБЯЗАТЕЛЬНО eth*: mobileproxy распознаёт ethN+.100 как модем
TABLE_BASE   = 100        # таблица модема N = 100 + N  (конвенция mobileproxy)
HOST_OCTET   = 100        # 192.168.N.100 — "модем" для mproxy (данные)
MGMT_OCTET   = 1          # 192.168.N.1   — веб/API модема (управление)
NS_OCTET     = 254        # 192.168.N.254 — наш конец внутри netns (НЕ .1!)
RP_FILTER    = "2"        # loose — нужен для source-routing с асимметрией

MODEMS_CONF  = "/etc/proxyveth/modems.conf"

# --- sing-box ---
SINGBOX_BIN  = shutil.which("sing-box") or "/usr/local/bin/sing-box"
SINGBOX_DIR  = "/etc/proxyveth/singbox"
TUN_MTU      = 1500       # knob: при зависании КРУПНЫХ передач пробовать 1400 (НЕ первый подозреваемый)
SB_STACK     = "system"   # system|gvisor|mixed — system легче для 100 инстансов

DRY_RUN = True


# ---------------------------------------------------------------------------
@dataclass
class Modem:
    n: int
    proxy_host: str
    proxy_port: int
    login: str
    password: str

    @property
    def net(self) -> str:        return f"192.168.{self.n}"
    @property
    def host_if(self) -> str:    return f"{IFACE_PREFIX}{self.n}"
    @property
    def ns(self) -> str:         return f"ns_{self.n}"
    @property
    def tun(self) -> str:        return f"tun{self.n}"
    @property
    def table(self) -> int:      return TABLE_BASE + self.n
    @property
    def ip100(self) -> str:      return f"{self.net}.{HOST_OCTET}"
    @property
    def ip1(self) -> str:        return f"{self.net}.{MGMT_OCTET}"


# ---------------------------------------------------------------------------
def run(cmd: str, ns: str | None = None, check: bool = True) -> int:
    """Мутирующая команда: в dry-run печатает, иначе выполняет."""
    if ns:
        cmd = f"ip netns exec {ns} {cmd}"
    if DRY_RUN:
        print(f"    [dry] {cmd}")
        return 0
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if check and r.returncode != 0:
        sys.stderr.write(f"  ! rc={r.returncode}: {cmd}\n  {(r.stderr or '').strip()}\n")
    return r.returncode


def sh(cmd: str, ns: str | None = None, timeout: int = 15) -> subprocess.CompletedProcess:
    """Read-only команда: выполняется ВСЕГДА (для check/status)."""
    if ns:
        cmd = f"ip netns exec {ns} {cmd}"
    try:
        return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "timeout")


def wan_iface() -> str:
    r = sh("ip route show default | grep -oP 'dev \\K\\S+' | head -1")
    return (r.stdout or "").strip() or "eth0"


def wait_for_iface(ns: str, name: str, timeout: int = 10) -> bool:
    if DRY_RUN:
        print(f"    [dry] wait {name} in {ns} (<= {timeout}s)")
        return True
    for _ in range(timeout * 5):
        if sh(f"ip link show {name}", ns=ns, timeout=3).returncode == 0:
            return True
        time.sleep(0.2)
    return False


def ensure_rt_table(table_id: int, name: str) -> None:
    run(f"grep -qxF '{table_id}\t{name}' /etc/iproute2/rt_tables "
        f"|| echo '{table_id}\t{name}' >> /etc/iproute2/rt_tables")


def fence_iface(host_if: str) -> None:
    """Сказать NetworkManager (десктоп!) и systemd-networkd не трогать ethN —
    иначе DHCP/managed-state сорвут наш .100. Идемпотентно."""
    if DRY_RUN:
        print(f"    [dry] fence {host_if}: NM unmanaged-devices + networkd Unmanaged + reload")
        return
    # systemd-networkd
    os.makedirs("/etc/systemd/network", exist_ok=True)
    with open(f"/etc/systemd/network/10-pvlab-{host_if}.network", "w") as f:
        f.write(f"[Match]\nName={host_if}\n\n[Link]\nUnmanaged=yes\n")
    # NetworkManager (если есть) — добавляем интерфейс в unmanaged-devices
    if shutil.which("nmcli"):
        os.makedirs("/etc/NetworkManager/conf.d", exist_ok=True)
        conf = "/etc/NetworkManager/conf.d/99-pvlab-unmanaged.conf"
        ifaces = set()
        if os.path.exists(conf):
            for tok in open(conf).read().split("unmanaged-devices", 1)[-1].split("=", 1)[-1].split(";"):
                tok = tok.strip()
                if tok.startswith("interface-name:"):
                    ifaces.add(tok.split(":", 1)[1].strip())
        ifaces.add(host_if)
        spec = ";".join(f"interface-name:{i}" for i in sorted(ifaces))
        with open(conf, "w") as f:
            f.write(f"[keyfile]\nunmanaged-devices={spec}\n")
        sh("nmcli connection reload", timeout=10)
        sh(f"nmcli device set {host_if} managed no", timeout=10)
    sh("networkctl reload", timeout=10)


def write_netns_resolv(m: Modem) -> None:
    """Per-netns DNS (резолвер на VM). NB: mproxy резолвит сам в host-ns (dns-cache.js),
    так что для него это не используется — лишь для нужд внутри ns."""
    if DRY_RUN:
        print(f"    [dry] /etc/netns/{m.ns}/resolv.conf -> nameserver {m.ip100}")
        return
    os.makedirs(f"/etc/netns/{m.ns}", exist_ok=True)
    with open(f"/etc/netns/{m.ns}/resolv.conf", "w") as f:
        f.write(f"nameserver {m.ip100}\n")


# ---------------------------------------------------------------------------
# sing-box
def singbox_config(m: Modem) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "tun", "tag": "tun-in",
            "interface_name": m.tun,
            "address": [f"10.0.{m.n}.1/30"],
            "mtu": TUN_MTU,
            "auto_route": False,        # маршрутизацией владеем МЫ
            "stack": SB_STACK,
        }],
        "outbounds": [{
            "type": "socks", "tag": "proxy",
            "server": m.proxy_host, "server_port": m.proxy_port,
            "version": "5",
            "username": m.login, "password": m.password,
        }],
        "route": {
            "rules": [
                # UDP -> reject (ICMP unreachable): QUIC падает на TCP, UDP не уходит
                # в socks -> не флудим/не убиваем 3proxy.
                {"network": "udp", "action": "reject", "method": "default"},
            ],
            "final": "proxy",
        },
    }


def write_singbox_config(m: Modem) -> str:
    cfg = json.dumps(singbox_config(m), indent=2, ensure_ascii=False)
    path = f"{SINGBOX_DIR}/{m.n}.json"
    if DRY_RUN:
        print(f"    [dry] write {path} (пароль -> chmod 600)")
        return path
    os.makedirs(SINGBOX_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write(cfg)
    os.chmod(path, 0o600)
    return path


def ensure_singbox_unit() -> None:
    """systemd-шаблон: sing-box ВНУТРИ netns модема, автоперезапуск."""
    unit = (f"[Unit]\nDescription=ProxyVethLab sing-box (modem %i)\n"
            f"After=network-online.target\n\n[Service]\n"
            f"NetworkNamespacePath=/run/netns/ns_%i\n"
            f"ExecStart={SINGBOX_BIN} run -c {SINGBOX_DIR}/%i.json\n"
            f"Restart=always\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n")
    if DRY_RUN:
        print("    [dry] write /etc/systemd/system/proxyveth-singbox@.service + daemon-reload")
        return
    with open("/etc/systemd/system/proxyveth-singbox@.service", "w") as f:
        f.write(unit)
    run("systemctl daemon-reload")


def start_transport(m: Modem) -> str:
    ensure_singbox_unit()
    write_singbox_config(m)
    run(f"systemctl start proxyveth-singbox@{m.n}")
    if not wait_for_iface(m.ns, m.tun):
        raise RuntimeError(f"{m.tun} не появился — sing-box не стартовал "
                           f"(journalctl -u proxyveth-singbox@{m.n})")
    return m.tun


def stop_transport(m: Modem) -> None:
    run(f"systemctl stop proxyveth-singbox@{m.n}", check=False)
    run(f"rm -f {SINGBOX_DIR}/{m.n}.json", check=False)


# ---------------------------------------------------------------------------
def bring_up(m: Modem) -> None:
    print(f"\n── UP modem {m.n} ──  {m.proxy_host}:{m.proxy_port}")
    net, ns, host_if, ns_if = m.net, m.ns, m.host_if, f"{m.host_if}_ns"

    run(f"ip netns add {ns}")
    run("ip link set lo up", ns=ns)
    write_netns_resolv(m)

    run(f"ip link add {host_if} type veth peer name {ns_if}")
    run(f"ip link set {ns_if} netns {ns}")
    fence_iface(host_if)
    run(f"ip addr add {m.ip100}/24 dev {host_if}")
    run(f"ip link set {host_if} up")
    run(f"ip addr add {net}.{NS_OCTET}/24 dev {ns_if}", ns=ns)
    run(f"ip link set {ns_if} up", ns=ns)

    run(f"sysctl -w net.ipv4.conf.{host_if}.rp_filter={RP_FILTER}")

    # BYPASS: прокся мимо тоннеля (ДО старта sing-box, чтобы он достучался)
    run(f"ip route add {m.proxy_host}/32 via {m.ip100}", ns=ns)

    # host: policy-routing .100 -> в netns; NAT наружу
    ensure_rt_table(m.table, f"pvlab_{m.n}")
    run(f"ip rule add from {m.ip100} table {m.table}")
    run(f"ip route add default via {net}.{NS_OCTET} dev {host_if} table {m.table}")
    run(f"iptables -t nat -C POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE "
        f"|| iptables -t nat -A POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE")

    tun = start_transport(m)

    run(f"ip route add default dev {tun}", ns=ns)
    run(f"ip route add {m.ip1}/32 dev {tun}", ns=ns)   # .1 ВНУТРИ ns -> тоннель
    # ОТКРЫТЫЙ РИСК (README): mproxy НЕ биндит mgmt к .100 (modem-handlers.js:329),
    # поэтому host->.1 в тоннель сам не попадёт. curl --interface .100 -> .1 работает
    # (источник .100). Фикс для mproxy проверяем на VM, не вслепую.
    print(f"   modem {m.n} READY (dry-run plan)" if DRY_RUN else f"   modem {m.n} up")


def tear_down(m: Modem) -> None:
    print(f"\n── DOWN modem {m.n} ──")
    net = m.net
    stop_transport(m)
    run(f"ip netns del {m.ns}", check=False)
    run(f"ip link del {m.host_if}", check=False)
    run(f"ip rule del from {m.ip100} table {m.table}", check=False)
    run(f"ip route flush table {m.table}", check=False)
    run(f"iptables -t nat -D POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE", check=False)
    run(f"rm -rf /etc/netns/{m.ns}", check=False)
    run(f"rm -f /etc/systemd/network/10-pvlab-{m.host_if}.network", check=False)


# ---------------------------------------------------------------------------
def load_modems() -> dict[int, Modem]:
    """Читает /etc/proxyveth/modems.conf. Строка: host:port:login:password.
    N модема = номер непустой строки (1-based)."""
    modems: dict[int, Modem] = {}
    if not os.path.exists(MODEMS_CONF):
        return modems
    n = 0
    for raw in open(MODEMS_CONF):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        n += 1
        try:
            host, port, login, password = line.split(":", 3)
            modems[n] = Modem(n, host.strip(), int(port), login.strip(), password.strip())
        except ValueError:
            sys.stderr.write(f"  ! строка {n}: неверный формат (нужно host:port:login:password)\n")
    return modems


def get_modem(n: int) -> Modem:
    m = load_modems().get(n)
    if not m:
        sys.exit(f"модем {n} не найден в {MODEMS_CONF}")
    return m


# ---------------------------------------------------------------------------
def cmd_check(n: int) -> None:
    m = get_modem(n)
    print(f"── CHECK modem {m.n} ──  {m.proxy_host}:{m.proxy_port}")
    ns_ok = sh(f"ip netns list | grep -qw {m.ns}").returncode == 0
    print(f"  netns {m.ns:<8} : {'OK' if ns_ok else 'НЕТ'}")
    sb = sh(f"systemctl is-active proxyveth-singbox@{m.n}").stdout.strip()
    print(f"  sing-box        : {sb or '—'}")
    tun_ok = ns_ok and sh(f"ip link show {m.tun}", ns=m.ns, timeout=3).returncode == 0
    print(f"  {m.tun:<15} : {'OK' if tun_ok else 'НЕТ'}")
    # данные: exit IP через .100
    r = sh(f"curl -s --max-time 12 --interface {m.ip100} https://api.ipify.org", timeout=15)
    ip = (r.stdout or "").strip()
    print(f"  exit IP (.100)  : {ip or '— (пусто/таймаут; пробуй google, см. README)'}")
    # управление: Huawei API на .1 через .100
    r = sh(f"curl -s --max-time 8 --interface {m.ip100} "
           f"http://{m.ip1}/api/webserver/SesTokInfo", timeout=12)
    ok = "SesInfo" in (r.stdout or "")
    print(f"  Huawei .1 (.100): {'OK' if ok else '— (см. риск mgmt в README)'}")


def cmd_status() -> None:
    modems = load_modems()
    if not modems:
        print(f"нет модемов в {MODEMS_CONF}")
        return
    print(f"{'N':>3} {'proxy':<24} {'netns':<6} {'sing-box':<10} {'tun':<5}")
    for n in sorted(modems):
        m = modems[n]
        ns_ok = sh(f"ip netns list | grep -qw {m.ns}").returncode == 0
        sb = sh(f"systemctl is-active proxyveth-singbox@{n}").stdout.strip() or "—"
        tun = "OK" if ns_ok and sh(f"ip link show {m.tun}", ns=m.ns, timeout=3).returncode == 0 else "—"
        print(f"{n:>3} {m.proxy_host+':'+str(m.proxy_port):<24} "
              f"{'UP' if ns_ok else 'down':<6} {sb:<10} {tun:<5}")


def cmd_sync() -> None:
    print(f"[stub] sync из Google Sheets пока не реализован — правь {MODEMS_CONF} вручную")


def cmd_watchdog() -> None:
    print("[stub] watchdog: sing-box супервизит systemd; здесь — целостность маршрутов/ns")


# ---------------------------------------------------------------------------
def main() -> None:
    global DRY_RUN
    p = argparse.ArgumentParser(prog="proxyveth", description="ProxyVethLab (experimental)")
    p.add_argument("cmd", choices=["up", "down", "status", "check", "sync", "watchdog"])
    p.add_argument("target", nargs="?", help="N | all")
    p.add_argument("--apply", action="store_true", help="реально выполнять up/down (иначе dry-run)")
    a = p.parse_args()
    DRY_RUN = not a.apply

    if a.cmd == "status":
        cmd_status()
    elif a.cmd == "sync":
        cmd_sync()
    elif a.cmd == "watchdog":
        cmd_watchdog()
    elif a.cmd == "check":
        if not a.target:
            sys.exit("proxyveth check N")
        cmd_check(int(a.target))
    elif a.cmd in ("up", "down"):
        if not a.target:
            sys.exit(f"proxyveth {a.cmd} [N|all]")
        fn = bring_up if a.cmd == "up" else tear_down
        if a.target == "all":
            modems = load_modems()
            if not modems:
                sys.exit(f"нет модемов в {MODEMS_CONF}")
            for n in sorted(modems):
                fn(modems[n])
        else:
            fn(get_modem(int(a.target)))


if __name__ == "__main__":
    main()
