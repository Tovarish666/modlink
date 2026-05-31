#!/usr/bin/env python3
"""
ProxyVethLab — экспериментальный rewrite адаптера proxyveth.  БОЛВАНКА.

Удалённый SOCKS5-прокси (модем в СПб) -> локальный "модем" ethN @ 192.168.N.100,
чтобы немодифицированный mobileproxy.space работал как с физическим модемом.

Обе плоскости одного модема -> в ОДНУ проксю:
    данные      192.168.N.100  -> прокся -> 3proxy(СПб) -> модем -> интернет
    управление  192.168.N.1    -> та же прокся -> 3proxy connect к своему .1 (веб модема)

Транспорт socks5->tun: sing-box (по одному инстансу на netns, супервизия systemd).
Подробности и обоснования решений — в README.md.  run() по умолчанию dry-run.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Инварианты (см. README). Менять осознанно.
# ---------------------------------------------------------------------------
IFACE_PREFIX = "eth"      # ОБЯЗАТЕЛЬНО eth*: mobileproxy распознаёт ethN+.100 как модем
TABLE_BASE   = 100        # таблица модема N = 100 + N  (конвенция mobileproxy)
HOST_OCTET   = 100        # 192.168.N.100 — "модем" для mproxy (данные); резолвер DNS
MGMT_OCTET   = 1          # 192.168.N.1   — веб/API модема (управление)
NS_OCTET     = 254        # 192.168.N.254 — наш конец внутри netns (НЕ .1!)
RP_FILTER    = "2"        # loose — нужен для source-routing с асимметрией

# --- sing-box ---
SINGBOX_BIN  = "/usr/local/bin/sing-box"
SINGBOX_DIR  = "/etc/proxyveth/singbox"
SINGBOX_UNIT = "proxyveth-singbox@.service"
TUN_MTU      = 1500       # knob: при стойких зависаниях КРУПНЫХ передач — пробовать 1400
                          #       (НЕ первый подозреваемый: см. README, история 20ч по MTU)
SB_STACK     = "system"   # system|gvisor|mixed — system легче для 100 инстансов; UDP всё равно reject

DRY_RUN = True            # по умолчанию печатаем план, не выполняем (--apply снимает)


# ---------------------------------------------------------------------------
@dataclass
class Modem:
    n: int            # номер модема == третий октет (192.168.N.x)
    proxy_host: str   # напр. 95.165.86.25
    proxy_port: int
    login: str
    password: str

    @property
    def net(self) -> str:
        return f"192.168.{self.n}"

    @property
    def host_if(self) -> str:        # host-конец veth: остаётся в init-netns, mproxy биндит .100
        return f"{IFACE_PREFIX}{self.n}"

    @property
    def ns(self) -> str:
        return f"ns_{self.n}"

    @property
    def tun(self) -> str:
        return f"tun{self.n}"

    @property
    def table(self) -> int:
        return TABLE_BASE + self.n


# ---------------------------------------------------------------------------
def run(cmd: str, ns: str | None = None, check: bool = True) -> int:
    """Выполнить (или в dry-run напечатать) shell-команду. ns=имя netns -> обернуть."""
    if ns:
        cmd = f"ip netns exec {ns} {cmd}"
    if DRY_RUN:
        print(f"    [dry] {cmd}")
        return 0
    r = subprocess.run(cmd, shell=True, text=True, capture_output=True)
    if check and r.returncode != 0:
        sys.stderr.write(f"  ! rc={r.returncode}: {cmd}\n  {r.stderr.strip()}\n")
    return r.returncode


def wan_iface() -> str:
    """Основной (WAN) интерфейс хоста — НЕ хардкодить eth0."""
    if DRY_RUN:
        return "$(WAN)"
    r = subprocess.run("ip route show default | grep -oP 'dev \\K\\S+' | head -1",
                       shell=True, text=True, capture_output=True)
    return r.stdout.strip() or "eth0"


def wait_for_iface(ns: str, name: str, timeout: int = 10) -> bool:
    """Дождаться появления интерфейса в netns (заменяет фиксированный sleep)."""
    if DRY_RUN:
        print(f"    [dry] wait {name} in {ns} (<= {timeout}s)")
        return True
    for _ in range(timeout * 5):
        if subprocess.run(f"ip netns exec {ns} ip link show {name}",
                          shell=True, capture_output=True).returncode == 0:
            return True
        time.sleep(0.2)
    return False


def ensure_rt_table(table_id: int, name: str) -> None:
    """Добавить запись в /etc/iproute2/rt_tables идемпотентно (точная строка)."""
    run(f"grep -qxF '{table_id}\t{name}' /etc/iproute2/rt_tables "
        f"|| echo '{table_id}\t{name}' >> /etc/iproute2/rt_tables")


def fence_iface(host_if: str) -> None:
    """Сказать systemd-networkd / NetworkManager не трогать ethN. TODO: реализовать."""
    # networkd: /etc/systemd/network/10-pvlab-<if>.network: [Match]Name=<if> -> Unmanaged=yes
    # NM (если есть): /etc/NetworkManager/conf.d/ unmanaged-devices+=interface-name:<if>
    print(f"    [stub] fence {host_if} from networkd/NM (Unmanaged)")


def write_netns_resolv(m: Modem) -> None:
    """Per-netns DNS: резолвер на VM (host-конец .100). NB: для проксируемого трафика
    DNS резолвит сам mproxy на VM ДО тоннеля (см. README) — это лишь для нужд внутри ns."""
    print(f"    [stub] /etc/netns/{m.ns}/resolv.conf -> nameserver {m.net}.{HOST_OCTET}")


# ---------------------------------------------------------------------------
# sing-box
def singbox_config(m: Modem) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": m.tun,
            "address": [f"10.0.{m.n}.1/30"],
            "mtu": TUN_MTU,
            "auto_route": False,        # маршрутизацией владеем МЫ (ip rule/route)
            "stack": SB_STACK,
        }],
        "outbounds": [{
            "type": "socks",
            "tag": "proxy",
            "server": m.proxy_host,
            "server_port": m.proxy_port,
            "version": "5",
            "username": m.login,
            "password": m.password,
        }],
        "route": {
            "rules": [
                # UDP -> reject (ICMP unreachable): QUIC быстро падает на TCP,
                # в socks UDP НЕ шлём -> не флудим и не убиваем 3proxy (старая болезнь).
                {"network": "udp", "action": "reject", "method": "default"},
            ],
            "final": "proxy",
        },
    }


def write_singbox_config(m: Modem) -> str:
    cfg = json.dumps(singbox_config(m), indent=2, ensure_ascii=False)
    path = f"{SINGBOX_DIR}/{m.n}.json"
    if DRY_RUN:
        print(f"    [dry] write {path}  (содержит пароль -> chmod 600)")
        return path
    os.makedirs(SINGBOX_DIR, exist_ok=True)
    with open(path, "w") as f:
        f.write(cfg)
    os.chmod(path, 0o600)
    return path


def ensure_singbox_unit() -> None:
    """systemd-шаблон: sing-box крутится ВНУТРИ netns модема, супервизия + автоперезапуск.
    Заменяет nohup+pkill старого кода."""
    unit = f"""[Unit]
Description=ProxyVethLab sing-box (modem %i)
After=network-online.target
[Service]
NetworkNamespacePath=/run/netns/ns_%i
ExecStart={SINGBOX_BIN} run -c {SINGBOX_DIR}/%i.json
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
"""
    path = f"/etc/systemd/system/{SINGBOX_UNIT}"
    if DRY_RUN:
        print(f"    [dry] ensure {path} + systemctl daemon-reload")
        return
    with open(path, "w") as f:
        f.write(unit)
    run("systemctl daemon-reload")


def start_transport(m: Modem) -> str:
    """Поднять sing-box для модема. Вернуть имя tun (sing-box сам создаёт и адресует его)."""
    ensure_singbox_unit()
    write_singbox_config(m)
    run(f"systemctl start proxyveth-singbox@{m.n}")
    if not wait_for_iface(m.ns, m.tun):
        raise RuntimeError(f"{m.tun} не появился — sing-box не стартовал")
    return m.tun


def stop_transport(m: Modem) -> None:
    run(f"systemctl stop proxyveth-singbox@{m.n}", check=False)
    run(f"rm -f {SINGBOX_DIR}/{m.n}.json", check=False)


# ---------------------------------------------------------------------------
def bring_up(m: Modem) -> None:
    """Поднять модем ЦЕЛИКОМ (инвариант: существует => настроен полностью).

    Порядок важен: bypass+NAT готовим ДО старта sing-box (чтобы он достучался до
    прокси), tun-маршруты — ПОСЛЕ (tun создаёт sing-box)."""
    print(f"\n── UP modem {m.n} ──  {m.proxy_host}:{m.proxy_port}")
    net, ns, host_if, ns_if = m.net, m.ns, m.host_if, f"{m.host_if}_ns"

    # 1. netns + lo + DNS на VM
    run(f"ip netns add {ns}")
    run("ip link set lo up", ns=ns)
    write_netns_resolv(m)

    # 2. veth: host-конец = ethN (.100, виден mproxy), ns-конец = .254
    run(f"ip link add {host_if} type veth peer name {ns_if}")
    run(f"ip link set {ns_if} netns {ns}")
    fence_iface(host_if)
    run(f"ip addr add {net}.{HOST_OCTET}/24 dev {host_if}")
    run(f"ip link set {host_if} up")
    run(f"ip addr add {net}.{NS_OCTET}/24 dev {ns_if}", ns=ns)
    run(f"ip link set {ns_if} up", ns=ns)

    # 3. rp_filter loose на нашем пути
    run(f"sysctl -w net.ipv4.conf.{host_if}.rp_filter={RP_FILTER}")
    run(f"sysctl -w net.ipv4.conf.all.rp_filter={RP_FILTER}")   # TODO: проверить влияние на хост

    # 4. BYPASS: прокся мимо тоннеля (нужно ДО старта sing-box)
    run(f"ip route add {m.proxy_host}/32 via {net}.{HOST_OCTET}", ns=ns)
    # DNS-резолвер {net}.{HOST_OCTET} — линк-локально через ns_if, маршрут не нужен

    # 5. host: policy-routing .100 -> в netns; NAT для bypass-трафика наружу
    ensure_rt_table(m.table, f"pvlab_{m.n}")
    run(f"ip rule add from {net}.{HOST_OCTET} table {m.table}")
    run(f"ip route add default via {net}.{NS_OCTET} dev {host_if} table {m.table}")
    run(f"iptables -t nat -C POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE "
        f"|| iptables -t nat -A POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE")

    # 6. транспорт: sing-box создаёт tunN (теперь может достучаться до прокси)
    tun = start_transport(m)

    # 7. маршруты через тоннель (tunN уже существует)
    run(f"ip route add default dev {tun}", ns=ns)
    run(f"ip route add {net}.{MGMT_OCTET}/32 dev {tun}", ns=ns)   # управление модемом -> тоннель
    print(f"   modem {m.n} READY (dry-run plan)" if DRY_RUN else f"   modem {m.n} up")


def tear_down(m: Modem) -> None:
    """Снять модем ЦЕЛИКОМ. Порядок: транспорт -> ns/veth -> host-правила."""
    print(f"\n── DOWN modem {m.n} ──")
    net = m.net
    stop_transport(m)
    run(f"ip netns del {m.ns}", check=False)            # удаляет ns + ns-конец veth + tun
    run(f"ip link del {m.host_if}", check=False)        # host-конец (если остался)
    run(f"ip rule del from {net}.{HOST_OCTET} table {m.table}", check=False)
    run(f"ip route flush table {m.table}", check=False)
    run(f"iptables -t nat -D POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE", check=False)
    print(f"    [stub] rm /etc/netns/{m.ns}/ , rm fence-файл {m.host_if}")


# ---------------------------------------------------------------------------
# Заглушки периферии
def cmd_sync() -> list[Modem]:
    """ЗАГЛУШКА: тянуть список модемов (Google Sheets CSV / локальный конфиг)."""
    print("[stub] sync: загрузить модемы из источника конфигурации")
    return []


def cmd_status() -> None:
    print("[stub] status: ethN / ns / sing-box(tun) / WAN IP по каждому модему")


def cmd_watchdog() -> None:
    print("[stub] watchdog: sing-box супервизит systemd; здесь — целостность маршрутов/ns")


# ---------------------------------------------------------------------------
def _demo_modem(n: int) -> Modem:
    return Modem(n=n, proxy_host="95.165.86.25", proxy_port=12000 + n,
                 login=f"user{n}", password="xxx")


def main() -> None:
    global DRY_RUN
    p = argparse.ArgumentParser(prog="proxyveth", description="ProxyVethLab (experimental)")
    p.add_argument("cmd", choices=["up", "down", "status", "sync", "watchdog"])
    p.add_argument("target", nargs="?", help="N | all")
    p.add_argument("--apply", action="store_true", help="реально выполнять (иначе dry-run)")
    a = p.parse_args()
    DRY_RUN = not a.apply

    if a.cmd == "status":
        cmd_status()
    elif a.cmd == "sync":
        cmd_sync()
    elif a.cmd == "watchdog":
        cmd_watchdog()
    elif a.cmd in ("up", "down"):
        if not a.target:
            sys.exit(f"proxyveth {a.cmd} [N|all]")
        fn = bring_up if a.cmd == "up" else tear_down
        if a.target == "all":
            for m in cmd_sync():
                fn(m)
        else:
            fn(_demo_modem(int(a.target)))   # TODO: брать модем из конфига, не demo


if __name__ == "__main__":
    main()
