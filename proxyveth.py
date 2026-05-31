#!/usr/bin/env python3
"""
ProxyVethLab — экспериментальный rewrite адаптера proxyveth.  БОЛВАНКА.

Удалённый SOCKS5-прокси (модем в СПб) -> локальный "модем" ethN @ 192.168.N.100,
чтобы немодифицированный mobileproxy.space работал как с физическим модемом.

Обе плоскости одного модема -> в ОДНУ проксю:
    данные      192.168.N.100  -> прокся -> 3proxy(СПб) -> модем -> интернет
    управление  192.168.N.1    -> та же прокся -> 3proxy connect к своему .1 (веб модема)

Подробности и обоснования решений — в README.md.
Транспорт (socks5->tun) пока ЗАГЛУШКА. run() по умолчанию dry-run.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
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
    def table(self) -> int:
        return TABLE_BASE + self.n

    @property
    def proxy_url(self) -> str:
        return f"socks5://{self.login}:{self.password}@{self.proxy_host}:{self.proxy_port}"


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
    """Основной (WAN) интерфейс хоста — НЕ хардкодить eth0. TODO: кэшировать."""
    if DRY_RUN:
        return "$(WAN)"
    r = subprocess.run("ip route show default | grep -oP 'dev \\K\\S+' | head -1",
                       shell=True, text=True, capture_output=True)
    return r.stdout.strip() or "eth0"


def ensure_rt_table(table_id: int, name: str) -> None:
    """Добавить запись в /etc/iproute2/rt_tables идемпотентно (точное совпадение строки)."""
    # TODO: точная проверка строки "<id>\t<name>", без подстрочных ложных срабатываний
    run(f"grep -qxF '{table_id}\t{name}' /etc/iproute2/rt_tables "
        f"|| echo '{table_id}\t{name}' >> /etc/iproute2/rt_tables")


def fence_iface(host_if: str) -> None:
    """Сказать systemd-networkd / NetworkManager не трогать ethN. TODO: реализовать."""
    # networkd: /etc/systemd/network/10-pvlab-<if>.network с [Match]Name=<if> + Unmanaged=yes
    # NM (если есть): /etc/NetworkManager/conf.d/ unmanaged-devices+=interface-name:<if>
    print(f"    [stub] fence {host_if} from networkd/NM (Unmanaged)")


def write_netns_resolv(m: Modem) -> None:
    """Per-netns DNS: резолвер на VM (host-конец .100), не модем. TODO: реальный резолвер."""
    # /etc/netns/ns_N/resolv.conf -> nameserver 192.168.N.100
    # резолвер (dnsmasq/unbound) на VM слушает .100:53; запрос ns->.100 линк-локально, мимо тоннеля
    print(f"    [stub] /etc/netns/{m.ns}/resolv.conf -> nameserver {m.net}.{HOST_OCTET}")


def start_transport(m: Modem) -> str:
    """ЗАГЛУШКА. Поднять socks5->tun внутри netns. Вернуть имя tun-устройства.

    РАЗВИЛКА (см. README): tun2socks | hev-socks5-tunnel | sing-box.
    Должно: создать tunN в ns_N, направить весь трафик в m.proxy_url,
    НЕ трогать UDP так, чтобы убивать 3proxy, но и не глушить QUIC насмерть.
    """
    print(f"    [stub] start_transport -> tun{m.n} via {m.proxy_url}")
    return f"tun{m.n}"


def stop_transport(m: Modem) -> None:
    print(f"    [stub] stop_transport tun{m.n}")


# ---------------------------------------------------------------------------
def bring_up(m: Modem) -> None:
    """Поднять один модем ЦЕЛИКОМ (инвариант: существует => настроен полностью)."""
    print(f"\n── UP modem {m.n} ──  {m.proxy_host}:{m.proxy_port}")
    net, ns, host_if, ns_if, table = m.net, m.ns, m.host_if, f"{m.host_if}_ns", m.table

    # 1. netns + lo + DNS на VM
    run(f"ip netns add {ns}")
    run(f"ip link set lo up", ns=ns)
    write_netns_resolv(m)

    # 2. veth: host-конец = ethN (.100, виден mproxy), ns-конец = .254 (в netns)
    run(f"ip link add {host_if} type veth peer name {ns_if}")
    run(f"ip link set {ns_if} netns {ns}")
    fence_iface(host_if)
    run(f"ip addr add {net}.{HOST_OCTET}/24 dev {host_if}")
    run(f"ip link set {host_if} up")
    run(f"ip addr add {net}.{NS_OCTET}/24 dev {ns_if}", ns=ns)
    run(f"ip link set {ns_if} up", ns=ns)

    # 3. rp_filter loose на нашем пути (сторож mobileproxy тоже подержит 0, но не полагаемся)
    run(f"sysctl -w net.ipv4.conf.{host_if}.rp_filter={RP_FILTER}")
    run(f"sysctl -w net.ipv4.conf.all.rp_filter={RP_FILTER}")   # TODO: проверить влияние на хост

    # 4. транспорт внутри netns (ЗАГЛУШКА)
    tun = start_transport(m)

    # 5. маршруты ВНУТРИ netns
    run(f"ip route add default dev {tun}", ns=ns)                       # всё в тоннель
    run(f"ip route add {net}.{MGMT_OCTET}/32 dev {tun}", ns=ns)         # управление .1 — в тоннель
    run(f"ip route add {m.proxy_host}/32 via {net}.{HOST_OCTET}", ns=ns)  # BYPASS: прокся мимо тоннеля
    # DNS-резолвер = {net}.{HOST_OCTET} — линк-локально через ns_if, маршрут не нужен

    # 6. host: policy-routing .100 -> в netns; NAT для bypass-трафика наружу
    ensure_rt_table(table, f"pvlab_{m.n}")
    run(f"ip rule add from {net}.{HOST_OCTET} table {table}")
    run(f"ip route add default via {net}.{NS_OCTET} dev {host_if} table {table}")
    run(f"iptables -t nat -C POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE "
        f"|| iptables -t nat -A POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE")
    print(f"   modem {m.n} READY (dry-run plan)" if DRY_RUN else f"   modem {m.n} up")


def tear_down(m: Modem) -> None:
    """Снять модем ЦЕЛИКОМ. Порядок: транспорт -> ns/veth -> host-правила."""
    print(f"\n── DOWN modem {m.n} ──")
    net, ns, host_if, table = m.net, m.ns, m.host_if, m.table
    stop_transport(m)
    run(f"ip netns del {ns}", check=False)            # удаляет ns + ns-конец veth + процессы в ns
    run(f"ip link del {host_if}", check=False)        # host-конец (если остался)
    run(f"ip rule del from {net}.{HOST_OCTET} table {table}", check=False)
    run(f"ip route flush table {table}", check=False)
    run(f"iptables -t nat -D POSTROUTING -s {net}.0/24 -o {wan_iface()} -j MASQUERADE", check=False)
    print(f"    [stub] rm /etc/netns/{ns}/ , rm fence-файл {host_if}")


# ---------------------------------------------------------------------------
# Заглушки периферии
def cmd_sync() -> list[Modem]:
    """ЗАГЛУШКА: тянуть список модемов (Google Sheets CSV / локальный конфиг)."""
    print("[stub] sync: загрузить модемы из источника конфигурации")
    return []


def cmd_status() -> None:
    print("[stub] status: ethN / ns / tun / WAN IP по каждому модему")


def cmd_watchdog() -> None:
    print("[stub] watchdog: пересоздавать упавшие модемы целиком (idempotent)")


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
