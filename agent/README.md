# ProxyVeth agent (Proxmox / QEMU approach)

Новый подход к «агентским» интерфейсам. Старый вариант (TAP-адаптер в Windows +
правка реестра под «Remote NDIS») **заброшен** — это была *имитация*, которую
Windows периодически видит насквозь («от пары до пары»). Здесь — *эмуляция*:
настоящее виртуальное USB-устройство создаёт гипервизор, а всё сетевое живёт на
Linux.

## Идея

Машины — это QEMU/KVM VM на Proxmox. У QEMU есть штатное устройство `usb-net`,
эмулирующее USB-сетевой адаптер по протоколу **RNDIS**. Любой RNDIS-девайс
Windows называет ровно `Remote NDIS based Internet Sharing Device` — то есть то,
что нам нужно, но **по-настоящему**: Windows грузит свой инбоксовый драйвер,
врать некому, подписи внутри Windows не нужно.

Реальные модемы и так проброшены в Windows-VM как USB (`USB\VID_12D1…`).
Виртуальные встают **на тот же слой, рядом с реальными** — настоящий паритет.

```
Windows VM      [USB RNDIS N]  ← QEMU usb-net (VID можно выставить 12D1)
                     │ Windows грузит родной RNDIS-драйвер, берёт 192.168.N.100 по DHCP
Proxmox host    netdev usb-net ──socket──►
pvagent (Linux VM)   · dnsmasq  — DHCP подсети N: .100, шлюз .1
                     · HiLink   — эмуляция веб-морды 192.168.N.1 (реконнект/ребут)
                     · redsocks/sing-box — выход через SOCKS5 нужного реального модема
```

Тяжёлое (DHCP, маршрут, туннель) — на Linux, где надёжно и дёшево.

## Связи

| линк | транспорт | зачем |
|---|---|---|
| `modlink.exe` → `pvagent` | **HTTP/JSON + токен** (WinHTTP уже в .exe) | создать/удалить/список адаптеров, статус |
| `pvagent` → Proxmox host | **SSH-ключ** или Proxmox API-токен | `qm`/QMP: подключить usb-net к Windows-VM |
| usb-net → `pvagent` | socket (netdev) | данные гостя в агент |

Control API (черновик):
```
POST   /adapter      {"n":103,"socks5":"95.165.83.236:15000:log:pass"}
DELETE /adapter/103
GET    /adapters
GET    /status
```
Вкладка «Адаптеры» в .exe — тонкий клиент этого API.

## Провижининг VM

`provision-vm.sh` запускается **на Proxmox-хосте от root**: качает Debian 12
cloud-image, создаёт VM с cloud-init (пользователь, SSH-ключ, management-сеть,
guest-agent), ставит зависимости, разворачивает pvagent и настраивает ключ
VM→хост для `qm`.

```bash
# на Proxmox-хосте
ssh-keygen -t ed25519          # если ключа ещё нет
VMID=9000 BRIDGE=vmbr0 AGENT_IP=192.168.99.10/24 GW=192.168.99.1 ./provision-vm.sh
```

Параметры (env): `VMID VMNAME STORAGE BRIDGE CORES MEM DISK CIUSER AGENT_IP GW
IMG_URL REPO_URL REPO_REF HOST_SSHKEY FORCE`.

## Статус / что дальше

- [x] Архитектура и провижининг VM (этот каталог).
- [ ] `pvagent`: HTTP-API + управление QEMU usb-net (qm/QMP) + dnsmasq + SOCKS5-выход.
- [ ] Проверка на стенде: один usb-net в Windows-VM опознаётся как реальный RNDIS,
      получает интернет через модем, состояние становится «Сеть N».
- [ ] Масштаб до ~40, VID/PID под Huawei, при желании — HiLink-эмуляция.

Открытые вопросы к согласованию: зрелость QEMU `usb-net`/RNDIS на этой Win10 и
сколько устройств тянет одна VM; нужен ли патч QEMU для VID/PID; жёсткость
требования «не полагаться на Proxmox» (bare-metal fallback = usbip-win2 в
Windows, тяжелее).
