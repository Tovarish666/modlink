# modlink — server

Exposes LTE modems as a managed HTTPS/SOCKS5 proxy pool.

Each modem N → dedicated port `BASE_PORT + N` → sing-box `mixed` inbound (handles both HTTP CONNECT and SOCKS5) → outbound bound to `192.168.N.100` (modem interface).  
Huawei web-API (`192.168.N.1`) accessible transparently via HTTP CONNECT through the proxy.

---

## Architecture

```
Client (Proxmox / proxyveth)
    │ HTTPS proxy  →  IP:PORT:modemN:pass
    ▼
modlink server  (this repo)
    sing-box  mixed inbound  (port BASE+N, TLS)
    │
    outbound  bind 192.168.N.100
    │
    LTE modem N  →  internet (mobile IP)
```

---

## Quick start — Linux

```bash
# 1. Install sing-box
bash <(curl -fsSL https://sing-box.app/installer.sh)

# 2. Get scripts
curl -fsSL https://raw.githubusercontent.com/Tovarish666/modlink/main/server.py \
  -o /usr/local/bin/modlink-server && chmod +x /usr/local/bin/modlink-server
curl -fsSL https://raw.githubusercontent.com/Tovarish666/modlink/main/panel.py \
  -o /usr/local/bin/modlink-panel  && chmod +x /usr/local/bin/modlink-panel

# 3. Create modem list  (/etc/modlink/modems.conf)
mkdir -p /etc/modlink
printf "1  pass1\n2  pass2\n" > /etc/modlink/modems.conf

# 4. Apply
modlink-server apply
modlink-server status
modlink-server test 1

# 5. Web panel
python3 /usr/local/bin/modlink-panel    # → http://localhost:5000
```

---

## Quick start — Windows 10 (temporary)

```powershell
# Run as Administrator:
Set-ExecutionPolicy Bypass -Scope Process
irm https://raw.githubusercontent.com/Tovarish666/modlink/main/deploy-win.ps1 | iex
```

What the script does:
1. Checks / installs Python 3
2. Downloads `sing-box.exe` (latest release)
3. Generates self-signed TLS cert (PowerShell PKI, no openssl required)
4. Downloads `panel.py` and `server.py`
5. Registers autostart via Task Scheduler (runs as SYSTEM at boot)
6. Opens panel at `http://localhost:5000`

Manage the service:
```powershell
Start-ScheduledTask -TaskName "modlink-panel"
Stop-ScheduledTask  -TaskName "modlink-panel"
Get-ScheduledTask   -TaskName "modlink-panel" | Select TaskName, State
```

---

## modems.conf format

```
# /etc/modlink/modems.conf      (Linux)
# %ProgramData%\modlink\modems.conf  (Windows)
#
# N  password
# N = modem number = third octet of 192.168.N.x
1   abc123def4
2   xyz987mnpq
```

Passwords are auto-generated if omitted.

---

## Web panel features

- **External IP** — auto-detect or set manually (shown in copy output)  
- **Base port** — configurable (default 10000), modem N → port `BASE + N`  
- **⟳ Auto** — fetches public IP from api.ipify.org  
- **↺** — regenerate password per modem  
- **▶ Test** — checks exit IP + Huawei `.1` API via proxy  
- **⎘ Copy** — copies `IP:PORT:modemN:pass` lines (ready for client `modems.conf`)  
- **Apply** — saves config + restarts sing-box  

---

## Proxy credentials format

```
IP:PORT:LOGIN:PASS

Example (modem 1, base port 10000):
  1.2.3.4:10001:modem1:abc123def4

Protocol: HTTP CONNECT + SOCKS5 (mixed, on the same port)
TLS: yes (self-signed cert, use --proxy-insecure or add cert to trust store)
```

---

## Port layout

| Modem | Port      | Protocol       |
|-------|-----------|----------------|
| 1     | BASE+1    | HTTP + SOCKS5  |
| 2     | BASE+2    | HTTP + SOCKS5  |
| N     | BASE+N    | HTTP + SOCKS5  |

Default BASE = 10000. One port per modem, both protocols.

---

## Huawei gateway emulation

The remote server has L2 access to `192.168.N.1` (Huawei router web-API).  
A client doing `CONNECT 192.168.N.1:80` through the proxy gets forwarded to the real device — same address, same API, no VPN.
