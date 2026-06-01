# modlink

Turn remote modems into local network interfaces via HTTPS proxy.

Each modem on a remote server (MSK/SPB) becomes a virtual eth interface on the target machine — with the same `192.168.N.1` gateway address and Huawei web-API accessible transparently through HTTP CONNECT.

Transport: **sing-box HTTPS proxy** (TLS, Basic Auth per modem). No VPN protocols.

---

## Components

| File | Role |
|---|---|
| `server.py` | Runs on the **remote host** (where modems are). Starts sing-box as HTTPS proxy. |
| `panel.py`  | Web UI for managing modems. Works on Linux (systemd) and Windows 10+. |
| `deploy-win.ps1` | One-shot setup for Windows 10: Python, Flask, sing-box, TLS cert. |

---

## Remote server setup (Linux)

```bash
# 1. Install sing-box
bash <(curl -fsSL https://sing-box.app/installer.sh)

# 2. Get scripts
curl -fsSL https://raw.githubusercontent.com/Tovarish666/modlink/main/server.py \
  -o /usr/local/bin/modlink-server && chmod +x /usr/local/bin/modlink-server

curl -fsSL https://raw.githubusercontent.com/Tovarish666/modlink/main/panel.py \
  -o /usr/local/bin/modlink-panel && chmod +x /usr/local/bin/modlink-panel

# 3. Create modem list
mkdir -p /etc/modlink
cat > /etc/modlink/modems.conf << 'EOF'
# N  password
4   abc123def4
41  xyz987mnpq
EOF

# 4. Apply + verify
modlink-server apply
modlink-server status
modlink-server test 4
```

**Or use the web panel:**

```bash
pip install flask
modlink-panel          # → http://localhost:5000
```

---

## Windows 10 setup (temporary)

```powershell
# Run PowerShell as Administrator:
Set-ExecutionPolicy Bypass -Scope Process
irm https://raw.githubusercontent.com/Tovarish666/modlink/main/deploy-win.ps1 | iex
```

Opens panel at `http://localhost:5000` automatically.

---

## modems.conf format

```
# /etc/modlink/modems.conf  (Linux)
# %ProgramData%\modlink\modems.conf  (Windows)
#
# N  password
# N = modem number = third octet of 192.168.N.x
4   abc123def4
41  xyz987mnpq
```

Passwords are auto-generated if omitted.

---

## How gateway emulation works

The remote server runs sing-box with L2 access to `192.168.N.1` (Huawei router).  
A client doing `CONNECT 192.168.N.1:80` through the proxy gets transparently forwarded to the real device — no VPN, plain HTTP CONNECT.

---

## Client modems.conf format

After running `⎘ Copy` in the panel:

```
N  SERVER_IP:8443:modem-N:password
```

Paste into the client-side `modems.conf`.
