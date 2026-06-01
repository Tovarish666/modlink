#!/usr/bin/env python3
"""
modlink panel — веб-панель управления. Только stdlib, pip не нужен.
Запуск: python panel.py [--port 5000]
Открыть: http://localhost:5000
"""
from __future__ import annotations
import argparse, atexit, json, os, random, re, shutil, socket, subprocess
import sys, time, urllib.request, webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

def strip_ansi(s: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', s)

# ---------------------------------------------------------------------------
IS_WIN = sys.platform == "win32"

if IS_WIN:
    CONF_DIR    = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "modlink"
    SINGBOX_BIN = Path("C:/modlink/sing-box.exe")
else:
    CONF_DIR    = Path("/etc/modlink")
    SINGBOX_BIN = Path(shutil.which("sing-box") or "/usr/local/bin/sing-box")

MODEMS_CONF  = CONF_DIR / "modems.conf"
SB_CONF      = CONF_DIR / "singbox.json"
SERVER_CONF  = CONF_DIR / "server.json"
SB_LOG       = CONF_DIR / "singbox.log"
CERT_FILE    = CONF_DIR / "certs" / "cert.pem"
KEY_FILE     = CONF_DIR / "certs" / "key.pem"

def has_tls() -> bool:
    return CERT_FILE.exists() and KEY_FILE.exists()

def read_log(tail: int = 80) -> list[str]:
    if not SB_LOG.exists():
        return []
    lines = SB_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-tail:]

DEFAULT_BASE_PORT = 10000

_sb_proc: subprocess.Popen | None = None

# ---------------------------------------------------------------------------
def rand_pass(length: int = 10) -> str:
    chars = "abcdefghjkmnpqrstuvwxyz23456789"
    return "".join(random.choices(chars, k=length))

def load_server_conf() -> dict:
    if SERVER_CONF.exists():
        try:
            return json.loads(SERVER_CONF.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"ext_ip": "", "base_port": DEFAULT_BASE_PORT}

def save_server_conf(conf: dict) -> None:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    SERVER_CONF.write_text(json.dumps(conf, indent=2), encoding="utf-8")

def fetch_external_ip() -> str:
    candidates = [
        ("https://api.ipify.org",          {}),
        ("https://api4.ipify.org",         {}),
        ("http://checkip.amazonaws.com",   {}),
        ("http://ip.me",                   {"Accept": "text/plain",
                                            "User-Agent": "curl/7.68.0"}),
    ]
    for url, headers in candidates:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=6) as r:
                ip = r.read().decode().strip()
            # убеждаемся что получили IP, а не HTML
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return ip
        except Exception:
            continue
    return ""

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_sb_status() -> str:
    if IS_WIN:
        return "active" if (_sb_proc and _sb_proc.poll() is None) else "stopped"
    r = subprocess.run("systemctl is-active modlink",
                       shell=True, capture_output=True, text=True)
    return r.stdout.strip() or "unknown"

def load_modems() -> list[dict]:
    if not MODEMS_CONF.exists():
        return []
    result = []
    for line in MODEMS_CONF.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        try:
            n = int(parts[0])
        except (ValueError, IndexError):
            continue
        result.append({"n": n, "password": parts[1] if len(parts) > 1 else rand_pass()})
    return sorted(result, key=lambda x: x["n"])

def save_modems(modems: list[dict]) -> None:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    lines = [f"{m['n']}  {m['password']}" for m in sorted(modems, key=lambda x: x["n"])]
    MODEMS_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")

def gen_singbox_config(modems: list[dict], base_port: int = DEFAULT_BASE_PORT) -> dict:
    """
    Диапазон портов: каждый модем N слушает на BASE_PORT + N.
    Тип mixed — один порт обслуживает HTTP CONNECT и SOCKS5.
    Маршрутизация по inbound тегу (не auth_user) — чище и надёжнее.
    """
    inbounds, outbounds, rules = [], [], []
    for m in modems:
        port    = base_port + m["n"]
        tag_in  = f"in-{m['n']}"
        tag_out = f"out-{m['n']}"
        # mixed не поддерживает TLS → http+TLS или mixed без TLS
        tls = has_tls()
        inbound: dict = {
            "type": "http" if tls else "mixed",
            "tag": tag_in,
            "listen": "0.0.0.0",
            "listen_port": port,
            "users": [{"username": f"modem{m['n']}", "password": m["password"]}],
        }
        if tls:
            inbound["tls"] = {"enabled": True,
                              "certificate_path": str(CERT_FILE),
                              "key_path": str(KEY_FILE)}
        inbounds.append(inbound)
        outbounds.append({
            "type": "direct",
            "tag": tag_out,
            "inet4_bind_address": f"192.168.{m['n']}.100",
        })
        rules.append({"inbound": [tag_in], "outbound": tag_out})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules},
    }

def apply_singbox(modems: list[dict], base_port: int) -> tuple[bool, str]:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    SB_CONF.write_text(
        json.dumps(gen_singbox_config(modems, base_port), indent=2), encoding="utf-8")
    if not IS_WIN:
        SB_CONF.chmod(0o600)
    r = subprocess.run([str(SINGBOX_BIN), "check", "-c", str(SB_CONF)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, strip_ansi((r.stderr or r.stdout).strip())
    if IS_WIN:
        global _sb_proc
        if _sb_proc and _sb_proc.poll() is None:
            _sb_proc.terminate()
            try: _sb_proc.wait(timeout=5)
            except subprocess.TimeoutExpired: _sb_proc.kill()
        log_fh = open(SB_LOG, "w", encoding="utf-8")
        _sb_proc = subprocess.Popen(
            [str(SINGBOX_BIN), "run", "-c", str(SB_CONF)],
            stdout=log_fh, stderr=log_fh)
        time.sleep(2)
        ok = _sb_proc.poll() is None
        log_fh.flush()
        if not ok:
            err = strip_ansi("\n".join(read_log(20)))
            return False, err or "crashed (no output)"
        return True, "active"
    else:
        r2 = subprocess.run("systemctl restart modlink",
                            shell=True, capture_output=True, text=True, timeout=30)
        if r2.returncode != 0:
            return False, strip_ansi((r2.stderr or r2.stdout).strip())
        time.sleep(1)
        return True, get_sb_status()

if IS_WIN:
    atexit.register(lambda: _sb_proc.terminate()
                    if _sb_proc and _sb_proc.poll() is None else None)

# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status: int = 200) -> None:
        self._send(status, json.dumps(data, ensure_ascii=False).encode(), "application/json")

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length)) if length else {}

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            body = HTML_PAGE.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/info":
            sconf = load_server_conf()
            self._json({
                "local_ip":  get_local_ip(),
                "ext_ip":    sconf.get("ext_ip", ""),
                "base_port": sconf.get("base_port", DEFAULT_BASE_PORT),
                "status":    get_sb_status(),
                "tls":       has_tls(),
            })

        elif path == "/api/modems":
            self._json(load_modems())

        elif path == "/api/logs":
            self._json({"lines": read_log(100)})

        elif path == "/api/external-ip":
            ip = fetch_external_ip()
            if ip:
                sconf = load_server_conf()
                sconf["ext_ip"] = ip
                save_server_conf(sconf)
                self._json({"ip": ip})
            else:
                self._json({"error": "не удалось определить"}, 500)

        elif path.startswith("/api/test/"):
            try:
                n = int(path.split("/")[-1])
            except ValueError:
                return self._json({"error": "invalid N"}, 400)
            modems = load_modems()
            m = next((x for x in modems if x["n"] == n), None)
            if not m:
                return self._json({"error": f"модем {n} не найден"}, 404)
            sconf    = load_server_conf()
            port     = sconf.get("base_port", DEFAULT_BASE_PORT) + n
            scheme   = "https" if has_tls() else "http"
            proxy    = f"{scheme}://modem{n}:{m['password']}@127.0.0.1:{port}"
            insecure = "--proxy-insecure" if has_tls() else ""
            curl_cmd = f'curl -s --max-time 8 --proxy "{proxy}" {insecure}'.strip()
            r1 = subprocess.run(f"{curl_cmd} http://ip.me",
                                shell=True, capture_output=True, text=True, timeout=12)
            exit_ip = r1.stdout.strip()
            r2 = subprocess.run(
                f"{curl_cmd} http://192.168.{n}.1/api/webserver/SesTokInfo",
                shell=True, capture_output=True, text=True, timeout=10)
            self._json({"n": n, "exit_ip": exit_ip,
                        "huawei_ok": "SesInfo" in (r2.stdout or "")})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/apply":
            data   = self._read_body()
            modems = data.get("modems", [])
            if not modems:
                return self._json({"ok": False, "error": "нет модемов"}, 400)
            try:
                parsed = [{"n": int(m["n"]),
                           "password": str(m["password"]).strip()} for m in modems]
            except (KeyError, ValueError) as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            sconf = load_server_conf()
            if "base_port" in data:
                sconf["base_port"] = int(data["base_port"])
                save_server_conf(sconf)
            base_port = sconf.get("base_port", DEFAULT_BASE_PORT)
            save_modems(parsed)
            ok, status = apply_singbox(parsed, base_port)
            if not ok:
                return self._json({"ok": False, "error": status}, 500)
            self._json({"ok": True, "status": status})

        elif path == "/api/server-config":
            data  = self._read_body()
            sconf = load_server_conf()
            if "ext_ip" in data:
                sconf["ext_ip"] = str(data["ext_ip"]).strip()
            if "base_port" in data:
                sconf["base_port"] = int(data["base_port"])
            save_server_conf(sconf)
            self._json({"ok": True})

        else:
            self._json({"error": "not found"}, 404)

# ---------------------------------------------------------------------------
HTML_PAGE = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>modlink</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0e1117;--surface:#161b22;--surface2:#1c2128;
  --border:#21262d;--accent:#58a6ff;--success:#3fb950;
  --error:#f85149;--text:#c9d1d9;--muted:#8b949e;--r:6px;
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;min-height:100vh}
.wrap{max-width:940px;margin:0 auto;padding:24px 16px}
.hdr{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.hdr-title{font-size:17px;font-weight:600;color:#fff;letter-spacing:-.3px}
.hdr-title span{color:var(--muted);font-weight:400;font-size:13px;margin-left:4px}
.chips{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-left:auto}
.chip{display:flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:5px 11px;font-size:12px;font-family:monospace}
.chip-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em;margin-right:2px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;transition:background .3s}
.dot.on{background:var(--success);box-shadow:0 0 5px var(--success)}.dot.off{background:var(--error)}

/* server config row */
.sconf{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:9px 14px;margin-bottom:12px;flex-wrap:wrap}
.sconf-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.sconf input{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:13px;font-family:monospace;padding:4px 8px;outline:none;transition:border-color .15s;width:160px}
.sconf input:focus{border-color:var(--accent)}
.sconf-sep{width:1px;height:20px;background:var(--border);margin:0 4px}

.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:12px}
table{width:100%;border-collapse:collapse}
thead th{padding:9px 10px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;font-weight:500}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:rgba(255,255,255,.025)}
td{padding:6px 10px;vertical-align:middle}
.col-n{width:64px}.col-login{width:120px}.col-port{width:76px}.col-pass{min-width:160px}.col-test{width:160px}.col-act{width:84px;text-align:right}

input[type=text],input[type=number]{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:13px;font-family:monospace;padding:5px 8px;width:100%;outline:none;transition:border-color .15s}
input:focus{border-color:var(--accent)}
input[readonly]{color:var(--muted);cursor:default;background:var(--surface2)}
.inp-n{width:56px;-moz-appearance:textfield}
.inp-n::-webkit-inner-spin-button,.inp-n::-webkit-outer-spin-button{-webkit-appearance:none;margin:0}
.pass-wrap{display:flex;gap:4px}.pass-wrap input{flex:1}
.badge-h{font-size:10px;padding:1px 4px;border:1px solid var(--success);border-radius:3px;color:var(--success);margin-left:4px;vertical-align:middle;white-space:nowrap}

.btn{display:inline-flex;align-items:center;gap:5px;padding:6px 12px;border-radius:var(--r);border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:13px;cursor:pointer;transition:all .15s;white-space:nowrap;line-height:1.4}
.btn:hover{border-color:var(--accent);color:var(--accent)}.btn:active{opacity:.75}
.btn:disabled{opacity:.45;cursor:not-allowed;pointer-events:none}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#000;font-weight:600}
.btn-primary:hover{background:#79b8ff;border-color:#79b8ff;color:#000}
.btn-icon{padding:5px 7px}.btn-del:hover{border-color:var(--error);color:var(--error)}.btn-sm{padding:4px 9px;font-size:12px}

.bar{display:flex;gap:8px;align-items:center;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);flex-wrap:wrap}
.bar-right{margin-left:auto;display:flex;gap:8px}

.tres{font-size:12px;font-family:monospace;white-space:nowrap}
.tres.ok{color:var(--success)}.tres.fail{color:var(--error)}.tres.pend{color:var(--muted)}

.toasts{position:fixed;top:18px;right:18px;z-index:999;display:flex;flex-direction:column;gap:6px}
.toast{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:9px 15px;font-size:13px;max-width:300px;animation:tin .18s ease}
.toast.ok{border-color:var(--success);color:var(--success)}.toast.err{border-color:var(--error);color:var(--error)}.toast.info{border-color:var(--accent);color:var(--accent)}
@keyframes tin{from{transform:translateX(16px);opacity:0}to{transform:translateX(0);opacity:1}}
.spin{display:inline-block;width:11px;height:11px;border:2px solid currentColor;border-top-color:transparent;border-radius:50%;animation:rot .6s linear infinite}
@keyframes rot{to{transform:rotate(360deg)}}
.empty{text-align:center;padding:36px;color:var(--muted);font-size:13px}

/* log modal */
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);width:min(860px,95vw);max-height:80vh;display:flex;flex-direction:column}
.modal-hdr{display:flex;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);gap:8px}
.modal-hdr h3{font-size:14px;font-weight:600;flex:1;color:#fff}
.log-body{flex:1;overflow-y:auto;padding:12px 16px;font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;color:var(--text);background:var(--bg)}
.log-body .err{color:var(--error)}.log-body .warn{color:var(--warn,#d29922)}.log-body .ok{color:var(--success)}
</style>
</head>
<body>
<div class="wrap">
  <!-- header -->
  <div class="hdr">
    <div class="hdr-title">modlink <span>server</span></div>
    <div class="chips">
      <div class="chip"><span class="chip-label">Локальный IP</span><span id="localIp">…</span></div>
      <div class="chip"><div class="dot" id="dot"></div><span id="srvStatus">…</span></div>
    </div>
  </div>

  <!-- server config: external IP + base port -->
  <div class="sconf">
    <span class="sconf-label">Внешний IP</span>
    <input id="extIp" type="text" placeholder="1.2.3.4" oninput="markDirty()">
    <button class="btn btn-sm" id="fetchIpBtn" onclick="fetchExtIp()" title="Определить автоматически">⟳ Авто</button>
    <div class="sconf-sep"></div>
    <span class="sconf-label">Базовый порт</span>
    <input id="basePort" type="number" value="10000" min="1024" max="60000" style="width:90px" oninput="markDirty()">
    <button class="btn btn-sm" id="saveConfBtn" onclick="saveConf()" style="display:none">Сохранить</button>
  </div>

  <!-- table -->
  <div class="card">
    <table>
      <thead><tr>
        <th class="col-n">N</th>
        <th class="col-login">Логин</th>
        <th class="col-port">Порт</th>
        <th class="col-pass">Пароль</th>
        <th class="col-test">Тест</th>
        <th class="col-act"></th>
      </tr></thead>
      <tbody id="tbody"><tr><td colspan="6" class="empty">Загрузка…</td></tr></tbody>
    </table>
  </div>

  <div class="bar">
    <button class="btn" onclick="addRow()">+ Добавить</button>
    <button class="btn" onclick="openLogs()" style="color:var(--muted)">≡ Логи</button>
    <div class="bar-right">
      <button class="btn" onclick="copyClient()">⎘&nbsp;Скопировать</button>
      <button class="btn btn-primary" id="applyBtn" onclick="doApply()">Применить</button>
    </div>
  </div>
</div>

<!-- log modal -->
<div class="modal-overlay" id="logModal" onclick="if(event.target===this)closeLogs()">
  <div class="modal">
    <div class="modal-hdr">
      <h3>≡ sing-box logs</h3>
      <button class="btn btn-sm" onclick="refreshLogs()">⟳ Обновить</button>
      <button class="btn btn-sm" onclick="closeLogs()">✕</button>
    </div>
    <div class="log-body" id="logBody">Загрузка…</div>
  </div>
</div>

<div class="toasts" id="toasts"></div>

<script>
let localIp='', extIp='', basePort=10000, confDirty=false, hasTls=false;

function toast(msg,type='info',ms=3200){
  const el=document.createElement('div');el.className=`toast ${type}`;el.textContent=msg;
  document.getElementById('toasts').appendChild(el);setTimeout(()=>el.remove(),ms);
}
function randPass(len=10){
  const a='abcdefghjkmnpqrstuvwxyz23456789';
  return Array.from({length:len},()=>a[Math.floor(Math.random()*a.length)]).join('');
}
function calcPort(n){return basePort+parseInt(n||0);}

function markDirty(){
  confDirty=true;
  document.getElementById('saveConfBtn').style.display='';
}

function makeRow(n='',pass=''){
  const tr=document.createElement('tr');if(n)tr.dataset.n=n;
  const p=pass||randPass();
  const port=n?calcPort(n):'—';
  tr.innerHTML=`
    <td class="col-n"><input class="inp-n" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="3" value="${n}" placeholder="N" oninput="onN(this)"></td>
    <td class="col-login"><input type="text" value="${n?'modem'+n:''}" readonly tabindex="-1"></td>
    <td class="col-port"><input type="text" value="${port}" readonly tabindex="-1" id="port-${n}"></td>
    <td class="col-pass"><div class="pass-wrap"><input type="text" value="${p}" autocomplete="off"><button class="btn btn-icon" onclick="repass(this)" title="Новый пароль">↺</button></div></td>
    <td class="col-test"><span class="tres" id="tr${n}"></span></td>
    <td class="col-act" style="display:flex;gap:3px;justify-content:flex-end;padding:6px 10px">
      <button class="btn btn-sm" onclick="doTest(this)">▶ Test</button>
      <button class="btn btn-icon btn-del" onclick="delRow(this)">✕</button>
    </td>`;
  return tr;
}

function onN(inp){
  inp.value=inp.value.replace(/\\D/g,'').slice(0,3);   // только цифры, max 3
  const tr=inp.closest('tr');const n=inp.value;tr.dataset.n=n;
  tr.querySelector('.col-login input').value=n?`modem${n}`:'';
  const portInp=tr.querySelector('.col-port input');
  portInp.id=`port-${n}`;
  portInp.value=n?calcPort(n):'—';
  const sp=tr.querySelector('.tres');if(sp)sp.id=`tr${n}`;
}

function refreshPorts(){
  document.querySelectorAll('#tbody tr[data-n]').forEach(tr=>{
    const n=tr.dataset.n;
    const pi=tr.querySelector('.col-port input');
    if(pi&&n)pi.value=calcPort(n);
  });
}

function repass(btn){btn.closest('.pass-wrap').querySelector('input').value=randPass();}

function addRow(n='',pass=''){
  const tb=document.getElementById('tbody');
  const em=tb.querySelector('.empty');if(em)em.closest('tr').remove();
  tb.appendChild(makeRow(n,pass));
}
function delRow(btn){
  btn.closest('tr').remove();
  const tb=document.getElementById('tbody');
  if(!tb.querySelector('tr'))tb.innerHTML='<tr><td colspan="6" class="empty">Нет модемов — нажми + Добавить</td></tr>';
}
function getRows(){
  return[...document.querySelectorAll('#tbody tr[data-n]')]
    .map(tr=>({n:parseInt(tr.dataset.n),password:tr.querySelector('.pass-wrap input').value.trim()}))
    .filter(m=>m.n&&m.password);
}

async function loadInfo(){
  try{
    const d=await fetch('/api/info').then(r=>r.json());
    localIp=d.local_ip; basePort=d.base_port; hasTls=d.tls||false;
    document.getElementById('localIp').textContent=d.local_ip;
    const dot=document.getElementById('dot');
    dot.className='dot '+(d.status==='active'?'on':'off');
    document.getElementById('srvStatus').textContent=d.status;
    if(!confDirty){
      document.getElementById('extIp').value=d.ext_ip||'';
      document.getElementById('basePort').value=d.base_port;
      extIp=d.ext_ip||'';
    }
    refreshPorts();
  }catch(e){}
}

async function loadModems(){
  try{
    const ms=await fetch('/api/modems').then(r=>r.json());
    const tb=document.getElementById('tbody');tb.innerHTML='';
    if(!ms.length){tb.innerHTML='<tr><td colspan="6" class="empty">Нет модемов — нажми + Добавить</td></tr>';return;}
    ms.forEach(m=>tb.appendChild(makeRow(m.n,m.password)));
  }catch(e){}
}

async function fetchExtIp(){
  const btn=document.getElementById('fetchIpBtn');
  btn.disabled=true;btn.textContent='…';
  try{
    const d=await fetch('/api/external-ip').then(r=>r.json());
    if(d.ip){
      document.getElementById('extIp').value=d.ip;
      extIp=d.ip; confDirty=false;
      document.getElementById('saveConfBtn').style.display='none';
      toast(`Внешний IP: ${d.ip}`,'ok');
    } else {
      toast(d.error||'Не удалось определить IP','err');
    }
  }catch(e){toast('Ошибка','err');}
  btn.disabled=false;btn.innerHTML='⟳ Авто';
}

async function saveConf(){
  extIp=document.getElementById('extIp').value.trim();
  basePort=parseInt(document.getElementById('basePort').value)||10000;
  try{
    await fetch('/api/server-config',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ext_ip:extIp,base_port:basePort})});
    confDirty=false;
    document.getElementById('saveConfBtn').style.display='none';
    refreshPorts();
    toast('Настройки сохранены','ok');
  }catch(e){toast('Ошибка сохранения','err');}
}

async function doApply(){
  const rows=getRows();
  if(!rows.length){toast('Добавь хотя бы один модем','err');return;}
  // auto-save conf if dirty
  if(confDirty) await saveConf();
  const btn=document.getElementById('applyBtn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>&nbsp;Применяю…';
  try{
    const d=await fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({modems:rows,base_port:basePort})}).then(r=>r.json());
    if(d.ok)toast(`Применено  sing-box: ${d.status}`,'ok');
    else toast(d.error||'Ошибка','err',6000);
    loadInfo();
  }catch(e){toast('Нет связи','err');}
  btn.disabled=false;btn.innerHTML='Применить';
}

async function doTest(btn){
  const tr=btn.closest('tr');const n=parseInt(tr.dataset.n);
  if(!n){toast('Укажи N','err');return;}
  btn.disabled=true;
  const sp=document.getElementById(`tr${n}`);
  sp.className='tres pend';sp.innerHTML='<span class="spin"></span>';
  try{
    const d=await fetch(`/api/test/${n}`).then(r=>r.json());
    if(d.exit_ip){
      sp.className='tres ok';
      sp.innerHTML=d.exit_ip+(d.huawei_ok?'<span class="badge-h">H✓</span>':'');
      sp.title=`exit: ${d.exit_ip}  Huawei: ${d.huawei_ok?'OK':'нет'}`;
    }else{sp.className='tres fail';sp.textContent=d.error||'нет ответа';}
  }catch(e){sp.className='tres fail';sp.textContent='ошибка';}
  btn.disabled=false;
}

function copyClient(){
  const rows=getRows();
  if(!rows.length){toast('Нет модемов','err');return;}
  const ip=document.getElementById('extIp').value.trim()||localIp;
  const bp=parseInt(document.getElementById('basePort').value)||basePort;
  // формат: IP:PORT:login:pass  (без N-префикса)
  const lines=rows.map(m=>`${ip}:${bp+m.n}:modem${m.n}:${m.password}`);
  const text=lines.join('\\n');
  navigator.clipboard.writeText(text)
    .then(()=>toast(`Скопировано ${lines.length} строк`,'ok'))
    .catch(()=>{const ta=document.createElement('textarea');ta.value=text;
      document.body.appendChild(ta);ta.select();document.execCommand('copy');
      ta.remove();toast(`Скопировано ${lines.length} строк`,'ok');});
}

async function refreshLogs(){
  const el=document.getElementById('logBody');
  try{
    const d=await fetch('/api/logs').then(r=>r.json());
    if(!d.lines||!d.lines.length){el.textContent='(лог пуст)';return;}
    el.innerHTML=d.lines.map(l=>{
      const cls=l.match(/FATAL|ERROR|error/i)?'err':l.match(/WARN/i)?'warn':l.match(/INFO.*started|active/i)?'ok':'';
      const safe=l.replace(/&/g,'&amp;').replace(/</g,'&lt;');
      return cls?`<span class="${cls}">${safe}</span>`:safe;
    }).join('\n');
    el.scrollTop=el.scrollHeight;
  }catch(e){el.textContent='Ошибка загрузки логов';}
}
function openLogs(){document.getElementById('logModal').classList.add('open');refreshLogs();}
function closeLogs(){document.getElementById('logModal').classList.remove('open');}

loadInfo();loadModems();
setInterval(loadInfo,8000);
</script>
</body>
</html>"""

# ---------------------------------------------------------------------------
def main() -> None:
    p = argparse.ArgumentParser(prog="panel", description="modlink веб-панель")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--no-browser", action="store_true")
    a = p.parse_args()
    url = f"http://{a.host}:{a.port}"
    print(f"  modlink panel → {url}")
    if not a.no_browser:
        webbrowser.open(url)
    server = HTTPServer((a.host, a.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  остановлено")

if __name__ == "__main__":
    main()
