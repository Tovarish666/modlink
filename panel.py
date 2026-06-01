#!/usr/bin/env python3
"""
modlink panel — веб-панель управления. Только stdlib, pip не нужен.
Запуск: python panel.py [--port 5000]
Открыть: http://localhost:5000
"""
from __future__ import annotations
import argparse, atexit, json, os, random, shutil, socket, subprocess
import re, sys, time, webbrowser
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

MODEMS_CONF = CONF_DIR / "modems.conf"
SB_CONF     = CONF_DIR / "singbox.json"
CERT_FILE   = CONF_DIR / "cert.pem"
KEY_FILE    = CONF_DIR / "key.pem"
PROXY_PORT  = 8443

_sb_proc: subprocess.Popen | None = None

# ---------------------------------------------------------------------------
def rand_pass(length: int = 10) -> str:
    chars = "abcdefghjkmnpqrstuvwxyz23456789"
    return "".join(random.choices(chars, k=length))

def get_server_ip() -> str:
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

def has_tls() -> bool:
    return CERT_FILE.exists() and KEY_FILE.exists()

def proxy_scheme() -> str:
    return "https" if has_tls() else "http"

def gen_singbox_config(modems: list[dict]) -> dict:
    users     = [{"username": f"modem-{m['n']}", "password": m["password"]} for m in modems]
    outbounds = [{"type": "direct", "tag": f"out-{m['n']}",
                  "inet4_bind_address": f"192.168.{m['n']}.100"} for m in modems]
    rules     = [{"auth_user": [f"modem-{m['n']}"], "outbound": f"out-{m['n']}"} for m in modems]
    inbound: dict = {
        "type": "http", "listen": "0.0.0.0", "listen_port": PROXY_PORT,
        "users": users,
    }
    if has_tls():
        inbound["tls"] = {"enabled": True,
                          "certificate_path": str(CERT_FILE),
                          "key_path": str(KEY_FILE)}
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [inbound],
        "outbounds": outbounds,
        "route": {"rules": rules},
    }

def apply_singbox(modems: list[dict]) -> tuple[bool, str]:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    SB_CONF.write_text(json.dumps(gen_singbox_config(modems), indent=2), encoding="utf-8")
    if not IS_WIN:
        SB_CONF.chmod(0o600)
    r = subprocess.run([str(SINGBOX_BIN), "check", "-c", str(SB_CONF)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return False, (r.stderr or r.stdout).strip()
    if IS_WIN:
        global _sb_proc
        if _sb_proc and _sb_proc.poll() is None:
            _sb_proc.terminate()
            try: _sb_proc.wait(timeout=5)
            except subprocess.TimeoutExpired: _sb_proc.kill()
        _sb_proc = subprocess.Popen(
            [str(SINGBOX_BIN), "run", "-c", str(SB_CONF)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        ok = _sb_proc.poll() is None
        return ok, ("active" if ok else "crashed")
    else:
        r2 = subprocess.run("systemctl restart modlink",
                            shell=True, capture_output=True, text=True, timeout=30)
        if r2.returncode != 0:
            return False, (r2.stderr or r2.stdout).strip()
        time.sleep(1)
        return True, get_sb_status()

if IS_WIN:
    atexit.register(lambda: _sb_proc.terminate()
                    if _sb_proc and _sb_proc.poll() is None else None)

# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass   # тихий режим

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
            self._send(200, HTML_PAGE.encode(), "text/html; charset=utf-8")

        elif path == "/api/info":
            self._json({"ip": get_server_ip(), "port": PROXY_PORT,
                        "status": get_sb_status(), "tls": has_tls()})

        elif path == "/api/modems":
            self._json(load_modems())

        elif path.startswith("/api/test/"):
            try:
                n = int(path.split("/")[-1])
            except ValueError:
                return self._json({"error": "invalid N"}, 400)
            modems = load_modems()
            m = next((x for x in modems if x["n"] == n), None)
            if not m:
                return self._json({"error": f"модем {n} не найден"}, 404)
            proxy    = f"{proxy_scheme()}://modem-{n}:{m['password']}@127.0.0.1:{PROXY_PORT}"
            curl_cmd = f'curl -s --max-time 8 --proxy "{proxy}" --proxy-insecure'
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
            save_modems(parsed)
            ok, status = apply_singbox(parsed)
            if not ok:
                return self._json({"ok": False, "error": strip_ansi(status)}, 500)
            self._json({"ok": True, "status": status})
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
.wrap{max-width:860px;margin:0 auto;padding:28px 16px}
.hdr{display:flex;align-items:center;gap:12px;margin-bottom:24px;flex-wrap:wrap}
.hdr-title{font-size:17px;font-weight:600;color:#fff;letter-spacing:-.3px}
.hdr-title span{color:var(--muted);font-weight:400;font-size:13px;margin-left:4px}
.chips{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-left:auto}
.chip{display:flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:5px 11px;font-size:12px;font-family:monospace}
.chip-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em;margin-right:2px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;transition:background .3s}
.dot.on{background:var(--success);box-shadow:0 0 5px var(--success)}.dot.off{background:var(--error)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:12px}
table{width:100%;border-collapse:collapse}
thead th{padding:9px 12px;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;font-weight:500}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:rgba(255,255,255,.025)}
td{padding:7px 12px;vertical-align:middle}
.col-n{width:72px}.col-login{width:130px}.col-pass{min-width:180px}.col-test{width:140px}.col-act{width:90px;text-align:right}
input[type=text],input[type=number]{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:13px;font-family:monospace;padding:5px 8px;width:100%;outline:none;transition:border-color .15s}
input:focus{border-color:var(--accent)}
input[readonly]{color:var(--muted);cursor:default;background:var(--surface2)}
.inp-n{width:58px}
.pass-wrap{display:flex;gap:4px}.pass-wrap input{flex:1}
.btn{display:inline-flex;align-items:center;gap:5px;padding:6px 13px;border-radius:var(--r);border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:13px;cursor:pointer;transition:all .15s;white-space:nowrap;line-height:1.4}
.btn:hover{border-color:var(--accent);color:var(--accent)}.btn:active{opacity:.75}
.btn:disabled{opacity:.45;cursor:not-allowed;pointer-events:none}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#000;font-weight:600}
.btn-primary:hover{background:#79b8ff;border-color:#79b8ff;color:#000}
.btn-icon{padding:5px 8px}.btn-del:hover{border-color:var(--error);color:var(--error)}.btn-sm{padding:4px 9px;font-size:12px}
.bar{display:flex;gap:8px;align-items:center;padding:11px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);flex-wrap:wrap}
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
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="hdr-title">modlink <span>server</span></div>
    <div class="chips">
      <div class="chip"><span class="chip-label">IP</span><span id="srvIp">…</span></div>
      <div class="chip"><span class="chip-label">Порт</span><span id="srvPort">…</span></div>
      <div class="chip" id="tlsChip" title=""><div class="dot" id="tlsDot"></div><span id="tlsLabel">…</span></div>
      <div class="chip"><div class="dot" id="dot"></div><span id="srvStatus">…</span></div>
    </div>
  </div>
  <div class="card">
    <table>
      <thead><tr>
        <th class="col-n">N</th><th class="col-login">Логин</th>
        <th class="col-pass">Пароль</th><th class="col-test">Тест</th><th class="col-act"></th>
      </tr></thead>
      <tbody id="tbody"><tr><td colspan="5" class="empty">Загрузка…</td></tr></tbody>
    </table>
  </div>
  <div class="bar">
    <button class="btn" onclick="addRow()">+ Добавить</button>
    <div class="bar-right">
      <button class="btn" onclick="copyClient()">⎘&nbsp;Скопировать</button>
      <button class="btn btn-primary" id="applyBtn" onclick="doApply()">Применить</button>
    </div>
  </div>
</div>
<div class="toasts" id="toasts"></div>
<script>
let srvIp='',srvPort=8443;
function toast(msg,type='info',ms=3200){const el=document.createElement('div');el.className=`toast ${type}`;el.textContent=msg;document.getElementById('toasts').appendChild(el);setTimeout(()=>el.remove(),ms);}
function randPass(len=10){const a='abcdefghjkmnpqrstuvwxyz23456789';return Array.from({length:len},()=>a[Math.floor(Math.random()*a.length)]).join('');}
function makeRow(n='',pass=''){
  const tr=document.createElement('tr');if(n)tr.dataset.n=n;
  const p=pass||randPass();
  tr.innerHTML=`
    <td class="col-n"><input class="inp-n" type="number" min="1" max="254" value="${n}" placeholder="N" oninput="onN(this)"></td>
    <td class="col-login"><input type="text" value="${n?'modem-'+n:''}" readonly tabindex="-1"></td>
    <td class="col-pass"><div class="pass-wrap"><input type="text" value="${p}" autocomplete="off"><button class="btn btn-icon" onclick="repass(this)">↺</button></div></td>
    <td class="col-test"><span class="tres" id="tr${n}"></span></td>
    <td class="col-act" style="display:flex;gap:4px;justify-content:flex-end;padding:7px 12px">
      <button class="btn btn-sm" onclick="doTest(this)">▶ Test</button>
      <button class="btn btn-icon btn-del" onclick="delRow(this)">✕</button>
    </td>`;
  return tr;
}
function onN(inp){const tr=inp.closest('tr');const n=inp.value;tr.dataset.n=n;tr.querySelector('.col-login input').value=n?`modem-${n}`:'';const sp=tr.querySelector('.tres');if(sp)sp.id=`tr${n}`;}
function repass(btn){btn.closest('.pass-wrap').querySelector('input').value=randPass();}
function addRow(n='',pass=''){const tb=document.getElementById('tbody');const em=tb.querySelector('.empty');if(em)em.closest('tr').remove();tb.appendChild(makeRow(n,pass));}
function delRow(btn){btn.closest('tr').remove();const tb=document.getElementById('tbody');if(!tb.querySelector('tr'))tb.innerHTML='<tr><td colspan="5" class="empty">Нет модемов</td></tr>';}
function getRows(){return[...document.querySelectorAll('#tbody tr[data-n]')].map(tr=>({n:parseInt(tr.dataset.n),password:tr.querySelector('.pass-wrap input').value.trim()})).filter(m=>m.n&&m.password);}
async function loadInfo(){try{const d=await fetch('/api/info').then(r=>r.json());srvIp=d.ip;srvPort=d.port;document.getElementById('srvIp').textContent=d.ip;document.getElementById('srvPort').textContent=d.port;const dot=document.getElementById('dot');dot.className='dot '+(d.status==='active'?'on':'off');document.getElementById('srvStatus').textContent=d.status;const tlsDot=document.getElementById('tlsDot');const tlsLabel=document.getElementById('tlsLabel');const tlsChip=document.getElementById('tlsChip');if(d.tls){tlsDot.className='dot on';tlsLabel.textContent='TLS';tlsChip.title='Шифрование включено';}else{tlsDot.className='dot off';tlsLabel.textContent='no TLS';tlsChip.title='Сертификат не найден — прокся работает по HTTP (только для локальной сети)';};}catch(e){}}
async function loadModems(){try{const ms=await fetch('/api/modems').then(r=>r.json());const tb=document.getElementById('tbody');tb.innerHTML='';if(!ms.length){tb.innerHTML='<tr><td colspan="5" class="empty">Нет модемов — нажми + Добавить</td></tr>';return;}ms.forEach(m=>tb.appendChild(makeRow(m.n,m.password)));}catch(e){}}
async function doApply(){const rows=getRows();if(!rows.length){toast('Добавь хотя бы один модем','err');return;}const btn=document.getElementById('applyBtn');btn.disabled=true;btn.innerHTML='<span class="spin"></span>&nbsp;Применяю…';try{const d=await fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({modems:rows})}).then(r=>r.json());if(d.ok)toast(`Применено  sing-box: ${d.status}`,'ok');else toast(d.error||'Ошибка','err',6000);loadInfo();}catch(e){toast('Нет связи','err');}btn.disabled=false;btn.innerHTML='Применить';}
async function doTest(btn){const tr=btn.closest('tr');const n=parseInt(tr.dataset.n);if(!n){toast('Укажи N','err');return;}btn.disabled=true;const sp=document.getElementById(`tr${n}`);sp.className='tres pend';sp.innerHTML='<span class="spin"></span>';try{const d=await fetch(`/api/test/${n}`).then(r=>r.json());if(d.exit_ip){sp.className='tres ok';sp.textContent=d.exit_ip+(d.huawei_ok?' ✓H':'');sp.title=`exit: ${d.exit_ip}  Huawei: ${d.huawei_ok?'OK':'нет'}`;}else{sp.className='tres fail';sp.textContent=d.error||'нет ответа';}}catch(e){sp.className='tres fail';sp.textContent='ошибка';}btn.disabled=false;}
function copyClient(){const rows=getRows();if(!rows.length){toast('Нет модемов','err');return;}const lines=rows.map(m=>`${m.n}  ${srvIp}:${srvPort}:modem-${m.n}:${m.password}`);navigator.clipboard.writeText(lines.join('\\n')).then(()=>toast(`Скопировано ${lines.length} строк`,'ok')).catch(()=>{const ta=document.createElement('textarea');ta.value=lines.join('\\n');document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();toast(`Скопировано ${lines.length} строк`,'ok');});}
loadInfo();loadModems();setInterval(loadInfo,8000);
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
