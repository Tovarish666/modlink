#!/usr/bin/env python3
"""
modlink panel — веб-панель управления. Только stdlib, pip не нужен.
Запуск: python panel.py [--port 5000]
Открыть: http://localhost:5000
"""
from __future__ import annotations
import argparse, atexit, json, os, random, re, shutil, socket, subprocess
import sys, threading, time, urllib.request, webbrowser
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

def strip_ansi(s: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', s)

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
LOG_DIR      = CONF_DIR / "logs"

def has_tls() -> bool:
    return (CERT_FILE.exists() and CERT_FILE.stat().st_size > 64 and
            KEY_FILE.exists()  and KEY_FILE.stat().st_size  > 64)

def read_log(tail: int = 80) -> list[str]:
    if not SB_LOG.exists():
        return []
    lines = SB_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-tail:]

DEFAULT_BASE_PORT = 10000
_sb_proc: subprocess.Popen | None = None

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
    for url, hdrs in [
        ("https://api.ipify.org", {}),
        ("http://checkip.amazonaws.com", {}),
        ("http://ip.me", {"Accept": "text/plain", "User-Agent": "curl/7.68.0"}),
    ]:
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=6) as r:
                ip = r.read().decode().strip()
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
        ip = s.getsockname()[0]; s.close(); return ip
    except Exception:
        return "127.0.0.1"

def get_sb_status() -> str:
    if IS_WIN:
        return "active" if (_sb_proc and _sb_proc.poll() is None) else "stopped"
    r = subprocess.run("systemctl is-active modlink", shell=True, capture_output=True, text=True)
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
        interval_min = 0
        if len(parts) > 2:
            try: interval_min = int(parts[2])
            except ValueError: pass
        result.append({"n": n,
                        "password": parts[1] if len(parts) > 1 else rand_pass(),
                        "interval_min": interval_min})
    return sorted(result, key=lambda x: x["n"])

def save_modems(modems: list[dict]) -> None:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    lines = []
    for m in sorted(modems, key=lambda x: x["n"]):
        line = f"{m['n']}  {m['password']}"
        if m.get("interval_min"):
            line += f"  {m['interval_min']}"
        lines.append(line)
    MODEMS_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")

# ---------------------------------------------------------------------------
# Port layout: 2 ports per modem (sorted index i):
#   BASE + i*2 + 0  → mixed proxy  (sing-box type=mixed: HTTP CONNECT + SOCKS5)
#   BASE + i*2 + 1  → Reconnect    (mini HTTP server /reconnect)
# ---------------------------------------------------------------------------
def calc_ports(modems: list[dict], base_port: int) -> dict[int, dict]:
    result = {}
    for i, m in enumerate(sorted(modems, key=lambda x: x["n"])):
        result[m["n"]] = {
            "mixed_port":  base_port + i * 2,
            "reconn_port": base_port + i * 2 + 1,
        }
    return result

# ---------------------------------------------------------------------------
# Huawei HiLink API (stdlib urllib, no pip)
# ---------------------------------------------------------------------------
def _http_xml_get(url: str, headers: dict | None = None, timeout: int = 8) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")

def _http_xml_post(url: str, xml_body: str, headers: dict, timeout: int = 8) -> str:
    req = urllib.request.Request(url, data=xml_body.encode("utf-8"), headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")

def _get_huawei_token(base_url: str, timeout: int = 8) -> tuple[str, str]:
    txt = _http_xml_get(base_url + "/api/webserver/SesTokInfo", timeout=timeout)
    ses = re.search(r"<SesInfo>([^<]+)</SesInfo>", txt)
    tok = re.search(r"<TokInfo>([^<]+)</TokInfo>", txt)
    if not ses or not tok:
        raise RuntimeError("SesTokInfo parse failed")
    return tok.group(1), ses.group(1)

def _huawei_post(base_url: str, path: str, xml: str, token: str, cookie: str, timeout: int = 8) -> None:
    _http_xml_post(base_url + path, xml,
                   {"__RequestVerificationToken": token, "Cookie": cookie,
                    "Content-Type": "text/xml; charset=UTF-8"}, timeout)

def reconnect_e3372h(webui_ip: str, timeout: int = 8) -> tuple[bool, str]:
    base = f"http://{webui_ip}"
    def set_net_mode(mode: str, lte_band: str) -> None:
        tok, ck = _get_huawei_token(base, timeout)
        _huawei_post(base, "/api/net/net-mode",
                     f"<?xml version='1.0' encoding='UTF-8'?>"
                     f"<request><NetworkMode>{mode}</NetworkMode>"
                     f"<NetworkBand>3FFFFFFF</NetworkBand>"
                     f"<LTEBand>{lte_band}</LTEBand></request>",
                     tok, ck, timeout)
    try:
        tok, ck = _get_huawei_token(base, timeout)
        _huawei_post(base, "/api/dialup/mobile-dataswitch",
                     "<?xml version='1.0' encoding='UTF-8'?><request><dataswitch>0</dataswitch></request>",
                     tok, ck, timeout)
        time.sleep(2.0)
        set_net_mode("00", "5");                time.sleep(2.0)
        set_net_mode("02", "5");                time.sleep(0.5)
        set_net_mode("03", "7FFFFFFFFFFFFFFF"); time.sleep(0.8)
        tok, ck = _get_huawei_token(base, timeout)
        _huawei_post(base, "/api/dialup/mobile-dataswitch",
                     "<?xml version='1.0' encoding='UTF-8'?><request><dataswitch>1</dataswitch></request>",
                     tok, ck, timeout)
        for _ in range(20):
            time.sleep(0.4)
            try:
                req = urllib.request.Request(base + "/api/dialup/mobile-dataswitch",
                                             headers={"Cookie": ck})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    if "<dataswitch>1</dataswitch>" in r.read().decode("utf-8", errors="replace"):
                        return True, "reconnected"
            except Exception:
                pass
        return False, "dataswitch not confirmed"
    except Exception as e:
        return False, str(e)

def reboot_huawei(webui_ip: str, timeout: int = 8) -> tuple[bool, str]:
    base = f"http://{webui_ip}"
    try:
        tok, ck = _get_huawei_token(base, timeout)
        _huawei_post(base, "/api/device/control",
                     "<?xml version='1.0' encoding='UTF-8'?><request><Control>1</Control></request>",
                     tok, ck, timeout)
        return True, "reboot sent"
    except Exception as e:
        return False, str(e)

# ---------------------------------------------------------------------------
# Reconnect log
# ---------------------------------------------------------------------------
_log_locks: dict[int, threading.Lock] = {}

def _now_strs() -> tuple[str, str]:
    utc = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    loc = datetime.now().astimezone().replace(microsecond=0).strftime("%Y-%m-%d %H:%M:%S")
    return utc, loc

def append_reconnect_log(n: int, line: str) -> None:
    lock = _log_locks.setdefault(n, threading.Lock())
    log_path = LOG_DIR / f"modem{n}_reconnect.txt"
    with lock:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
            try: log_path.rename(str(log_path) + ".1")
            except Exception: pass
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def read_reconnect_log(n: int, tail: int = 60) -> list[str]:
    log_path = LOG_DIR / f"modem{n}_reconnect.txt"
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-tail:]

# ---------------------------------------------------------------------------
# Reconnect mini-server (per modem, standalone /reconnect endpoint)
# ---------------------------------------------------------------------------
class _ReconnBase(BaseHTTPRequestHandler):
    _modem_n: int = 0
    def log_message(self, *_): pass
    def do_GET(self):
        if self.path.rstrip("/") == "/reconnect":
            n = self.__class__._modem_n
            t0 = time.perf_counter()
            ok, msg = reconnect_e3372h(f"192.168.{n}.1")
            dt = time.perf_counter() - t0
            utc_s, loc_s = _now_strs()
            line = (f"{utc_s} | {loc_s} | modem{n} | url-trigger "
                    f"| {dt:.2f}s | {'ok' if ok else 'fail'} | {msg}")
            append_reconnect_log(n, line)
            resp = json.dumps({"ok": ok, "msg": msg, "dt": round(dt, 2)}).encode()
            self.send_response(200 if ok else 500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers(); self.wfile.write(resp)
        else:
            self.send_response(404); self.end_headers()

class ReconnectServer:
    def __init__(self, n: int, port: int):
        self.n = n; self.port = port
        handler = type(f"RH_{n}", (_ReconnBase,), {"_modem_n": n})
        self.httpd = ThreadingHTTPServer(("0.0.0.0", port), handler)
        self._thr = threading.Thread(target=self.httpd.serve_forever,
                                     daemon=True, name=f"reconn-{n}")
    def start(self):
        try: self._thr.start(); print(f"[reconn] modem{self.n} :{self.port}")
        except Exception as e: print(f"[reconn] modem{self.n} error: {e}")
    def stop(self):
        try: self.httpd.shutdown(); self.httpd.server_close()
        except Exception: pass

_reconn_servers: dict[int, ReconnectServer] = {}
_reconn_lock = threading.Lock()

def rebuild_reconn_servers(modems: list[dict], base_port: int) -> None:
    ports = calc_ports(modems, base_port)
    wanted = {m["n"]: ports[m["n"]]["reconn_port"] for m in modems}
    with _reconn_lock:
        for n in list(_reconn_servers):
            if n not in wanted or _reconn_servers[n].port != wanted[n]:
                _reconn_servers[n].stop(); del _reconn_servers[n]
        for n, port in wanted.items():
            if n not in _reconn_servers:
                srv = ReconnectServer(n, port)
                _reconn_servers[n] = srv; srv.start()

# ---------------------------------------------------------------------------
# Interval scheduler (auto-reconnect by timer)
# ---------------------------------------------------------------------------
class IntervalJob:
    def __init__(self, n: int, interval_sec: int):
        self.n = n; self.interval = max(60, int(interval_sec))
        self._stop = threading.Event()
        self._thr = threading.Thread(target=self._run, daemon=True, name=f"timer-{n}")
    def start(self):
        print(f"[timer] modem{self.n} every {self.interval}s"); self._thr.start()
    def stop(self): self._stop.set()
    def _run(self):
        next_at = time.time() + self.interval
        while not self._stop.is_set():
            wait = max(0.0, next_at - time.time())
            if self._stop.wait(wait): break
            t0 = time.perf_counter()
            ok, msg = reconnect_e3372h(f"192.168.{self.n}.1")
            dt = time.perf_counter() - t0
            utc_s, loc_s = _now_strs()
            append_reconnect_log(self.n,
                f"{utc_s} | {loc_s} | modem{self.n} | auto | {dt:.2f}s | {'ok' if ok else 'fail'} | {msg}")
            print(f"[timer] modem{self.n} -> {'ok' if ok else 'fail'} in {dt:.2f}s")
            next_at += self.interval

_jobs: dict[int, IntervalJob] = {}
_jobs_lock = threading.Lock()

def rebuild_scheduler(modems: list[dict]) -> None:
    wanted = {m["n"]: int(m.get("interval_min", 0)) * 60
              for m in modems if int(m.get("interval_min", 0)) > 0}
    with _jobs_lock:
        for n in list(_jobs):
            if n not in wanted or _jobs[n].interval != wanted[n]:
                _jobs[n].stop(); del _jobs[n]
        for n, sec in wanted.items():
            if n not in _jobs:
                job = IntervalJob(n, sec); _jobs[n] = job; job.start()

# ---------------------------------------------------------------------------
# sing-box config
# Ports per modem (sorted index i):
#   mixed=BASE+i*2  — handles both HTTP CONNECT (HTTPS) and SOCKS5 on one port
# No custom DNS section — sing-box uses system resolver (avoids version issues)
# ---------------------------------------------------------------------------
def gen_singbox_config(modems: list[dict], base_port: int = DEFAULT_BASE_PORT) -> dict:
    inbounds, outbounds, rules = [], [], []
    tls = has_tls()
    ports = calc_ports(modems, base_port)
    for m in sorted(modems, key=lambda x: x["n"]):
        p = ports[m["n"]]
        n = m["n"]
        inbound: dict = {
            "type": "http" if tls else "mixed",
            "tag": f"in-{n}",
            "listen": "0.0.0.0",
            "listen_port": p["mixed_port"],
            "users": [{"username": f"modem{n}", "password": m["password"]}],
        }
        if tls:
            inbound["tls"] = {"enabled": True,
                              "certificate_path": str(CERT_FILE),
                              "key_path": str(KEY_FILE)}
        inbounds.append(inbound)
        outbounds.append({
            "type": "direct",
            "tag": f"out-{n}",
            "inet4_bind_address": f"192.168.{n}.100",
        })
        rules.append({"inbound": [f"in-{n}"], "outbound": f"out-{n}"})

    outbounds.append({"type": "direct", "tag": "direct"})
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": rules, "final": "direct"},
    }

_BUNDLED_CERT = """\
-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgIUekx/rYOXzGAhasTUefpS7TbHtI0wDQYJKoZIhvcNAQEL
BQAwGTEXMBUGA1UEAwwObW9kbGluay1zZXJ2ZXIwHhcNMjYwNjAzMjIzMTE1WhcN
MzYwNTMxMjIzMTE1WjAZMRcwFQYDVQQDDA5tb2RsaW5rLXNlcnZlcjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALF9cN90IwH8/+bujseBCYuNq31zcbwY
E9YE8AiL0+BfGOXJoojor1fpv5W6Tj6+lYYs79soBzT+CUpN44iyz9E2Gup8vqD4
dZpS9luWpaDbYUOJTaQrNXoYb8l+w8lkPtxPFoWJc/5BgCHOYUsqT4C3TnfBpa7z
zjiPrGCfp8MIhxtKWP8USIQoKeVkgHtbQSJsera8Ll7qrwbO8Gjl19/cMGqyk494
leT+IDowRbW8pnrcB0YzOhharHqMajFnNCJOYz+z4L8AF4c5QN41fq8zaYTNPouq
n4LX6pEPWAPCFvnHdyNrQreWUJZWUX9QMOjNXxCmjGhAQ9DmPeoAWc0CAwEAAaNT
MFEwHQYDVR0OBBYEFCo8pBnBisR/vq0RK7GXEC67byIMMB8GA1UdIwQYMBaAFCo8
pBnBisR/vq0RK7GXEC67byIMMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL
BQADggEBAA+7csEzoJJHTdguqEDjCEYPGXfyC7KmHf7aKLIJJ2MriRkUXGqKPljx
rRQHUN0fEE2dOzmxUAEvUBOIViDMfcBDl6VWG0Go04xbNrqIvNz/armW0Isj6TgN
11e6VdVFJM88yArIoiiSARTvrdTqI2SgQUT91kPrj6akANhMDXAJo6Hd2gay2uAl
gzUrie/I9KuWxuqsJbBQ9O8HLOELy3CEgRS5rUkw8RU6E6sK3JLZ0/mI2khtU+e9
2LqKzxVu4FhlKZt+AThLX8NTjTAroGAmx9sT4SYpJUNplfGvzO8UsFxtoWWCVxMR
3BszaCihRPAo+fGOe4LkZen65J8gXx8=
-----END CERTIFICATE-----"""

_BUNDLED_KEY = """\
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxfXDfdCMB/P/m
7o7HgQmLjat9c3G8GBPWBPAIi9PgXxjlyaKI6K9X6b+Vuk4+vpWGLO/bKAc0/glK
TeOIss/RNhrqfL6g+HWaUvZblqWg22FDiU2kKzV6GG/JfsPJZD7cTxaFiXP+QYAh
zmFLKk+At053waWu8844j6xgn6fDCIcbSlj/FEiEKCnlZIB7W0EibHq2vC5e6q8G
zvBo5dff3DBqspOPeJXk/iA6MEW1vKZ63AdGMzoYWqx6jGoxZzQiTmM/s+C/ABeH
OUDeNX6vM2mEzT6Lqp+C1+qRD1gDwhb5x3cja0K3llCWVlF/UDDozV8QpoxoQEPQ
5j3qAFnNAgMBAAECggEAJhB374QxqdB/dSA+QKz8xhAI8iua/bLQNjry23JZayoZ
5dX7ZI86Y4k+zDabZztqR89FVWPdP9EnXucbYAqxJPYMibNdEpqWZhVavkOtm7TQ
xDIjE40st9Wby8PC62LzVD4l31eeJ64Wc6mWFg+p4znsuyQtizrAREMTvdkfmmTS
7jEWEKakI4tSSDHZ5PJKJgWhBXJguAk0LRg1sxVuR8J8yztWsuRj5+x5JDLOSuA/
AviTT1RPoyQ4DravEBUWnwWMJMKj8TsDW/2wfkGjUcXsefGmCJ/Em5JNcy9WjjY4
LhZpOQt5jfetG0MBOiRP5BmNqOxnG1SZ8YrO1/WooQKBgQDrHzswu2UPQRgr4bqr
p0bJmQXnPWCVHN1tdarn1ff5oHT2fuyvnbec56aUP8iJe0hVS2OFhXxlvYRhVfjB
q8n/cEaS/P63WAB5fi1nr5yJyFpl6+Semc4IIpP7Enk4NhFYEwypRdSgaqXx1Ayp
Iuz49UYASlBGEdW8ujpgzeIBeQKBgQDBQCAOKxUeFUOBSuWEfU3ppIs44B1k8H18
5ztn8BxFbWqaoASVtdiG9piIofn3wgyI711KLuFcNLxVsKqmDI9eVLwKI7q0SaNa
FAdN4ZFCgTn7T/DEVOn0zvkAiLeknHGEaPfoMehCSSDDifxZDcP0D0LHsqV4KHw+
vUM3Yik59QKBgQCm1ORE8dMFfeTOzj6MKgdaaI/9wllTtMWRM5rvIa3wnGAhv3Hm
MnzkgqJ6Mr/yfV2X2ARn642XC2BxSHVXxrNv4pTRG18JbRH5IwTIu5zRTy6Ff1ob
B3tf3lkuH6+PqR2pZurm+TukD8hrzVCmere29yKSdih7b5A/d8yQf8XL0QKBgBCZ
76cH8HJ7JSdwRbNSCGVv6z3hkuTe/AjE3IebSvJz6dqKsJoj2wwNFyF1uMGd+/Gv
jnYW/Oks5pj96ksFfTN/WAAO/bULNmtAmTgJjq8F5vM99NMI8GhFd4KiPBR6FA5p
7hIWZ3t6SMRDkFgeJJ1MylHZePmPkMza+XFCj4QZAoGAPJG4ov39NW1LB6ciRBGd
iXcUpxfLnT5xA2/CpxTTLn4R+iWnPR6lu8rHEb60m0AiDInhyhBNrUkMYTBFTs4y
n9nAmMJBA6YI+BT7eEXD1HdWVj2WseaHqUwoBvbcpMe5TAq4cuxcy9Zs86llqmoJ
2nwt+LfJWSFSvEtN+8WWQDM=
-----END PRIVATE KEY-----"""

def _find_openssl() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    if IS_WIN:
        try:
            r = subprocess.run(["where.exe", "openssl"], capture_output=True, text=True)
            if r.returncode == 0:
                first = r.stdout.strip().splitlines()[0]
                if first:
                    return first
        except Exception:
            pass
        for candidate in [
            r"C:\Program Files\Git\usr\bin\openssl.exe",
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            r"C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
            r"C:\Program Files\OpenSSL\bin\openssl.exe",
        ]:
            if Path(candidate).exists():
                return candidate
    return None

def _ensure_cert_ps() -> None:
    ps = (
        '$c=New-SelfSignedCertificate -DnsName modlink-server '
        '-CertStoreLocation Cert:\\LocalMachine\\My '
        '-NotAfter (Get-Date).AddYears(10) -KeyExportPolicy Exportable;'
        '$cb=[Convert]::ToBase64String($c.RawData,"InsertLineBreaks");'
        'echo "-----BEGIN CERTIFICATE-----";echo $cb;echo "-----END CERTIFICATE-----";'
        '$rsa=[System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($c);'
        '$kb=[Convert]::ToBase64String($rsa.ExportPkcs8PrivateKey(),"InsertLineBreaks");'
        'echo "-----BEGIN PRIVATE KEY-----";echo $kb;echo "-----END PRIVATE KEY-----"'
    )
    r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                       capture_output=True, text=True)
    o = r.stdout
    c0 = o.find("-----BEGIN CERTIFICATE-----")
    c1 = o.find("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")
    k0 = o.find("-----BEGIN PRIVATE KEY-----")
    k1 = o.find("-----END PRIVATE KEY-----") + len("-----END PRIVATE KEY-----")
    if c0 < 0 or k0 < 0:
        raise RuntimeError(f"PowerShell cert gen failed:\n{r.stderr}")
    CERT_FILE.write_text(o[c0:c1], encoding="ascii")
    KEY_FILE.write_text(o[k0:k1], encoding="ascii")

def ensure_cert() -> None:
    CERT_FILE.parent.mkdir(parents=True, exist_ok=True)
    if has_tls():
        return
    openssl = _find_openssl()
    if openssl:
        r = subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
             "-days", "3650", "-subj", "/CN=modlink-server"],
            capture_output=True
        )
        if r.returncode == 0 and has_tls():
            return
    if IS_WIN:
        try:
            _ensure_cert_ps()
            if has_tls():
                return
        except Exception:
            pass
    # fallback: write bundled self-signed cert
    CERT_FILE.write_text(_BUNDLED_CERT, encoding="ascii")
    KEY_FILE.write_text(_BUNDLED_KEY, encoding="ascii")

def apply_singbox(modems: list[dict], base_port: int) -> tuple[bool, str]:
    CONF_DIR.mkdir(parents=True, exist_ok=True)
    ensure_cert()
    SB_CONF.write_text(json.dumps(gen_singbox_config(modems, base_port), indent=2), encoding="utf-8")
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
            try: _sb_proc.wait(timeout=3)
            except subprocess.TimeoutExpired: _sb_proc.kill()
        subprocess.run(["taskkill", "/F", "/IM", "sing-box.exe"], capture_output=True, text=True)
        time.sleep(0.5)
        log_fh = open(SB_LOG, "w", encoding="utf-8")
        _sb_proc = subprocess.Popen([str(SINGBOX_BIN), "run", "-c", str(SB_CONF)],
                                    stdout=log_fh, stderr=log_fh)
        time.sleep(2)
        if _sb_proc.poll() is not None:
            log_fh.flush()
            return False, strip_ansi("\n".join(read_log(20))) or "crashed"
        return True, "active"
    else:
        r2 = subprocess.run("systemctl restart modlink",
                            shell=True, capture_output=True, text=True, timeout=30)
        if r2.returncode != 0:
            return False, strip_ansi((r2.stderr or r2.stdout).strip())
        time.sleep(1); return True, get_sb_status()

if IS_WIN:
    atexit.register(lambda: _sb_proc.terminate() if _sb_proc and _sb_proc.poll() is None else None)
atexit.register(lambda: [j.stop() for j in list(_jobs.values())])
atexit.register(lambda: [s.stop() for s in list(_reconn_servers.values())])

# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def _send(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers(); self.wfile.write(body)

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
            self.end_headers(); self.wfile.write(body); return

        elif path == "/api/info":
            sconf = load_server_conf()
            self._json({"local_ip": get_local_ip(), "ext_ip": sconf.get("ext_ip", ""),
                        "base_port": sconf.get("base_port", DEFAULT_BASE_PORT),
                        "status": get_sb_status(), "tls": has_tls()})

        elif path == "/api/modems":
            modems = load_modems()
            sconf = load_server_conf()
            base = sconf.get("base_port", DEFAULT_BASE_PORT)
            ports = calc_ports(modems, base)
            ext_ip = sconf.get("ext_ip", "") or get_local_ip()
            result = []
            for m in modems:
                p = ports.get(m["n"], {})
                result.append({**m,
                    "mixed_port":  p.get("mixed_port"),
                    "reconn_port": p.get("reconn_port"),
                    "reconn_url":  f"http://{ext_ip}:{p['reconn_port']}/reconnect" if p else "",
                })
            self._json(result)

        elif path == "/api/logs":
            self._json({"lines": read_log(100)})

        elif path == "/api/external-ip":
            ip = fetch_external_ip()
            if ip:
                sconf = load_server_conf(); sconf["ext_ip"] = ip; save_server_conf(sconf)
                self._json({"ip": ip})
            else:
                self._json({"error": "не удалось определить"}, 500)

        elif path.startswith("/api/test/"):
            try: n = int(path.split("/")[-1])
            except ValueError: return self._json({"error": "invalid N"}, 400)
            modems = load_modems()
            m = next((x for x in modems if x["n"] == n), None)
            if not m: return self._json({"error": f"modem {n} not found"}, 404)
            sconf = load_server_conf()
            base = sconf.get("base_port", DEFAULT_BASE_PORT)
            p = calc_ports(modems, base).get(n, {})
            mixed_port = p.get("mixed_port", base + n)
            scheme = "https" if has_tls() else "http"
            proxy = f"{scheme}://modem{n}:{m['password']}@127.0.0.1:{mixed_port}"
            insecure = "--proxy-insecure" if has_tls() else ""
            curl_cmd = f'curl -s --max-time 8 --proxy "{proxy}" {insecure}'.strip()
            r1 = subprocess.run(f"{curl_cmd} http://ip.me",
                                shell=True, capture_output=True, text=True, timeout=12)
            r2 = subprocess.run(f"{curl_cmd} http://192.168.{n}.1/api/webserver/SesTokInfo",
                                shell=True, capture_output=True, text=True, timeout=10)
            self._json({"n": n, "exit_ip": r1.stdout.strip(),
                        "huawei_ok": "SesInfo" in (r2.stdout or "")})

        elif path.startswith("/api/reconnect/"):
            try: n = int(path.split("/")[-1])
            except ValueError: return self._json({"error": "invalid N"}, 400)
            if not any(x["n"] == n for x in load_modems()):
                return self._json({"error": f"modem {n} not found"}, 404)
            t0 = time.perf_counter()
            ok, msg = reconnect_e3372h(f"192.168.{n}.1")
            dt = time.perf_counter() - t0
            utc_s, loc_s = _now_strs()
            append_reconnect_log(n,
                f"{utc_s} | {loc_s} | modem{n} | manual | {dt:.2f}s | {'ok' if ok else 'fail'} | {msg}")
            self._json({"ok": ok, "msg": msg, "dt": round(dt, 2)})

        elif path.startswith("/api/reboot/"):
            try: n = int(path.split("/")[-1])
            except ValueError: return self._json({"error": "invalid N"}, 400)
            if not any(x["n"] == n for x in load_modems()):
                return self._json({"error": f"modem {n} not found"}, 404)
            ok, msg = reboot_huawei(f"192.168.{n}.1")
            utc_s, loc_s = _now_strs()
            append_reconnect_log(n,
                f"{utc_s} | {loc_s} | modem{n} | reboot | {'ok' if ok else 'fail'} | {msg}")
            self._json({"ok": ok, "msg": msg})

        elif path.startswith("/api/reconnect-log/"):
            try: n = int(path.split("/")[-1])
            except ValueError: return self._json({"error": "invalid N"}, 400)
            self._json({"lines": read_reconnect_log(n)})

        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/api/apply":
            data = self._read_body()
            modems = data.get("modems", [])
            if not modems:
                return self._json({"ok": False, "error": "нет модемов"}, 400)
            try:
                parsed = [{"n": int(m["n"]),
                           "password": str(m["password"]).strip(),
                           "interval_min": int(m.get("interval_min") or 0)} for m in modems]
            except (KeyError, ValueError) as e:
                return self._json({"ok": False, "error": str(e)}, 400)
            sconf = load_server_conf()
            if "base_port" in data:
                sconf["base_port"] = int(data["base_port"]); save_server_conf(sconf)
            base_port = sconf.get("base_port", DEFAULT_BASE_PORT)
            save_modems(parsed)
            ok, status = apply_singbox(parsed, base_port)
            if not ok:
                return self._json({"ok": False, "error": status}, 500)
            rebuild_reconn_servers(parsed, base_port)
            rebuild_scheduler(parsed)
            self._json({"ok": True, "status": status})

        elif path == "/api/server-config":
            data = self._read_body(); sconf = load_server_conf()
            if "ext_ip" in data: sconf["ext_ip"] = str(data["ext_ip"]).strip()
            if "base_port" in data: sconf["base_port"] = int(data["base_port"])
            save_server_conf(sconf); self._json({"ok": True})

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
  --error:#f85149;--warn:#d29922;--text:#c9d1d9;--muted:#8b949e;--r:6px;
}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;min-height:100vh}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
.hdr{display:flex;align-items:center;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.hdr-title{font-size:17px;font-weight:600;color:#fff}
.hdr-title span{color:var(--muted);font-weight:400;font-size:13px;margin-left:4px}
.chips{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-left:auto}
.chip{display:flex;align-items:center;gap:6px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:5px 11px;font-size:12px;font-family:monospace}
.chip-label{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.05em;margin-right:2px}
.dot{width:7px;height:7px;border-radius:50%;background:var(--muted);flex-shrink:0;transition:background .3s}
.dot.on{background:var(--success);box-shadow:0 0 5px var(--success)}.dot.off{background:var(--error)}
.sconf{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:9px 14px;margin-bottom:12px;flex-wrap:wrap}
.sconf-label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap}
.sconf input{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:13px;font-family:monospace;padding:4px 8px;outline:none;transition:border-color .15s;width:160px}
.sconf input:focus{border-color:var(--accent)}
.sconf-sep{width:1px;height:20px;background:var(--border);margin:0 4px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:12px}
table{width:100%;border-collapse:collapse}
thead th{padding:8px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);border-bottom:1px solid var(--border);white-space:nowrap;font-weight:500}
tbody tr{border-bottom:1px solid var(--border);transition:background .1s}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:rgba(255,255,255,.025)}
td{padding:5px 8px;vertical-align:middle}
.col-n{width:48px}.col-login{width:90px}.col-ports{width:110px}.col-pass{min-width:130px}
.col-reconn{min-width:200px}.col-interval{width:80px}.col-test{width:110px}.col-act{width:130px;text-align:right}
input[type=text],input[type=number]{background:var(--bg);border:1px solid var(--border);border-radius:var(--r);color:var(--text);font-size:12px;font-family:monospace;padding:4px 7px;width:100%;outline:none;transition:border-color .15s}
input:focus{border-color:var(--accent)}
input[readonly]{color:var(--muted);cursor:default;background:var(--surface2)}
.inp-n{width:44px;-moz-appearance:textfield}.inp-n::-webkit-inner-spin-button,.inp-n::-webkit-outer-spin-button{-webkit-appearance:none}
.inp-interval{width:54px;-moz-appearance:textfield}.inp-interval::-webkit-inner-spin-button,.inp-interval::-webkit-outer-spin-button{-webkit-appearance:none}
.pass-wrap{display:flex;gap:3px}.pass-wrap input{flex:1}
.ports-wrap{font-size:11px;font-family:monospace;color:var(--muted);line-height:1.8}
.ports-wrap span{display:block}
.badge-h{font-size:10px;padding:1px 4px;border:1px solid var(--success);border-radius:3px;color:var(--success);margin-left:4px;vertical-align:middle}
.btn{display:inline-flex;align-items:center;gap:4px;padding:5px 10px;border-radius:var(--r);border:1px solid var(--border);background:var(--surface);color:var(--text);font-size:12px;cursor:pointer;transition:all .15s;white-space:nowrap;line-height:1.4}
.btn:hover{border-color:var(--accent);color:var(--accent)}.btn:active{opacity:.75}
.btn:disabled{opacity:.45;cursor:not-allowed;pointer-events:none}
.btn-primary{background:var(--accent);border-color:var(--accent);color:#000;font-weight:600}
.btn-primary:hover{background:#79b8ff;border-color:#79b8ff;color:#000}
.btn-icon{padding:4px 6px}
.btn-del:hover{border-color:var(--error);color:var(--error)}
.btn-reboot:hover{border-color:var(--warn);color:var(--warn)}
.btn-sm{padding:4px 8px;font-size:11px}
.bar{display:flex;gap:8px;align-items:center;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);flex-wrap:wrap}
.bar-right{margin-left:auto;display:flex;gap:8px}
.tres{font-size:11px;font-family:monospace;white-space:nowrap}
.tres.ok{color:var(--success)}.tres.fail{color:var(--error)}.tres.pend{color:var(--muted)}
.toasts{position:fixed;top:18px;right:18px;z-index:999;display:flex;flex-direction:column;gap:6px}
.toast{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:9px 15px;font-size:13px;max-width:320px;animation:tin .18s ease}
.toast.ok{border-color:var(--success);color:var(--success)}.toast.err{border-color:var(--error);color:var(--error)}.toast.info{border-color:var(--accent);color:var(--accent)}.toast.warn{border-color:var(--warn);color:var(--warn)}
@keyframes tin{from{transform:translateX(16px);opacity:0}to{transform:translateX(0);opacity:1}}
.spin{display:inline-block;width:10px;height:10px;border:2px solid currentColor;border-top-color:transparent;border-radius:50%;animation:rot .6s linear infinite}
@keyframes rot{to{transform:rotate(360deg)}}
.empty{text-align:center;padding:36px;color:var(--muted);font-size:13px}
.modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:100;align-items:center;justify-content:center}
.modal-overlay.open{display:flex}
.modal{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);width:min(900px,95vw);max-height:80vh;display:flex;flex-direction:column}
.modal-hdr{display:flex;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border);gap:8px}
.modal-hdr h3{font-size:14px;font-weight:600;flex:1;color:#fff}
.log-body{flex:1;overflow-y:auto;padding:12px 16px;font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;color:var(--text);background:var(--bg)}
.log-body .err{color:var(--error)}.log-body .warn{color:var(--warn)}.log-body .ok{color:var(--success)}
.reconn-wrap{display:flex;gap:3px;align-items:center}
.reconn-wrap input{flex:1;font-size:11px}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="hdr-title">modlink <span>server</span></div>
    <div class="chips">
      <div class="chip"><span class="chip-label">IP</span><span id="localIp">…</span></div>
      <div class="chip"><div class="dot" id="dot"></div><span id="srvStatus">…</span></div>
    </div>
  </div>

  <div class="sconf">
    <span class="sconf-label">Внешний IP</span>
    <input id="extIp" type="text" placeholder="1.2.3.4" oninput="markDirty()">
    <button class="btn btn-sm" id="fetchIpBtn" onclick="fetchExtIp()">⟳ Авто</button>
    <div class="sconf-sep"></div>
    <span class="sconf-label">База порт</span>
    <input id="basePort" type="number" value="10000" min="1024" max="60000" style="width:88px" oninput="markDirty();refreshComputedPorts()">
    <button class="btn btn-sm" id="saveConfBtn" onclick="saveConf()" style="display:none">Сохранить</button>
  </div>

  <div class="card">
    <table>
      <thead><tr>
        <th class="col-n">N</th>
        <th class="col-login">Логин</th>
        <th class="col-ports">Порт (mix)</th>
        <th class="col-reconn">Реконнект URL</th>
        <th class="col-pass">Пароль</th>
        <th class="col-interval">Интервал<br><span style="font-size:9px;font-weight:400">(мин,0=выкл)</span></th>
        <th class="col-test">Тест</th>
        <th class="col-act"></th>
      </tr></thead>
      <tbody id="tbody"><tr><td colspan="8" class="empty">Загрузка…</td></tr></tbody>
    </table>
  </div>

  <div class="bar">
    <button class="btn" onclick="addRow()">+ Добавить</button>
    <button class="btn" onclick="openLogs()" style="color:var(--muted)">≡ Логи SB</button>
    <div class="bar-right">
      <button class="btn" onclick="copyClient()">⎘ Копировать</button>
      <button class="btn btn-primary" id="applyBtn" onclick="doApply()">Применить</button>
    </div>
  </div>
</div>

<!-- sing-box log -->
<div class="modal-overlay" id="logModal" onclick="if(event.target===this)closeLogs()">
  <div class="modal">
    <div class="modal-hdr">
      <h3>sing-box logs</h3>
      <button class="btn btn-sm" onclick="refreshLogs()">⟳</button>
      <button class="btn btn-sm" onclick="closeLogs()">✕</button>
    </div>
    <div class="log-body" id="logBody"></div>
  </div>
</div>

<!-- reconnect log -->
<div class="modal-overlay" id="reconnModal" onclick="if(event.target===this)closeReconn()">
  <div class="modal">
    <div class="modal-hdr">
      <h3 id="reconnModalTitle">Reconnect Log</h3>
      <button class="btn btn-sm" onclick="refreshReconnLog()">⟳</button>
      <button class="btn btn-sm" onclick="closeReconn()">✕</button>
    </div>
    <div class="log-body" id="reconnLogBody"></div>
  </div>
</div>

<div class="toasts" id="toasts"></div>

<script>
let localIp='', extIp='', basePort=10000, confDirty=false, hasTls=false;
let _reconnLogN=0;

window.onerror=function(msg,src,line){toast('JS: '+msg+' ('+line+')','err',12000);return false;};
window.addEventListener('unhandledrejection',e=>toast(''+e.reason,'err',8000));

function toast(msg,type='info',ms=3200){
  const el=document.createElement('div');el.className='toast '+type;el.textContent=msg;
  document.getElementById('toasts').appendChild(el);setTimeout(()=>el.remove(),ms);
}
function randPass(len=10){
  const a='abcdefghjkmnpqrstuvwxyz23456789';
  return Array.from({length:len},()=>a[Math.floor(Math.random()*a.length)]).join('');
}
function markDirty(){confDirty=true;document.getElementById('saveConfBtn').style.display='';}

function getPortsForIndex(idx){
  const bp=parseInt(document.getElementById('basePort').value)||10000;
  return {http:bp+idx*3, socks:bp+idx*3+1, reconn:bp+idx*3+2};
}
function getSortedNs(){
  return [...document.querySelectorAll('#tbody tr[data-n]')]
    .map(tr=>parseInt(tr.dataset.n)).filter(n=>n>0).sort((a,b)=>a-b);
}

function refreshComputedPorts(){
  const ns=getSortedNs();
  const ip=document.getElementById('extIp').value.trim()||localIp||'...';
  document.querySelectorAll('#tbody tr[data-n]').forEach(tr=>{
    const n=parseInt(tr.dataset.n);
    const idx=ns.indexOf(n);if(idx<0)return;
    const bp=parseInt(document.getElementById('basePort').value)||10000;
    const mp=bp+idx*2; const rp=bp+idx*2+1;
    const portsDiv=tr.querySelector('.ports-val');
    if(portsDiv)portsDiv.innerHTML=`<span>${mp}</span>`;
    const reconnInp=tr.querySelector('.inp-reconn');
    if(reconnInp)reconnInp.value=`http://${ip}:${rp}/reconnect`;
    tr.dataset.mixedPort=mp;tr.dataset.reconnPort=rp;
  });
}

function makeRow(n='',pass='',interval=0,mixedPort='',reconnUrl=''){
  const tr=document.createElement('tr');if(n)tr.dataset.n=n;
  const p=pass||randPass();
  if(mixedPort)tr.dataset.mixedPort=mixedPort;
  tr.innerHTML=`
    <td class="col-n"><input class="inp-n" type="text" inputmode="numeric" pattern="[0-9]*" maxlength="3" value="${n}" placeholder="N" oninput="onN(this)"></td>
    <td class="col-login"><input type="text" value="${n?'modem'+n:''}" readonly tabindex="-1"></td>
    <td class="col-ports"><div class="ports-wrap"><div class="ports-val">${mixedPort?`<span>${mixedPort}</span>`:'<span style="color:var(--muted)">—</span>'}</div></div></td>
    <td class="col-reconn"><div class="reconn-wrap"><input class="inp-reconn" type="text" value="${reconnUrl||''}" readonly tabindex="-1"><button class="btn btn-icon" onclick="copyReconn(this)" title="Копировать URL">⎘</button></div></td>
    <td class="col-pass"><div class="pass-wrap"><input type="text" value="${p}" autocomplete="off"><button class="btn btn-icon" onclick="repass(this)" title="Новый пароль">↺</button></div></td>
    <td class="col-interval"><input class="inp-interval" type="number" min="0" max="9999" value="${interval||0}" title="Авто-реконнект (мин, 0=выкл)"></td>
    <td class="col-test"><span class="tres" id="tr${n}"></span></td>
    <td class="col-act" style="display:flex;gap:2px;justify-content:flex-end;padding:5px 8px">
      <button class="btn btn-sm" onclick="doTest(this)">▶ Test</button>
      <button class="btn btn-icon" onclick="doReconnect(this)" title="Реконнект (смена IP)">⟲</button>
      <button class="btn btn-icon btn-reboot" onclick="doReboot(this)" title="Ребут модема">↺</button>
      <button class="btn btn-icon" onclick="showReconnLog(parseInt(this.closest('tr').dataset.n))" title="Лог реконнектов">☰</button>
      <button class="btn btn-icon btn-del" onclick="delRow(this)">✕</button>
    </td>`;
  return tr;
}

function onN(inp){
  inp.value=inp.value.replace(/\\D/g,'').slice(0,3);
  const tr=inp.closest('tr');const n=inp.value;tr.dataset.n=n;
  tr.querySelector('.col-login input').value=n?`modem${n}`:'';
  const sp=tr.querySelector('.tres');if(sp)sp.id=`tr${n}`;
  refreshComputedPorts();
}

function repass(btn){btn.closest('.pass-wrap').querySelector('input').value=randPass();}
function copyReconn(btn){
  const url=btn.closest('.reconn-wrap').querySelector('input').value;
  if(!url)return;
  navigator.clipboard.writeText(url).then(()=>toast('URL скопирован','ok'))
    .catch(()=>{const ta=document.createElement('textarea');ta.value=url;
      document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();toast('Скопирован','ok');});
}

function addRow(n='',pass='',interval=0,mp='',ru=''){
  const tb=document.getElementById('tbody');
  const em=tb.querySelector('.empty');if(em)em.closest('tr').remove();
  tb.appendChild(makeRow(n,pass,interval,mp,ru));
  refreshComputedPorts();
}
function delRow(btn){
  btn.closest('tr').remove();
  const tb=document.getElementById('tbody');
  if(!tb.querySelector('tr'))tb.innerHTML='<tr><td colspan="8" class="empty">Нет модемов</td></tr>';
  refreshComputedPorts();
}
function getRows(){
  return[...document.querySelectorAll('#tbody tr[data-n]')]
    .map(tr=>({n:parseInt(tr.dataset.n),
               password:tr.querySelector('.pass-wrap input').value.trim(),
               interval_min:parseInt(tr.querySelector('.inp-interval').value)||0,
               _mp:parseInt(tr.dataset.mixedPort||0),
               _rp:parseInt(tr.dataset.reconnPort||0),
               _ru:tr.querySelector('.inp-reconn').value}))
    .filter(m=>m.n&&m.password);
}

async function loadInfo(){
  try{
    const d=await fetch('/api/info').then(r=>r.json());
    localIp=d.local_ip;basePort=d.base_port;hasTls=d.tls||false;
    document.getElementById('localIp').textContent=d.local_ip;
    const dot=document.getElementById('dot');
    dot.className='dot '+(d.status==='active'?'on':'off');
    document.getElementById('srvStatus').textContent=d.status;
    if(!confDirty){
      document.getElementById('extIp').value=d.ext_ip||'';
      document.getElementById('basePort').value=d.base_port;
      extIp=d.ext_ip||'';
    }
    refreshComputedPorts();
  }catch(e){}
}

async function loadModems(){
  try{
    const ms=await fetch('/api/modems').then(r=>r.json());
    const tb=document.getElementById('tbody');tb.innerHTML='';
    if(!ms.length){tb.innerHTML='<tr><td colspan="8" class="empty">Нет модемов — нажми + Добавить</td></tr>';return;}
    ms.forEach(m=>tb.appendChild(makeRow(m.n,m.password,m.interval_min||0,
      m.mixed_port,m.reconn_url)));
  }catch(e){}
}

async function fetchExtIp(){
  const btn=document.getElementById('fetchIpBtn');btn.disabled=true;btn.textContent='…';
  try{
    const d=await fetch('/api/external-ip').then(r=>r.json());
    if(d.ip){document.getElementById('extIp').value=d.ip;extIp=d.ip;confDirty=false;
      document.getElementById('saveConfBtn').style.display='none';
      refreshComputedPorts();toast(`IP: ${d.ip}`,'ok');
    }else toast(d.error||'Не удалось','err');
  }catch(e){toast('Ошибка','err');}
  btn.disabled=false;btn.innerHTML='⟳ Авто';
}

async function saveConf(){
  extIp=document.getElementById('extIp').value.trim();
  basePort=parseInt(document.getElementById('basePort').value)||10000;
  try{
    await fetch('/api/server-config',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({ext_ip:extIp,base_port:basePort})});
    confDirty=false;document.getElementById('saveConfBtn').style.display='none';
    refreshComputedPorts();toast('Сохранено','ok');
  }catch(e){toast('Ошибка','err');}
}

async function doApply(){
  const rows=getRows();
  if(!rows.length){toast('Добавь хотя бы один модем','err');return;}
  if(confDirty)await saveConf();
  const btn=document.getElementById('applyBtn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>&nbsp;Применяю…';
  try{
    const d=await fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({modems:rows,base_port:basePort})}).then(r=>r.json());
    if(d.ok){toast(`sing-box: ${d.status}`,'ok');await loadModems();}
    else toast(d.error||'Ошибка','err',7000);
    loadInfo();
  }catch(e){toast('Нет связи','err');}
  btn.disabled=false;btn.innerHTML='Применить';
}

async function doTest(btn){
  const tr=btn.closest('tr');const n=parseInt(tr.dataset.n);
  if(!n){toast('Укажи N','err');return;}
  btn.disabled=true;
  const sp=document.getElementById(`tr${n}`)||tr.querySelector('.tres');
  sp.className='tres pend';sp.innerHTML='<span class="spin"></span>';
  try{
    const d=await fetch(`/api/test/${n}`).then(r=>r.json());
    if(d.exit_ip){sp.className='tres ok';
      sp.innerHTML=d.exit_ip+(d.huawei_ok?'<span class="badge-h">H✓</span>':'');
    }else{sp.className='tres fail';sp.textContent=d.error||'нет';}
  }catch(e){sp.className='tres fail';sp.textContent='err';}
  btn.disabled=false;
}

async function doReconnect(btn){
  const tr=btn.closest('tr');const n=parseInt(tr.dataset.n);
  if(!n){toast('Укажи N','err');return;}
  btn.disabled=true;const orig=btn.innerHTML;btn.innerHTML='<span class="spin"></span>';
  toast(`modem${n}: реконнект…`,'info',20000);
  try{
    const d=await fetch(`/api/reconnect/${n}`).then(r=>r.json());
    if(d.ok)toast(`modem${n}: ${d.msg} (${d.dt}s)`,'ok');
    else toast(`modem${n}: ${d.msg}`,'err',7000);
  }catch(e){toast(`modem${n}: ошибка`,'err');}
  btn.disabled=false;btn.innerHTML=orig;
}

async function doReboot(btn){
  const tr=btn.closest('tr');const n=parseInt(tr.dataset.n);
  if(!n){toast('Укажи N','err');return;}
  if(!confirm(`Ребут modem${n}? (~30–60 сек недоступен)`))return;
  btn.disabled=true;const orig=btn.innerHTML;btn.innerHTML='<span class="spin"></span>';
  try{
    const d=await fetch(`/api/reboot/${n}`).then(r=>r.json());
    if(d.ok)toast(`modem${n}: ${d.msg}`,'warn',6000);
    else toast(`modem${n}: ${d.msg}`,'err',7000);
  }catch(e){toast(`modem${n}: ошибка`,'err');}
  btn.disabled=false;btn.innerHTML=orig;
}

async function showReconnLog(n){
  _reconnLogN=n;
  document.getElementById('reconnModalTitle').textContent=`Reconnect Log — modem${n}`;
  document.getElementById('reconnModal').classList.add('open');
  await refreshReconnLog();
}
async function refreshReconnLog(){
  const el=document.getElementById('reconnLogBody');el.textContent='Загрузка…';
  try{
    const d=await fetch(`/api/reconnect-log/${_reconnLogN}`).then(r=>r.json());
    if(!d.lines||!d.lines.length){el.textContent='(нет записей)';return;}
    el.innerHTML=d.lines.map(l=>{
      const s=l.replace(/&/g,'&amp;').replace(/</g,'&lt;');
      if(l.includes('| ok |')||l.includes('reconnected'))return`<span class="ok">${s}</span>`;
      if(l.includes('| fail |'))return`<span class="err">${s}</span>`;
      if(l.includes('| reboot |'))return`<span class="warn">${s}</span>`;
      return s;
    }).join('\\n');
    el.scrollTop=el.scrollHeight;
  }catch(e){el.textContent='Ошибка';}
}
function closeReconn(){document.getElementById('reconnModal').classList.remove('open');}

function copyClient(){
  const rows=getRows();
  if(!rows.length){toast('Нет модемов','err');return;}
  const ip=document.getElementById('extIp').value.trim()||localIp;
  // формат: IP:PORT:login:pass \t http://IP:RECONN/reconnect
  const lines=rows.map(m=>{
    const mp=m._mp||'?';
    const ru=m._ru||'?';
    return `${ip}:${mp}:modem${m.n}:${m.password}\\t${ru}`;
  });
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
    if(!d.lines||!d.lines.length){el.textContent='(пусто)';return;}
    el.innerHTML=d.lines.map(l=>{
      const cls=l.match(/FATAL|ERROR/i)?'err':l.match(/WARN/i)?'warn':l.match(/started|active/i)?'ok':'';
      const s=l.replace(/&/g,'&amp;').replace(/</g,'&lt;');
      return cls?`<span class="${cls}">${s}</span>`:s;
    }).join('\\n');
    el.scrollTop=el.scrollHeight;
  }catch(e){el.textContent='Ошибка';}
}
function openLogs(){document.getElementById('logModal').classList.add('open');refreshLogs();}
function closeLogs(){document.getElementById('logModal').classList.remove('open');}

document.title='modlink ✓';
try{loadInfo();loadModems();}catch(e){document.title='ERR:'+e.message;}
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

    try:
        modems = load_modems()
        sconf  = load_server_conf()
        base   = sconf.get("base_port", DEFAULT_BASE_PORT)
        rebuild_reconn_servers(modems, base)
        rebuild_scheduler(modems)
    except Exception as e:
        print(f"[startup] {e}")

    url = f"http://{a.host}:{a.port}"
    print(f"  modlink panel → {url}")
    if not a.no_browser:
        webbrowser.open(url)
    server = ThreadingHTTPServer((a.host, a.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  остановлено")

if __name__ == "__main__":
    main()
