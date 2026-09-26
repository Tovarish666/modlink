/* ProxyVeth — implementation of the UI<->backend bridge (see bridge.h).
 *
 * Holds the single in-memory Config, guarded by one lock. Fast mutations run
 * on the UI thread; the host runs apply/test/reconnect/reboot on worker
 * threads, so those snapshot what they need under the lock and release it
 * before touching the network. */
#include "common.h"
#include "json.h"
#include "bridge.h"
#include <string.h>
#include <stdlib.h>

static Config           g_cfg;
static CRITICAL_SECTION g_lock;
static BOOL             g_ready = FALSE;

static void lock(void)   { if (g_ready) EnterCriticalSection(&g_lock); }
static void unlock(void) { if (g_ready) LeaveCriticalSection(&g_lock); }

/* The modem's HiLink web UI is always .1 in the interface's /24 (192.168.X.100
 * -> 192.168.X.1). It is derived from the one IP field, never entered — a
 * different value could only ever fail, so there is nothing to ask. */
static void derive_gateway(const char *iface_ip, char *out, size_t cap)
{
    int a, b, c, d;
    if (iface_ip && sscanf(iface_ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4)
        snprintf(out, cap, "%d.%d.%d.1", a, b, c);
    else if (cap) out[0] = 0;
}

/* ------------------------------------------------- background worker control
 * The engine (3proxy + reconnect + watchdog) lives in a separate windowless
 * process, modlink.exe --worker, so it survives the GUI window closing. The GUI
 * only saves config.json and drives the worker: spawn it, signal reload/quit,
 * and read its status.json. */
#define EV_RELOAD "Local\\modlink_reload"
#define EV_QUIT   "Local\\modlink_quit"
#define MTX_WORK  "Local\\modlink_worker_mtx"

static BOOL worker_alive(void)
{
    HANDLE m = OpenMutexA(SYNCHRONIZE, FALSE, MTX_WORK);
    if (m) { CloseHandle(m); return TRUE; }
    return FALSE;
}

static void worker_spawn(void)
{
    char self[ML_PATH_LEN], cmd[ML_PATH_LEN + 16];
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    if (worker_alive()) return;
    if (!GetModuleFileNameA(NULL, self, sizeof(self))) return;
    snprintf(cmd, sizeof(cmd), "\"%s\" --worker", self);
    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
}

static void worker_signal(const char *name)
{
    HANDLE e = OpenEventA(EVENT_MODIFY_STATE, FALSE, name);
    if (e) { SetEvent(e); CloseHandle(e); }
}

/* Read the worker's status.json. A file older than ~10 s means the worker is
 * gone (it rewrites status every few seconds), so treat that as stopped. */
static BOOL svc_running(void)
{
    char path[ML_PATH_LEN], *buf = NULL; size_t len = 0; BOOL r = FALSE;
    WIN32_FILE_ATTRIBUTE_DATA fad; FILETIME now; ULONGLONG age;
    snprintf(path, sizeof(path), "%s\\status.json", ml_dir_data());
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) return FALSE;
    GetSystemTimeAsFileTime(&now);
    age = ((((ULONGLONG)now.dwHighDateTime) << 32) | now.dwLowDateTime)
        - ((((ULONGLONG)fad.ftLastWriteTime.dwHighDateTime) << 32) | fad.ftLastWriteTime.dwLowDateTime);
    if (age > 100000000ULL) return FALSE;
    if (ml_read_file(path, &buf, &len) && buf) {
        JVal *root = json_parse(buf);           /* parse, don't substring-match:
                                                 * the file has "running": true
                                                 * with a space, which the old
                                                 * strstr missed. */
        if (root) { r = json_bool(root, "running", 0); json_free(root); }
        free(buf);
    }
    return r;
}

static void svc_read_err(char *out, size_t cap)
{
    char path[ML_PATH_LEN], *buf = NULL; size_t len = 0;
    if (out && cap) out[0] = 0;
    snprintf(path, sizeof(path), "%s\\status.json", ml_dir_data());
    if (ml_read_file(path, &buf, &len) && buf) {
        JVal *root = json_parse(buf);
        if (root) { ml_strlcpy(out, json_str(root, "err", ""), cap); json_free(root); }
        free(buf);
    }
}

/* Keep the HKCU Run entry in sync so the worker autostarts at logon. */
static void sync_autostart(BOOL on)
{
    HKEY k;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS)
        return;
    if (on) {
        char self[ML_PATH_LEN], val[ML_PATH_LEN + 16];
        if (GetModuleFileNameA(NULL, self, sizeof(self))) {
            snprintf(val, sizeof(val), "\"%s\" --worker", self);
            RegSetValueExA(k, "modlink", 0, REG_SZ, (const BYTE*)val, (DWORD)strlen(val) + 1);
        }
    } else {
        RegDeleteValueA(k, "modlink");
    }
    RegCloseKey(k);
}

/* ------------------------------------------------------------- emitting */
static char *jret(JBuf *b) { return b->buf ? b->buf : NULL; }

static void emit_modem(JBuf *b, const Modem *m)
{
    jb_raw(b, "{");
    jb_kv_int (b, "id",           m->id);           jb_raw(b, ",");
    jb_kv_int (b, "n",            m->n);            jb_raw(b, ",");
    jb_kv_str (b, "login",        m->login);        jb_raw(b, ",");
    jb_kv_str (b, "pass",         m->pass);         jb_raw(b, ",");
    jb_kv_str (b, "lan_ip",       m->lan_ip);       jb_raw(b, ",");
    jb_kv_str (b, "modem_ip",     m->modem_ip);     jb_raw(b, ",");
    jb_kv_int (b, "proxy_port",   m->proxy_port);   jb_raw(b, ",");
    jb_kv_int (b, "reconn_port",  m->reconn_port);  jb_raw(b, ",");
    jb_kv_int (b, "reboot_port",  m->reboot_port);  jb_raw(b, ",");
    jb_kv_int (b, "interval_min", m->interval_min); jb_raw(b, ",");
    jb_kv_bool(b, "enabled",      m->enabled);      jb_raw(b, ",");
    jb_kv_str (b, "exit_ip",      m->last_exit_ip);
    jb_raw(b, "}");
}

/* Full state snapshot. Caller must already hold the lock. */
static char *emit_state_locked(void)
{
    JBuf b; int i;
    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_bool(&b, "running", svc_running()); jb_raw(&b, ",");
    jb_raw(&b, "\"network\":{");
    jb_kv_str (&b, "lan_ip",    g_cfg.lan_ip);  jb_raw(&b, ",");
    jb_kv_str (&b, "wan_ip",    g_cfg.wan_ip);  jb_raw(&b, ",");
    jb_kv_int (&b, "base_port", g_cfg.base_port); jb_raw(&b, ",");
    jb_kv_int (&b, "mode",      g_cfg.mode);      jb_raw(&b, ",");
    jb_kv_bool(&b, "autostart", g_cfg.autostart);
    jb_raw(&b, "},\"modems\":[");
    for (i = 0; i < g_cfg.count; i++) {
        if (i) jb_raw(&b, ",");
        emit_modem(&b, &g_cfg.modems[i]);
    }
    jb_raw(&b, "]}");
    return jret(&b);
}

/* ------------------------------------------------------------- req parsing */
/* The webview RPC hands the callback a JSON array of the JS call's arguments.
 * Our calls pass at most one argument, so element 0 is what we want. Returns
 * the parsed root (caller frees with json_free) and *first = element 0. */
static JVal *req_root(const char *req, const JVal **first)
{
    JVal *root = req ? json_parse(req) : NULL;
    *first = (root && root->type == J_ARR) ? root->child : NULL;
    return root;
}

/* ------------------------------------------------------------- lifecycle */
void pv_init(void)
{
    if (!g_ready) { InitializeCriticalSection(&g_lock); g_ready = TRUE; }
    ml_ensure_dirs();

    /* One-time migration from the earlier "ProxyVeth" name: carry the config
     * over so an existing install keeps its modems. */
    {
        const char *la = getenv("LOCALAPPDATA");
        char oldcfg[ML_PATH_LEN];
        if (la && GetFileAttributesA(ml_path_config()) == INVALID_FILE_ATTRIBUTES) {
            snprintf(oldcfg, sizeof(oldcfg), "%s\\ProxyVeth\\config.json", la);
            if (GetFileAttributesA(oldcfg) != INVALID_FILE_ATTRIBUTES &&
                CopyFileA(oldcfg, ml_path_config(), FALSE))
                ml_log("migrated config ProxyVeth -> modlink");
        }
    }

    p3_extract_binary();
    lock();
    if (!cfg_load(&g_cfg)) cfg_defaults(&g_cfg);
    unlock();
    ml_log("bridge init: %d modems", g_cfg.count);
}

void pv_shutdown(void)
{
    /* Closing the GUI must NOT stop the proxies — that is the whole point of the
     * worker. The worker keeps running; nothing to do here. */
}

/* ------------------------------------------------------------- read */
char *pv_get_state(const char *req)
{
    char *s; (void)req;
    lock(); s = emit_state_locked(); unlock();
    return s;
}

char *pv_status(const char *req)
{
    JBuf b; (void)req;
    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_bool(&b, "running", svc_running());
    jb_raw(&b, "}");
    return jret(&b);
}

/* Put text on the Windows clipboard from C — navigator.clipboard is blocked in
 * the WebView's opaque (NavigateToString) origin, so copying is done host-side. */
char *pv_clip(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    const char *text = (o && o->type == J_STR && o->str) ? o->str : "";
    BOOL ok = FALSE;
    JBuf b;

    if (OpenClipboard(NULL)) {
        wchar_t *w = ml_utf8_to_w(text);
        EmptyClipboard();
        if (w) {
            size_t bytes = (wcslen(w) + 1) * sizeof(wchar_t);
            HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (h) {
                void *p = GlobalLock(h);
                if (p) {
                    memcpy(p, w, bytes);
                    GlobalUnlock(h);
                    if (SetClipboardData(CF_UNICODETEXT, h)) ok = TRUE;
                    else GlobalFree(h);
                } else GlobalFree(h);
            }
            free(w);
        }
        CloseClipboard();
    }
    json_free(root);
    jb_init(&b); jb_raw(&b, "{"); jb_kv_bool(&b, "ok", ok); jb_raw(&b, "}");
    return jret(&b);
}

/* ------------------------------------------------------------- mutate */
char *pv_save_network(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    char *s;
    lock();
    BOOL autostart_changed = FALSE, autostart_val = FALSE;
    if (o && o->type == J_OBJ) {
        ml_strlcpy(g_cfg.lan_ip, json_str(o, "lan_ip", g_cfg.lan_ip), sizeof(g_cfg.lan_ip));
        ml_strlcpy(g_cfg.wan_ip, json_str(o, "wan_ip", g_cfg.wan_ip), sizeof(g_cfg.wan_ip));
        int bp = (int)json_num(o, "base_port", g_cfg.base_port);
        if (ml_port_valid(bp)) g_cfg.base_port = bp;
        if (json_get(o, "autostart")) {
            autostart_val = json_bool(o, "autostart", g_cfg.autostart);
            autostart_changed = (autostart_val != g_cfg.autostart);
            g_cfg.autostart = autostart_val;
        }
        cfg_save(&g_cfg);
    }
    s = emit_state_locked();
    unlock();
    if (autostart_changed) sync_autostart(autostart_val);
    json_free(root);
    return s;
}

char *pv_add_modem(const char *req)
{
    char *s; int idx; (void)req;
    lock();
    idx = cfg_add_modem(&g_cfg);
    if (idx >= 0) ml_log("модем №%d добавлен (%s)", g_cfg.modems[idx].n, g_cfg.modems[idx].login);
    cfg_save(&g_cfg);
    s = emit_state_locked();
    unlock();
    return s;
}

/* Switch mode (0 = port triples, 1 = one shared port) and re-fill every modem's
 * ports to match. req[0] = the new mode as a number. */
char *pv_set_mode(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    char *s;
    lock();
    if (o && o->type == J_NUM) g_cfg.mode = ((int)o->num) ? 1 : 0;
    cfg_assign_ports(&g_cfg);
    cfg_save(&g_cfg);
    s = emit_state_locked();
    unlock();
    json_free(root);
    return s;
}

char *pv_update_modem(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    char *s;
    lock();
    if (o && o->type == J_OBJ) {
        int id = (int)json_num(o, "id", 0);
        Modem *m = cfg_find_by_id(&g_cfg, id);
        if (m) {
            m->n = (int)json_num(o, "n", m->n);
            ml_strlcpy(m->login,    json_str(o, "login",    m->login),    sizeof(m->login));
            ml_strlcpy(m->pass,     json_str(o, "pass",     m->pass),     sizeof(m->pass));
            ml_strlcpy(m->lan_ip,   json_str(o, "lan_ip",   m->lan_ip),   sizeof(m->lan_ip));
            /* web UI address is derived from the interface, not entered */
            derive_gateway(m->lan_ip, m->modem_ip, sizeof(m->modem_ip));
            m->proxy_port   = (int)json_num(o, "proxy_port",   m->proxy_port);
            m->reconn_port  = (int)json_num(o, "reconn_port",  m->reconn_port);
            m->reboot_port  = (int)json_num(o, "reboot_port",  m->reboot_port);
            m->interval_min = (int)json_num(o, "interval_min", m->interval_min);
            m->enabled      =      json_bool(o, "enabled",     m->enabled);
            cfg_save(&g_cfg);
        }
    }
    s = emit_state_locked();
    unlock();
    json_free(root);
    return s;
}

char *pv_delete_modem(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    char *s; int id, i;
    lock();
    id = (o && o->type == J_NUM) ? (int)o->num : 0;
    for (i = 0; i < g_cfg.count; i++)
        if (g_cfg.modems[i].id == id) { cfg_remove_modem(&g_cfg, i); cfg_save(&g_cfg); break; }
    s = emit_state_locked();
    unlock();
    json_free(root);
    return s;
}

char *pv_stop(const char *req)
{
    JBuf b; int i; (void)req;
    worker_signal(EV_QUIT);                 /* worker stops 3proxy and exits */
    for (i = 0; i < 30 && svc_running(); i++) Sleep(100);
    jb_init(&b);
    jb_raw(&b, "{"); jb_kv_bool(&b, "ok", 1); jb_raw(&b, ",");
    jb_kv_bool(&b, "running", svc_running()); jb_raw(&b, "}");
    return jret(&b);
}

/* ------------------------------------------------------------- slow ops */
/* Apply now goes through the background worker: save config, then either signal
 * a running worker to reload or spawn a fresh one (which applies on startup),
 * and read back what it reports in status.json. */
char *pv_apply(const char *req)
{
    char err[ML_PATH_LEN] = {0}, sp[ML_PATH_LEN];
    JBuf b; BOOL ok = FALSE; int bad, i; (void)req;

    lock();
    cfg_save(&g_cfg);                       /* the worker reads config.json */
    bad = cfg_validate(&g_cfg, err, sizeof(err));
    unlock();

    if (bad == -1) {
        /* drop the previous status so we only read the fresh worker's report */
        snprintf(sp, sizeof(sp), "%s\\status.json", ml_dir_data());
        DeleteFileA(sp);

        if (worker_alive()) worker_signal(EV_RELOAD);
        else                worker_spawn();

        for (i = 0; i < 70; i++) {
            if (svc_running()) { ok = TRUE; break; }
            svc_read_err(err, sizeof(err));
            if (err[0]) break;
            Sleep(100);
        }
        if (!ok) {
            svc_read_err(err, sizeof(err));
            if (!err[0]) ml_strlcpy(err, "фоновая служба не ответила", sizeof(err));
        }
    }

    jb_init(&b);
    jb_raw(&b, "{"); jb_kv_bool(&b, "ok", ok); jb_raw(&b, ",");
    jb_kv_bool(&b, "running", svc_running()); jb_raw(&b, ",");
    jb_kv_str(&b, "err", ok ? "" : err);
    jb_raw(&b, "}");
    return jret(&b);
}

char *pv_test(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    int id, port = 0; char host[ML_ADDR_LEN] = {0}, proxy[ML_ADDR_LEN] = {0};
    char login[ML_LOGIN_LEN] = {0}, pass[ML_PASS_LEN] = {0};
    char exit_ip[ML_ADDR_LEN] = {0}; BOOL huawei = FALSE, have = FALSE;
    HttpResp r; JBuf b;

    id = (o && o->type == J_NUM) ? (int)o->num : 0;

    lock();
    { Modem *m = cfg_find_by_id(&g_cfg, id);
      if (m) {
          have = TRUE;
          port = m->proxy_port;
          ml_strlcpy(host,  m->modem_ip, sizeof(host));
          ml_strlcpy(login, m->login,    sizeof(login));
          ml_strlcpy(pass,  m->pass,     sizeof(pass));
          ml_strlcpy(proxy, g_cfg.lan_ip[0] ? g_cfg.lan_ip : "127.0.0.1", sizeof(proxy));
      }
    }
    unlock();
    json_free(root);

    if (have && ml_port_valid(port) && svc_running()) {
        /* Exit IP as seen from outside, through this modem's own port — proves
         * -e pinned the right LTE interface. */
        if (http_get_via_proxy("http://api.ipify.org", proxy, port, login, pass, 9000, &r)
            && r.status == 200 && r.body) {
            char *p = r.body, *w = exit_ip;
            while (*p == ' ' || *p == '\n' || *p == '\r') p++;
            while (*p && *p != '\n' && *p != '\r' &&
                   (size_t)(w - exit_ip) < sizeof(exit_ip) - 1) *w++ = *p++;
            *w = 0;
        }
        http_free(&r);

        if (host[0]) {
            char url[ML_URL_LEN];
            snprintf(url, sizeof(url), "http://%s/api/webserver/SesTokInfo", host);
            if (http_get_via_proxy(url, proxy, port, login, pass, 8000, &r)
                && r.body && strstr(r.body, "SesInfo")) huawei = TRUE;
            http_free(&r);
        }
    }

    /* Cache the last exit IP so a state refresh shows it too. */
    if (ml_is_ipv4(exit_ip)) {
        lock();
        { Modem *m = cfg_find_by_id(&g_cfg, id);
          if (m) ml_strlcpy(m->last_exit_ip, exit_ip, sizeof(m->last_exit_ip)); }
        unlock();
    }

    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_int(&b, "id", id); jb_raw(&b, ",");
    jb_kv_bool(&b, "ok", ml_is_ipv4(exit_ip)); jb_raw(&b, ",");
    jb_kv_str(&b, "exit_ip", exit_ip); jb_raw(&b, ",");
    jb_kv_bool(&b, "huawei", huawei); jb_raw(&b, ",");
    jb_kv_str(&b, "err", have ? (svc_running() ? "" : "прокси не запущен — нажми «Применить»") : "модем не найден");
    jb_raw(&b, "}");
    return jret(&b);
}

char *pv_reconnect(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    int id; char host[ML_ADDR_LEN] = {0}, msg[256] = {0}; double secs = 0; BOOL ok = FALSE, have = FALSE;
    JBuf b; char t[80];

    id = (o && o->type == J_NUM) ? (int)o->num : 0;
    lock();
    { Modem *m = cfg_find_by_id(&g_cfg, id);
      if (m && m->modem_ip[0]) { have = TRUE; ml_strlcpy(host, m->modem_ip, sizeof(host)); } }
    unlock();
    json_free(root);

    if (have) ok = hilink_reconnect(host, msg, sizeof(msg), &secs);
    else ml_strlcpy(msg, "не задан IP модема", sizeof(msg));

    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_int(&b, "id", id); jb_raw(&b, ",");
    jb_kv_bool(&b, "ok", ok); jb_raw(&b, ",");
    jb_kv_str(&b, "msg", msg); jb_raw(&b, ",");
    snprintf(t, sizeof(t), "\"secs\":%.1f", secs); jb_raw(&b, t);
    jb_raw(&b, "}");
    return jret(&b);
}

char *pv_reboot(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    int id; char host[ML_ADDR_LEN] = {0}, msg[256] = {0}; BOOL ok = FALSE, have = FALSE;
    JBuf b;

    id = (o && o->type == J_NUM) ? (int)o->num : 0;
    lock();
    { Modem *m = cfg_find_by_id(&g_cfg, id);
      if (m && m->modem_ip[0]) { have = TRUE; ml_strlcpy(host, m->modem_ip, sizeof(host)); } }
    unlock();
    json_free(root);

    if (have) ok = hilink_reboot(host, msg, sizeof(msg));
    else ml_strlcpy(msg, "не задан IP модема", sizeof(msg));

    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_int(&b, "id", id); jb_raw(&b, ",");
    jb_kv_bool(&b, "ok", ok); jb_raw(&b, ",");
    jb_kv_str(&b, "msg", msg);
    jb_raw(&b, "}");
    return jret(&b);
}

/* The worker's periodic results (checks.json), handed to the UI verbatim — it
 * is already {modems:[{id,wan_ip,wan_ts,down,up,ping,speed_ts,speed_err}]}. */
char *pv_checks(const char *req)
{
    char path[ML_PATH_LEN]; char *buf = NULL; size_t len = 0;
    (void)req;
    snprintf(path, sizeof(path), "%s\\checks.json", ml_dir_data());
    if (ml_read_file(path, &buf, &len) && buf && len) return buf;
    free(buf);
    { char *s = (char *)malloc(16); if (s) memcpy(s, "{\"modems\":[]}", 14); return s; }
}

/* Tail a log file into {"lines":[...]} (oldest first). */
static char *log_tail_json(const char *path, int maxlines)
{
    char **lines = NULL;
    int n = ml_tail_file(path, maxlines, &lines), i;
    JBuf b;
    jb_init(&b);
    jb_raw(&b, "{\"lines\":[");
    for (i = 0; i < n; i++) {
        if (i) jb_raw(&b, ",");
        jb_str(&b, lines[i] ? lines[i] : "");
        free(lines[i]);
    }
    free(lines);
    jb_raw(&b, "]}");
    return jret(&b);
}

char *pv_log_modlink(const char *req)
{
    char path[ML_PATH_LEN];
    (void)req;
    snprintf(path, sizeof(path), "%s\\modlink.log", ml_dir_logs());
    return log_tail_json(path, 500);
}

char *pv_log_3proxy(const char *req)
{
    (void)req;
    return log_tail_json(ml_path_3plog(), 500);
}

/* Manual speed test for one modem — the native yaspeed port, run through the
 * modem's own proxy, so the user can verify a link now instead of waiting for
 * the daily 12:00 sweep. Slow — the host runs it on a worker thread. */
char *pv_speedtest(const char *req)
{
    const JVal *o; JVal *root = req_root(req, &o);
    int id, port = 0; BOOL have = FALSE, ok = FALSE;
    char proxy[ML_ADDR_LEN] = {0}, login[ML_LOGIN_LEN] = {0}, pass[ML_PASS_LEN] = {0};
    double down = 0, up = 0, ping = 0; char err[96] = {0};
    JBuf b;

    id = (o && o->type == J_NUM) ? (int)o->num : 0;
    lock();
    { Modem *m = cfg_find_by_id(&g_cfg, id);
      if (m) { have = TRUE; port = m->proxy_port;
               ml_strlcpy(login, m->login, sizeof(login));
               ml_strlcpy(pass,  m->pass,  sizeof(pass));
               ml_strlcpy(proxy, g_cfg.lan_ip[0] ? g_cfg.lan_ip : "127.0.0.1", sizeof(proxy)); } }
    unlock();
    json_free(root);

    if (!have) ml_strlcpy(err, "модем не найден", sizeof(err));
    else if (!svc_running()) ml_strlcpy(err, "прокси не запущен — нажми «Применить»", sizeof(err));
    else ok = speedtest_run(proxy, port, login, pass, 8, 6,
                            &down, &up, &ping, NULL, 0, err, sizeof(err));

    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_int(&b, "id", id); jb_raw(&b, ",");
    jb_kv_bool(&b, "ok", ok); jb_raw(&b, ",");
    { char n[64];
      snprintf(n, sizeof(n), "\"down\":%.2f,\"up\":%.2f,\"ping\":%.2f,", down, up, ping);
      jb_raw(&b, n); }
    jb_kv_str(&b, "err", err);
    jb_raw(&b, "}");
    return jret(&b);
}
