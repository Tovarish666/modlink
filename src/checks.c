/* modlink — periodic auto-checks.
 *
 * Two background probes, owned by the worker process and persisted to
 * checks.json (the GUI reads that file through pv_checks and shows the
 * numbers next to each modem):
 *
 *   - WAN IP, hourly: fetch the external IP as seen THROUGH each modem's own
 *     proxy port (same route a client would take), so a silent SIM/IP change is
 *     visible. Needs 3proxy up.
 *   - speed test, daily at 12:00 local: run the user's yaspeed CLI bound to each
 *     modem's LAN source IP (`--source-ip`, which on Windows selects the modem's
 *     interface — see the source-routing note) and record down/up/ping.
 *
 * yaspeed.exe is NOT bundled: it is the user's own tool. We look for it next to
 * modlink.exe and in the data dir; if it is missing the speed sweep just records
 * a short note and tries again the next day.
 *
 * checks.json shape (one row per modem id):
 *   { "modems": [ { "id":1, "wan_ip":"1.2.3.4", "wan_ts":"2026-09-24 09:00",
 *                   "down":523.18, "up":231.44, "ping":12.3,
 *                   "speed_ts":"2026-09-24 12:00", "speed_err":"" }, ... ] }
 */
#include "common.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>

typedef struct {
    int    id;
    char   wan_ip[ML_ADDR_LEN];
    char   wan_ts[24];
    double down, up, ping;
    int    have_speed;
    char   speed_ts[24];
    char   speed_err[96];
} CheckRow;

static CheckRow g_rows[ML_MAX_MODEMS];
static int      g_nrows = 0;
static BOOL     g_loaded = FALSE;

/* scheduling */
static ULONGLONG g_next_wan = 0;     /* GetTickCount64 of the next WAN sweep    */
static int       g_speed_day = -1;   /* day-key of the last speed sweep, -1=none */

/* ------------------------------------------------------------- helpers */
static const char *checks_path(void)
{
    static char p[ML_PATH_LEN];
    snprintf(p, sizeof(p), "%s\\checks.json", ml_dir_data());
    return p;
}

static void ts_now(char *out, size_t cap)
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(out, cap, "%04d-%02d-%02d %02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
}

static int day_key(const SYSTEMTIME *st)   /* unique per calendar day */
{
    return st->wYear * 512 + st->wMonth * 32 + st->wDay;
}

static CheckRow *row_for(int id)
{
    int i;
    for (i = 0; i < g_nrows; i++) if (g_rows[i].id == id) return &g_rows[i];
    if (g_nrows >= ML_MAX_MODEMS) return NULL;
    memset(&g_rows[g_nrows], 0, sizeof(g_rows[g_nrows]));
    g_rows[g_nrows].id = id;
    return &g_rows[g_nrows++];
}

/* ------------------------------------------------------------- persistence */
static void load_rows(void)
{
    char *buf = NULL; size_t len = 0;
    JVal *root; const JVal *arr, *it;
    if (g_loaded) return;
    g_loaded = TRUE;
    if (!ml_read_file(checks_path(), &buf, &len) || !buf) return;
    root = json_parse(buf);
    free(buf);
    if (!root) return;
    arr = json_get(root, "modems");
    if (arr && arr->type == J_ARR) {
        for (it = arr->child; it && g_nrows < ML_MAX_MODEMS; it = it->next) {
            CheckRow *r;
            int id = (int)json_num(it, "id", 0);
            if (id <= 0) continue;
            r = row_for(id);
            if (!r) break;
            ml_strlcpy(r->wan_ip,   json_str(it, "wan_ip",   ""), sizeof(r->wan_ip));
            ml_strlcpy(r->wan_ts,   json_str(it, "wan_ts",   ""), sizeof(r->wan_ts));
            ml_strlcpy(r->speed_ts, json_str(it, "speed_ts", ""), sizeof(r->speed_ts));
            ml_strlcpy(r->speed_err,json_str(it, "speed_err",""), sizeof(r->speed_err));
            r->down = json_num(it, "down", 0);
            r->up   = json_num(it, "up",   0);
            r->ping = json_num(it, "ping", 0);
            r->have_speed = r->speed_ts[0] ? 1 : 0;
        }
    }
    json_free(root);
}

static void jb_kv_num(JBuf *b, const char *k, double v)
{
    char line[64];
    snprintf(line, sizeof(line), "\"%s\":%.2f", k, v);
    jb_raw(b, line);
}

static void save_rows(void)
{
    JBuf b; int i;
    jb_init(&b);
    jb_raw(&b, "{\"modems\":[");
    for (i = 0; i < g_nrows; i++) {
        const CheckRow *r = &g_rows[i];
        if (i) jb_raw(&b, ",");
        jb_raw(&b, "{");
        jb_kv_int (&b, "id",       r->id);        jb_raw(&b, ",");
        jb_kv_str (&b, "wan_ip",   r->wan_ip);    jb_raw(&b, ",");
        jb_kv_str (&b, "wan_ts",   r->wan_ts);    jb_raw(&b, ",");
        jb_kv_num (&b, "down",     r->down);      jb_raw(&b, ",");
        jb_kv_num (&b, "up",       r->up);        jb_raw(&b, ",");
        jb_kv_num (&b, "ping",     r->ping);      jb_raw(&b, ",");
        jb_kv_str (&b, "speed_ts", r->speed_ts);  jb_raw(&b, ",");
        jb_kv_str (&b, "speed_err",r->speed_err);
        jb_raw(&b, "}");
    }
    jb_raw(&b, "]}\n");
    if (b.buf) ml_write_file_atomic(checks_path(), b.buf, b.len);
    jb_free(&b);
}

/* ------------------------------------------------------------- yaspeed */
/* Resolve yaspeed.exe: next to modlink.exe first, then the data dir. */
static BOOL yaspeed_path(char *out, size_t cap)
{
    char exe[ML_PATH_LEN]; DWORD n; char *slash;
    n = GetModuleFileNameA(NULL, exe, sizeof(exe));
    if (n > 0 && n < sizeof(exe)) {
        slash = strrchr(exe, '\\');
        if (slash) {
            *slash = 0;
            snprintf(out, cap, "%s\\yaspeed.exe", exe);
            if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return TRUE;
        }
    }
    snprintf(out, cap, "%s\\yaspeed.exe", ml_dir_data());
    if (GetFileAttributesA(out) != INVALID_FILE_ATTRIBUTES) return TRUE;
    return FALSE;
}

BOOL checks_speedtest(const char *lan_ip, double *down, double *up, double *ping,
                      char *err, size_t errcap)
{
    char exe[ML_PATH_LEN], cmd[ML_PATH_LEN * 2], outpath[ML_PATH_LEN];
    STARTUPINFOA si; PROCESS_INFORMATION pi; SECURITY_ATTRIBUTES sa;
    HANDLE hout; DWORD wr;
    char *buf = NULL; size_t len = 0; char *brace; JVal *root;
    BOOL ok = FALSE;

    if (err && errcap) err[0] = 0;
    if (down) *down = 0; if (up) *up = 0; if (ping) *ping = 0;

    if (!yaspeed_path(exe, sizeof(exe))) {
        if (err) ml_strlcpy(err, "yaspeed.exe не найден (положи рядом с modlink.exe)", errcap);
        return FALSE;
    }

    /* per-call output file so a manual run and the daily sweep can't clash */
    snprintf(outpath, sizeof(outpath), "%s\\yaspeed_%llu.json",
             ml_dir_data(), (unsigned long long)GetTickCount64());

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    hout = CreateFileA(outpath, GENERIC_WRITE, FILE_SHARE_READ, &sa,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hout == INVALID_HANDLE_VALUE) {
        if (err) ml_strlcpy(err, "не удалось создать временный файл", errcap);
        return FALSE;
    }

    /* --json prints one clean JSON object to stdout; progress goes to stderr,
     * which we leave attached to nothing. CREATE_NO_WINDOW: no console flashes. */
    if (lan_ip && lan_ip[0])
        snprintf(cmd, sizeof(cmd),
                 "\"%s\" --json --duration 8 --threads 6 --source-ip %s", exe, lan_ip);
    else
        snprintf(cmd, sizeof(cmd), "\"%s\" --json --duration 8 --threads 6", exe);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hout;
    si.hStdError  = hout;
    si.hStdInput  = NULL;
    memset(&pi, 0, sizeof(pi));

    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(hout);
        DeleteFileA(outpath);
        if (err) snprintf(err, errcap, "не удалось запустить yaspeed (код %lu)", GetLastError());
        return FALSE;
    }

    wr = WaitForSingleObject(pi.hProcess, 120000);   /* 2 min hard cap */
    if (wr != WAIT_OBJECT_0) TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hout);

    if (ml_read_file(outpath, &buf, &len) && buf) {
        brace = strchr(buf, '{');
        root = brace ? json_parse(brace) : NULL;
        if (root) {
            double d = json_num(root, "download_mbps", -1);
            double u = json_num(root, "upload_mbps",   -1);
            double p = json_num(root, "ping_ms",       -1);
            if (d >= 0 || u >= 0) {
                if (down) *down = d < 0 ? 0 : d;
                if (up)   *up   = u < 0 ? 0 : u;
                if (ping) *ping = p < 0 ? 0 : p;
                ok = TRUE;
            }
            json_free(root);
        }
        free(buf);
    }
    DeleteFileA(outpath);

    if (!ok && err && !err[0])
        ml_strlcpy(err, wr != WAIT_OBJECT_0 ? "yaspeed завис (таймаут)" : "нет результата от yaspeed", errcap);
    return ok;
}

/* ------------------------------------------------------------- sweeps */
static void wan_sweep(const Config *c)
{
    int i;
    const char *proxy = c->lan_ip[0] ? c->lan_ip : "127.0.0.1";
    load_rows();
    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        HttpResp r;
        char ip[ML_ADDR_LEN] = {0};
        CheckRow *row;
        if (!m->enabled || !m->login[0] || !ml_port_valid(m->proxy_port)) continue;
        if (http_get_via_proxy("http://api.ipify.org", proxy, m->proxy_port,
                               m->login, m->pass, 9000, &r)
            && r.status == 200 && r.body) {
            const char *p = r.body; char *w = ip;
            while (*p == ' ' || *p == '\n' || *p == '\r') p++;
            while (*p && *p != '\n' && *p != '\r' &&
                   (size_t)(w - ip) < sizeof(ip) - 1) *w++ = *p++;
            *w = 0;
        }
        http_free(&r);
        if (!ml_is_ipv4(ip)) continue;
        row = row_for(m->id);
        if (!row) continue;
        ml_strlcpy(row->wan_ip, ip, sizeof(row->wan_ip));
        ts_now(row->wan_ts, sizeof(row->wan_ts));
    }
    save_rows();
    ml_log("checks: WAN sweep done");
}

static void speed_sweep(const Config *c)
{
    int i;
    load_rows();
    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        CheckRow *row;
        double d = 0, u = 0, p = 0;
        char err[96] = {0};
        BOOL ok;
        if (!m->enabled || !m->login[0]) continue;
        row = row_for(m->id);
        if (!row) continue;
        ok = checks_speedtest(m->lan_ip, &d, &u, &p, err, sizeof(err));
        ts_now(row->speed_ts, sizeof(row->speed_ts));
        if (ok) {
            row->down = d; row->up = u; row->ping = p;
            row->speed_err[0] = 0; row->have_speed = 1;
        } else {
            ml_strlcpy(row->speed_err, err, sizeof(row->speed_err));
        }
        save_rows();   /* persist as we go; a test is slow, don't lose earlier ones */
        if (!ok && !strncmp(err, "yaspeed.exe", 11)) break;  /* missing tool: stop */
    }
    ml_log("checks: speed sweep done");
}

/* A sweep can take minutes (a speed test per modem), so it runs on its own
 * thread — the worker's event loop and watchdog must stay responsive. Only one
 * sweep runs at a time; the config is snapshotted so a mid-sweep reload is safe. */
typedef struct { Config cfg; int do_wan, do_speed; } SweepJob;
static volatile LONG g_busy = 0;

static DWORD WINAPI sweep_thread(LPVOID arg)
{
    SweepJob *j = (SweepJob *)arg;
    if (j->do_wan)   wan_sweep(&j->cfg);
    if (j->do_speed) speed_sweep(&j->cfg);
    free(j);
    InterlockedExchange(&g_busy, 0);
    return 0;
}

/* Called by the worker each loop tick (~3s). Cheap unless a sweep is due, and
 * never blocks: the actual probing happens on sweep_thread. */
void checks_tick(const Config *c, int svc_up)
{
    ULONGLONG now = GetTickCount64();
    SYSTEMTIME st;
    int today, do_wan = 0, do_speed = 0;
    SweepJob *j;
    HANDLE h;

    if (!svc_up) return;                 /* nothing to probe while stopped */

    if (g_next_wan == 0) g_next_wan = now + 30000;   /* first sweep ~30s after start */
    if (now >= g_next_wan) do_wan = 1;

    GetLocalTime(&st);
    today = day_key(&st);
    if (st.wHour == 12 && g_speed_day != today) do_speed = 1;   /* noon, once a day */

    if (!do_wan && !do_speed) return;
    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return; /* one already runs; retry next tick */

    /* commit the schedule only now that we're actually starting the sweep */
    if (do_wan)   g_next_wan  = now + 3600000ULL;   /* hourly */
    if (do_speed) g_speed_day = today;

    j = (SweepJob *)malloc(sizeof(*j));
    if (!j) { InterlockedExchange(&g_busy, 0); return; }
    j->cfg = *c; j->do_wan = do_wan; j->do_speed = do_speed;
    h = CreateThread(NULL, 0, sweep_thread, j, 0, NULL);
    if (h) CloseHandle(h);
    else { free(j); InterlockedExchange(&g_busy, 0); }
}
