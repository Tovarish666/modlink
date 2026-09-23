/* modlink — control HTTP listeners (reconnect / reboot) and interval timers.
 *
 * A tiny HTTP server answers  GET /reconnect  and  GET /reboot  so anything
 * (a script, a client scheduler, curl) can force a new IP or reboot a modem.
 *
 * Two layouts are supported, and the listener figures out which modem a request
 * is for on its own:
 *   - mode 0 (port triples): each modem has its own reboot/reconnect ports, so
 *     the port alone identifies the modem — no auth needed.
 *   - mode 1 (one shared control port): many modems answer on one port, so the
 *     request must carry HTTP Basic auth (login:pass) and, like 3proxy, the
 *     login picks the modem.
 * A listener therefore owns a PORT and resolves the modem from a config
 * snapshot by auth, falling back to the sole modem on that port when unique.
 */
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    int      port;
    SOCKET   sock;
    HANDLE   thread;
    volatile LONG stop;
} Listener;

typedef struct {
    int      modem_id;
    int      interval_min;
    char     modem_ip[ML_ADDR_LEN];
    char     login[ML_LOGIN_LEN];
    HANDLE   thread;
    HANDLE   wake;
    volatile LONG stop;
} Timer;

/* Heap-allocated so a running thread's arg pointer stays valid across a rebuild
 * (it must never point into rebuild's local array). */
static Listener *g_lis[ML_MAX_MODEMS];
static Timer    *g_tim[ML_MAX_MODEMS];
static int      g_nlis = 0, g_ntim = 0;

/* config snapshot the listeners resolve against, guarded on its own so a slow
 * request can never block reconn_rebuild joining threads. */
static Modem    g_snap[ML_MAX_MODEMS];
static int      g_nsnap = 0;
static CRITICAL_SECTION g_cs, g_snap_cs;
static BOOL     g_ready = FALSE;

static void rc_init(void)
{
    if (!g_ready) {
        InitializeCriticalSection(&g_cs);
        InitializeCriticalSection(&g_snap_cs);
        g_ready = TRUE;
    }
}

/* ------------------------------------------------------------- log */
static void log_path(int modem_id, char *out, size_t cap)
{
    snprintf(out, cap, "%s\\modem%d_reconnect.txt", ml_dir_logs(), modem_id);
}

void reconn_log_append(int modem_id, const char *line)
{
    char path[ML_PATH_LEN];
    HANDLE h;
    DWORD wrote = 0;
    char buf[1024];
    SYSTEMTIME st, stu;

    ml_ensure_dirs();
    log_path(modem_id, path, sizeof(path));
    {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad) &&
            fad.nFileSizeLow > 5u * 1024u * 1024u) {
            char old[ML_PATH_LEN];
            snprintf(old, sizeof(old), "%s.1", path);
            MoveFileExA(path, old, MOVEFILE_REPLACE_EXISTING);
        }
    }
    GetSystemTime(&stu);
    GetLocalTime(&st);
    snprintf(buf, sizeof(buf),
             "%04d-%02d-%02dT%02d:%02d:%02dZ | %04d-%02d-%02d %02d:%02d:%02d | %s\r\n",
             stu.wYear, stu.wMonth, stu.wDay, stu.wHour, stu.wMinute, stu.wSecond,
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, line);
    h = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    WriteFile(h, buf, (DWORD)strlen(buf), &wrote, NULL);
    CloseHandle(h);
}

int reconn_log_read(int modem_id, int max_lines, char ***out)
{
    char path[ML_PATH_LEN];
    log_path(modem_id, path, sizeof(path));
    return ml_tail_file(path, max_lines, out);
}

static BOOL do_reconnect(int modem_id, const char *ip, const char *login,
                         const char *source, char *msg, size_t msgcap, double *secs)
{
    BOOL ok;
    char line[512];
    double dt = 0;
    ok = hilink_reconnect(ip, msg, msgcap, &dt);
    if (secs) *secs = dt;
    snprintf(line, sizeof(line), "%s | %s | %.2fs | %s | %s",
             login && login[0] ? login : "modem", source, dt,
             ok ? "ok" : "fail", msg ? msg : "");
    reconn_log_append(modem_id, line);
    return ok;
}

/* ------------------------------------------------------------- http bits */
static void send_all(SOCKET s, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = send(s, buf + sent, len - sent, 0);
        if (n <= 0) break;
        sent += n;
    }
}

static int b64val(int c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}
static int b64decode(const char *in, char *out, int outcap)
{
    int val = 0, bits = 0, n = 0;
    for (; *in && *in != '\r' && *in != '\n' && *in != ' '; in++) {
        int v;
        if (*in == '=') break;
        v = b64val((unsigned char)*in);
        if (v < 0) continue;
        val = (val << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; if (n < outcap - 1) out[n++] = (char)((val >> bits) & 0xFF); }
    }
    out[n] = 0;
    return n;
}

/* Pull login:pass out of an "Authorization: Basic <b64>" request header. */
static BOOL parse_auth(const char *req, char *login, size_t lcap, char *pass, size_t pcap)
{
    const char *p = strstr(req, "Authorization: Basic ");
    char dec[256], *colon;
    if (!p) p = strstr(req, "authorization: basic ");
    if (!p) return FALSE;
    p += 21;                                  /* len("Authorization: Basic ") */
    b64decode(p, dec, sizeof(dec));
    colon = strchr(dec, ':');
    if (!colon) return FALSE;
    *colon = 0;
    ml_strlcpy(login, dec, lcap);
    ml_strlcpy(pass, colon + 1, pcap);
    return TRUE;
}

/* Resolve which modem a request on `port` targets. action: 0=reconnect,
 * 1=reboot. Copies the modem out under the snapshot lock. Returns TRUE on a
 * match, and sets *need_auth when the port is ambiguous and no valid creds were
 * given (so the caller can answer 401). */
static BOOL resolve_modem(int port, int action, const char *login, const char *pass,
                          BOOL have_auth, Modem *out, BOOL *need_auth)
{
    int i, cand = -1, ncand = 0;
    BOOL ok = FALSE;
    if (need_auth) *need_auth = FALSE;
    EnterCriticalSection(&g_snap_cs);
    for (i = 0; i < g_nsnap; i++) {
        const Modem *m = &g_snap[i];
        int cport;
        if (!m->enabled) continue;
        cport = action ? m->reboot_port : m->reconn_port;
        if (cport != port) continue;
        ncand++; cand = i;
        if (have_auth && !strcmp(m->login, login) && !strcmp(m->pass, pass)) {
            *out = *m; ok = TRUE; break;
        }
    }
    if (!ok) {
        if (!have_auth && ncand == 1) { *out = g_snap[cand]; ok = TRUE; }
        else if (need_auth && ncand > 0) *need_auth = TRUE;   /* creds needed/ wrong */
    }
    LeaveCriticalSection(&g_snap_cs);
    return ok;
}

static void reply_json(SOCKET c, BOOL ok, const char *body)
{
    char resp[1024];
    snprintf(resp, sizeof(resp),
             "HTTP/1.1 %s\r\nContent-Type: application/json\r\n"
             "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
             ok ? "200 OK" : "500 Internal Server Error", (int)strlen(body), body);
    send_all(c, resp, (int)strlen(resp));
}

static DWORD WINAPI listener_thread(LPVOID arg)
{
    Listener *L = (Listener *)arg;
    for (;;) {
        SOCKET c;
        char req[2048];
        int  n, action = -1;
        char login[ML_LOGIN_LEN] = {0}, pass[ML_PASS_LEN] = {0};
        BOOL have_auth, need_auth = FALSE;
        Modem m;

        c = accept(L->sock, NULL, NULL);
        if (InterlockedCompareExchange(&L->stop, 0, 0)) { if (c != INVALID_SOCKET) closesocket(c); break; }
        if (c == INVALID_SOCKET) continue;
        { DWORD tv = 5000; setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv)); }

        n = recv(c, req, sizeof(req) - 1, 0);
        if (n <= 0) { closesocket(c); continue; }
        req[n] = 0;

        if      (!strncmp(req, "GET /reconnect", 14)) action = 0;
        else if (!strncmp(req, "GET /reboot",    11)) action = 1;
        if (action < 0) {
            static const char R404[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send_all(c, R404, (int)sizeof(R404) - 1); closesocket(c); continue;
        }

        have_auth = parse_auth(req, login, sizeof(login), pass, sizeof(pass));
        if (!resolve_modem(L->port, action, login, pass, have_auth, &m, &need_auth)) {
            if (need_auth) {
                static const char R401[] =
                    "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"modlink\"\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n";
                send_all(c, R401, (int)sizeof(R401) - 1);
            } else {
                static const char R404[] = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                send_all(c, R404, (int)sizeof(R404) - 1);
            }
            closesocket(c); continue;
        }

        if (action == 0) {
            char msg[256] = {0}, body[512];
            double dt = 0;
            BOOL ok = do_reconnect(m.id, m.modem_ip, m.login, "url", msg, sizeof(msg), &dt);
            snprintf(body, sizeof(body), "{\"ok\":%s,\"msg\":\"%s\",\"dt\":%.2f}",
                     ok ? "true" : "false", msg, dt);
            reply_json(c, ok, body);
        } else {
            char msg[256] = {0}, body[512];
            BOOL ok = hilink_reboot(m.modem_ip, msg, sizeof(msg));
            reconn_log_append(m.id, ok ? "reboot (url) отправлен" : "reboot (url) ошибка");
            snprintf(body, sizeof(body), "{\"ok\":%s,\"msg\":\"%s\"}", ok ? "true" : "false", msg);
            reply_json(c, ok, body);
        }
        closesocket(c);
    }
    return 0;
}

static BOOL listener_start(Listener *L)
{
    struct sockaddr_in a;
    BOOL exclusive = TRUE;
    L->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (L->sock == INVALID_SOCKET) return FALSE;
    setsockopt(L->sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&exclusive, sizeof(exclusive));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((u_short)L->port);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(L->sock, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(L->sock, 16) != 0) {
        ml_log("control listener: port %d unavailable (err %d)", L->port, WSAGetLastError());
        closesocket(L->sock); L->sock = INVALID_SOCKET; return FALSE;
    }
    L->stop = 0;
    L->thread = CreateThread(NULL, 0, listener_thread, L, 0, NULL);
    if (!L->thread) { closesocket(L->sock); L->sock = INVALID_SOCKET; return FALSE; }
    ml_log("control listener up on :%d", L->port);
    return TRUE;
}

static void listener_stop(Listener *L)
{
    if (!L->thread) return;
    InterlockedExchange(&L->stop, 1);
    if (L->sock != INVALID_SOCKET) { closesocket(L->sock); L->sock = INVALID_SOCKET; }
    WaitForSingleObject(L->thread, 3000);
    CloseHandle(L->thread);
    L->thread = NULL;
}

/* ------------------------------------------------------------- timer */
static DWORD WINAPI timer_thread(LPVOID arg)
{
    Timer *T = (Timer *)arg;
    DWORD period = (DWORD)T->interval_min * 60u * 1000u;
    for (;;) {
        char msg[256] = {0};
        if (WaitForSingleObject(T->wake, period) == WAIT_OBJECT_0) break;
        if (InterlockedCompareExchange(&T->stop, 0, 0)) break;
        do_reconnect(T->modem_id, T->modem_ip, T->login, "auto", msg, sizeof(msg), NULL);
    }
    return 0;
}
static BOOL timer_start(Timer *T)
{
    T->stop = 0;
    T->wake = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!T->wake) return FALSE;
    T->thread = CreateThread(NULL, 0, timer_thread, T, 0, NULL);
    if (!T->thread) { CloseHandle(T->wake); T->wake = NULL; return FALSE; }
    ml_log("auto-reconnect timer: %s every %d min", T->login, T->interval_min);
    return TRUE;
}
static void timer_stop(Timer *T)
{
    if (!T->thread) return;
    InterlockedExchange(&T->stop, 1);
    if (T->wake) SetEvent(T->wake);
    WaitForSingleObject(T->thread, 5000);
    CloseHandle(T->thread);
    if (T->wake) CloseHandle(T->wake);
    T->thread = NULL; T->wake = NULL;
}

/* ------------------------------------------------------------- rebuild */
/* Listeners and timers are heap-allocated: a running thread's arg is the very
 * pointer we keep in g_lis[]/g_tim[], so it can never dangle into a caller's
 * local array across a rebuild. keep_* collect the survivors; whatever is left
 * in g_* after the sweep is stopped (joined) and freed. */
BOOL reconn_rebuild(const Config *c)
{
    Listener *keep_l[ML_MAX_MODEMS];
    Timer    *keep_t[ML_MAX_MODEMS];
    int nl = 0, nt = 0, i, j;

    rc_init();
    ml_ensure_dirs();

    /* refresh the resolution snapshot first (brief, own lock) */
    EnterCriticalSection(&g_snap_cs);
    g_nsnap = c->count;
    if (c->count) memcpy(g_snap, c->modems, sizeof(Modem) * (size_t)c->count);
    LeaveCriticalSection(&g_snap_cs);

    EnterCriticalSection(&g_cs);

    /* --- one listener per distinct control port (reconnect and/or reboot) --- */
    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        int ports[2], pi;
        if (!m->enabled) continue;
        ports[0] = m->reconn_port; ports[1] = m->reboot_port;
        for (pi = 0; pi < 2; pi++) {
            int port = ports[pi], found = -1, dup = 0, k;
            if (!ml_port_valid(port)) continue;
            for (k = 0; k < nl; k++) if (keep_l[k]->port == port) { dup = 1; break; }
            if (dup) continue;                    /* already carried this port */
            for (j = 0; j < g_nlis; j++)
                if (g_lis[j] && g_lis[j]->port == port) { found = j; break; }
            if (found >= 0) {
                keep_l[nl++] = g_lis[found];       /* carry the live listener   */
                g_lis[found] = NULL;               /* so the sweep skips it     */
            } else {
                Listener *L = (Listener *)calloc(1, sizeof(*L));
                if (!L) continue;
                L->port = port;
                L->sock = INVALID_SOCKET;
                if (listener_start(L)) keep_l[nl++] = L;
                else free(L);
            }
        }
    }
    for (j = 0; j < g_nlis; j++)                   /* drop stale ports */
        if (g_lis[j]) { listener_stop(g_lis[j]); free(g_lis[j]); }
    for (j = 0; j < nl; j++) g_lis[j] = keep_l[j];
    g_nlis = nl;

    /* --- timers (per-modem interval reconnect) --- */
    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        int found = -1;
        if (!m->enabled || m->interval_min <= 0) continue;
        for (j = 0; j < g_ntim; j++) {
            Timer *T = g_tim[j];
            if (T && T->modem_id == m->id && T->interval_min == m->interval_min &&
                !strcmp(T->modem_ip, m->modem_ip) && !strcmp(T->login, m->login)) { found = j; break; }
        }
        if (found >= 0) { keep_t[nt++] = g_tim[found]; g_tim[found] = NULL; }
        else {
            Timer *T = (Timer *)calloc(1, sizeof(*T));
            if (!T) continue;
            T->modem_id = m->id;
            T->interval_min = m->interval_min;
            ml_strlcpy(T->modem_ip, m->modem_ip, sizeof(T->modem_ip));
            ml_strlcpy(T->login, m->login, sizeof(T->login));
            if (timer_start(T)) keep_t[nt++] = T;
            else free(T);
        }
    }
    for (j = 0; j < g_ntim; j++)
        if (g_tim[j]) { timer_stop(g_tim[j]); free(g_tim[j]); }
    for (j = 0; j < nt; j++) g_tim[j] = keep_t[j];
    g_ntim = nt;

    LeaveCriticalSection(&g_cs);
    ml_log("control: %d listeners, %d timers active", nl, nt);
    return TRUE;
}

void reconn_shutdown(void)
{
    int i;
    if (!g_ready) return;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_nlis; i++) if (g_lis[i]) { listener_stop(g_lis[i]); free(g_lis[i]); g_lis[i] = NULL; }
    for (i = 0; i < g_ntim; i++) if (g_tim[i]) { timer_stop(g_tim[i]);    free(g_tim[i]); g_tim[i] = NULL; }
    g_nlis = g_ntim = 0;
    LeaveCriticalSection(&g_cs);
    EnterCriticalSection(&g_snap_cs);
    g_nsnap = 0;
    LeaveCriticalSection(&g_snap_cs);
}
