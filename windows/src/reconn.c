/* modlink — per-modem reconnect listeners and interval timers.
 *
 * Each modem gets:
 *   - a tiny HTTP listener on its reconnect port answering GET /reconnect,
 *     so anything (a script, a client-side scheduler, curl) can force a new IP;
 *   - an optional timer thread that fires the same reconnect every N minutes.
 *
 * rebuild() diffs the running set against the config and only touches what
 * actually changed, so pressing Apply does not interrupt modems whose settings
 * were left alone. */
#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    int      modem_id;
    int      port;
    char     modem_ip[ML_ADDR_LEN];
    char     login[ML_LOGIN_LEN];
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
    HANDLE   wake;          /* signalled to cut a sleep short on shutdown */
    volatile LONG stop;
} Timer;

static Listener g_lis[ML_MAX_MODEMS];
static Timer    g_tim[ML_MAX_MODEMS];
static int      g_nlis = 0, g_ntim = 0;
static CRITICAL_SECTION g_cs;
static BOOL     g_ready = FALSE;

static void rc_init(void)
{
    if (!g_ready) { InitializeCriticalSection(&g_cs); g_ready = TRUE; }
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

    /* Roll at 5 MB so a modem stuck in a reconnect loop cannot fill the disk. */
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

/* Shared by the URL trigger, the timer and the UI button. */
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

/* ------------------------------------------------------------- listener */
static void send_all(SOCKET s, const char *buf, int len)
{
    int sent = 0;
    while (sent < len) {
        int n = send(s, buf + sent, len - sent, 0);
        if (n <= 0) break;
        sent += n;
    }
}

static DWORD WINAPI listener_thread(LPVOID arg)
{
    Listener *L = (Listener *)arg;

    for (;;) {
        SOCKET c;
        char req[2048];
        int  n;

        c = accept(L->sock, NULL, NULL);
        if (InterlockedCompareExchange(&L->stop, 0, 0)) {
            if (c != INVALID_SOCKET) closesocket(c);
            break;
        }
        if (c == INVALID_SOCKET) continue;

        {   /* 5 s is plenty for a request line from a local trigger */
            DWORD tv = 5000;
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        }

        n = recv(c, req, sizeof(req) - 1, 0);
        if (n <= 0) { closesocket(c); continue; }
        req[n] = 0;

        if (!strncmp(req, "GET /reconnect", 14)) {
            char msg[256] = {0}, body[512], resp[1024];
            double dt = 0;
            BOOL ok = do_reconnect(L->modem_id, L->modem_ip, L->login,
                                   "url-trigger", msg, sizeof(msg), &dt);

            snprintf(body, sizeof(body),
                     "{\"ok\":%s,\"msg\":\"%s\",\"dt\":%.2f}",
                     ok ? "true" : "false", msg, dt);
            snprintf(resp, sizeof(resp),
                     "HTTP/1.1 %s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n\r\n%s",
                     ok ? "200 OK" : "500 Internal Server Error",
                     (int)strlen(body), body);
            send_all(c, resp, (int)strlen(resp));
        } else {
            static const char R404[] =
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send_all(c, R404, (int)sizeof(R404) - 1);
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

    /* Without SO_EXCLUSIVEADDRUSE another process could bind the same port on
     * Windows and silently steal the reconnect trigger. */
    setsockopt(L->sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
               (const char *)&exclusive, sizeof(exclusive));

    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_port        = htons((u_short)L->port);
    a.sin_addr.s_addr = INADDR_ANY;

    if (bind(L->sock, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        listen(L->sock, 8) != 0) {
        ml_log("reconnect listener: port %d unavailable (err %d)", L->port, WSAGetLastError());
        closesocket(L->sock);
        L->sock = INVALID_SOCKET;
        return FALSE;
    }

    L->stop   = 0;
    L->thread = CreateThread(NULL, 0, listener_thread, L, 0, NULL);
    if (!L->thread) { closesocket(L->sock); L->sock = INVALID_SOCKET; return FALSE; }

    ml_log("reconnect listener up: %s on :%d", L->login, L->port);
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
    T->thread = NULL;
    T->wake   = NULL;
}

/* ------------------------------------------------------------- rebuild */
BOOL reconn_rebuild(const Config *c)
{
    Listener keep_l[ML_MAX_MODEMS];
    Timer    keep_t[ML_MAX_MODEMS];
    int nl = 0, nt = 0, i, j;

    rc_init();
    ml_ensure_dirs();
    EnterCriticalSection(&g_cs);

    memset(keep_l, 0, sizeof(keep_l));
    memset(keep_t, 0, sizeof(keep_t));

    /* --- listeners --- */
    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        int found = -1;
        if (!m->enabled || !ml_port_valid(m->reconn_port)) continue;

        for (j = 0; j < g_nlis; j++) {
            Listener *L = &g_lis[j];
            if (L->thread && L->modem_id == m->id && L->port == m->reconn_port &&
                !strcmp(L->modem_ip, m->modem_ip) && !strcmp(L->login, m->login)) {
                found = j; break;
            }
        }
        if (found >= 0) {
            keep_l[nl++] = g_lis[found];          /* carry the live one over */
            g_lis[found].thread = NULL;           /* so the sweep skips it   */
        } else {
            Listener *L = &keep_l[nl];
            memset(L, 0, sizeof(*L));
            L->modem_id = m->id;
            L->port     = m->reconn_port;
            L->sock     = INVALID_SOCKET;
            ml_strlcpy(L->modem_ip, m->modem_ip, sizeof(L->modem_ip));
            ml_strlcpy(L->login,    m->login,    sizeof(L->login));
            if (listener_start(L)) nl++;
        }
    }
    for (j = 0; j < g_nlis; j++) listener_stop(&g_lis[j]);   /* drop the rest */
    memcpy(g_lis, keep_l, sizeof(g_lis));
    g_nlis = nl;

    /* --- timers --- */
    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        int found = -1;
        if (!m->enabled || m->interval_min <= 0) continue;

        for (j = 0; j < g_ntim; j++) {
            Timer *T = &g_tim[j];
            if (T->thread && T->modem_id == m->id && T->interval_min == m->interval_min &&
                !strcmp(T->modem_ip, m->modem_ip) && !strcmp(T->login, m->login)) {
                found = j; break;
            }
        }
        if (found >= 0) {
            keep_t[nt++] = g_tim[found];
            g_tim[found].thread = NULL;
        } else {
            Timer *T = &keep_t[nt];
            memset(T, 0, sizeof(*T));
            T->modem_id     = m->id;
            T->interval_min = m->interval_min;
            ml_strlcpy(T->modem_ip, m->modem_ip, sizeof(T->modem_ip));
            ml_strlcpy(T->login,    m->login,    sizeof(T->login));
            if (timer_start(T)) nt++;
        }
    }
    for (j = 0; j < g_ntim; j++) timer_stop(&g_tim[j]);
    memcpy(g_tim, keep_t, sizeof(g_tim));
    g_ntim = nt;

    LeaveCriticalSection(&g_cs);
    ml_log("reconnect: %d listeners, %d timers active", nl, nt);
    return TRUE;
}

void reconn_shutdown(void)
{
    int i;
    if (!g_ready) return;
    EnterCriticalSection(&g_cs);
    for (i = 0; i < g_nlis; i++) listener_stop(&g_lis[i]);
    for (i = 0; i < g_ntim; i++) timer_stop(&g_tim[i]);
    g_nlis = g_ntim = 0;
    LeaveCriticalSection(&g_cs);
}
