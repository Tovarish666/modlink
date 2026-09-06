/* modlink — paths, logging, strings, small file helpers. */
#include "common.h"
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <shlobj.h>
#include <ws2tcpip.h>

/* ------------------------------------------------------------------ paths */
/* Built once on first use. Not thread-safe on the very first call, so the UI
 * thread touches these during startup before any worker thread exists. */
static char g_data[ML_PATH_LEN];
static char g_bin [ML_PATH_LEN];
static char g_logs[ML_PATH_LEN];
static char g_cfg [ML_PATH_LEN];
static char g_3cfg[ML_PATH_LEN];
static char g_3exe[ML_PATH_LEN];
static char g_3log[ML_PATH_LEN];
static char g_applog[ML_PATH_LEN];
static BOOL g_paths_ready = FALSE;

static void paths_init(void)
{
    char base[ML_PATH_LEN];
    if (g_paths_ready) return;

    /* %ProgramData%\modlink — survives per-user reinstalls and is where a
     * service-mode run would look too. Falls back to %LOCALAPPDATA% when
     * ProgramData is not writable (non-admin install). */
    if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_COMMON_APPDATA, NULL, 0, base)))
        if (!SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, base)))
            ml_strlcpy(base, "C:\\ProgramData", sizeof(base));

    snprintf(g_data,   sizeof(g_data),   "%s\\modlink", base);
    snprintf(g_bin,    sizeof(g_bin),    "%s\\bin",       g_data);
    snprintf(g_logs,   sizeof(g_logs),   "%s\\logs",      g_data);
    snprintf(g_cfg,    sizeof(g_cfg),    "%s\\config.json", g_data);
    snprintf(g_3cfg,   sizeof(g_3cfg),   "%s\\3proxy.cfg",  g_data);
    snprintf(g_3exe,   sizeof(g_3exe),   "%s\\3proxy.exe",  g_bin);
    snprintf(g_3log,   sizeof(g_3log),   "%s\\3proxy.log",  g_logs);
    snprintf(g_applog, sizeof(g_applog), "%s\\modlink.log", g_logs);
    g_paths_ready = TRUE;
}

const char *ml_dir_data(void)    { paths_init(); return g_data; }
const char *ml_dir_bin(void)     { paths_init(); return g_bin;  }
const char *ml_dir_logs(void)    { paths_init(); return g_logs; }
const char *ml_path_config(void) { paths_init(); return g_cfg;  }
const char *ml_path_3pcfg(void)  { paths_init(); return g_3cfg; }
const char *ml_path_3pexe(void)  { paths_init(); return g_3exe; }
const char *ml_path_3plog(void)  { paths_init(); return g_3log; }

BOOL ml_ensure_dirs(void)
{
    paths_init();
    CreateDirectoryA(g_data, NULL);
    CreateDirectoryA(g_bin,  NULL);
    CreateDirectoryA(g_logs, NULL);
    return GetFileAttributesA(g_data) != INVALID_FILE_ATTRIBUTES;
}

/* ------------------------------------------------------------------ log */
static CRITICAL_SECTION g_log_cs;
static BOOL g_log_cs_ready = FALSE;

void ml_log(const char *fmt, ...)
{
    va_list ap;
    SYSTEMTIME st;
    FILE *f;
    char line[2048];
    int n;

    if (!g_log_cs_ready) { InitializeCriticalSection(&g_log_cs); g_log_cs_ready = TRUE; }
    paths_init();

    GetLocalTime(&st);
    n = snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d  ",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof(line) - (size_t)n - 2, fmt, ap);
    va_end(ap);

    EnterCriticalSection(&g_log_cs);
    f = fopen(g_applog, "a");
    if (f) { fprintf(f, "%s\n", line); fclose(f); }
    LeaveCriticalSection(&g_log_cs);
}

/* ------------------------------------------------------------------ str */
char *ml_strlcpy(char *dst, const char *src, size_t cap)
{
    size_t i = 0;
    if (!dst || cap == 0) return dst;
    if (src) for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = 0;
    return dst;
}

BOOL ml_is_ipv4(const char *s)
{
    int parts = 0, val, digits;
    if (!s || !*s) return FALSE;
    while (*s) {
        if (*s < '0' || *s > '9') return FALSE;
        val = 0; digits = 0;
        while (*s >= '0' && *s <= '9') {
            val = val * 10 + (*s - '0');
            if (++digits > 3) return FALSE;
            s++;
        }
        if (val > 255) return FALSE;
        parts++;
        if (*s == '.') { s++; if (!*s) return FALSE; }
        else if (*s)   return FALSE;
    }
    return parts == 4;
}

BOOL ml_port_valid(int p) { return p >= 1 && p <= 65535; }

void ml_rand_pass(char *out, size_t cap, int len)
{
    /* Same alphabet as the Python panel: no look-alike glyphs (0/o, 1/l/i). */
    static const char A[] = "abcdefghjkmnpqrstuvwxyz23456789";
    static LONG seeded = 0;
    int i;
    if (InterlockedExchange(&seeded, 1) == 0)
        srand((unsigned)(GetTickCount() ^ GetCurrentThreadId()));
    if (len <= 0 || (size_t)len + 1 > cap) len = (int)cap - 1;
    for (i = 0; i < len; i++) out[i] = A[rand() % (int)(sizeof(A) - 1)];
    out[len] = 0;
}

wchar_t *ml_utf8_to_w(const char *s)
{
    int n;
    wchar_t *w;
    if (!s) return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0) return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

char *ml_w_to_utf8(const wchar_t *s)
{
    int n;
    char *a;
    if (!s) return NULL;
    n = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    a = (char *)malloc((size_t)n);
    if (!a) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, s, -1, a, n, NULL, NULL);
    return a;
}

/* ------------------------------------------------------------------ files */
BOOL ml_read_file(const char *path, char **out, size_t *len)
{
    HANDLE h;
    DWORD sz, got = 0;
    char *buf;

    *out = NULL; if (len) *len = 0;
    h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;

    sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > 64u * 1024u * 1024u) { CloseHandle(h); return FALSE; }

    buf = (char *)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return FALSE; }
    if (!ReadFile(h, buf, sz, &got, NULL)) { free(buf); CloseHandle(h); return FALSE; }
    CloseHandle(h);

    buf[got] = 0;
    *out = buf;
    if (len) *len = got;
    return TRUE;
}

/* Write to a sibling .tmp then MoveFileEx over the target, so a crash or a
 * power cut can never leave a half-written config.json behind. */
BOOL ml_write_file_atomic(const char *path, const char *data, size_t len)
{
    char tmp[ML_PATH_LEN];
    HANDLE h;
    DWORD wrote = 0;

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    h = CreateFileA(tmp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    if (!WriteFile(h, data, (DWORD)len, &wrote, NULL) || wrote != (DWORD)len) {
        CloseHandle(h); DeleteFileA(tmp); return FALSE;
    }
    FlushFileBuffers(h);
    CloseHandle(h);

    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileA(tmp);
        return FALSE;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ net util */
void ml_detect_lan_ip(char *out, size_t cap)
{
    /* Same trick as the Python version: a UDP socket "connected" to a public
     * address picks the outbound interface without sending a packet. */
    SOCKET s;
    struct sockaddr_in to, me;
    int melen = (int)sizeof(me);

    ml_strlcpy(out, "127.0.0.1", cap);
    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return;

    memset(&to, 0, sizeof(to));
    to.sin_family = AF_INET;
    to.sin_port   = htons(53);
    to.sin_addr.s_addr = inet_addr("8.8.8.8");

    if (connect(s, (struct sockaddr *)&to, sizeof(to)) == 0 &&
        getsockname(s, (struct sockaddr *)&me, &melen) == 0) {
        const char *p = inet_ntoa(me.sin_addr);
        if (p) ml_strlcpy(out, p, cap);
    }
    closesocket(s);
}

/* ------------------------------------------------------------------ tail */
int ml_tail_file(const char *path, int max_lines, char ***out_lines)
{
    char *buf = NULL, **lines = NULL, *p;
    size_t len = 0;
    int total = 0, keep, i, k;

    *out_lines = NULL;
    if (!ml_read_file(path, &buf, &len) || !buf) return 0;

    for (p = buf; *p; p++) if (*p == '\n') total++;
    if (len && buf[len - 1] != '\n') total++;
    if (total == 0) { free(buf); return 0; }

    keep = total < max_lines ? total : max_lines;
    lines = (char **)calloc((size_t)keep, sizeof(char *));
    if (!lines) { free(buf); return 0; }

    /* Walk once, keeping only the last `keep` lines. */
    k = 0; i = 0;
    p = buf;
    while (*p) {
        char *start = p;
        char *nl = strchr(p, '\n');
        size_t n;
        if (nl) { n = (size_t)(nl - start); p = nl + 1; }
        else    { n = strlen(start);        p = start + n; }
        if (n && start[n - 1] == '\r') n--;
        if (i >= total - keep) {
            char *s = (char *)malloc(n + 1);
            if (s) { memcpy(s, start, n); s[n] = 0; lines[k++] = s; }
        }
        i++;
    }
    free(buf);
    *out_lines = lines;
    return k;
}

void ml_free_lines(char **lines, int n)
{
    int i;
    if (!lines) return;
    for (i = 0; i < n; i++) free(lines[i]);
    free(lines);
}
