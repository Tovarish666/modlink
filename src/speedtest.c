/* modlink — native speed test (a C port of the user's yaspeed CLI).
 *
 * Same backend as yaspeed: Yandex Internetometer
 * (https://yandex.ru/internet/api/v0), which stays reachable in RU where the
 * Ookla Speedtest CLI is blocked. The flow mirrors yaspeed.py:
 *   1. GET /get-probes           -> JSON with latency / download / upload probes
 *   2. latency: ping the probes, pick the fastest host, average a few samples
 *   3. download: N threads GET the download probe for `duration`s, count bytes
 *   4. upload:   N threads POST random data for `duration`s, count bytes
 *   Mbit/s = bytes * 8 / 1e6 / seconds.
 *
 * The one deliberate difference from yaspeed: instead of binding a raw socket to
 * a source IP, every request is routed THROUGH the modem's own 3proxy port. The
 * proxy already pins that modem's LTE interface (parent extip per login), so the
 * number reflects exactly the path a client uses — and it needs no raw sockets,
 * reusing the same WinHTTP proxy+TLS plumbing as the rest of modlink.
 */
#include "common.h"
#include "json.h"
#include <winhttp.h>
#include <string.h>
#include <stdlib.h>

#define ST_UA L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " \
              L"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

#define ST_API   "https://yandex.ru/internet/api/v0"
#define ST_PAYLOAD_SZ  65536
#define ST_MAX_THREADS 16

static unsigned char g_payload[ST_PAYLOAD_SZ];
static LONG          g_payload_ready = 0;

static void payload_init(void)
{
    int i;
    if (InterlockedCompareExchange(&g_payload_ready, 1, 0) != 0) return;
    for (i = 0; i < ST_PAYLOAD_SZ; i++) g_payload[i] = (unsigned char)(rand() & 0xFF);
}

/* ------------------------------------------------------------- small helpers */
static void url_host(const char *url, char *out, size_t cap)
{
    const char *p = strstr(url, "://");
    size_t i = 0;
    p = p ? p + 3 : url;
    while (p[i] && p[i] != '/' && p[i] != ':' && i < cap - 1) { out[i] = p[i]; i++; }
    out[i] = 0;
}

/* append yaspeed's cache-buster: ?rid=<16 rand>&_=<ms> */
static void url_with_rid(const char *base, char *out, size_t cap)
{
    static const char al[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char rid[17];
    int i;
    char sep = strchr(base, '?') ? '&' : '?';
    for (i = 0; i < 16; i++) rid[i] = al[rand() % 36];
    rid[16] = 0;
    snprintf(out, cap, "%s%crid=%s&_=%llu", base, sep, rid,
             (unsigned long long)GetTickCount64());
}

/* ------------------------------------------------------------- worker ctx */
typedef struct {
    char  url[ML_URL_LEN];
    char  proxy[80];           /* "host:port" for WinHttpOpen NAMED_PROXY */
    char  login[ML_LOGIN_LEN];
    char  pass[ML_PASS_LEN];
    int   upload;              /* 0 = download, 1 = upload */
    DWORD up_size;             /* bytes to POST per request (upload)      */
    volatile LONG     running;
    volatile LONGLONG bytes;
} Ctx;

/* Open a WinHTTP session bound to the modem's proxy. */
static HINTERNET st_session(const Ctx *c)
{
    HINTERNET s;
    wchar_t *wp = ml_utf8_to_w(c->proxy);
    if (!wp) return NULL;
    s = WinHttpOpen(ST_UA, WINHTTP_ACCESS_TYPE_NAMED_PROXY, wp, WINHTTP_NO_PROXY_BYPASS, 0);
    free(wp);
    if (s) WinHttpSetTimeouts(s, 10000, 10000, 10000, 12000);
    return s;
}

/* Open a request on hCon for `rurl`; sets TLS-ignore + proxy Basic creds. */
static HINTERNET st_open_req(const Ctx *c, HINTERNET hCon, const wchar_t *path, BOOL secure)
{
    HINTERNET hReq = WinHttpOpenRequest(hCon, c->upload ? L"POST" : L"GET", path, NULL,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        secure ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) return NULL;
    if (secure) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }
    if (c->login[0]) {
        wchar_t *wu = ml_utf8_to_w(c->login), *wp = ml_utf8_to_w(c->pass);
        if (wu && wp)
            WinHttpSetCredentials(hReq, WINHTTP_AUTH_TARGET_PROXY,
                                  WINHTTP_AUTH_SCHEME_BASIC, wu, wp, NULL);
        free(wu); free(wp);
    }
    return hReq;
}

/* Crack rurl -> host/port/path/secure. Returns FALSE on a malformed URL. */
static BOOL st_crack(const char *rurl, wchar_t *host, size_t hostcap,
                     wchar_t *path, size_t pathcap, INTERNET_PORT *port, BOOL *secure)
{
    URL_COMPONENTS uc;
    wchar_t *w = ml_utf8_to_w(rurl);
    BOOL ok;
    if (!w) return FALSE;
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize   = sizeof(uc);
    uc.lpszHostName   = host; uc.dwHostNameLength = (DWORD)hostcap;
    uc.lpszUrlPath    = path; uc.dwUrlPathLength  = (DWORD)pathcap;
    ok = WinHttpCrackUrl(w, 0, 0, &uc);
    free(w);
    if (!ok) return FALSE;
    *port   = uc.nPort;
    *secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return TRUE;
}

static DWORD WINAPI worker(LPVOID arg)
{
    Ctx *c = (Ctx *)arg;
    HINTERNET hSes = st_session(c), hCon = NULL;
    wchar_t curhost[256] = {0};
    if (!hSes) return 0;

    while (InterlockedCompareExchange(&c->running, 1, 1)) {
        char rurl[ML_URL_LEN + 96];
        wchar_t host[256], path[2048];
        INTERNET_PORT port; BOOL secure;
        HINTERNET hReq;

        url_with_rid(c->url, rurl, sizeof(rurl));
        if (!st_crack(rurl, host, 256, path, 2048, &port, &secure)) { Sleep(100); continue; }
        if (!hCon || wcscmp(host, curhost) != 0) {
            if (hCon) WinHttpCloseHandle(hCon);
            hCon = WinHttpConnect(hSes, host, port, 0);
            wcsncpy(curhost, host, 255); curhost[255] = 0;
            if (!hCon) { Sleep(150); continue; }
        }

        hReq = st_open_req(c, hCon, path, secure);
        if (!hReq) { Sleep(100); continue; }

        if (c->upload) {
            /* POST up_size bytes; the CONNECT/407 proxy auth is settled during
             * SendRequest (tunnel layer) before we stream the body. */
            if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, c->up_size, 0)) {
                DWORD sent = 0;
                while (sent < c->up_size && InterlockedCompareExchange(&c->running, 1, 1)) {
                    DWORD chunk = c->up_size - sent;
                    DWORD wrote = 0;
                    if (chunk > ST_PAYLOAD_SZ) chunk = ST_PAYLOAD_SZ;
                    if (!WinHttpWriteData(hReq, g_payload, chunk, &wrote) || wrote == 0) break;
                    sent += wrote;
                    InterlockedExchangeAdd64(&c->bytes, (LONGLONG)wrote);
                }
                /* only drain the reply if we actually finished the body; on a
                 * stop we just abort (close below) instead of blocking on it */
                if (sent >= c->up_size) WinHttpReceiveResponse(hReq, NULL);
            }
        } else {
            if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hReq, NULL)) {
                DWORD avail, got;
                char buf[ST_PAYLOAD_SZ];
                while (InterlockedCompareExchange(&c->running, 1, 1)) {
                    if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
                    if (avail > sizeof(buf)) avail = sizeof(buf);
                    if (!WinHttpReadData(hReq, buf, avail, &got) || got == 0) break;
                    InterlockedExchangeAdd64(&c->bytes, (LONGLONG)got);
                }
            }
        }
        WinHttpCloseHandle(hReq);
    }

    if (hCon) WinHttpCloseHandle(hCon);
    WinHttpCloseHandle(hSes);
    return 0;
}

/* Run one phase for `duration_s`, return Mbit/s. Ctx is heap-owned and freed
 * only after every worker joins; on a (pathological) join timeout it is leaked
 * rather than freed, so a late thread can never touch freed memory. */
static double run_phase(int upload, const char *url, const char *proxy,
                        const char *login, const char *pass,
                        int threads, int duration_s, DWORD up_size)
{
    Ctx *c;
    HANDLE th[ST_MAX_THREADS];
    int n = threads, i, joined = 1;
    ULONGLONG start, el;
    double mbps;

    if (n < 1) n = 1;
    if (n > ST_MAX_THREADS) n = ST_MAX_THREADS;

    c = (Ctx *)calloc(1, sizeof(*c));
    if (!c) return 0.0;
    ml_strlcpy(c->url,   url,   sizeof(c->url));
    ml_strlcpy(c->proxy, proxy, sizeof(c->proxy));
    ml_strlcpy(c->login, login, sizeof(c->login));
    ml_strlcpy(c->pass,  pass,  sizeof(c->pass));
    c->upload = upload; c->up_size = up_size; c->running = 1; c->bytes = 0;

    start = GetTickCount64();
    for (i = 0; i < n; i++) th[i] = CreateThread(NULL, 0, worker, c, 0, NULL);

    while (GetTickCount64() - start < (ULONGLONG)duration_s * 1000) Sleep(100);
    InterlockedExchange(&c->running, 0);

    el = GetTickCount64() - start; if (el < 1) el = 1;
    for (i = 0; i < n; i++) {
        if (!th[i]) continue;
        if (WaitForSingleObject(th[i], 15000) == WAIT_OBJECT_0) CloseHandle(th[i]);
        else joined = 0;   /* a worker is still stuck in WinHTTP; do not free c */
    }

    mbps = (double)c->bytes * 8.0 / 1000.0 / (double)el;   /* bytes*8 / ms = Mbit/s */
    if (joined) free(c);
    return mbps;
}

/* ------------------------------------------------------------- latency */
static double ping_once(const char *base, const char *proxy_host, int pport,
                        const char *login, const char *pass)
{
    char rurl[ML_URL_LEN + 96];
    HttpResp r;
    LARGE_INTEGER f, a, b;
    double ms = -1;
    url_with_rid(base, rurl, sizeof(rurl));
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&a);
    if (http_get_via_proxy(rurl, proxy_host, pport, login, pass, 3000, &r) && r.status) {
        QueryPerformanceCounter(&b);
        ms = (double)(b.QuadPart - a.QuadPart) * 1000.0 / (double)f.QuadPart;
    }
    http_free(&r);
    return ms;
}

/* ------------------------------------------------------------- probe pick */
/* Choose a probe URL from config[section].probes: prefer one whose url contains
 * `strhint`, else one on `hosthint`, else the first. Fills *size when present. */
static BOOL pick_probe(const JVal *root, const char *section,
                       const char *hosthint, const char *strhint,
                       char *urlout, size_t cap, DWORD *sizeout)
{
    const JVal *sec = json_get(root, section), *arr, *it;
    const char *first = NULL, *hostm = NULL, *hintm = NULL;
    double firstsz = 0, hostsz = 0, hintsz = 0;
    if (!sec) return FALSE;
    arr = json_get(sec, "probes");
    if (!arr || arr->type != J_ARR) return FALSE;
    for (it = arr->child; it; it = it->next) {
        const char *u = json_str(it, "url", "");
        double sz = json_num(it, "size", 0);
        if (!u[0]) continue;
        if (!first) { first = u; firstsz = sz; }
        if (hosthint && hosthint[0] && !hostm && strstr(u, hosthint)) { hostm = u; hostsz = sz; }
        if (strhint  && strhint[0]  && !hintm && strstr(u, strhint))  { hintm = u; hintsz = sz; }
    }
    if (hintm)      { ml_strlcpy(urlout, hintm, cap); if (sizeout) *sizeout = (DWORD)hintsz; }
    else if (hostm) { ml_strlcpy(urlout, hostm, cap); if (sizeout) *sizeout = (DWORD)hostsz; }
    else if (first) { ml_strlcpy(urlout, first, cap); if (sizeout) *sizeout = (DWORD)firstsz; }
    else return FALSE;
    return TRUE;
}

/* ------------------------------------------------------------- orchestration */
BOOL speedtest_run(const char *proxy_host, int proxy_port,
                   const char *login, const char *pass,
                   int duration_s, int threads,
                   double *down, double *up, double *ping,
                   char *server, size_t servercap,
                   char *err, size_t errcap)
{
    char proxy[80], cfgurl[ML_URL_LEN], dlurl[ML_URL_LEN], ulurl[ML_URL_LEN];
    char host[256] = {0};
    HttpResp r;
    JVal *cfg = NULL;
    const JVal *lat, *arr, *it;
    DWORD ulsize = 52428800u;      /* yaspeed's default 50 MB upload target */
    double best = 1e18;
    const char *besturl = NULL;
    int i, nping;
    double psum = 0; int pn = 0;

    if (down) *down = 0; if (up) *up = 0; if (ping) *ping = 0;
    if (server && servercap) server[0] = 0;
    if (err && errcap) err[0] = 0;
    if (duration_s <= 0) duration_s = 8;
    if (threads   <= 0) threads   = 6;

    payload_init();
    if (!proxy_host || !proxy_host[0]) proxy_host = "127.0.0.1";
    snprintf(proxy, sizeof(proxy), "%s:%d", proxy_host, proxy_port);

    /* 1) probe config, fetched through the modem's proxy */
    snprintf(cfgurl, sizeof(cfgurl), "%s/get-probes?t=%llu",
             ST_API, (unsigned long long)GetTickCount64());
    if (!http_get_via_proxy(cfgurl, proxy_host, proxy_port, login, pass, 8000, &r) ||
        r.status != 200 || !r.body) {
        if (err) snprintf(err, errcap, "нет ответа от Яндекс-интернетометра%s%s",
                          r.err[0] ? ": " : "", r.err);
        http_free(&r);
        return FALSE;
    }
    cfg = json_parse(r.body);
    http_free(&r);
    if (!cfg) { if (err) ml_strlcpy(err, "не разобрать список серверов", errcap); return FALSE; }

    /* 2) latency: ping each probe once, keep the fastest host */
    lat = json_get(cfg, "latency");
    arr = lat ? json_get(lat, "probes") : NULL;
    if (arr && arr->type == J_ARR) {
        for (it = arr->child; it; it = it->next) {
            const char *u = json_str(it, "url", "");
            double ms;
            if (!u[0]) continue;
            ms = ping_once(u, proxy_host, proxy_port, login, pass);
            if (ms >= 0 && ms < best) { best = ms; besturl = u; }
        }
    }
    if (besturl) {
        url_host(besturl, host, sizeof(host));
        nping = 6;
        for (i = 0; i < nping; i++) {
            double ms = ping_once(besturl, proxy_host, proxy_port, login, pass);
            if (ms >= 0) { psum += ms; pn++; }
            Sleep(30);
        }
        if (pn && ping) *ping = psum / pn;
        if (server && servercap) ml_strlcpy(server, host, servercap);
    }

    /* 3) download */
    if (pick_probe(cfg, "download", host, "", dlurl, sizeof(dlurl), NULL)) {
        double m = run_phase(0, dlurl, proxy, login, pass, threads, duration_s, 0);
        if (down) *down = m;
    }

    /* 4) upload (prefer the 50 MB probe, like yaspeed) */
    if (pick_probe(cfg, "upload", host, "52428800", ulurl, sizeof(ulurl), &ulsize) ||
        pick_probe(cfg, "upload", host, "",         ulurl, sizeof(ulurl), &ulsize)) {
        double m;
        if (ulsize == 0) ulsize = 52428800u;
        m = run_phase(1, ulurl, proxy, login, pass, threads, duration_s, ulsize);
        if (up) *up = m;
    }

    json_free(cfg);

    if ((down && *down > 0) || (up && *up > 0)) return TRUE;
    if (err && !err[0]) ml_strlcpy(err, "не удалось измерить скорость", errcap);
    return FALSE;
}
