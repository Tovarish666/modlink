/* modlink — HTTP client on WinHTTP.
 *
 * WinHTTP speaks TLS and HTTP-CONNECT proxying natively, so nothing here needs
 * OpenSSL, a bundled CA store, or the curl.exe subprocess the Python panel
 * shelled out to for its Test button. */
#include "common.h"
#include <winhttp.h>
#include <string.h>
#include <stdlib.h>

#define UA L"modlink/2.0"

void http_free(HttpResp *r)
{
    if (!r) return;
    free(r->body);
    r->body = NULL;
    r->len  = 0;
}

/* Reads the whole response body. Capped so a misbehaving endpoint (or a captive
 * portal serving a huge page) cannot exhaust memory. */
static BOOL read_body(HINTERNET hReq, HttpResp *out)
{
    char  *buf = NULL;
    size_t cap = 8192, len = 0;
    DWORD  avail = 0, got = 0;

    buf = (char *)malloc(cap);
    if (!buf) return FALSE;

    for (;;) {
        if (!WinHttpQueryDataAvailable(hReq, &avail)) break;
        if (avail == 0) break;
        if (len + avail + 1 > cap) {
            size_t ncap = cap;
            char *nb;
            while (ncap < len + avail + 1) ncap *= 2;
            if (ncap > 8u * 1024u * 1024u) break;
            nb = (char *)realloc(buf, ncap);
            if (!nb) break;
            buf = nb; cap = ncap;
        }
        if (!WinHttpReadData(hReq, buf + len, avail, &got) || got == 0) break;
        len += got;
    }

    buf[len]  = 0;
    out->body = buf;
    out->len  = len;
    return TRUE;
}

/* Core request. proxy_host==NULL means direct. */
static BOOL do_request(const char *url, const char *verb, const char *body,
                       const char *const *hdrs, int nhdrs,
                       const char *proxy_host, int proxy_port,
                       const char *puser, const char *ppass,
                       int timeout_ms, HttpResp *out)
{
    HINTERNET hSes = NULL, hCon = NULL, hReq = NULL;
    URL_COMPONENTS uc;
    wchar_t *wurl = NULL, *wverb = NULL;
    wchar_t  host[256], path[2048];
    wchar_t  wproxy[128];
    DWORD    flags = 0, status = 0, slen = sizeof(DWORD);
    BOOL     ok = FALSE;

    memset(out, 0, sizeof(*out));
    wurl = ml_utf8_to_w(url);
    if (!wurl) { ml_strlcpy(out->err, "bad url", sizeof(out->err)); goto done; }

    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize      = sizeof(uc);
    uc.lpszHostName      = host; uc.dwHostNameLength     = 256;
    uc.lpszUrlPath       = path; uc.dwUrlPathLength      = 2048;
    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        ml_strlcpy(out->err, "не удалось разобрать URL", sizeof(out->err));
        goto done;
    }

    if (proxy_host && proxy_host[0]) {
        wchar_t *wp;
        char tmp[128];
        snprintf(tmp, sizeof(tmp), "%s:%d", proxy_host, proxy_port);
        wp = ml_utf8_to_w(tmp);
        if (!wp) goto done;
        wcsncpy(wproxy, wp, 127); wproxy[127] = 0;
        free(wp);
        hSes = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                           wproxy, WINHTTP_NO_PROXY_BYPASS, 0);
    } else {
        hSes = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_NO_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    }
    if (!hSes) { ml_strlcpy(out->err, "WinHttpOpen failed", sizeof(out->err)); goto done; }

    WinHttpSetTimeouts(hSes, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    hCon = WinHttpConnect(hSes, host, uc.nPort, 0);
    if (!hCon) { ml_strlcpy(out->err, "connect failed", sizeof(out->err)); goto done; }

    if (uc.nScheme == INTERNET_SCHEME_HTTPS) flags |= WINHTTP_FLAG_SECURE;
    wverb = ml_utf8_to_w(verb ? verb : "GET");
    hReq = WinHttpOpenRequest(hCon, wverb, path, NULL,
                              WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hReq) { ml_strlcpy(out->err, "open request failed", sizeof(out->err)); goto done; }

    /* The modem's web UI serves a self-signed cert on HTTPS and the proxy test
     * only cares that bytes flow, so certificate errors are not fatal here. */
    if (flags & WINHTTP_FLAG_SECURE) {
        DWORD opt = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS, &opt, sizeof(opt));
    }

    if (proxy_host && puser && puser[0]) {
        wchar_t *wu = ml_utf8_to_w(puser);
        wchar_t *wp = ml_utf8_to_w(ppass ? ppass : "");
        if (wu && wp)
            WinHttpSetCredentials(hReq, WINHTTP_AUTH_TARGET_PROXY,
                                  WINHTTP_AUTH_SCHEME_BASIC, wu, wp, NULL);
        free(wu); free(wp);
    }

    {
        wchar_t *whdr = NULL;
        int i;
        if (nhdrs > 0 && hdrs) {
            /* Join "Name: value" pairs with CRLF into one header block. */
            size_t total = 1;
            char *joined;
            for (i = 0; i < nhdrs; i++) total += strlen(hdrs[i]) + 2;
            joined = (char *)malloc(total);
            if (joined) {
                joined[0] = 0;
                for (i = 0; i < nhdrs; i++) {
                    strcat(joined, hdrs[i]);
                    if (i + 1 < nhdrs) strcat(joined, "\r\n");
                }
                whdr = ml_utf8_to_w(joined);
                free(joined);
            }
        }
        ok = WinHttpSendRequest(hReq,
                                whdr ? whdr : WINHTTP_NO_ADDITIONAL_HEADERS,
                                whdr ? (DWORD)-1 : 0,
                                (LPVOID)(body ? (void *)body : WINHTTP_NO_REQUEST_DATA),
                                body ? (DWORD)strlen(body) : 0,
                                body ? (DWORD)strlen(body) : 0, 0);
        free(whdr);
    }
    if (!ok) {
        snprintf(out->err, sizeof(out->err), "нет ответа (ошибка %lu)", GetLastError());
        goto done;
    }

    if (!WinHttpReceiveResponse(hReq, NULL)) {
        snprintf(out->err, sizeof(out->err), "нет ответа (ошибка %lu)", GetLastError());
        ok = FALSE;
        goto done;
    }

    WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    out->status = (int)status;

    ok = read_body(hReq, out);

done:
    free(wurl); free(wverb);
    if (hReq) WinHttpCloseHandle(hReq);
    if (hCon) WinHttpCloseHandle(hCon);
    if (hSes) WinHttpCloseHandle(hSes);
    return ok;
}

BOOL http_get(const char *url, int timeout_ms, HttpResp *out)
{
    return do_request(url, "GET", NULL, NULL, 0, NULL, 0, NULL, NULL, timeout_ms, out);
}

BOOL http_get_via_proxy(const char *url, const char *proxy_host, int proxy_port,
                        const char *user, const char *pass,
                        int timeout_ms, HttpResp *out)
{
    return do_request(url, "GET", NULL, NULL, 0,
                      proxy_host, proxy_port, user, pass, timeout_ms, out);
}

BOOL http_post_xml(const char *url, const char *body,
                   const char *const *hdrs, int nhdrs,
                   int timeout_ms, HttpResp *out)
{
    return do_request(url, "POST", body, hdrs, nhdrs, NULL, 0, NULL, NULL, timeout_ms, out);
}

/* ------------------------------------------------------------- external IP */
BOOL net_fetch_external_ip(char *out, size_t cap)
{
    static const char *SRC[] = {
        "https://api.ipify.org",
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    };
    size_t i;

    for (i = 0; i < sizeof(SRC) / sizeof(SRC[0]); i++) {
        HttpResp r;
        if (http_get(SRC[i], 6000, &r) && r.status == 200 && r.body) {
            char ip[ML_ADDR_LEN];
            char *p = r.body, *w = ip;
            /* trim to the first line and strip whitespace */
            while (*p == ' ' || *p == '\r' || *p == '\n' || *p == '\t') p++;
            while (*p && *p != '\r' && *p != '\n' && *p != ' ' &&
                   (size_t)(w - ip) < sizeof(ip) - 1) *w++ = *p++;
            *w = 0;
            if (ml_is_ipv4(ip)) {
                ml_strlcpy(out, ip, cap);
                http_free(&r);
                ml_log("external IP resolved: %s (via %s)", out, SRC[i]);
                return TRUE;
            }
        }
        http_free(&r);
    }
    ml_log("external IP lookup failed on all sources");
    return FALSE;
}
