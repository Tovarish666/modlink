/* modlink — Huawei HiLink (E3372h and relatives) control.
 *
 * Direct port of reconnect_e3372h() from the Python panel. The device wants a
 * fresh session cookie + verification token for every state-changing POST, and
 * the IP only actually changes if the radio is bounced through the net-mode
 * sequence rather than just toggling the data switch. */
#include "common.h"
#include <string.h>
#include <stdlib.h>

#define HL_TIMEOUT 8000

/* Extracts the text between <tag> and </tag>. HiLink responses are tiny and
 * flat, so a full XML parser would be dead weight. */
static BOOL xml_tag(const char *xml, const char *tag, char *out, size_t cap)
{
    char open[64], close[64];
    const char *a, *b;

    out[0] = 0;
    if (!xml) return FALSE;
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);

    a = strstr(xml, open);
    if (!a) return FALSE;
    a += strlen(open);
    b = strstr(a, close);
    if (!b || b <= a) return FALSE;

    if ((size_t)(b - a) >= cap) return FALSE;
    memcpy(out, a, (size_t)(b - a));
    out[b - a] = 0;
    return TRUE;
}

/* GET /api/webserver/SesTokInfo — returns the pair every POST must echo back. */
static BOOL hl_token(const char *host, char *tok, size_t tokcap,
                     char *cookie, size_t ckcap)
{
    char url[ML_URL_LEN];
    HttpResp r;
    BOOL ok = FALSE;

    snprintf(url, sizeof(url), "http://%s/api/webserver/SesTokInfo", host);
    if (http_get(url, HL_TIMEOUT, &r) && r.status == 200 && r.body) {
        char ses[256];
        if (xml_tag(r.body, "TokInfo", tok, tokcap) &&
            xml_tag(r.body, "SesInfo", ses, sizeof(ses))) {
            ml_strlcpy(cookie, ses, ckcap);
            ok = TRUE;
        }
    }
    http_free(&r);
    return ok;
}

static BOOL hl_post(const char *host, const char *path, const char *xml,
                    const char *tok, const char *cookie)
{
    char url[ML_URL_LEN];
    char h_tok[512], h_ck[512];
    const char *hdrs[3];
    HttpResp r;
    BOOL ok;

    snprintf(url,   sizeof(url),   "http://%s%s", host, path);
    snprintf(h_tok, sizeof(h_tok), "__RequestVerificationToken: %s", tok);
    snprintf(h_ck,  sizeof(h_ck),  "Cookie: %s", cookie);
    hdrs[0] = h_tok;
    hdrs[1] = h_ck;
    hdrs[2] = "Content-Type: text/xml; charset=UTF-8";

    ok = http_post_xml(url, xml, hdrs, 3, HL_TIMEOUT, &r) && r.status == 200;
    http_free(&r);
    return ok;
}

/* Each net-mode change needs its own freshly minted token. */
static BOOL hl_set_net_mode(const char *host, const char *mode, const char *lte_band)
{
    char tok[512], ck[512], xml[512];
    if (!hl_token(host, tok, sizeof(tok), ck, sizeof(ck))) return FALSE;
    snprintf(xml, sizeof(xml),
             "<?xml version='1.0' encoding='UTF-8'?>"
             "<request><NetworkMode>%s</NetworkMode>"
             "<NetworkBand>3FFFFFFF</NetworkBand>"
             "<LTEBand>%s</LTEBand></request>",
             mode, lte_band);
    return hl_post(host, "/api/net/net-mode", xml, tok, ck);
}

static BOOL hl_dataswitch(const char *host, int on)
{
    char tok[512], ck[512], xml[256];
    if (!hl_token(host, tok, sizeof(tok), ck, sizeof(ck))) return FALSE;
    snprintf(xml, sizeof(xml),
             "<?xml version='1.0' encoding='UTF-8'?>"
             "<request><dataswitch>%d</dataswitch></request>", on ? 1 : 0);
    return hl_post(host, "/api/dialup/mobile-dataswitch", xml, tok, ck);
}

BOOL hilink_probe(const char *host, int timeout_ms)
{
    char url[ML_URL_LEN];
    HttpResp r;
    BOOL ok;

    if (!host || !host[0]) return FALSE;
    snprintf(url, sizeof(url), "http://%s/api/webserver/SesTokInfo", host);
    ok = http_get(url, timeout_ms, &r) && r.body && strstr(r.body, "SesInfo") != NULL;
    http_free(&r);
    return ok;
}

BOOL hilink_reconnect(const char *host, char *msg, size_t msgcap, double *secs)
{
    LARGE_INTEGER freq, t0, t1;
    int i;

    if (msg && msgcap) msg[0] = 0;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t0);

    if (!host || !host[0]) {
        if (msg) ml_strlcpy(msg, "не задан IP модема", msgcap);
        return FALSE;
    }

    /* 1. data off */
    if (!hl_dataswitch(host, 0)) {
        if (msg) ml_strlcpy(msg, "модем не отвечает (SesTokInfo)", msgcap);
        goto fail;
    }
    Sleep(2000);

    /* 2. bounce the radio: LTE-only -> 3G -> auto. Toggling the data switch on
     *    its own usually gets the same IP back; forcing a mode change makes the
     *    network hand out a new one. */
    hl_set_net_mode(host, "00", "5");                 Sleep(2000);
    hl_set_net_mode(host, "02", "5");                 Sleep(500);
    hl_set_net_mode(host, "03", "7FFFFFFFFFFFFFFF");  Sleep(800);

    /* 3. data on */
    if (!hl_dataswitch(host, 1)) {
        if (msg) ml_strlcpy(msg, "не удалось включить передачу данных", msgcap);
        goto fail;
    }

    /* 4. wait for the device to confirm it is back up */
    for (i = 0; i < 20; i++) {
        char url[ML_URL_LEN];
        HttpResp r;
        BOOL up;
        Sleep(400);
        snprintf(url, sizeof(url), "http://%s/api/dialup/mobile-dataswitch", host);
        up = http_get(url, HL_TIMEOUT, &r) && r.body &&
             strstr(r.body, "<dataswitch>1</dataswitch>") != NULL;
        http_free(&r);
        if (up) {
            QueryPerformanceCounter(&t1);
            if (secs) *secs = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
            if (msg) ml_strlcpy(msg, "reconnected", msgcap);
            return TRUE;
        }
    }
    if (msg) ml_strlcpy(msg, "dataswitch не подтверждён", msgcap);

fail:
    QueryPerformanceCounter(&t1);
    if (secs) *secs = (double)(t1.QuadPart - t0.QuadPart) / (double)freq.QuadPart;
    return FALSE;
}

BOOL hilink_reboot(const char *host, char *msg, size_t msgcap)
{
    char tok[512], ck[512];

    if (msg && msgcap) msg[0] = 0;
    if (!host || !host[0]) {
        if (msg) ml_strlcpy(msg, "не задан IP модема", msgcap);
        return FALSE;
    }
    if (!hl_token(host, tok, sizeof(tok), ck, sizeof(ck))) {
        if (msg) ml_strlcpy(msg, "модем не отвечает", msgcap);
        return FALSE;
    }
    if (!hl_post(host, "/api/device/control",
                 "<?xml version='1.0' encoding='UTF-8'?>"
                 "<request><Control>1</Control></request>", tok, ck)) {
        if (msg) ml_strlcpy(msg, "команда ребута отклонена", msgcap);
        return FALSE;
    }
    if (msg) ml_strlcpy(msg, "ребут отправлен", msgcap);
    return TRUE;
}
