/* modlink — HTTP-посредник, см. mediator.h */
#include "mediator.h"
#include "socks5.h"
#include <ws2tcpip.h>
#include <string.h>
#include <stdlib.h>

#define HDR_MAX   32768
#define IO_CHUNK  16384

static MediatorCfg    g_cfg;
static SOCKET         g_listen = INVALID_SOCKET;
static HANDLE         g_thread = NULL;
static volatile LONG  g_stop   = 0;

/* ------------------------------------------------------------- утилиты */
static int find_ci(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle), i, j;
    if (nlen > hlen) return -1;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen; j++) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == nlen) return (int)i;
    }
    return -1;
}

static BOOL send_all_s(SOCKET s, const char *b, int n)
{
    int sent = 0;
    while (sent < n) {
        int r = send(s, b + sent, n - sent, 0);
        if (r <= 0) return FALSE;
        sent += r;
    }
    return TRUE;
}

/* Читает заголовки до пустой строки. Возвращает длину заголовков вместе с
 * разделителем, всё прочитанное сверх — начало тела, оно уже в buf. */
static int read_headers(SOCKET s, char *buf, int cap, int *total)
{
    int n = 0;
    *total = 0;
    while (n < cap - 1) {
        int r = recv(s, buf + n, cap - 1 - n, 0);
        if (r <= 0) return -1;
        n += r;
        buf[n] = 0;
        {
            int p = find_ci(buf, (size_t)n, "\r\n\r\n");
            if (p >= 0) { *total = n; return p + 4; }
        }
    }
    return -1;
}

/* Переписывает значение заголовка `name` с from на to. Возвращает новую длину
 * блока заголовков. Работает по одному вхождению — большего и не бывает. */
static int rewrite_header(char *buf, int len, int cap,
                          const char *name, const char *from, const char *to)
{
    int pos = 0;
    while (pos < len) {
        int line_end = -1, i;
        for (i = pos; i + 1 < len; i++)
            if (buf[i] == '\r' && buf[i + 1] == '\n') { line_end = i; break; }
        if (line_end < 0) break;
        if (line_end == pos) break;                    /* пустая строка — конец */

        if (find_ci(buf + pos, (size_t)(line_end - pos), name) == 0) {
            int fpos = find_ci(buf + pos, (size_t)(line_end - pos), from);
            if (fpos >= 0) {
                int abs   = pos + fpos;
                int flen  = (int)strlen(from);
                int tlen  = (int)strlen(to);
                int delta = tlen - flen;
                if (len + delta >= cap) return len;     /* не влезает — оставляем как есть */
                memmove(buf + abs + tlen, buf + abs + flen, (size_t)(len - abs - flen));
                memcpy(buf + abs, to, (size_t)tlen);
                len += delta;
            }
            return len;
        }
        pos = line_end + 2;
    }
    return len;
}

/* Гасит keep-alive: одна пара запрос-ответ на соединение. Так разбор
 * заголовков остаётся однопроходным, а не превращается в конечный автомат. */
static int force_close(char *buf, int len, int cap)
{
    static const char CL[] = "Connection: close\r\n";
    int clen = (int)sizeof(CL) - 1;
    int eol  = find_ci(buf, (size_t)len, "\r\n");
    if (eol < 0 || len + clen >= cap) return len;
    memmove(buf + eol + 2 + clen, buf + eol + 2, (size_t)(len - eol - 2));
    memcpy(buf + eol + 2, CL, (size_t)clen);
    return len + clen;
}

/* ------------------------------------------------------------- прокачка */
static void pump(SOCKET a, SOCKET b)
{
    char buf[IO_CHUNK];
    for (;;) {
        fd_set rf;
        struct timeval tv;
        SOCKET mx = a > b ? a : b;
        int r;

        FD_ZERO(&rf); FD_SET(a, &rf); FD_SET(b, &rf);
        tv.tv_sec = 30; tv.tv_usec = 0;
        r = select((int)mx + 1, &rf, NULL, NULL, &tv);
        if (r <= 0) return;

        if (FD_ISSET(a, &rf)) {
            int n = recv(a, buf, sizeof(buf), 0);
            if (n <= 0 || !send_all_s(b, buf, n)) return;
        }
        if (FD_ISSET(b, &rf)) {
            int n = recv(b, buf, sizeof(buf), 0);
            if (n <= 0 || !send_all_s(a, buf, n)) return;
        }
    }
}

/* ------------------------------------------------------------- сессия */
typedef struct { SOCKET client; } Session;

static DWORD WINAPI session_thread(LPVOID arg)
{
    Session *S = (Session *)arg;
    SOCKET c = S->client, up = INVALID_SOCKET;
    char *hdr = (char *)malloc(HDR_MAX);
    char err[256];
    int hlen, total;

    free(S);
    if (!hdr) { closesocket(c); return 0; }

    {   /* клиент может замолчать — не держим поток вечно */
        DWORD tv = 20000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    }

    hlen = read_headers(c, hdr, HDR_MAX, &total);
    if (hlen <= 0) goto done;

    /* Запрос: подменяем Host на настоящий адрес модема и гасим keep-alive. */
    hlen = rewrite_header(hdr, hlen, HDR_MAX, "Host:", g_cfg.virt_ip, g_cfg.real_ip);
    hlen = force_close(hdr, hlen, HDR_MAX);

    up = socks5_connect(g_cfg.proxy_ip, g_cfg.proxy_port, g_cfg.user, g_cfg.pass,
                        g_cfg.real_ip, 80, 15000, err, sizeof(err));
    if (up == INVALID_SOCKET) {
        char resp[512];
        int n = snprintf(resp, sizeof(resp),
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\n"
            "Connection: close\r\nContent-Length: %d\r\n\r\n%s",
            (int)strlen(err), err);
        send_all_s(c, resp, n);
        ml_log("mediator: SOCKS5 failed - %s", err);
        goto done;
    }

    if (!send_all_s(up, hdr, hlen)) goto done;
    /* хвост запроса, прочитанный вместе с заголовками */
    if (total > hlen && !send_all_s(up, hdr + hlen, total - hlen)) goto done;

    /* Ответ: модем ставит в Location свой настоящий адрес и увёл бы браузер
     * с виртуального. Правим обратно. */
    hlen = read_headers(up, hdr, HDR_MAX, &total);
    if (hlen <= 0) goto done;
    hlen = rewrite_header(hdr, hlen, HDR_MAX, "Location:", g_cfg.real_ip, g_cfg.virt_ip);

    if (!send_all_s(c, hdr, hlen)) goto done;
    if (total > hlen && !send_all_s(c, hdr + hlen, total - hlen)) goto done;

    pump(c, up);

done:
    free(hdr);
    if (up != INVALID_SOCKET) closesocket(up);
    closesocket(c);
    return 0;
}

/* ------------------------------------------------------------- слушатель */
static DWORD WINAPI listen_thread(LPVOID arg)
{
    (void)arg;
    for (;;) {
        SOCKET c = accept(g_listen, NULL, NULL);
        if (InterlockedCompareExchange(&g_stop, 0, 0)) {
            if (c != INVALID_SOCKET) closesocket(c);
            break;
        }
        if (c == INVALID_SOCKET) continue;
        {
            Session *S = (Session *)calloc(1, sizeof(Session));
            HANDLE h;
            if (!S) { closesocket(c); continue; }
            S->client = c;
            h = CreateThread(NULL, 0, session_thread, S, 0, NULL);
            if (h) CloseHandle(h); else { free(S); closesocket(c); }
        }
    }
    return 0;
}

BOOL mediator_start(const MediatorCfg *cfg, char *err, size_t errcap)
{
    struct sockaddr_in a;
    BOOL excl = TRUE;

    g_cfg = *cfg;
    if (g_cfg.listen_port <= 0) g_cfg.listen_port = 80;
    if (err && errcap) err[0] = 0;

    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_listen == INVALID_SOCKET) {
        if (err) ml_strlcpy(err, "не удалось создать слушающий сокет", errcap);
        return FALSE;
    }
    setsockopt(g_listen, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&excl, sizeof(excl));

    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_port        = htons((u_short)g_cfg.listen_port);
    a.sin_addr.s_addr = inet_addr(g_cfg.virt_ip);
    if (a.sin_addr.s_addr == INADDR_NONE) {
        if (err) snprintf(err, errcap, "«%s» — не IPv4-адрес", g_cfg.virt_ip);
        goto fail;
    }
    if (bind(g_listen, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (err) snprintf(err, errcap,
            "не удалось занять %s:%d (ошибка %d). Адрес назначен на адаптер?",
            g_cfg.virt_ip, g_cfg.listen_port, WSAGetLastError());
        goto fail;
    }
    if (listen(g_listen, 16) != 0) {
        if (err) ml_strlcpy(err, "listen() не удался", errcap);
        goto fail;
    }

    g_stop   = 0;
    g_thread = CreateThread(NULL, 0, listen_thread, NULL, 0, NULL);
    if (!g_thread) {
        if (err) ml_strlcpy(err, "не удалось создать поток", errcap);
        goto fail;
    }

    ml_log("mediator: %s:%d -> %s via %s:%d",
           g_cfg.virt_ip, g_cfg.listen_port, g_cfg.real_ip,
           g_cfg.proxy_ip, g_cfg.proxy_port);
    return TRUE;

fail:
    closesocket(g_listen);
    g_listen = INVALID_SOCKET;
    return FALSE;
}

void mediator_stop(void)
{
    if (!g_thread) return;
    InterlockedExchange(&g_stop, 1);
    if (g_listen != INVALID_SOCKET) { closesocket(g_listen); g_listen = INVALID_SOCKET; }
    WaitForSingleObject(g_thread, 3000);
    CloseHandle(g_thread);
    g_thread = NULL;
}
