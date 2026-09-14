/* modlink — клиент SOCKS5, см. socks5.h */
#include "socks5.h"
#include <ws2tcpip.h>
#include <string.h>

/* Читает ровно n байт или падает: короткое чтение в SOCKS5 — всегда ошибка,
 * потому что все ответы протокола фиксированной длины. */
static BOOL recv_all(SOCKET s, unsigned char *buf, int n)
{
    int got = 0;
    while (got < n) {
        int r = recv(s, (char *)buf + got, n - got, 0);
        if (r <= 0) return FALSE;
        got += r;
    }
    return TRUE;
}

static BOOL send_all(SOCKET s, const unsigned char *buf, int n)
{
    int sent = 0;
    while (sent < n) {
        int r = send(s, (const char *)buf + sent, n - sent, 0);
        if (r <= 0) return FALSE;
        sent += r;
    }
    return TRUE;
}

SOCKET socks5_connect(const char *proxy_ip, int proxy_port,
                      const char *user, const char *pass,
                      const char *dst_ip, int dst_port,
                      int timeout_ms, char *err, size_t errcap)
{
    SOCKET s = INVALID_SOCKET;
    struct sockaddr_in a;
    unsigned char buf[512];
    int n;
    BOOL want_auth = (user && user[0]);
    DWORD tv = (DWORD)timeout_ms;

    if (err && errcap) err[0] = 0;

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        if (err) ml_strlcpy(err, "не удалось создать сокет", errcap);
        return INVALID_SOCKET;
    }
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));

    memset(&a, 0, sizeof(a));
    a.sin_family      = AF_INET;
    a.sin_port        = htons((u_short)proxy_port);
    a.sin_addr.s_addr = inet_addr(proxy_ip);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        if (err) snprintf(err, errcap, "прокси %s:%d недоступен (%d)",
                          proxy_ip, proxy_port, WSAGetLastError());
        goto fail;
    }

    /* --- приветствие: предлагаем «без аутентификации» и/или «логин/пароль» --- */
    n = 0;
    buf[n++] = 0x05;
    if (want_auth) { buf[n++] = 2; buf[n++] = 0x00; buf[n++] = 0x02; }
    else           { buf[n++] = 1; buf[n++] = 0x00; }
    if (!send_all(s, buf, n) || !recv_all(s, buf, 2) || buf[0] != 0x05) {
        if (err) ml_strlcpy(err, "прокси не отвечает по протоколу SOCKS5", errcap);
        goto fail;
    }

    if (buf[1] == 0x02) {
        size_t ul, pl;
        if (!want_auth) {
            if (err) ml_strlcpy(err, "прокси требует логин, а он не задан", errcap);
            goto fail;
        }
        ul = strlen(user);
        pl = pass ? strlen(pass) : 0;
        if (ul > 255 || pl > 255) {
            if (err) ml_strlcpy(err, "логин или пароль длиннее 255 символов", errcap);
            goto fail;
        }
        n = 0;
        buf[n++] = 0x01;
        buf[n++] = (unsigned char)ul; memcpy(buf + n, user, ul); n += (int)ul;
        buf[n++] = (unsigned char)pl; if (pl) memcpy(buf + n, pass, pl); n += (int)pl;
        if (!send_all(s, buf, n) || !recv_all(s, buf, 2) || buf[1] != 0x00) {
            if (err) ml_strlcpy(err, "прокси отверг логин или пароль", errcap);
            goto fail;
        }
    } else if (buf[1] != 0x00) {
        if (err) snprintf(err, errcap, "прокси предложил метод 0x%02X, он не поддерживается", buf[1]);
        goto fail;
    }

    /* --- CONNECT на IPv4 --- */
    {
        unsigned long ip = inet_addr(dst_ip);
        if (ip == INADDR_NONE) {
            if (err) snprintf(err, errcap, "«%s» — не IPv4-адрес", dst_ip);
            goto fail;
        }
        n = 0;
        buf[n++] = 0x05; buf[n++] = 0x01; buf[n++] = 0x00; buf[n++] = 0x01;
        memcpy(buf + n, &ip, 4); n += 4;
        buf[n++] = (unsigned char)((dst_port >> 8) & 0xFF);
        buf[n++] = (unsigned char)(dst_port & 0xFF);
        if (!send_all(s, buf, n)) {
            if (err) ml_strlcpy(err, "не удалось отправить запрос CONNECT", errcap);
            goto fail;
        }
    }

    /* Ответ: VER REP RSV ATYP + адрес переменной длины. Адрес нам не нужен,
     * но вычитать его обязательно — иначе он попадёт в поток данных. */
    if (!recv_all(s, buf, 4) || buf[0] != 0x05) {
        if (err) ml_strlcpy(err, "испорченный ответ на CONNECT", errcap);
        goto fail;
    }
    if (buf[1] != 0x00) {
        static const char *R[] = {"ок", "сбой сервера", "запрещено правилами",
                                  "сеть недоступна", "хост недоступен",
                                  "соединение отклонено", "истёк TTL",
                                  "команда не поддерживается", "тип адреса не поддерживается"};
        int rep = buf[1];
        if (err) snprintf(err, errcap, "прокси отказал: %s (0x%02X)",
                          rep < 9 ? R[rep] : "неизвестная причина", rep);
        goto fail;
    }
    switch (buf[3]) {
    case 0x01: if (!recv_all(s, buf, 4 + 2)) goto fail; break;          /* IPv4 */
    case 0x04: if (!recv_all(s, buf, 16 + 2)) goto fail; break;         /* IPv6 */
    case 0x03: if (!recv_all(s, buf, 1)) goto fail;                     /* домен */
               if (!recv_all(s, buf + 1, buf[0] + 2)) goto fail; break;
    default:
        if (err) ml_strlcpy(err, "прокси вернул неизвестный тип адреса", errcap);
        goto fail;
    }

    return s;

fail:
    if (s != INVALID_SOCKET) closesocket(s);
    return INVALID_SOCKET;
}
