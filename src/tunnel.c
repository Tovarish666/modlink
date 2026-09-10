/* modlink-agent — туннель, см. tunnel.h */
#include "tunnel.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdlib.h>

#include "httprw.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/timeouts.h"
#include "lwip/etharp.h"
#include "netif/ethernet.h"

#define MAX_CONNS     256
#define BUF_SIZE      (64 * 1024)
/* Тик петли. Каждый шаг рукопожатия SOCKS5 ждёт следующей итерации, поэтому
 * крупный тик прямо умножается на число шагов: при 50 мс один DNS-запрос
 * терял четверть секунды на ровном месте. 5 мс — компромисс между задержкой и
 * холостыми пробуждениями; правильное решение — ждать сразу и кадр, и события
 * сокетов через WaitForMultipleObjects, но это требует разбить tap_read на
 * начало и завершение операции. */
#define LOOP_TICK_MS  5

/* Диагностика: где именно умерло соединение. Причина важнее факта — без неё
 * "не работает" неотличимо от "прокси отказал" и "клиент отвалился". */
#define DIE(c, why) do { ml_log("tunnel: conn dead (%s) st=%d", (why), (int)(c)->st);                          (c)->st = CS_DEAD; } while (0)

/* --------------------------------------------------------------- состояние */
typedef struct Iface Iface;      /* определён ниже; на него ссылаются Conn и DnsQ */

typedef enum {
    CS_FREE = 0,
    CS_CONNECTING,   /* TCP до прокси в процессе */
    CS_GREET,        /* отправлено приветствие, ждём выбор метода */
    CS_AUTH,         /* отправлен логин, ждём подтверждение */
    CS_REQUEST,      /* отправлен CONNECT, ждём ответ */
    CS_OPEN,         /* качаем данные */
    CS_DEAD          /* подлежит уборке */
} ConnState;

typedef struct {
    ConnState       st;
    Iface          *ifc;        /* через какой модем уходить */
    struct tcp_pcb *pcb;        /* сторона lwIP */
    SOCKET          sock;       /* сторона прокси */
    ip4_addr_t      dst_ip;     /* куда клиент на самом деле шёл */
    u16_t           dst_port;

    /* Данные от клиента, ждущие отправки в прокси. */
    char  up[BUF_SIZE];  int up_len;
    /* Данные от прокси, ждущие передачи клиенту. */
    char  dn[BUF_SIZE];  int dn_len;

    BOOL  client_closed;        /* клиент прислал FIN */
    BOOL  want_write;           /* есть что отправить наружу */

    /* Соединение к самому 192.168.N.1 — это веб-морда модема, а не транзит.
     * Тогда правим Host в запросе и Location в ответе, иначе прошивка ответит
     * редиректом вместо данных и уведёт браузер на свой настоящий адрес. */
    BOOL  mediated;
    BOOL  req_fixed;            /* заголовки запроса уже поправлены */
    BOOL  resp_fixed;           /* заголовки ответа уже поправлены */

    /* Ответы SOCKS5 крошечные, но TCP не обязан отдавать их одним куском.
     * Копим, пока не наберётся нужное, иначе на канале с джиттером соединение
     * изредка умирает на ровном месте — и выглядит это как «иногда не works». */
    unsigned char hs[300]; int hslen;
} Conn;

/* Всё, что раньше было глобальным на единственный туннель, теперь живёт здесь.
 * netif->state указывает на свой Iface — так обработчики lwIP узнают, через
 * какой модем уходить, не заводя таблиц соответствия. */
struct Iface {
    BOOL         used;
    TunnelCfg    cfg;
    ip4_addr_t   ip;
    HANDLE       tap;
    OVERLAPPED   ov;
    BOOL         pending;
    struct netif netif;
    char         frame[TAP_FRAME_MAX];
};

static Iface           g_ifaces[TUNNEL_MAX_IFACES];
static int             g_niface = 0;

static Conn            g_conns[MAX_CONNS];
static HANDLE          g_thread = NULL;
static HANDLE          g_stop_ev = NULL;
/* Одно событие на все сокеты сразу: WSAEventSelect это разрешает, и тогда
 * петля ждёт три объекта вместо сотен — иначе упёрлись бы в MAXIMUM_WAIT_OBJECTS
 * (64), а соединений может быть 256. Кто именно проснулся, выясняет
 * WSAEnumNetworkEvents при обходе. */
static WSAEVENT        g_sock_ev = WSA_INVALID_EVENT;
static volatile LONG   g_stop = 0;
static struct tcp_pcb *g_listener = NULL;

/* ------------------------------------------------------------ DNS
 * Запросы уводим по TCP через тот же прокси. Пустить UDP мимо туннеля нельзя:
 * имена тогда резолвятся с адреса датацентра, а не модема — это и утечка, и
 * расхождение геолокации между DNS и выходным адресом. */
#define MAX_DNSQ   64
#define DNS_TTL_MS 8000

typedef struct {
    BOOL      used;
    Iface    *ifc;
    SOCKET    sock;
    ConnState st;
    unsigned char hs[300]; int hslen;     /* накопитель ответов SOCKS5 */
    char      q[1024]; int qlen, qsent;   /* запрос с 2-байтовым префиксом длины */
    char      r[2048]; int rlen;          /* ответ, тоже с префиксом */
    ip_addr_t from; u16_t fromport;       /* кому вернуть */
    DWORD     started;
} DnsQ;

static DnsQ            g_dns[MAX_DNSQ];
static struct udp_pcb *g_udp = NULL;

static int                 g_active = 0, g_total = 0;
static unsigned long long  g_bytes_up = 0, g_bytes_dn = 0;

void tunnel_stats(int *active, int *total, unsigned long long *bu, unsigned long long *bd)
{
    if (active) *active = g_active;
    if (total)  *total  = g_total;
    if (bu)     *bu     = g_bytes_up;
    if (bd)     *bd     = g_bytes_dn;
}

/* --------------------------------------------------------------- утилиты */
static Conn *conn_alloc(void)
{
    int i;
    for (i = 0; i < MAX_CONNS; i++)
        if (g_conns[i].st == CS_FREE) {
            memset(&g_conns[i], 0, sizeof(Conn));
            g_conns[i].sock = INVALID_SOCKET;
            g_active++; g_total++;
            return &g_conns[i];
        }
    return NULL;
}

static void conn_kill(Conn *c)
{
    if (c->st == CS_FREE) return;
    if (c->pcb) {
        tcp_arg(c->pcb, NULL);
        tcp_recv(c->pcb, NULL);
        tcp_sent(c->pcb, NULL);
        tcp_err(c->pcb, NULL);
        /* Закрываем по-человечески: клиент должен увидеть FIN, а не RST, иначе
         * HTTP-клиент сочтёт уже полученный ответ оборванным. tcp_abort — только
         * если закрыть не удалось (нет памяти под сегмент). */
        if (tcp_close(c->pcb) != ERR_OK) tcp_abort(c->pcb);
        c->pcb = NULL;
    }
    if (c->sock != INVALID_SOCKET) { closesocket(c->sock); c->sock = INVALID_SOCKET; }
    c->st = CS_FREE;
    if (g_active > 0) g_active--;
}

static BOOL sock_send_all(Conn *c, const void *buf, int len)
{
    int sent = send(c->sock, (const char *)buf, len, 0);
    return sent == len;
}

/* Копит из сокета, пока не наберётся `need` байт. TRUE — набралось.
 * FALSE без ошибки означает «ещё придёт», ошибку сообщает *dead. */
static BOOL hs_fill(SOCKET s, unsigned char *buf, int *len, int need, BOOL *dead)
{
    int n;
    *dead = FALSE;
    while (*len < need) {
        n = recv(s, (char *)buf + *len, need - *len, 0);
        if (n > 0) { *len += n; continue; }
        if (n == 0) { *dead = TRUE; return FALSE; }
        if (WSAGetLastError() == WSAEWOULDBLOCK) return FALSE;
        *dead = TRUE;
        return FALSE;
    }
    return TRUE;
}

/* --------------------------------------------------------------- lwIP → нам */
static void lw_err(void *arg, err_t err)
{
    Conn *c = (Conn *)arg;
    (void)err;
    if (!c) return;
    c->pcb = NULL;             /* lwIP уже освободил pcb — трогать его нельзя */
    c->st  = CS_DEAD;
}

static err_t lw_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    Conn *c = (Conn *)arg;
    (void)pcb; (void)len;
    if (!c) return ERR_OK;
    return ERR_OK;             /* разгребается в drain_down() из главной петли */
}

static err_t lw_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    Conn *c = (Conn *)arg;
    struct pbuf *q;
    int room;

    if (!c) { if (p) pbuf_free(p); return ERR_OK; }
    if (err != ERR_OK) { if (p) pbuf_free(p); c->st = CS_DEAD; return ERR_OK; }

    if (p == NULL) {           /* клиент закрыл свою половину */
        c->client_closed = TRUE;
        if (c->sock != INVALID_SOCKET && c->up_len == 0) shutdown(c->sock, SD_SEND);
        return ERR_OK;
    }

    room = BUF_SIZE - c->up_len;
    if (p->tot_len > room) {
        /* Буфер полон. Не подтверждаем приём — lwIP сам придержит окно и
         * клиент притормозит. Это и есть управление потоком: без него быстрый
         * клиент забил бы память при медленном канале модема. */
        pbuf_free(p);
        return ERR_MEM;
    }

    for (q = p; q != NULL; q = q->next) {
        memcpy(c->up + c->up_len, q->payload, q->len);
        c->up_len += q->len;
    }
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    c->want_write = TRUE;
    return ERR_OK;
}

static err_t lw_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    Conn *c;
    struct sockaddr_in a;
    (void)arg;

    if (err != ERR_OK || pcb == NULL) return ERR_VAL;

    c = conn_alloc();
    if (!c) { tcp_abort(pcb); return ERR_ABRT; }

    /* Через какой модем уходить,знает сам lwIP: пакет пришёл на конкретный
     * netif, а в его state лежит наш интерфейс. Таблиц соответствия не нужно. */
    {
        struct netif *in = ip_current_netif();
        if (!in || !in->state) { conn_kill(c); tcp_abort(pcb); return ERR_ABRT; }
        c->ifc = (Iface *)in->state;
    }

    /* Благодаря правкам в lwIP здесь лежит НАСТОЯЩИЙ адресат, куда шёл клиент,
     * а не адрес нашего интерфейса. Ради этого патчи и делались. */
    ip4_addr_copy(c->dst_ip, *ip_2_ip4(&pcb->local_ip));
    c->dst_port = pcb->local_port;
    c->pcb = pcb;
    c->st  = CS_CONNECTING;

    /* Клиент постучался на адрес самого интерфейса — значит ему нужна морда
     * модема. Подменяем адресата на настоящий и включаем правку заголовков.
     * Отдельный сокет для этого не нужен: слушатель-ловушка и так поймал всё. */
    if (c->ifc->cfg.real_ip[0] && c->dst_ip.addr == c->ifc->ip.addr && c->dst_port == 80) {
        ip4addr_aton(c->ifc->cfg.real_ip, &c->dst_ip);
        c->mediated = TRUE;
    }

    tcp_arg(pcb, c);
    tcp_recv(pcb, lw_recv);
    tcp_sent(pcb, lw_sent);
    tcp_err(pcb, lw_err);
    tcp_nagle_disable(pcb);

    /* Соединяемся с прокси неблокирующе: петля не имеет права встать. */
    c->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c->sock == INVALID_SOCKET) { conn_kill(c); return ERR_ABRT; }
    WSAEventSelect(c->sock, g_sock_ev, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons((u_short)c->ifc->cfg.proxy_port);
    a.sin_addr.s_addr = inet_addr(c->ifc->cfg.proxy_ip);
    if (connect(c->sock, (struct sockaddr *)&a, sizeof(a)) != 0 &&
        WSAGetLastError() != WSAEWOULDBLOCK) {
        conn_kill(c);
        return ERR_ABRT;
    }
    return ERR_OK;
}

/* --------------------------------------------------------------- SOCKS5 */
static void socks_send_greeting(Conn *c)
{
    unsigned char b[4];
    int n = 0;
    b[n++] = 0x05;
    if (c->ifc->cfg.user[0]) { b[n++] = 2; b[n++] = 0x00; b[n++] = 0x02; }
    else               { b[n++] = 1; b[n++] = 0x00; }
    if (!sock_send_all(c, b, n)) { c->st = CS_DEAD; return; }
    c->st = CS_GREET;
}

static void socks_send_auth(Conn *c)
{
    unsigned char b[600];
    size_t ul = strlen(c->ifc->cfg.user), pl = strlen(c->ifc->cfg.pass);
    int n = 0;
    b[n++] = 0x01;
    b[n++] = (unsigned char)ul; memcpy(b + n, c->ifc->cfg.user, ul); n += (int)ul;
    b[n++] = (unsigned char)pl; memcpy(b + n, c->ifc->cfg.pass, pl); n += (int)pl;
    if (!sock_send_all(c, b, n)) { c->st = CS_DEAD; return; }
    c->st = CS_AUTH;
}

static void socks_send_request(Conn *c)
{
    unsigned char b[16];
    int n = 0;
    b[n++] = 0x05; b[n++] = 0x01; b[n++] = 0x00; b[n++] = 0x01;
    memcpy(b + n, &c->dst_ip.addr, 4); n += 4;
    b[n++] = (unsigned char)(c->dst_port >> 8);
    b[n++] = (unsigned char)(c->dst_port & 0xFF);
    if (!sock_send_all(c, b, n)) { c->st = CS_DEAD; return; }
    c->st = CS_REQUEST;
}

/* Разбор ответов прокси. Данные приходят порциями, поэтому каждый шаг сначала
 * убеждается, что пришло достаточно байт, и только потом двигает автомат. */
static void socks_on_readable(Conn *c)
{
    BOOL dead;
    int n;

    switch (c->st) {
    case CS_GREET:
        if (!hs_fill(c->sock, c->hs, &c->hslen, 2, &dead)) {
            if (dead) DIE(c, "greet: соединение оборвано");
            return;
        }
        if (c->hs[0] != 0x05) { DIE(c, "greet: не SOCKS5"); return; }
        { unsigned char m = c->hs[1]; c->hslen = 0;
          if      (m == 0x02) socks_send_auth(c);
          else if (m == 0x00) socks_send_request(c);
          else                DIE(c, "greet: метод не поддержан"); }
        return;

    case CS_AUTH:
        if (!hs_fill(c->sock, c->hs, &c->hslen, 2, &dead)) {
            if (dead) DIE(c, "auth: соединение оборвано");
            return;
        }
        if (c->hs[1] != 0x00) { DIE(c, "auth: отказ"); return; }
        c->hslen = 0;
        socks_send_request(c);
        return;

    case CS_REQUEST: {
        int need;
        if (!hs_fill(c->sock, c->hs, &c->hslen, 4, &dead)) {
            if (dead) DIE(c, "request: соединение оборвано");
            return;
        }
        if (c->hs[0] != 0x05) { DIE(c, "request: испорчен"); return; }
        if (c->hs[1] != 0x00) {
            ml_log("tunnel: proxy REP=0x%02X", c->hs[1]);
            DIE(c, "request: прокси отказал");
            return;
        }
        /* Адрес из ответа не нужен, но вычитать его обязательно — иначе он
         * уедет клиенту как полезные данные. */
        need = (c->hs[3] == 0x01) ? 4 + 4 + 2 : (c->hs[3] == 0x04) ? 4 + 16 + 2 : -1;
        if (need < 0) {
            if (!hs_fill(c->sock, c->hs, &c->hslen, 5, &dead)) {
                if (dead) DIE(c, "request: домен обрезан");
                return;
            }
            need = 4 + 1 + c->hs[4] + 2;
        }
        if (!hs_fill(c->sock, c->hs, &c->hslen, need, &dead)) {
            if (dead) DIE(c, "request: адрес не дочитан");
            return;
        }
        c->hslen = 0;
        c->st = CS_OPEN;
        return;
    }

    case CS_OPEN: {
        int room = BUF_SIZE - c->dn_len;
        if (room <= 0) return;                 /* клиент не успевает — не читаем */
        n = recv(c->sock, c->dn + c->dn_len, room, 0);
        if (n > 0)      { c->dn_len += n; g_bytes_dn += (unsigned long long)n; }
        else if (n == 0) DIE(c,"прокси закрыл");
        return;
    }

    default:
        return;
    }
}

/* --------------------------------------------------------------- перекачка */
static void drain_up(Conn *c)          /* клиент → прокси */
{
    int n;
    if (c->st != CS_OPEN || c->up_len == 0 || c->sock == INVALID_SOCKET) return;

    if (c->mediated && !c->req_fixed) {
        /* Ждём заголовки целиком: Host правится до того, как уйдёт хоть байт. */
        if (hrw_headers_end(c->up, c->up_len) < 0) {
            if (c->up_len < BUF_SIZE) return;      /* ещё придёт */
            c->req_fixed = TRUE;                   /* заголовки безумного размера — шлём как есть */
        } else {
            c->up_len = hrw_rewrite_header(c->up, c->up_len, BUF_SIZE,
                                           "Host:", c->ifc->cfg.virt_ip, c->ifc->cfg.real_ip);
            c->up_len = hrw_force_close(c->up, c->up_len, BUF_SIZE);
            c->req_fixed = TRUE;
        }
    }
    n = send(c->sock, c->up, c->up_len, 0);
    if (n > 0) {
        memmove(c->up, c->up + n, (size_t)(c->up_len - n));
        c->up_len -= n;
        g_bytes_up += (unsigned long long)n;
    } else if (n == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) {
        c->st = CS_DEAD;
        return;
    }
    if (c->up_len == 0) {
        c->want_write = FALSE;
        if (c->client_closed) shutdown(c->sock, SD_SEND);
    }
}

static void drain_down(Conn *c)        /* прокси → клиент */
{
    int can, n;
    if (!c->pcb || c->dn_len == 0) return;

    if (c->mediated && !c->resp_fixed) {
        if (hrw_headers_end(c->dn, c->dn_len) < 0) {
            if (c->dn_len < BUF_SIZE) return;
            c->resp_fixed = TRUE;
        } else {
            c->dn_len = hrw_rewrite_header(c->dn, c->dn_len, BUF_SIZE,
                                           "Location:", c->ifc->cfg.real_ip, c->ifc->cfg.virt_ip);
            c->resp_fixed = TRUE;
        }
    }
    can = tcp_sndbuf(c->pcb);
    if (can <= 0) return;
    n = c->dn_len < can ? c->dn_len : can;
    if (tcp_write(c->pcb, c->dn, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) return;
    tcp_output(c->pcb);
    memmove(c->dn, c->dn + n, (size_t)(c->dn_len - n));
    c->dn_len -= n;
}

/* --------------------------------------------------------------- DNS */
static void dnsq_free(DnsQ *d)
{
    if (!d->used) return;
    if (d->sock != INVALID_SOCKET) { closesocket(d->sock); d->sock = INVALID_SOCKET; }
    d->used = FALSE;
}

static void dns_on_query(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                         const ip_addr_t *addr, u16_t port)
{
    DnsQ *d = NULL;
    struct sockaddr_in a;
    int i;
    (void)arg; (void)pcb;

    if (!p) return;
    if (p->tot_len == 0 || p->tot_len > (u16_t)(sizeof(d->q) - 2)) { pbuf_free(p); return; }

    for (i = 0; i < MAX_DNSQ; i++) if (!g_dns[i].used) { d = &g_dns[i]; break; }
    if (!d) { pbuf_free(p); return; }

    {
        struct netif *in = ip_current_netif();
        if (!in || !in->state) { pbuf_free(p); return; }
        memset(d, 0, sizeof(*d));
        d->ifc = (Iface *)in->state;
    }
    d->used = TRUE;
    d->sock = INVALID_SOCKET;
    d->started = GetTickCount();
    ip_addr_copy(d->from, *addr);
    d->fromport = port;

    /* DNS поверх TCP отличается от UDP только двухбайтовым префиксом длины. */
    d->q[0] = (char)((p->tot_len >> 8) & 0xFF);
    d->q[1] = (char)(p->tot_len & 0xFF);
    pbuf_copy_partial(p, d->q + 2, p->tot_len, 0);
    d->qlen = p->tot_len + 2;
    pbuf_free(p);

    d->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (d->sock == INVALID_SOCKET) { dnsq_free(d); return; }
    WSAEventSelect(d->sock, g_sock_ev, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);

    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port   = htons((u_short)d->ifc->cfg.proxy_port);
    a.sin_addr.s_addr = inet_addr(d->ifc->cfg.proxy_ip);
    if (connect(d->sock, (struct sockaddr *)&a, sizeof(a)) != 0 &&
        WSAGetLastError() != WSAEWOULDBLOCK) { dnsq_free(d); return; }
    d->st = CS_CONNECTING;
}

static void dns_send_greeting(DnsQ *d)
{
    unsigned char b[4]; int n = 0;
    b[n++] = 0x05;
    if (d->ifc->cfg.user[0]) { b[n++] = 2; b[n++] = 0x00; b[n++] = 0x02; }
    else               { b[n++] = 1; b[n++] = 0x00; }
    if (send(d->sock, (char *)b, n, 0) != n) { dnsq_free(d); return; }
    d->st = CS_GREET;
}

static void dns_send_request(DnsQ *d)
{
    unsigned char b[16]; int n = 0;
    ip4_addr_t r;
    ip4addr_aton(d->ifc->cfg.dns_ip[0] ? d->ifc->cfg.dns_ip : "1.1.1.1", &r);
    b[n++] = 0x05; b[n++] = 0x01; b[n++] = 0x00; b[n++] = 0x01;
    memcpy(b + n, &r.addr, 4); n += 4;
    b[n++] = 0; b[n++] = 53;
    if (send(d->sock, (char *)b, n, 0) != n) { dnsq_free(d); return; }
    d->st = CS_REQUEST;
}

static void dns_on_readable(DnsQ *d)
{
    BOOL dead;
    int n;

    switch (d->st) {
    case CS_GREET:
        if (!hs_fill(d->sock, d->hs, &d->hslen, 2, &dead)) { if (dead) dnsq_free(d); return; }
        if (d->hs[0] != 0x05) { dnsq_free(d); return; }
        { unsigned char m = d->hs[1]; d->hslen = 0;
          if (m == 0x02) {
              size_t ul = strlen(d->ifc->cfg.user), pl = strlen(d->ifc->cfg.pass);
              unsigned char a[600]; int k = 0;
              a[k++] = 0x01;
              a[k++] = (unsigned char)ul; memcpy(a + k, d->ifc->cfg.user, ul); k += (int)ul;
              a[k++] = (unsigned char)pl; memcpy(a + k, d->ifc->cfg.pass, pl); k += (int)pl;
              if (send(d->sock, (char *)a, k, 0) != k) { dnsq_free(d); return; }
              d->st = CS_AUTH;
          } else if (m == 0x00) dns_send_request(d);
          else dnsq_free(d); }
        return;

    case CS_AUTH:
        if (!hs_fill(d->sock, d->hs, &d->hslen, 2, &dead)) { if (dead) dnsq_free(d); return; }
        if (d->hs[1] != 0x00) { dnsq_free(d); return; }
        d->hslen = 0;
        dns_send_request(d);
        return;

    case CS_REQUEST: {
        int need;
        if (!hs_fill(d->sock, d->hs, &d->hslen, 4, &dead)) { if (dead) dnsq_free(d); return; }
        if (d->hs[0] != 0x05 || d->hs[1] != 0x00) { dnsq_free(d); return; }
        need = (d->hs[3] == 0x01) ? 4 + 4 + 2 : (d->hs[3] == 0x04) ? 4 + 16 + 2 : -1;
        if (need < 0) {
            if (!hs_fill(d->sock, d->hs, &d->hslen, 5, &dead)) { if (dead) dnsq_free(d); return; }
            need = 4 + 1 + d->hs[4] + 2;
        }
        if (!hs_fill(d->sock, d->hs, &d->hslen, need, &dead)) { if (dead) dnsq_free(d); return; }
        d->hslen = 0;
        d->st = CS_OPEN;
        if (send(d->sock, d->q, d->qlen, 0) == d->qlen) d->qsent = d->qlen;
        return;
    }

    case CS_OPEN: {
        int room = (int)sizeof(d->r) - d->rlen;
        if (room <= 0) { dnsq_free(d); return; }
        n = recv(d->sock, d->r + d->rlen, room, 0);
        if (n <= 0) { dnsq_free(d); return; }
        d->rlen += n;
        if (d->rlen >= 2) {
            int want = ((unsigned char)d->r[0] << 8) | (unsigned char)d->r[1];
            if (d->rlen >= want + 2) {
                struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)want, PBUF_RAM);
                if (p) {
                    pbuf_take(p, d->r + 2, (u16_t)want);   /* префикс длины снимаем */
                    udp_sendto(g_udp, p, &d->from, d->fromport);
                    pbuf_free(p);
                }
                dnsq_free(d);
            }
        }
        return;
    }
    default: return;
    }
}

static void dns_pump(void)
{
    int i;
    DWORD now = GetTickCount();
    for (i = 0; i < MAX_DNSQ; i++) {
        DnsQ *d = &g_dns[i];
        WSANETWORKEVENTS ne;
        if (!d->used) continue;
        if (now - d->started > DNS_TTL_MS) { dnsq_free(d); continue; }
        if (d->sock == INVALID_SOCKET) { dnsq_free(d); continue; }
        if (WSAEnumNetworkEvents(d->sock, NULL, &ne) != 0) continue;
        if (ne.lNetworkEvents & FD_CONNECT) {
            if (ne.iErrorCode[FD_CONNECT_BIT] != 0) { dnsq_free(d); continue; }
            dns_send_greeting(d);
        }
        if (ne.lNetworkEvents & FD_READ)  dns_on_readable(d);
        if (ne.lNetworkEvents & FD_CLOSE) { if (d->used) dnsq_free(d); }
    }
}

/* --------------------------------------------------------------- netif */
static err_t netif_linkoutput(struct netif *nif, struct pbuf *p)
{
    /* Буфер на стеке, а не статический: интерфейсов много, и общий буфер
     * пришлось бы защищать — при том что поток всё равно один. */
    char frame[TAP_FRAME_MAX];
    Iface *ifc = (Iface *)nif->state;
    struct pbuf *q;
    int len = 0;

    if (!ifc) return ERR_IF;
    for (q = p; q != NULL; q = q->next) {
        if (len + q->len > (int)sizeof(frame)) return ERR_BUF;
        memcpy(frame + len, q->payload, q->len);
        len += q->len;
    }
    return tap_write(ifc->tap, frame, len) ? ERR_OK : ERR_IF;
}

static err_t netif_init_cb(struct netif *nif)
{
    Iface *ifc = (Iface *)nif->state;
    unsigned char mac[6];

    if (!ifc) return ERR_ARG;
    nif->name[0] = 'm'; nif->name[1] = 'l';
    nif->output     = etharp_output;
    nif->linkoutput = netif_linkoutput;
    nif->mtu        = TAP_MTU;
    nif->hwaddr_len = 6;
    if (!tap_get_mac(ifc->tap, mac)) memset(mac, 0, 6);
    memcpy(nif->hwaddr, mac, 6);

    /* ACCEPT_ANY — наша правка: без неё lwIP выбросит всё, что адресовано не
     * этому интерфейсу, то есть ровно тот трафик, ради которого он и создан. */
    nif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP |
                 NETIF_FLAG_ETHERNET  | NETIF_FLAG_LINK_UP |
                 NETIF_FLAG_ACCEPT_ANY;
    return ERR_OK;
}

/* --------------------------------------------------------------- петля */
static void pump_all(void)
{
    int i;
    for (i = 0; i < MAX_CONNS; i++) {
        Conn *c = &g_conns[i];
        if (c->st == CS_FREE) continue;

        /* Порядок здесь принципиален. Прокси закрывает соединение сразу вслед
         * за ответом — мы сами просим Connection: close, — поэтому CS_DEAD
         * почти всегда наступает, когда ответ уже лежит в буфере. Убить
         * соединение раньше, чем оно отдано клиенту, значит потерять ответ
         * целиком: транзит этого не замечал, а короткий запрос-ответ ломался. */
        drain_up(c);
        drain_down(c);
        if (c->st == CS_DEAD && c->dn_len == 0) conn_kill(c);
    }
}

static void handle_socket_events(void)
{
    int i;
    for (i = 0; i < MAX_CONNS; i++) {
        Conn *c = &g_conns[i];
        WSANETWORKEVENTS ne;
        if (c->st == CS_FREE || c->st == CS_DEAD || c->sock == INVALID_SOCKET) continue;
        if (WSAEnumNetworkEvents(c->sock, NULL, &ne) != 0) continue;

        if (ne.lNetworkEvents & FD_CONNECT) {
            if (ne.iErrorCode[FD_CONNECT_BIT] != 0) { ml_log("tunnel: connect к прокси не удался (%d)", ne.iErrorCode[FD_CONNECT_BIT]); c->st = CS_DEAD; continue; }
            socks_send_greeting(c);
        }
        if (ne.lNetworkEvents & FD_READ)  socks_on_readable(c);
        if (ne.lNetworkEvents & FD_CLOSE) {
            socks_on_readable(c);                 /* дочитать хвост */
            if (c->st == CS_OPEN && c->dn_len == 0) c->st = CS_DEAD;
            else if (c->st != CS_OPEN)             c->st = CS_DEAD;
        }
        if (ne.lNetworkEvents & FD_WRITE) drain_up(c);
    }
}

static DWORD WINAPI loop_thread(LPVOID arg)
{
    /* Ждём: [0] остановка, [1] события всех сокетов, дальше по одному
     * событию на интерфейс. Сорок адаптеров дают 42 объекта — с запасом
     * укладывается в лимит WaitForMultipleObjects в 64. */
    HANDLE wait[2 + TUNNEL_MAX_IFACES];
    int    map[TUNNEL_MAX_IFACES];
    int    nwait, i;
    (void)arg;

    for (;;) {
        DWORD timeout, w;

        /* Держим по одному чтению в очереди на каждый интерфейс. Пока все
         * висят, поток спит. */
        nwait = 0;
        wait[nwait++] = g_stop_ev;
        wait[nwait++] = (HANDLE)g_sock_ev;
        for (i = 0; i < g_niface; i++) {
            Iface *f = &g_ifaces[i];
            if (!f->used) continue;
            if (!f->pending) {
                BOOL done = FALSE;
                if (!tap_read_begin(f->tap, f->frame, sizeof(f->frame), &f->ov, &done)) {
                    ml_log("tunnel[%s]: чтение из TAP не удалось, интерфейс снят", f->cfg.label);
                    f->used = FALSE;
                    continue;
                }
                f->pending = TRUE;
                if (done) SetEvent(f->ov.hEvent);
            }
            map[nwait - 2] = i;
            wait[nwait++] = f->ov.hEvent;
        }

        timeout = sys_timeouts_sleeptime();
        if (timeout == SYS_TIMEOUTS_SLEEPTIME_INFINITE) timeout = 1000;
        else if (timeout > 1000) timeout = 1000;

        w = WaitForMultipleObjects((DWORD)nwait, wait, FALSE, timeout);
        if (w == WAIT_OBJECT_0) break;                      /* остановка */

        if (w == WAIT_OBJECT_0 + 1) {
            /* Событие сокетов общее, поэтому сбрасываем его сами и перечисляем
             * с NULL — иначе WSAEnumNetworkEvents сбросит его за нас и сигнал,
             * пришедший во время обхода, потеряется. */
            WSAResetEvent(g_sock_ev);
        } else if (w > WAIT_OBJECT_0 + 1 && w < WAIT_OBJECT_0 + (DWORD)nwait) {
            Iface *f = &g_ifaces[map[w - WAIT_OBJECT_0 - 2]];
            int got = 0;
            f->pending = FALSE;
            if (!tap_read_end(f->tap, &f->ov, &got)) {
                ml_log("tunnel[%s]: чтение из TAP не удалось, интерфейс снят", f->cfg.label);
                f->used = FALSE;
            } else if (got > 0) {
                struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)got, PBUF_POOL);
                if (p) {
                    pbuf_take(p, f->frame, (u16_t)got);
                    if (f->netif.input(p, &f->netif) != ERR_OK) pbuf_free(p);
                }
            }
        }

        handle_socket_events();
        pump_all();
        dns_pump();
        sys_check_timeouts();

        if (InterlockedCompareExchange(&g_stop, 0, 0)) break;
    }

    for (i = 0; i < g_niface; i++)
        if (g_ifaces[i].pending) tap_read_cancel(g_ifaces[i].tap, &g_ifaces[i].ov);
    for (i = 0; i < MAX_CONNS; i++) conn_kill(&g_conns[i]);
    for (i = 0; i < MAX_DNSQ;  i++) dnsq_free(&g_dns[i]);
    return 0;
}

/* --------------------------------------------------------------- запуск */
static BOOL iface_up(Iface *f, const TunnelCfg *cfg, char *err, size_t errcap)
{
    ip4_addr_t mask, gw;

    memset(f, 0, sizeof(*f));
    f->cfg = *cfg;
    f->tap = INVALID_HANDLE_VALUE;

    f->tap = tap_open(f->cfg.guid, err, errcap);
    if (f->tap == INVALID_HANDLE_VALUE) return FALSE;

    f->ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!f->ov.hEvent) {
        if (err) ml_strlcpy(err, "не удалось создать событие чтения", errcap);
        tap_close(f->tap); f->tap = INVALID_HANDLE_VALUE;
        return FALSE;
    }

    ip4addr_aton(f->cfg.virt_ip, &f->ip);
    ip4addr_aton(f->cfg.netmask[0] ? f->cfg.netmask : "255.255.255.0", &mask);
    ip4_addr_set_zero(&gw);

    /* state = сам интерфейс: по нему обработчики lwIP узнают, чей это пакет. */
    if (!netif_add(&f->netif, &f->ip, &mask, &gw, f, netif_init_cb, ethernet_input)) {
        if (err) ml_strlcpy(err, "не удалось создать netif", errcap);
        CloseHandle(f->ov.hEvent);
        tap_close(f->tap); f->tap = INVALID_HANDLE_VALUE;
        return FALSE;
    }
    netif_set_up(&f->netif);
    netif_set_link_up(&f->netif);

    f->used = TRUE;
    return TRUE;
}

BOOL tunnel_start(const TunnelCfg *cfgs, int count, char *err, size_t errcap)
{
    struct tcp_pcb *pcb;
    int i, up = 0;

    if (err && errcap) err[0] = 0;
    if (count <= 0) {
        if (err) ml_strlcpy(err, "список интерфейсов пуст", errcap);
        return FALSE;
    }
    if (count > TUNNEL_MAX_IFACES) count = TUNNEL_MAX_IFACES;

    g_sock_ev = WSACreateEvent();
    if (g_sock_ev == WSA_INVALID_EVENT) {
        if (err) ml_strlcpy(err, "не удалось создать событие сокетов", errcap);
        return FALSE;
    }

    lwip_init();

    for (i = 0; i < count; i++) {
        char e[256];
        if (iface_up(&g_ifaces[g_niface], &cfgs[i], e, sizeof(e))) {
            ml_log("tunnel[%s]: %s на %s -> SOCKS5 %s:%d",
                   cfgs[i].label, cfgs[i].virt_ip, cfgs[i].guid,
                   cfgs[i].proxy_ip, cfgs[i].proxy_port);
            g_niface++;
            up++;
        } else {
            /* Один занятый адаптер не должен лишать связи остальные. */
            ml_log("tunnel[%s]: не поднят — %s", cfgs[i].label, e);
        }
    }
    if (!up) {
        if (err) ml_strlcpy(err, "не удалось поднять ни одного интерфейса", errcap);
        return FALSE;
    }
    netif_set_default(&g_ifaces[0].netif);

    /* Слушатель-ловушка один на все интерфейсы: порт 0 — условная метка
     * «любой порт», её понимает наша правка в tcp_in.c. */
    pcb = tcp_new();
    if (!pcb) { if (err) ml_strlcpy(err, "нет памяти под pcb", errcap); return FALSE; }
    tcp_bind(pcb, IP_ANY_TYPE, 9);
    g_listener = tcp_listen_with_backlog(pcb, TCP_DEFAULT_LISTEN_BACKLOG);
    if (!g_listener) {
        if (err) ml_strlcpy(err, "не удалось перевести pcb в listen", errcap);
        tcp_abort(pcb);
        return FALSE;
    }
    g_listener->local_port = 0;
    tcp_accept(g_listener, lw_accept);

    /* DNS: udp_input сопоставляет pcb по порту, а адрес уже принят флагом
     * ACCEPT_ANY — один pcb на порту 53 ловит запросы со всех интерфейсов. */
    g_udp = udp_new();
    if (g_udp) {
        udp_bind(g_udp, IP_ANY_TYPE, 53);
        udp_recv(g_udp, dns_on_query, NULL);
    }

    g_stop = 0;
    g_stop_ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    g_thread  = CreateThread(NULL, 0, loop_thread, NULL, 0, NULL);
    if (!g_thread) {
        if (err) ml_strlcpy(err, "не удалось создать поток петли", errcap);
        return FALSE;
    }

    ml_log("tunnel: поднято интерфейсов %d из %d", up, count);
    return TRUE;
}

int tunnel_iface_count(void) { return g_niface; }

void tunnel_stop(void)
{
    int i;
    if (!g_thread) return;
    InterlockedExchange(&g_stop, 1);
    if (g_stop_ev) SetEvent(g_stop_ev);      /* будим петлю, а не ждём таймаута */
    WaitForSingleObject(g_thread, 5000);
    CloseHandle(g_thread);
    g_thread = NULL;

    for (i = 0; i < g_niface; i++) {
        Iface *f = &g_ifaces[i];
        if (f->ov.hEvent) { CloseHandle(f->ov.hEvent); f->ov.hEvent = NULL; }
        if (f->tap != INVALID_HANDLE_VALUE) { tap_close(f->tap); f->tap = INVALID_HANDLE_VALUE; }
        f->used = FALSE;
    }
    g_niface = 0;

    if (g_stop_ev) { CloseHandle(g_stop_ev); g_stop_ev = NULL; }
    if (g_sock_ev != WSA_INVALID_EVENT) { WSACloseEvent(g_sock_ev); g_sock_ev = WSA_INVALID_EVENT; }
}
