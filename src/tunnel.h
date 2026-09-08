/* modlink-agent — туннель: TAP → lwIP → SOCKS5.
 *
 * Пакеты, которые система отправляет в TAP-адаптер, разбирает lwIP; каждое
 * TCP-соединение терминируется здесь и переоткрывается наружу через SOCKS5
 * сервера modlink. Для клиента это выглядит как обычный сетевой интерфейс,
 * а трафик уходит через LTE конкретного модема.
 *
 * Всё крутится в одном потоке: lwIP собран с NO_SYS, и его API нельзя звать
 * откуда попало. Сокеты поэтому неблокирующие, а рукопожатие SOCKS5 — автомат. */
#ifndef MODLINK_TUNNEL_H
#define MODLINK_TUNNEL_H

#include "common.h"
#include "tap.h"

typedef struct {
    char guid[TAP_GUID_LEN];      /* какой TAP-адаптер занимать */
    char virt_ip [ML_ADDR_LEN];   /* адрес netif — он же шлюз с точки зрения клиента */
    char netmask [ML_ADDR_LEN];
    char proxy_ip[ML_ADDR_LEN];
    int  proxy_port;
    char user[ML_LOGIN_LEN];
    char pass[ML_PASS_LEN];
} TunnelCfg;

BOOL tunnel_start(const TunnelCfg *cfg, char *err, size_t errcap);
void tunnel_stop(void);
/* Счётчики для строки состояния: сколько соединений живо и сколько прошло. */
void tunnel_stats(int *active, int *total, unsigned long long *bytes_up,
                  unsigned long long *bytes_down);

#endif
