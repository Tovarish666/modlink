/* modlink-agent — туннели: TAP → lwIP → SOCKS5.
 *
 * Пакеты, которые система отправляет в TAP-адаптер, разбирает lwIP; каждое
 * TCP-соединение терминируется здесь и переоткрывается наружу через SOCKS5
 * сервера modlink. Для клиента это обычный сетевой интерфейс, а трафик уходит
 * через LTE конкретного модема.
 *
 * Интерфейсов может быть много, но lwIP в режиме NO_SYS держит своё состояние
 * в глобальных переменных — второго экземпляра не завести. Поэтому схема
 * такая: один поток, один lwIP, по netif на каждый адаптер. Заодно это дёшево:
 * сорок интерфейсов ждут в одном WaitForMultipleObjects вместе с общим
 * событием сокетов, укладываясь в лимит в 64 объекта. */
#ifndef MODLINK_TUNNEL_H
#define MODLINK_TUNNEL_H

#include "common.h"
#include "tap.h"

#define TUNNEL_MAX_IFACES 48

typedef struct {
    char guid[TAP_GUID_LEN];      /* какой TAP-адаптер занимать */
    char virt_ip [ML_ADDR_LEN];   /* адрес netif — он же шлюз с точки зрения клиента */
    char netmask [ML_ADDR_LEN];
    char real_ip [ML_ADDR_LEN];   /* настоящая веб-морда модема; пусто — не обслуживать */
    char proxy_ip[ML_ADDR_LEN];
    int  proxy_port;
    char user[ML_LOGIN_LEN];
    char pass[ML_PASS_LEN];
    char dns_ip[ML_ADDR_LEN];     /* резолвер; пусто — 1.1.1.1 */
    char label[64];               /* для сообщений и статистики */
} TunnelCfg;

/* Поднимает все интерфейсы разом. Если какой-то поднять не удалось, он
 * пропускается с записью в лог, а остальные работают: один занятый адаптер не
 * должен лишать связи оставшиеся тридцать девять. Возвращает FALSE, только
 * если не поднялся ни один. */
BOOL tunnel_start(const TunnelCfg *cfgs, int count, char *err, size_t errcap);
void tunnel_stop(void);

int  tunnel_iface_count(void);
void tunnel_stats(int *active, int *total, unsigned long long *bytes_up,
                  unsigned long long *bytes_down);

#endif
