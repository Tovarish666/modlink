/* modlink — HTTP-посредник для веб-морды модема.
 *
 * Слушает виртуальный адрес (192.168.N.1), ходит через SOCKS5 на настоящий
 * (192.168.real.1) и правит заголовки в обе стороны. Без этого никак:
 * прошивка E3372 сверяет Host со своим адресом и на чужой отдаёт 307 вместо
 * данных — измерено на живом модеме, запрос к /api/webserver/SesTokInfo даёт
 * 200 и 277 байт с правильным Host и 307 с чужим. */
#ifndef MODLINK_MEDIATOR_H
#define MODLINK_MEDIATOR_H

#include "common.h"

typedef struct {
    char virt_ip [ML_ADDR_LEN];   /* что видит клиент, напр. 192.168.55.1  */
    char real_ip [ML_ADDR_LEN];   /* настоящая морда,  напр. 192.168.105.1 */
    char proxy_ip[ML_ADDR_LEN];
    int  proxy_port;
    char user[ML_LOGIN_LEN];
    char pass[ML_PASS_LEN];
    int  listen_port;             /* обычно 80 */
} MediatorCfg;

BOOL mediator_start(const MediatorCfg *cfg, char *err, size_t errcap);
void mediator_stop(void);

#endif
