/* modlink — минимальный клиент SOCKS5 (RFC 1928 + RFC 1929).
 *
 * Ровно столько, сколько нужно агенту: приветствие, необязательная
 * аутентификация по логину/паролю и CONNECT на IPv4-адрес. UDP ASSOCIATE и
 * BIND не поддерживаются — 3proxy в режиме `auto` их для нашей задачи и не
 * требует. */
#ifndef MODLINK_SOCKS5_H
#define MODLINK_SOCKS5_H

#include "common.h"
#include <winsock2.h>

/* Открывает TCP-сессию к прокси и просит соединить с dst_ip:dst_port.
 * Возвращает готовый к обмену сокет или INVALID_SOCKET; текст ошибки — в err. */
SOCKET socks5_connect(const char *proxy_ip, int proxy_port,
                      const char *user, const char *pass,
                      const char *dst_ip, int dst_port,
                      int timeout_ms, char *err, size_t errcap);

#endif
