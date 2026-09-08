/* modlink-agent — TAP-устройство (tap-windows6).
 *
 * Адаптер опознаётся по GUID (NetCfgInstanceId), а не по имени: имя — это
 * NetConnectionID, пользователь волен переименовать его хоть в «сеть2», и
 * привязка к имени сломалась бы молча. */
#ifndef MODLINK_TAP_H
#define MODLINK_TAP_H

#include "common.h"

#define TAP_GUID_LEN 64
#define TAP_MTU      1500
#define TAP_FRAME_MAX (TAP_MTU + 14 + 4)   /* + Ethernet-заголовок и запас */

typedef struct {
    char guid[TAP_GUID_LEN];      /* {XXXXXXXX-....} */
    char name[128];               /* NetConnectionID, только для сообщений */
    char desc[128];               /* описание устройства */
    char regkey[16];              /* подкаталог классового ключа, напр. 0016 */
} TapAdapter;

/* Перечисляет установленные адаптеры tap0901. Возвращает количество. */
int  tap_enumerate(TapAdapter *out, int cap);
/* Ищет по GUID; FALSE, если такого нет. */
BOOL tap_find_by_guid(const char *guid, TapAdapter *out);

/* Открывает устройство и поднимает линк. INVALID_HANDLE_VALUE при неудаче. */
HANDLE tap_open(const char *guid, char *err, size_t errcap);
void   tap_close(HANDLE h);

/* MAC, который драйвер реально использует. */
BOOL tap_get_mac(HANDLE h, unsigned char mac[6]);

/* Блокирующие чтение и запись Ethernet-кадра целиком.
 * tap_read ждёт не дольше timeout_ms; 0 означает «истёк таймаут, кадра нет»,
 * отрицательное — ошибку устройства. */
int  tap_read (HANDLE h, void *buf, int cap, int timeout_ms);
BOOL tap_write(HANDLE h, const void *buf, int len);

#endif
