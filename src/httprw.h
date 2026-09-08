/* modlink-agent — правка HTTP-заголовков на лету.
 *
 * Нужна и посреднику, и туннелю: прошивка E3372 сверяет Host со своим адресом
 * и на чужой отвечает 307 вместо данных, а в Location подставляет свой
 * настоящий адрес и увела бы браузер с виртуального. Измерено на живом модеме. */
#ifndef MODLINK_HTTPRW_H
#define MODLINK_HTTPRW_H

#include <stddef.h>

/* Поиск подстроки без учёта регистра. -1, если нет. */
int  hrw_find_ci(const char *hay, size_t hlen, const char *needle);
/* Конец блока заголовков (индекс после CRLFCRLF) или -1, если он ещё не весь. */
int  hrw_headers_end(const char *buf, int len);
/* Заменяет `from` на `to` в значении заголовка `name`. Возвращает новую длину. */
int  hrw_rewrite_header(char *buf, int len, int cap,
                        const char *name, const char *from, const char *to);
/* Дописывает Connection: close после строки запроса — так разбор остаётся
 * однопроходным вместо конечного автомата на keep-alive. */
int  hrw_force_close(char *buf, int len, int cap);

#endif
