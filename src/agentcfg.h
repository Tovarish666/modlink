/* modlink-agent — чтение и запись конфига интерфейсов (config.json агента).
 * Один формат для консольного запуска (--config) и для GUI, чтобы панель и
 * автозапуск видели одно и то же. */
#ifndef MODLINK_AGENTCFG_H
#define MODLINK_AGENTCFG_H

#include "common.h"
#include "tunnel.h"

const char *agentcfg_path(void);   /* %ProgramData%\modlink\agent.json */

/* Читает массив interfaces. Возвращает число прочитанных (0..cap) или -1 при
 * ошибке чтения/разбора (текст в err). Пустой/отсутствующий файл — это 0, не
 * ошибка: свежая установка стартует с пустым списком. */
int  agentcfg_load(const char *path, TunnelCfg *out, int cap, char *err, size_t errcap);
BOOL agentcfg_save(const char *path, const TunnelCfg *list, int count);

#endif
