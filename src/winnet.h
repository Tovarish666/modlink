/* modlink-agent — жизненный цикл виртуального адаптера.
 *
 * Всё, что раньше делалось руками через devcon + PowerShell: создать TAP,
 * замаскировать под USB-модем, задать адрес/маску/шлюз/метрику/DNS, удалить.
 * Через SetupAPI и IP Helper — без внешнего devcon.exe, чтобы не таскать
 * бинарь с ограничениями лицензии WDK. */
#ifndef MODLINK_WINNET_H
#define MODLINK_WINNET_H

#include "common.h"

/* Создаёт новый экземпляр адаптера tap0901. inf_path — путь к OemVista.inf.
 * В out_guid кладёт NetCfgInstanceId нового адаптера ({XXXX-...}). */
BOOL winnet_create_adapter(const char *inf_path, char *out_guid, size_t guidcap,
                           char *err, size_t errcap);

/* Удаляет адаптер по GUID (DIF_REMOVE). */
BOOL winnet_remove_adapter(const char *guid, char *err, size_t errcap);

/* Маскировка: описание, MAC и производитель в реестре. mac_hex — 12 hex-цифр
 * без разделителей; драйвер требует установленный бит locally-administered
 * (второй бит первого октета), иначе молча берёт свой. */
BOOL winnet_disguise(const char *guid, const char *desc, const char *mac_hex,
                     const char *vendor, char *err, size_t errcap);

/* Назначает адрес/маску, шлюз с метрикой и DNS. Прежние IPv4-адреса и маршруты
 * по умолчанию на интерфейсе снимаются. Метрика по умолчанию 5000 — иначе
 * виртуальный адаптер может перехватить маршрут по умолчанию. */
BOOL winnet_configure(const char *guid, const char *ip, int prefix,
                      const char *gateway, const char *dns, int metric,
                      char *err, size_t errcap);

/* Имя адаптера (NetConnectionID) — то, что видно в «Сетевых подключениях». */
BOOL winnet_rename(const char *guid, const char *new_name, char *err, size_t errcap);

/* Передёрнуть адаптер (disable/enable), чтобы драйвер перечитал реестр. */
BOOL winnet_cycle(const char *guid, char *err, size_t errcap);

#endif
