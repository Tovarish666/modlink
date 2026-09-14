/* modlink-agent — слой архитектуры для lwIP под Windows (MSVC и mingw). */
#ifndef MODLINK_LWIP_ARCH_CC_H
#define MODLINK_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

/* x86/x64 — little endian всегда */
#define BYTE_ORDER LITTLE_ENDIAN

typedef int sys_prot_t;

/* MSVC до C99 не знает snprintf под этим именем; у mingw он есть. */
#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf
#endif

#define LWIP_NO_UNISTD_H  1
#define LWIP_TIMEVAL_PRIVATE 1

/* Формат-строки для отладочных сообщений lwIP. */
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"

/* Упаковка структур: MSVC делает через pragma pack, gcc/clang — через атрибут. */
#if defined(_MSC_VER)
#define PACK_STRUCT_BEGIN __pragma(pack(push, 1))
#define PACK_STRUCT_END   __pragma(pack(pop))
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_FIELD(x) x
#else
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_FIELD(x) x
#endif

/* Провал внутренней проверки lwIP — это наша ошибка в интеграции, а не штатная
 * ситуация. Печатаем громко, чтобы не искать потом молчаливое повреждение. */
#define LWIP_PLATFORM_DIAG(x)   do { printf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { \
    printf("lwIP assert: %s (%s:%d)\n", x, __FILE__, __LINE__); \
    fflush(stdout); abort(); } while (0)

#endif
