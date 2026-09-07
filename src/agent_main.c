/* modlink-agent — клиентская сторона.
 *
 * Сейчас умеет одно, но целиком: отдаёт веб-морду модема на виртуальном
 * адресе. Клиент открывает http://192.168.N.1, посредник ходит через SOCKS5 на
 * 192.168.real.1 и правит Host и Location, чтобы прошивка отвечала данными, а
 * не редиректом на свой настоящий адрес.
 *
 * Туннелирование интернета (TAP + userspace TCP/IP) — следующий этап и
 * отдельный кусок работы; здесь его нет. */
#include "common.h"
#include "mediator.h"
#include <winsock2.h>
#include <stdlib.h>
#include <string.h>

static volatile BOOL g_running = TRUE;

static BOOL WINAPI on_break(DWORD type)
{
    (void)type;
    g_running = FALSE;
    return TRUE;
}

static void usage(void)
{
    printf(
    "modlink-agent — виртуальный адрес модема\n"
    "\n"
    "Использование:\n"
    "  modlink-agent --virt <ip> --real <ip> --proxy <ip:port> [--user U --pass P] [--port N]\n"
    "\n"
    "  --virt   адрес, на котором слушаем, напр. 192.168.55.1\n"
    "           (должен быть назначен на адаптер, иначе занять его нельзя)\n"
    "  --real   настоящая веб-морда модема,   напр. 192.168.105.1\n"
    "  --proxy  SOCKS5 сервера modlink,       напр. 192.168.1.20:15000\n"
    "  --user   логин прокси\n"
    "  --pass   пароль прокси\n"
    "  --port   порт прослушивания, по умолчанию 80\n"
    "\n"
    "Пример:\n"
    "  modlink-agent --virt 192.168.55.1 --real 192.168.105.1 \\\n"
    "                --proxy 192.168.1.20:15000 --user modem1 --pass 5hzsn8bmrp\n");
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    MediatorCfg cfg;
    char err[512];
    int i;

    memset(&cfg, 0, sizeof(cfg));
    cfg.listen_port = 80;

    for (i = 1; i < argc; i++) {
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if      (!strcmp(argv[i], "--virt")  && v) { ml_strlcpy(cfg.virt_ip, v, sizeof(cfg.virt_ip)); i++; }
        else if (!strcmp(argv[i], "--real")  && v) { ml_strlcpy(cfg.real_ip, v, sizeof(cfg.real_ip)); i++; }
        else if (!strcmp(argv[i], "--user")  && v) { ml_strlcpy(cfg.user,    v, sizeof(cfg.user));    i++; }
        else if (!strcmp(argv[i], "--pass")  && v) { ml_strlcpy(cfg.pass,    v, sizeof(cfg.pass));    i++; }
        else if (!strcmp(argv[i], "--port")  && v) { cfg.listen_port = atoi(v); i++; }
        else if (!strcmp(argv[i], "--proxy") && v) {
            const char *colon = strrchr(v, ':');
            if (!colon) { fprintf(stderr, "  --proxy ждёт вид ip:port\n"); return 2; }
            {
                size_t n = (size_t)(colon - v);
                if (n >= sizeof(cfg.proxy_ip)) n = sizeof(cfg.proxy_ip) - 1;
                memcpy(cfg.proxy_ip, v, n);
                cfg.proxy_ip[n] = 0;
            }
            cfg.proxy_port = atoi(colon + 1);
            i++;
        }
        else { usage(); return 2; }
    }

    if (!cfg.virt_ip[0] || !cfg.real_ip[0] || !cfg.proxy_ip[0] || !cfg.proxy_port) {
        usage();
        return 2;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "  Winsock не инициализируется\n");
        return 1;
    }
    SetConsoleCtrlHandler(on_break, TRUE);
    ml_ensure_dirs();

    printf("  %s:%d  ->  %s\n", cfg.virt_ip, cfg.listen_port, cfg.real_ip);
    printf("  через SOCKS5 %s:%d%s%s\n", cfg.proxy_ip, cfg.proxy_port,
           cfg.user[0] ? ", логин " : "", cfg.user[0] ? cfg.user : "");

    if (!mediator_start(&cfg, err, sizeof(err))) {
        fprintf(stderr, "\n  ОШИБКА: %s\n", err);
        WSACleanup();
        return 1;
    }

    printf("\n  Работает. Открой в браузере http://%s/\n", cfg.virt_ip);
    printf("  Ctrl+C — остановить.\n\n");

    while (g_running) Sleep(200);

    printf("  останавливаюсь...\n");
    mediator_stop();
    WSACleanup();
    return 0;
}
