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
#include "tunnel.h"
#include "tap.h"
#include "json.h"
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
    "  --tap    GUID TAP-адаптера — включает туннелирование интернета\n"
    "  --mask   маска для туннеля, по умолчанию 255.255.255.0\n"
    "\n"
    "  --list-tap   показать TAP-адаптеры и их GUID, и выйти\n"
    "\n"
    "  --config <файл>  поднять все интерфейсы из JSON — так и задают сорок штук:\n"
    "     { \"interfaces\": [\n"
    "         { \"label\": \"modem1\", \"tap\": \"{GUID}\",\n"
    "           \"virt\": \"192.168.55.1\", \"real\": \"192.168.105.1\",\n"
    "           \"proxy\": \"192.168.1.20:15000\",\n"
    "           \"user\": \"modem1\", \"pass\": \"...\" } ] }\n"
    "\n"
    "Пример:\n"
    "  modlink-agent --virt 192.168.55.1 --real 192.168.105.1 \\\n"
    "                --proxy 192.168.1.20:15000 --user modem1 --pass 5hzsn8bmrp\n");
}

/* Разбор конфига агента. Формат намеренно повторяет строку прокси из modlink
 * («ip:port:логин:пароль»), чтобы её можно было скопировать кнопкой
 * «Копировать» и вставить сюда без переписывания. */
static int load_config(const char *path, TunnelCfg *out, int cap, char *err, size_t errcap)
{
    char *text = NULL;
    size_t len = 0;
    JVal *root;
    const JVal *arr, *it;
    int n = 0;

    if (!ml_read_file(path, &text, &len) || !text) {
        snprintf(err, errcap, "не удалось прочитать %s", path);
        return -1;
    }
    root = json_parse(text);
    free(text);
    if (!root) { snprintf(err, errcap, "%s — не валидный JSON", path); return -1; }

    arr = json_get(root, "interfaces");
    if (!arr || arr->type != J_ARR) {
        snprintf(err, errcap, "в %s нет массива interfaces", path);
        json_free(root);
        return -1;
    }

    for (it = arr->child; it && n < cap; it = it->next) {
        TunnelCfg *t;
        const char *proxy;
        if (it->type != J_OBJ) continue;
        t = &out[n];
        memset(t, 0, sizeof(*t));
        ml_strlcpy(t->guid,    json_str(it, "tap",   ""),              sizeof(t->guid));
        ml_strlcpy(t->virt_ip, json_str(it, "virt",  ""),              sizeof(t->virt_ip));
        ml_strlcpy(t->netmask, json_str(it, "mask",  "255.255.255.0"), sizeof(t->netmask));
        ml_strlcpy(t->real_ip, json_str(it, "real",  ""),              sizeof(t->real_ip));
        ml_strlcpy(t->user,    json_str(it, "user",  ""),              sizeof(t->user));
        ml_strlcpy(t->pass,    json_str(it, "pass",  ""),              sizeof(t->pass));
        ml_strlcpy(t->dns_ip,  json_str(it, "dns",   ""),              sizeof(t->dns_ip));
        ml_strlcpy(t->label,   json_str(it, "label", ""),              sizeof(t->label));

        proxy = json_str(it, "proxy", "");
        if (proxy[0]) {
            const char *colon = strrchr(proxy, ':');
            if (colon) {
                size_t k = (size_t)(colon - proxy);
                if (k >= sizeof(t->proxy_ip)) k = sizeof(t->proxy_ip) - 1;
                memcpy(t->proxy_ip, proxy, k);
                t->proxy_ip[k] = 0;
                t->proxy_port = atoi(colon + 1);
            }
        }
        if (!t->label[0]) ml_strlcpy(t->label, t->virt_ip, sizeof(t->label));
        if (!t->guid[0] || !t->virt_ip[0] || !t->proxy_ip[0] || !t->proxy_port) {
            fprintf(stderr, "  пропускаю «%s»: не хватает tap, virt или proxy\n", t->label);
            continue;
        }
        n++;
    }
    json_free(root);
    if (n == 0) snprintf(err, errcap, "в %s не нашлось ни одного пригодного интерфейса", path);
    return n;
}

static void list_tap(void)
{
    TapAdapter a[32];
    int n = tap_enumerate(a, 32), i;
    printf("  TAP-адаптеров найдено: %d\n\n", n);
    for (i = 0; i < n; i++)
        printf("  %-40s  %s\n      %s\n", a[i].guid,
               a[i].name[0] ? a[i].name : "(без имени)", a[i].desc);
    if (!n) printf("  Драйвер установлен? Адаптер создан через devcon?\n");
}

int main(int argc, char **argv)
{
    WSADATA wsa;
    MediatorCfg cfg;
    TunnelCfg   tcfg;
    char err[512];
    char tap_guid[TAP_GUID_LEN] = {0};
    char cfg_path[ML_PATH_LEN] = {0};
    static TunnelCfg tlist[TUNNEL_MAX_IFACES];
    int  tcount = 0;
    char tap_mask[ML_ADDR_LEN]  = "255.255.255.0";
    BOOL tunnel_on = FALSE;
    int i;

    memset(&cfg,  0, sizeof(cfg));
    memset(&tcfg, 0, sizeof(tcfg));
    cfg.listen_port = 80;

    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "--list-tap")) { list_tap(); return 0; }

    for (i = 1; i < argc; i++) {
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if      (!strcmp(argv[i], "--virt")  && v) { ml_strlcpy(cfg.virt_ip, v, sizeof(cfg.virt_ip)); i++; }
        else if (!strcmp(argv[i], "--real")  && v) { ml_strlcpy(cfg.real_ip, v, sizeof(cfg.real_ip)); i++; }
        else if (!strcmp(argv[i], "--user")  && v) { ml_strlcpy(cfg.user,    v, sizeof(cfg.user));    i++; }
        else if (!strcmp(argv[i], "--pass")  && v) { ml_strlcpy(cfg.pass,    v, sizeof(cfg.pass));    i++; }
        else if (!strcmp(argv[i], "--port")  && v) { cfg.listen_port = atoi(v); i++; }
        else if (!strcmp(argv[i], "--tap")   && v) { ml_strlcpy(tap_guid, v, sizeof(tap_guid)); i++; }
        else if (!strcmp(argv[i], "--mask")  && v) { ml_strlcpy(tap_mask, v, sizeof(tap_mask)); i++; }
        else if (!strcmp(argv[i], "--config")&& v) { ml_strlcpy(cfg_path, v, sizeof(cfg_path)); i++; }
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

    /* --real включает посредника, --tap включает туннель; хотя бы одно нужно.
     * Вместе они пока не уживаются: посреднику нужен 192.168.N.1 локальным
     * адресом Windows, а туннелю — чтобы этот адрес принадлежал lwIP, иначе
     * система спрашивает ARP про сам адресат, а не про шлюз. */
    if (!cfg_path[0] &&
        (!cfg.virt_ip[0] || !cfg.proxy_ip[0] || !cfg.proxy_port ||
         (!cfg.real_ip[0] && !tap_guid[0]))) {
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

    /* Туннель занимает TAP-устройство и должен подняться первым: если адаптер
     * занят или GUID неверен, лучше упасть до того, как посредник займёт порт. */
    if (cfg_path[0]) {
        tcount = load_config(cfg_path, tlist, TUNNEL_MAX_IFACES, err, sizeof(err));
        if (tcount <= 0) {
            fprintf(stderr, "\n  ОШИБКА: %s\n", err);
            WSACleanup();
            return 1;
        }
        printf("  из конфига прочитано интерфейсов: %d\n", tcount);
    } else if (tap_guid[0]) {
        memset(&tcfg, 0, sizeof(tcfg));
        ml_strlcpy(tcfg.guid,     tap_guid,      sizeof(tcfg.guid));
        ml_strlcpy(tcfg.virt_ip,  cfg.virt_ip,   sizeof(tcfg.virt_ip));
        ml_strlcpy(tcfg.netmask,  tap_mask,      sizeof(tcfg.netmask));
        ml_strlcpy(tcfg.real_ip,  cfg.real_ip,   sizeof(tcfg.real_ip));
        ml_strlcpy(tcfg.proxy_ip, cfg.proxy_ip,  sizeof(tcfg.proxy_ip));
        ml_strlcpy(tcfg.user,     cfg.user,      sizeof(tcfg.user));
        ml_strlcpy(tcfg.pass,     cfg.pass,      sizeof(tcfg.pass));
        ml_strlcpy(tcfg.label,    cfg.virt_ip,   sizeof(tcfg.label));
        tcfg.proxy_port = cfg.proxy_port;
        tlist[0] = tcfg;
        tcount = 1;
    }

    if (tcount > 0) {
        if (!tunnel_start(tlist, tcount, err, sizeof(err))) {
            fprintf(stderr, "\n  ОШИБКА туннеля: %s\n", err);
            WSACleanup();
            return 1;
        }
        tunnel_on = TRUE;
        printf("  туннелей поднято: %d\n", tunnel_iface_count());
    }

    /* При включённом туннеле морду обслуживает он сам — отдельный сокет на
     * 192.168.N.1 занять всё равно нельзя, адрес принадлежит lwIP. */
    if (cfg.real_ip[0] && !tunnel_on && !mediator_start(&cfg, err, sizeof(err))) {
        fprintf(stderr, "\n  ОШИБКА: %s\n", err);
        if (tunnel_on) tunnel_stop();
        WSACleanup();
        return 1;
    }

    printf("\n  Работает.");
    if (cfg.real_ip[0]) printf(" Морда модема: http://%s/", cfg.virt_ip);
    printf("\n");
    printf("  Ctrl+C — остановить.\n\n");

    while (g_running) {
        Sleep(2000);
        if (tunnel_on) {
            int act, tot; unsigned long long bu, bd;
            tunnel_stats(&act, &tot, &bu, &bd);
            if (tot) printf("  интерфейсов %d   соединений: %d активных, %d всего   "
                            "вверх %llu КБ, вниз %llu КБ\r",
                            tunnel_iface_count(), act, tot, bu / 1024, bd / 1024);
        }
    }

    printf("\n  останавливаюсь...\n");
    if (cfg.real_ip[0] && !tunnel_on) mediator_stop();
    if (tunnel_on) tunnel_stop();
    WSACleanup();
    return 0;
}
