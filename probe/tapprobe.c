/* tapprobe — диагностический зонд для агентской части modlink.
 *
 * Отвечает на один вопрос, от которого зависит вся архитектура:
 *
 *   уводит ли Windows трафик, привязанный к source-адресу 192.168.N.100,
 *   в TAP-адаптер, которому этот адрес принадлежит?
 *
 * Windows выбирает интерфейс по адресу НАЗНАЧЕНИЯ, а не по источнику, и по
 * умолчанию работает в режиме weak host send: пакет с чужим source спокойно
 * уходит через физическую сетевую. Но у route selection есть нюансы вокруг
 * явного bind(), поэтому проверяем экспериментом, а не по памяти.
 *
 *   ПАКЕТЫ ПОЯВИЛИСЬ  -> перехват не нужен, хватит TAP + userspace-стека
 *   НЕ ПОЯВИЛИСЬ      -> нужен WinDivert для увода по source-адресу
 *
 * Заодно проверяется вторая гипотеза: опознает ли сторонний софт такой
 * адаптер как воткнутый USB-модем, если подменить описание и MAC.
 *
 * Драйвер: tap-windows6 (OpenVPN), ComponentId tap0901 — настоящий Ethernet
 * с MAC и ARP, в отличие от Wintun, который регистрируется как NdisMediumIP
 * с IfType = IF_TYPE_PROP_VIRTUAL и модемом выглядеть не может.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* ------------------------------------------------------------------ TAP */
#define TAP_CTL(req)  CTL_CODE(FILE_DEVICE_UNKNOWN, (req), METHOD_BUFFERED, FILE_ANY_ACCESS)
#define TAP_IOCTL_GET_MAC          TAP_CTL(1)
#define TAP_IOCTL_GET_VERSION      TAP_CTL(2)
#define TAP_IOCTL_GET_MTU          TAP_CTL(3)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CTL(6)

#define NET_CLASS_KEY  "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define NET_CONN_KEY   "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_COMPONENT  "tap0901"

/* Описание, под которое маскируемся. Подпись драйвера покрывает файлы пакета,
 * а не реестр, поэтому правка DriverDesc её не ломает. Слетит при обновлении
 * драйвера — тогда просто повторить `disguise`. */
#define FAKE_DESC "Remote NDIS based Internet Sharing Device"

/* OUI Huawei — первые три байта MAC настоящих модемов этого вендора. */
static const unsigned char HUAWEI_OUI[3] = { 0x00, 0x1E, 0x10 };

#define MAX_ADAPTERS 64

typedef struct {
    char guid[64];      /* {XXXXXXXX-....} — им адресуется устройство */
    char subkey[16];    /* NNNN в ветке Class */
    char conn_name[128];/* имя в «Сетевых подключениях» */
    char desc[256];     /* DriverDesc — то, что видно в диспетчере устройств */
} Adapter;

/* ------------------------------------------------------------------ util */
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "  ОШИБКА: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(1);
}

static BOOL is_admin(void)
{
    BOOL admin = FALSE;
    PSID grp = NULL;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &grp)) {
        CheckTokenMembership(NULL, grp, &admin);
        FreeSid(grp);
    }
    return admin;
}

/* netsh получает только числа, которые мы сами проверили — строки из внешних
 * источников в командную строку не попадают никогда. */
static int run(const char *cmd, BOOL quiet)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char buf[1024];
    DWORD code = 1;

    memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (quiet) { si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE; }

    snprintf(buf, sizeof(buf), "%s", cmd);
    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE,
                        quiet ? CREATE_NO_WINDOW : 0, NULL, NULL, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return (int)code;
}

/* ------------------------------------------------------------- реестр */
static BOOL reg_get_str(HKEY root, const char *path, const char *name,
                        char *out, DWORD cap)
{
    HKEY k;
    DWORD type = 0, sz = cap;
    LONG r;
    out[0] = 0;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return FALSE;
    r = RegQueryValueExA(k, name, NULL, &type, (LPBYTE)out, &sz);
    RegCloseKey(k);
    if (r != ERROR_SUCCESS) { out[0] = 0; return FALSE; }
    out[sz < cap ? sz : cap - 1] = 0;
    return TRUE;
}

static BOOL reg_set_str(HKEY root, const char *path, const char *name, const char *val)
{
    HKEY k;
    LONG r;
    if (RegOpenKeyExA(root, path, 0, KEY_SET_VALUE, &k) != ERROR_SUCCESS) return FALSE;
    r = RegSetValueExA(k, name, 0, REG_SZ, (const BYTE *)val, (DWORD)strlen(val) + 1);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

/* ------------------------------------------------- перечисление адаптеров */
static int find_adapters(Adapter *out, int cap)
{
    HKEY cls;
    DWORD i = 0;
    int n = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, NET_CLASS_KEY, 0, KEY_READ, &cls) != ERROR_SUCCESS)
        return 0;

    for (;; i++) {
        char sub[16], path[512], comp[128];
        DWORD sz = sizeof(sub);
        Adapter *a;

        if (RegEnumKeyExA(cls, i, sub, &sz, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (n >= cap) break;

        snprintf(path, sizeof(path), "%s\\%s", NET_CLASS_KEY, sub);
        if (!reg_get_str(HKEY_LOCAL_MACHINE, path, "ComponentId", comp, sizeof(comp))) continue;
        if (_stricmp(comp, TAP_COMPONENT) != 0) continue;

        a = &out[n];
        memset(a, 0, sizeof(*a));
        snprintf(a->subkey, sizeof(a->subkey), "%s", sub);
        if (!reg_get_str(HKEY_LOCAL_MACHINE, path, "NetCfgInstanceId", a->guid, sizeof(a->guid)))
            continue;
        reg_get_str(HKEY_LOCAL_MACHINE, path, "DriverDesc", a->desc, sizeof(a->desc));

        snprintf(path, sizeof(path), "%s\\%s\\Connection", NET_CONN_KEY, a->guid);
        reg_get_str(HKEY_LOCAL_MACHINE, path, "Name", a->conn_name, sizeof(a->conn_name));
        n++;
    }
    RegCloseKey(cls);
    return n;
}

/* ------------------------------------------------------------- открытие */
static HANDLE tap_open(const Adapter *a)
{
    char path[256];
    HANDLE h;
    ULONG status = TRUE;
    DWORD got = 0;

    snprintf(path, sizeof(path), "\\\\.\\Global\\%s.tap", a->guid);
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_SYSTEM, NULL);
    if (h == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    /* Без этого адаптер показывает «сетевой кабель не подключён», и стек
     * Windows не отправит в него ни одного пакета. */
    if (!DeviceIoControl(h, TAP_IOCTL_SET_MEDIA_STATUS, &status, sizeof(status),
                         &status, sizeof(status), &got, NULL)) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

/* ------------------------------------------------------------- Ethernet */
#pragma pack(push, 1)
typedef struct {
    unsigned char dst[6], src[6];
    unsigned short type;            /* big-endian */
} EthHdr;

typedef struct {
    unsigned short htype, ptype;
    unsigned char  hlen, plen;
    unsigned short oper;
    unsigned char  sha[6], spa[4];
    unsigned char  tha[6], tpa[4];
} ArpPkt;

typedef struct {
    unsigned char  ver_ihl, tos;
    unsigned short len, id, frag;
    unsigned char  ttl, proto;
    unsigned short csum;
    unsigned char  src[4], dst[4];
} Ip4Hdr;
#pragma pack(pop)

#define ETH_ARP 0x0806
#define ETH_IP4 0x0800

static unsigned short be16(unsigned short v) { return (unsigned short)((v >> 8) | (v << 8)); }

static const char *ipstr(const unsigned char *ip, char *buf)
{
    sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

static const char *proto_name(unsigned char p)
{
    switch (p) {
    case 1:  return "ICMP";
    case 6:  return "TCP";
    case 17: return "UDP";
    default: return "IP";
    }
}

/* ------------------------------------------------------------- listen */
/* Главный режим зонда. Читает кадры из TAP и печатает их.
 *
 * ARP обязателен: пока Windows не выяснит MAC шлюза 192.168.N.1, она не
 * отправит НИ ОДНОГО пакета в этот адаптер — и эксперимент дал бы ложный
 * отрицательный результат. Поэтому отвечаем на ARP сами. */
static void cmd_listen(int n, const Adapter *a)
{
    HANDLE h;
    unsigned char gw_mac[6];
    unsigned char buf[2048];
    DWORD got = 0;
    unsigned long long frames = 0, ip_pkts = 0, arps = 0, off_subnet = 0;
    char s1[32], s2[32];

    h = tap_open(a);
    if (h == INVALID_HANDLE_VALUE)
        die("не удалось открыть %s (нужны права администратора?)", a->guid);

    memcpy(gw_mac, HUAWEI_OUI, 3);
    gw_mac[3] = 0x00; gw_mac[4] = (unsigned char)n; gw_mac[5] = 0x01;

    printf("\n  слушаю адаптер «%s»\n", a->conn_name);
    printf("  шлюз 192.168.%d.1 отвечает с MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
           n, gw_mac[0], gw_mac[1], gw_mac[2], gw_mac[3], gw_mac[4], gw_mac[5]);
    printf("\n  ЖДУ ПАКЕТЫ. В другом окне запусти проверку из README.\n");
    printf("  Ctrl+C — выход.\n\n");
    fflush(stdout);

    for (;;) {
        EthHdr *eth;
        unsigned short type;

        if (!ReadFile(h, buf, sizeof(buf), &got, NULL) || got < sizeof(EthHdr))
            continue;
        frames++;
        eth  = (EthHdr *)buf;
        type = be16(eth->type);

        if (type == ETH_ARP && got >= sizeof(EthHdr) + sizeof(ArpPkt)) {
            ArpPkt *arp = (ArpPkt *)(buf + sizeof(EthHdr));
            arps++;
            if (be16(arp->oper) == 1) {           /* запрос */
                unsigned char out[sizeof(EthHdr) + sizeof(ArpPkt)];
                EthHdr *oe = (EthHdr *)out;
                ArpPkt *oa = (ArpPkt *)(out + sizeof(EthHdr));
                DWORD wrote = 0;

                printf("  ARP   кто такой %s?  -> отвечаю\n", ipstr(arp->tpa, s1));

                memcpy(oe->dst, eth->src, 6);
                memcpy(oe->src, gw_mac, 6);
                oe->type = be16(ETH_ARP);

                oa->htype = be16(1);
                oa->ptype = be16(ETH_IP4);
                oa->hlen  = 6;
                oa->plen  = 4;
                oa->oper  = be16(2);              /* ответ */
                memcpy(oa->sha, gw_mac,   6);
                memcpy(oa->spa, arp->tpa, 4);     /* тот адрес, о котором спросили */
                memcpy(oa->tha, arp->sha, 6);
                memcpy(oa->tpa, arp->spa, 4);

                WriteFile(h, out, sizeof(out), &wrote, NULL);
                fflush(stdout);
            }
            continue;
        }

        if (type == ETH_IP4 && got >= sizeof(EthHdr) + sizeof(Ip4Hdr)) {
            Ip4Hdr *ip = (Ip4Hdr *)(buf + sizeof(EthHdr));
            int hl = (ip->ver_ihl & 0x0F) * 4;
            unsigned sport = 0, dport = 0;
            BOOL outside;

            ip_pkts++;
            if ((ip->proto == 6 || ip->proto == 17) &&
                got >= sizeof(EthHdr) + (size_t)hl + 4) {
                unsigned char *l4 = buf + sizeof(EthHdr) + hl;
                sport = (unsigned)((l4[0] << 8) | l4[1]);
                dport = (unsigned)((l4[2] << 8) | l4[3]);
            }

            /* Вот ради этой строки всё и затевалось: адресат ВНЕ 192.168.N.0/24
             * означает, что Windows увела в TAP трафик, привязанный к нашему
             * source-адресу, — и перехватчик не нужен. */
            outside = !(ip->dst[0] == 192 && ip->dst[1] == 168 && ip->dst[2] == (unsigned char)n);
            if (outside) off_subnet++;

            printf("  %-4s  %s:%u -> %s:%u%s\n",
                   proto_name(ip->proto),
                   ipstr(ip->src, s1), sport,
                   ipstr(ip->dst, s2), dport,
                   outside ? "   <<< ВНЕ ПОДСЕТИ — ЭТО ТО, ЧТО МЫ ИЩЕМ" : "");
            fflush(stdout);
            continue;
        }

        printf("  кадр  ethertype 0x%04X, %lu байт\n", type, (unsigned long)got);
        fflush(stdout);
        (void)frames; (void)ip_pkts; (void)arps; (void)off_subnet;
    }
}

/* ------------------------------------------------------------- команды */
static void cmd_list(void)
{
    Adapter ad[MAX_ADAPTERS];
    int n, i;

    n = find_adapters(ad, MAX_ADAPTERS);
    if (!n) {
        printf("\n  TAP-адаптеров не найдено.\n");
        printf("  Поставь драйвер: tap-windows-9.24.7-I601-Win10.exe\n\n");
        return;
    }
    printf("\n  найдено адаптеров: %d\n\n", n);
    for (i = 0; i < n; i++)
        printf("  [%d] %-28s %s\n      %s\n      %s\n\n",
               i, ad[i].conn_name, ad[i].guid, ad[i].desc, ad[i].subkey);
}

/* Настраивает адаптер как «модем N»: адрес, шлюз, DNS и имя подключения. */
static void cmd_create(int n, Adapter *a)
{
    char cmd[512];

    printf("\n  настраиваю «%s» как модем %d\n", a->conn_name, n);

    /* Имя подключения — по нему потом находим адаптер. Кавычки вокруг обоих
     * имён обязательны: в текущем может быть пробел. */
    snprintf(cmd, sizeof(cmd),
             "netsh interface set interface name=\"%s\" newname=\"modem%d\"",
             a->conn_name, n);
    run(cmd, TRUE);
    snprintf(a->conn_name, sizeof(a->conn_name), "modem%d", n);

    snprintf(cmd, sizeof(cmd),
             "netsh interface ip set address name=\"modem%d\" static "
             "192.168.%d.100 255.255.255.0 192.168.%d.1 1", n, n, n);
    printf("  адрес   192.168.%d.100/24, шлюз 192.168.%d.1\n", n, n);
    if (run(cmd, TRUE) != 0)
        printf("  ! netsh вернул ошибку — адрес мог не примениться\n");

    snprintf(cmd, sizeof(cmd),
             "netsh interface ip set dns name=\"modem%d\" static 192.168.%d.1", n, n);
    run(cmd, TRUE);

    printf("  готово. Теперь: tapprobe disguise %d   и   tapprobe listen %d\n\n", n, n);
}

/* Маскировка под воткнутый USB-модем. */
static void cmd_disguise(int n, const Adapter *a)
{
    char path[512], mac[32];
    BOOL ok1, ok2;

    snprintf(path, sizeof(path), "%s\\%s", NET_CLASS_KEY, a->subkey);

    printf("\n  было:  %s\n", a->desc);
    ok1 = reg_set_str(HKEY_LOCAL_MACHINE, path, "DriverDesc", FAKE_DESC);
    printf("  стало: %s   %s\n", FAKE_DESC, ok1 ? "" : "(НЕ УДАЛОСЬ — нужен администратор)");

    /* MAC задаётся строкой без разделителей. OUI Huawei — как у настоящего
     * E3372, чтобы совпадал и вендор. */
    snprintf(mac, sizeof(mac), "%02X%02X%02X00%02X01",
             HUAWEI_OUI[0], HUAWEI_OUI[1], HUAWEI_OUI[2], (unsigned char)n);
    ok2 = reg_set_str(HKEY_LOCAL_MACHINE, path, "MAC", mac);
    printf("  MAC:   %s   %s\n", mac, ok2 ? "" : "(не удалось)");

    printf("\n  Изменения видны ПОСЛЕ перезапуска адаптера:\n");
    printf("    netsh interface set interface name=\"%s\" admin=disable\n", a->conn_name);
    printf("    netsh interface set interface name=\"%s\" admin=enable\n\n", a->conn_name);
}

static void usage(void)
{
    printf("\n  tapprobe — зонд для проверки маршрутизации через TAP\n\n");
    printf("  tapprobe list              показать TAP-адаптеры\n");
    printf("  tapprobe create <N>        настроить как модем N (192.168.N.100/24)\n");
    printf("  tapprobe disguise <N>      подменить описание и MAC под USB-модем\n");
    printf("  tapprobe listen <N>        слушать и печатать пакеты  <- главный тест\n\n");
    printf("  N — от 1 до 254, третий октет адреса.\n\n");
}

int main(int argc, char **argv)
{
    Adapter ad[MAX_ADAPTERS];
    int count, n = 0, idx = 0, i;
    const char *cmd;

    if (argc < 2) { usage(); return 1; }
    cmd = argv[1];

    if (!strcmp(cmd, "list")) { cmd_list(); return 0; }

    if (argc < 3) { usage(); return 1; }
    n = atoi(argv[2]);
    if (n < 1 || n > 254) die("N должно быть от 1 до 254, получено «%s»", argv[2]);

    if (!is_admin())
        printf("\n  ВНИМАНИЕ: запущено без прав администратора — настройка и\n"
               "  открытие адаптера, скорее всего, не сработают.\n");

    count = find_adapters(ad, MAX_ADAPTERS);
    if (!count) die("TAP-адаптеров нет. Поставь tap-windows-9.24.7-I601-Win10.exe");

    /* Ищем уже помеченный modemN, иначе берём первый свободный. */
    {
        char want[32];
        snprintf(want, sizeof(want), "modem%d", n);
        idx = -1;
        for (i = 0; i < count; i++)
            if (!_stricmp(ad[i].conn_name, want)) { idx = i; break; }
        if (idx < 0) {
            if (!strcmp(cmd, "create")) idx = 0;
            else die("адаптер «modem%d» не найден — сначала: tapprobe create %d", n, n);
        }
    }

    if (!strcmp(cmd, "create"))        cmd_create(n, &ad[idx]);
    else if (!strcmp(cmd, "disguise")) cmd_disguise(n, &ad[idx]);
    else if (!strcmp(cmd, "listen"))   cmd_listen(n, &ad[idx]);
    else { usage(); return 1; }

    return 0;
}
