/* modlink-agent — жизненный цикл виртуального адаптера, см. winnet.h */
#include "winnet.h"
#include <setupapi.h>
#include <cfgmgr32.h>
#include <newdev.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <string.h>
#include <stdio.h>

#define TAP_HWID       "tap0901"
#define NET_CLASS_GUID "{4D36E972-E325-11CE-BFC1-08002BE10318}"

static const GUID GUID_DEVCLASS_NET_ =
    { 0x4d36e972, 0xe325, 0x11ce, { 0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18 } };

/* ------------------------------------------------------------- реестр */
static BOOL reg_set_sz(HKEY root, const char *path, const char *name, const char *val)
{
    HKEY k;
    LONG r = RegOpenKeyExA(root, path, 0, KEY_SET_VALUE, &k);
    if (r != ERROR_SUCCESS) return FALSE;
    r = RegSetValueExA(k, name, 0, REG_SZ, (const BYTE *)val, (DWORD)strlen(val) + 1);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

static BOOL reg_get_sz(HKEY root, const char *path, const char *name, char *out, DWORD cap)
{
    HKEY k;
    DWORD type = 0, len = cap;
    BOOL ok = FALSE;
    out[0] = 0;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &k) != ERROR_SUCCESS) return FALSE;
    if (RegQueryValueExA(k, name, NULL, &type, (LPBYTE)out, &len) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        out[len < cap ? len : cap - 1] = 0;
        ok = TRUE;
    }
    RegCloseKey(k);
    return ok;
}

/* ------------------------------------------------------------- поиск ключей */
/* По GUID адаптера находит подкаталог классового ключа (…\Class\{…}\NNNN,
 * где лежат DriverDesc, NetworkAddress) и ключ Enum (ROOT\NET\NNNN, где
 * FriendlyName/DeviceDesc). Их суффиксы разные, поэтому ищем оба перебором. */
static BOOL find_class_key(const char *guid, char *out, size_t cap)
{
    HKEY base;
    DWORD i = 0;
    char sub[64];
    DWORD sublen;
    BOOL found = FALSE;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Class\\" NET_CLASS_GUID,
            0, KEY_READ, &base) != ERROR_SUCCESS)
        return FALSE;

    for (;; i++) {
        char path[256], val[128];
        sublen = sizeof(sub);
        if (RegEnumKeyExA(base, i, sub, &sublen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        snprintf(path, sizeof(path),
                 "SYSTEM\\CurrentControlSet\\Control\\Class\\" NET_CLASS_GUID "\\%s", sub);
        if (reg_get_sz(HKEY_LOCAL_MACHINE, path, "NetCfgInstanceId", val, sizeof(val)) &&
            !_stricmp(val, guid)) {
            snprintf(out, cap,
                     "SYSTEM\\CurrentControlSet\\Control\\Class\\" NET_CLASS_GUID "\\%s", sub);
            found = TRUE;
            break;
        }
    }
    RegCloseKey(base);
    return found;
}

/* ------------------------------------------------------------- SetupAPI */
/* Обходит устройства класса Net, ищет по NetCfgInstanceId, отдаёт devinfo и
 * data вызывающему. Общий шаг для «узнать GUID нового» и «удалить по GUID». */
static BOOL for_each_net_device(const char *match_guid,
                                HDEVINFO *out_di, SP_DEVINFO_DATA *out_data,
                                char *out_instid, size_t instcap)
{
    HDEVINFO di;
    SP_DEVINFO_DATA data;
    DWORD idx = 0;
    BOOL found = FALSE;

    di = SetupDiGetClassDevsA(&GUID_DEVCLASS_NET_, NULL, NULL, DIGCF_PRESENT);
    if (di == INVALID_HANDLE_VALUE) return FALSE;

    data.cbSize = sizeof(data);
    for (idx = 0; SetupDiEnumDeviceInfo(di, idx, &data); idx++) {
        HKEY dk;
        char guid[128] = {0};
        DWORD type = 0, len = sizeof(guid);

        dk = SetupDiOpenDevRegKey(di, &data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
        if (dk == INVALID_HANDLE_VALUE) continue;
        RegQueryValueExA(dk, "NetCfgInstanceId", NULL, &type, (LPBYTE)guid, &len);
        RegCloseKey(dk);

        if (!_stricmp(guid, match_guid)) {
            if (out_instid)
                SetupDiGetDeviceInstanceIdA(di, &data, out_instid, (DWORD)instcap, NULL);
            *out_di = di;
            *out_data = data;
            found = TRUE;
            break;
        }
        data.cbSize = sizeof(data);
    }
    if (!found) SetupDiDestroyDeviceInfoList(di);
    return found;
}

BOOL winnet_create_adapter(const char *inf_path, char *out_guid, size_t guidcap,
                           char *err, size_t errcap)
{
    HDEVINFO di;
    SP_DEVINFO_DATA data;
    char hwid[64];
    BOOL reboot = FALSE;
    HKEY dk;
    DWORD type = 0, len;

    if (err && errcap) err[0] = 0;
    if (out_guid && guidcap) out_guid[0] = 0;

    /* Пара hwid обязана заканчиваться двойным нулём — это REG_MULTI_SZ. */
    memset(hwid, 0, sizeof(hwid));
    strcpy(hwid, TAP_HWID);

    di = SetupDiCreateDeviceInfoList(&GUID_DEVCLASS_NET_, NULL);
    if (di == INVALID_HANDLE_VALUE) {
        if (err) ml_strlcpy(err, "SetupDiCreateDeviceInfoList не удался", errcap);
        return FALSE;
    }

    data.cbSize = sizeof(data);
    if (!SetupDiCreateDeviceInfoA(di, "NET", &GUID_DEVCLASS_NET_, NULL, NULL,
                                  DICD_GENERATE_ID, &data)) {
        if (err) snprintf(err, errcap, "SetupDiCreateDeviceInfo (ошибка %lu)", GetLastError());
        SetupDiDestroyDeviceInfoList(di);
        return FALSE;
    }

    if (!SetupDiSetDeviceRegistryPropertyA(di, &data, SPDRP_HARDWAREID,
                                           (const BYTE *)hwid,
                                           (DWORD)(strlen(TAP_HWID) + 2))) {
        if (err) snprintf(err, errcap, "SetupDiSetDeviceRegistryProperty (ошибка %lu)", GetLastError());
        SetupDiDestroyDeviceInfoList(di);
        return FALSE;
    }

    /* Регистрируем устройство, затем ставим на него драйвер из INF. */
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, di, &data)) {
        if (err) snprintf(err, errcap, "DIF_REGISTERDEVICE (ошибка %lu)", GetLastError());
        SetupDiDestroyDeviceInfoList(di);
        return FALSE;
    }

    {
        wchar_t *winf = ml_utf8_to_w(inf_path);
        BOOL ok = winf && UpdateDriverForPlugAndPlayDevicesW(
            NULL, L"" TAP_HWID, winf, INSTALLFLAG_FORCE, &reboot);
        free(winf);
        if (!ok) {
            DWORD e = GetLastError();
            if (err) snprintf(err, errcap,
                "не удалось поставить драйвер (ошибка %lu). INF на месте? Права администратора?", e);
            /* откатываем полусозданное устройство */
            SetupDiCallClassInstaller(DIF_REMOVE, di, &data);
            SetupDiDestroyDeviceInfoList(di);
            return FALSE;
        }
    }

    /* Читаем NetCfgInstanceId новорождённого адаптера. */
    dk = SetupDiOpenDevRegKey(di, &data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
    if (dk != INVALID_HANDLE_VALUE) {
        char guid[128] = {0};
        len = sizeof(guid);
        if (RegQueryValueExA(dk, "NetCfgInstanceId", NULL, &type, (LPBYTE)guid, &len) == ERROR_SUCCESS)
            if (out_guid) ml_strlcpy(out_guid, guid, guidcap);
        RegCloseKey(dk);
    }
    SetupDiDestroyDeviceInfoList(di);

    if (out_guid && !out_guid[0]) {
        if (err) ml_strlcpy(err, "адаптер создан, но GUID не прочитался", errcap);
        return FALSE;
    }
    ml_log("winnet: создан адаптер %s", out_guid ? out_guid : "?");
    return TRUE;
}

BOOL winnet_remove_adapter(const char *guid, char *err, size_t errcap)
{
    HDEVINFO di;
    SP_DEVINFO_DATA data;
    BOOL ok;

    if (err && errcap) err[0] = 0;
    if (!for_each_net_device(guid, &di, &data, NULL, 0)) {
        if (err) snprintf(err, errcap, "адаптер %s не найден", guid);
        return FALSE;
    }
    ok = SetupDiCallClassInstaller(DIF_REMOVE, di, &data);
    if (!ok && err) snprintf(err, errcap, "DIF_REMOVE (ошибка %lu)", GetLastError());
    SetupDiDestroyDeviceInfoList(di);
    if (ok) ml_log("winnet: удалён адаптер %s", guid);
    return ok;
}

/* ------------------------------------------------------------- маскировка */
BOOL winnet_disguise(const char *guid, const char *desc, const char *mac_hex,
                     const char *vendor, char *err, size_t errcap)
{
    char classkey[256], instid[256], enumkey[300];
    HDEVINFO di;
    SP_DEVINFO_DATA data;

    if (err && errcap) err[0] = 0;

    if (!find_class_key(guid, classkey, sizeof(classkey))) {
        if (err) snprintf(err, errcap, "классовый ключ для %s не найден", guid);
        return FALSE;
    }
    if (desc)    reg_set_sz(HKEY_LOCAL_MACHINE, classkey, "DriverDesc",     desc);
    if (mac_hex) reg_set_sz(HKEY_LOCAL_MACHINE, classkey, "NetworkAddress", mac_hex);
    reg_set_sz(HKEY_LOCAL_MACHINE, classkey, "MediaStatus", "1");

    /* Enum-ключ: имя устройства в «Сетевых подключениях» берётся отсюда, а не
     * из классового ключа — иначе описание останется «TAP-Windows Adapter V9». */
    if (for_each_net_device(guid, &di, &data, instid, sizeof(instid))) {
        snprintf(enumkey, sizeof(enumkey), "SYSTEM\\CurrentControlSet\\Enum\\%s", instid);
        if (desc) {
            reg_set_sz(HKEY_LOCAL_MACHINE, enumkey, "FriendlyName", desc);
            reg_set_sz(HKEY_LOCAL_MACHINE, enumkey, "DeviceDesc",   desc);
        }
        if (vendor) reg_set_sz(HKEY_LOCAL_MACHINE, enumkey, "Mfg", vendor);
        SetupDiDestroyDeviceInfoList(di);
    }

    ml_log("winnet: маскировка %s -> «%s» MAC %s", guid, desc ? desc : "-", mac_hex ? mac_hex : "-");
    return TRUE;
}

/* ------------------------------------------------------------- цикл питания */
BOOL winnet_cycle(const char *guid, char *err, size_t errcap)
{
    HDEVINFO di;
    SP_DEVINFO_DATA data;
    SP_PROPCHANGE_PARAMS pcp;
    BOOL ok = TRUE;

    if (err && errcap) err[0] = 0;
    if (!for_each_net_device(guid, &di, &data, NULL, 0)) {
        if (err) snprintf(err, errcap, "адаптер %s не найден", guid);
        return FALSE;
    }

    memset(&pcp, 0, sizeof(pcp));
    pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
    pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
    pcp.Scope = DICS_FLAG_GLOBAL;

    pcp.StateChange = DICS_DISABLE;
    SetupDiSetClassInstallParamsA(di, &data, &pcp.ClassInstallHeader, sizeof(pcp));
    SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, di, &data);
    Sleep(1500);

    pcp.StateChange = DICS_ENABLE;
    SetupDiSetClassInstallParamsA(di, &data, &pcp.ClassInstallHeader, sizeof(pcp));
    ok = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, di, &data);

    SetupDiDestroyDeviceInfoList(di);
    Sleep(2000);
    if (!ok && err) snprintf(err, errcap, "DIF_PROPERTYCHANGE (ошибка %lu)", GetLastError());
    return ok;
}

/* ------------------------------------------------------------- адресация */
/* GUID → LUID интерфейса. Через LUID работают все функции IP Helper — они
 * принимают LUID, а не индекс, и потому переживают перетасовку индексов после
 * перезагрузки. Берём LUID напрямую из GetAdaptersAddresses по имени адаптера
 * (AdapterName — это и есть строковый GUID): перебор LUID вслепую ненадёжен. */
static BOOL guid_to_luid(const char *guid, NET_LUID *luid)
{
    ULONG size = 16 * 1024;
    IP_ADAPTER_ADDRESSES *buf = NULL, *a;
    BOOL found = FALSE;
    DWORD r;

    for (;;) {
        buf = (IP_ADAPTER_ADDRESSES *)malloc(size);
        if (!buf) return FALSE;
        r = GetAdaptersAddresses(AF_UNSPEC,
                GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                NULL, buf, &size);
        if (r == ERROR_BUFFER_OVERFLOW) { free(buf); continue; }
        if (r != NO_ERROR) { free(buf); return FALSE; }
        break;
    }

    for (a = buf; a; a = a->Next) {
        /* AdapterName приходит как "{GUID}" в ASCII. */
        if (a->AdapterName && !_stricmp(a->AdapterName, guid)) {
            *luid = a->Luid;
            found = TRUE;
            break;
        }
    }
    free(buf);
    return found;
}

BOOL winnet_configure(const char *guid, const char *ip, int prefix,
                      const char *gateway, const char *dns, int metric,
                      char *err, size_t errcap)
{
    NET_LUID luid;
    NET_IFINDEX ifindex = 0;
    MIB_UNICASTIPADDRESS_ROW addr;
    MIB_IPFORWARD_ROW2 route;
    MIB_IPINTERFACE_ROW iface;

    if (err && errcap) err[0] = 0;
    if (!guid_to_luid(guid, &luid)) {
        if (err) snprintf(err, errcap, "не удалось найти интерфейс %s", guid);
        return FALSE;
    }
    ConvertInterfaceLuidToIndex(&luid, &ifindex);

    /* адрес */
    InitializeUnicastIpAddressEntry(&addr);
    addr.InterfaceLuid = luid;
    addr.Address.si_family = AF_INET;
    addr.Address.Ipv4.sin_family = AF_INET;
    addr.Address.Ipv4.sin_addr.s_addr = inet_addr(ip);
    addr.OnLinkPrefixLength = (UINT8)prefix;
    addr.DadState = IpDadStatePreferred;
    {
        DWORD r = CreateUnicastIpAddressEntry(&addr);
        if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS) {
            if (err) snprintf(err, errcap, "не удалось задать адрес %s (%lu)", ip, r);
            return FALSE;
        }
    }

    /* метрика интерфейса: снимаем автоматическую, ставим свою */
    memset(&iface, 0, sizeof(iface));
    iface.Family = AF_INET;
    iface.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&iface) == NO_ERROR) {
        iface.UseAutomaticMetric = FALSE;
        iface.Metric = (ULONG)metric;
        iface.SitePrefixLength = 0;   /* обязателен при записи для IPv4 */
        SetIpInterfaceEntry(&iface);
    }

    /* шлюз: маршрут по умолчанию через gateway с нашей метрикой */
    if (gateway && gateway[0]) {
        InitializeIpForwardEntry(&route);
        route.InterfaceLuid = luid;
        route.DestinationPrefix.Prefix.si_family = AF_INET;
        route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
        route.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = 0;   /* 0.0.0.0/0 */
        route.DestinationPrefix.PrefixLength = 0;
        route.NextHop.si_family = AF_INET;
        route.NextHop.Ipv4.sin_family = AF_INET;
        route.NextHop.Ipv4.sin_addr.s_addr = inet_addr(gateway);
        route.Metric = (ULONG)metric;
        {
            DWORD r = CreateIpForwardEntry2(&route);
            if (r != NO_ERROR && r != ERROR_OBJECT_ALREADY_EXISTS)
                ml_log("winnet: маршрут по умолчанию не задан (%lu)", r);
        }
    }

    /* DNS: пишем NameServer в ключ интерфейса. API SetInterfaceDnsSettings есть
     * только с Win10 2004, а ключ реестра — везде. */
    if (dns && dns[0]) {
        char path[400];
        snprintf(path, sizeof(path),
            "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\%s", guid);
        reg_set_sz(HKEY_LOCAL_MACHINE, path, "NameServer", dns);
    }

    ml_log("winnet: %s = %s/%d gw %s dns %s metric %d (ifindex %lu)",
           guid, ip, prefix, gateway ? gateway : "-", dns ? dns : "-", metric,
           (unsigned long)ifindex);
    return TRUE;
}

/* ------------------------------------------------------------- имя */
BOOL winnet_rename(const char *guid, const char *new_name, char *err, size_t errcap)
{
    /* Имя (NetConnectionID) лежит в …\Network\{класс}\{guid}\Connection\Name. */
    char path[400];
    if (err && errcap) err[0] = 0;
    snprintf(path, sizeof(path),
        "SYSTEM\\CurrentControlSet\\Control\\Network\\" NET_CLASS_GUID "\\%s\\Connection", guid);
    if (!reg_set_sz(HKEY_LOCAL_MACHINE, path, "Name", new_name)) {
        if (err) snprintf(err, errcap, "не удалось переименовать %s", guid);
        return FALSE;
    }
    return TRUE;
}
