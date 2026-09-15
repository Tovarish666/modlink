/* mkadapter — deterministic, multithreaded creation of disguised TAP adapters.
 *
 * Brick 1 of the agent side: feed it modem numbers, it creates one virtual
 * network adapter per number that looks like a Huawei "Remote NDIS based
 * Internet Sharing Device", with a fixed IP, metric 5000 and connection name
 * "Ethernet N". No tunnel here — this brick only proves the adapter can be
 * created reliably and identically, every time, in parallel.
 *
 * Design against the "phantom errors":
 *   - one process-wide lock serialises the PnP-unsafe steps (create device,
 *     install driver, disable/enable, remove); everything else (registry
 *     identity, waiting for the link, IP config, rename) runs per-adapter in
 *     parallel threads.
 *   - no blind Sleep on state: every wait polls the real OperStatus.
 *   - every step reads its result back and the flow verifies the description;
 *     the disable/enable cycle is retried once if the identity didn't take.
 *
 * Build (cross from macOS):
 *   zig cc -target x86_64-windows-gnu -O2 -o mkadapter.exe adapter/mkadapter.c \
 *     -lsetupapi -lnewdev -lcfgmgr32 -liphlpapi -lole32 -ladvapi32 -luser32 \
 *     -lshell32 -lws2_32
 *
 * Usage:
 *   mkadapter add <N> [N2 N3 ...]   create adapters (parallel)
 *   mkadapter list                  list our virtual TAP adapters
 *   mkadapter del  <N|all>          remove ours (never touches USB modems)
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define TAP_HWID    L"tap0901"
#define DEV_DESC     "Remote NDIS based Internet Sharing Device"
#define DEV_DESC_W  L"Remote NDIS based Internet Sharing Device"
#define DEV_VENDOR_W L"Huawei Technologies Co., Ltd."

static const GUID GUID_NET =
    {0x4d36e972,0xe325,0x11ce,{0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18}};

static CRITICAL_SECTION g_pnp;          /* serialises PnP-unsafe operations */
static wchar_t g_inf[MAX_PATH];         /* INF that carries tap0901         */
static volatile LONG g_ok = 0, g_fail = 0;

/* ------------------------------------------------------------------ log */
static void logf(int n, const char *fmt, ...)
{
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    printf("[%3d] %s\n", n, buf);
    fflush(stdout);
}

/* ------------------------------------------------------------ registry */
static LONG reg_set_sz(HKEY k, const wchar_t *name, const wchar_t *val)
{
    return RegSetValueExW(k, name, 0, REG_SZ, (const BYTE*)val,
                          (DWORD)((wcslen(val) + 1) * sizeof(wchar_t)));
}
static LONG reg_set_dw(HKEY k, const wchar_t *name, DWORD v)
{
    return RegSetValueExW(k, name, 0, REG_DWORD, (const BYTE*)&v, sizeof(v));
}
static BOOL reg_get_sz(const wchar_t *subkey, const wchar_t *name, wchar_t *out, DWORD ccap)
{
    HKEY k; DWORD type = 0, cb = ccap * sizeof(wchar_t); BOOL ok = FALSE;
    out[0] = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &k) == ERROR_SUCCESS) {
        if (RegQueryValueExW(k, name, NULL, &type, (BYTE*)out, &cb) == ERROR_SUCCESS) ok = TRUE;
        RegCloseKey(k);
    }
    return ok;
}

/* --------------------------------------------------------- find the INF */
/* The TAP driver is already in the store; UpdateDriverForPlugAndPlayDevices
 * still needs *an* INF that lists tap0901. Find it under %WINDIR%\INF\oem*.inf
 * so we do not hardcode oem17.inf (the number differs per machine). */
static BOOL find_inf(void)
{
    wchar_t pat[MAX_PATH], path[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    UINT wd = GetWindowsDirectoryW(pat, MAX_PATH);
    if (!wd) return FALSE;
    _snwprintf(pat, MAX_PATH, L"%.*s\\INF\\oem*.inf", wd, pat);
    /* rebuild cleanly */
    GetWindowsDirectoryW(path, MAX_PATH);
    _snwprintf(pat, MAX_PATH, L"%s\\INF\\oem*.inf", path);

    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) goto fallback;
    do {
        wchar_t full[MAX_PATH];
        FILE *f;
        char line[1024];
        BOOL found = FALSE;
        _snwprintf(full, MAX_PATH, L"%s\\INF\\%s", path, fd.cFileName);
        f = _wfopen(full, L"rb");
        if (!f) continue;
        while (fgets(line, sizeof(line), f)) {
            /* INF is ASCII/UTF-16; tap0901 appears as ASCII in both once we
             * scan bytes loosely. Do a cheap case-insensitive substring. */
            char *p; for (p = line; *p; p++) if (*p >= 'A' && *p <= 'Z') *p += 32;
            if (strstr(line, "tap0901")) { found = TRUE; break; }
        }
        fclose(f);
        if (found) { wcscpy(g_inf, full); FindClose(h); return TRUE; }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
fallback:
    {
        const wchar_t *pd = _wgetenv(L"ProgramData");
        if (pd) { _snwprintf(g_inf, MAX_PATH, L"%s\\modlink\\OemVista.inf", pd);
                  if (GetFileAttributesW(g_inf) != INVALID_FILE_ATTRIBUTES) return TRUE; }
    }
    return FALSE;
}

/* ---------------------------------------------------- one adapter handle */
typedef struct {
    int      n;
    HDEVINFO hdi;
    SP_DEVINFO_DATA did;
    wchar_t  instance[256];     /* ROOT\NET\000X                       */
    wchar_t  classkey[256];     /* {4d36e972..}\000X (SPDRP_DRIVER)    */
    wchar_t  guid[64];          /* NetCfgInstanceId {....}             */
} Dev;

/* Create the device and bind the tap0901 driver. PnP-unsafe: caller holds lock. */
static BOOL dev_create(Dev *d)
{
    DWORD req = 0;
    BOOL reboot = FALSE;
    HKEY ck;
    wchar_t path[512];
    DWORD type = 0, cb = sizeof(d->guid);

    d->hdi = SetupDiCreateDeviceInfoList(&GUID_NET, NULL);
    if (d->hdi == INVALID_HANDLE_VALUE) { logf(d->n, "CreateDeviceInfoList err %lu", GetLastError()); return FALSE; }

    d->did.cbSize = sizeof(SP_DEVINFO_DATA);
    if (!SetupDiCreateDeviceInfoW(d->hdi, L"Net", &GUID_NET, NULL, NULL,
                                  DICD_GENERATE_ID, &d->did)) {
        logf(d->n, "CreateDeviceInfo err %lu", GetLastError()); return FALSE;
    }
    if (!SetupDiSetDeviceRegistryPropertyW(d->hdi, &d->did, SPDRP_HARDWAREID,
            (const BYTE*)TAP_HWID L"\0", (DWORD)((wcslen(TAP_HWID) + 2) * sizeof(wchar_t)))) {
        logf(d->n, "SetHardwareID err %lu", GetLastError()); return FALSE;
    }
    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, d->hdi, &d->did)) {
        logf(d->n, "DIF_REGISTERDEVICE err %lu", GetLastError()); return FALSE;
    }
    if (!SetupDiGetDeviceInstanceIdW(d->hdi, &d->did, d->instance, 256, &req)) {
        logf(d->n, "GetInstanceId err %lu", GetLastError()); return FALSE;
    }
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, TAP_HWID, g_inf, INSTALLFLAG_FORCE, &reboot)) {
        logf(d->n, "UpdateDriver err %lu", GetLastError()); return FALSE;
    }
    if (!SetupDiGetDeviceRegistryPropertyW(d->hdi, &d->did, SPDRP_DRIVER, NULL,
            (BYTE*)d->classkey, sizeof(d->classkey), &req)) {
        logf(d->n, "get SPDRP_DRIVER err %lu", GetLastError()); return FALSE;
    }
    _snwprintf(path, 512, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", d->classkey);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &ck) != ERROR_SUCCESS) {
        logf(d->n, "open class key failed"); return FALSE;
    }
    if (RegQueryValueExW(ck, L"NetCfgInstanceId", NULL, &type, (BYTE*)d->guid, &cb) != ERROR_SUCCESS) {
        RegCloseKey(ck); logf(d->n, "read NetCfgInstanceId failed"); return FALSE;
    }
    RegCloseKey(ck);
    logf(d->n, "created %ls  guid=%ls", d->instance, d->guid);
    return TRUE;
}

/* MAC + link — must be set before the disable/enable cycle (the driver reads
 * NetworkAddress only on init). Per-adapter keys, safe without the lock. */
static void dev_set_mac(Dev *d)
{
    wchar_t path[512], mac[16];
    HKEY k;
    _snwprintf(mac, 16, L"021E10%02X%02X%02X",
               (unsigned)((d->n >> 4) & 0xFF), (unsigned)(d->n & 0xFF), (unsigned)((d->n * 7) & 0xFF));
    _snwprintf(path, 512, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", d->classkey);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        reg_set_sz(k, L"NetworkAddress", mac);   /* not "MAC" — the driver ignores that */
        reg_set_sz(k, L"MediaStatus",    L"1");   /* always-connected                    */
        RegCloseKey(k);
    } else logf(d->n, "set_mac: class key not writable");
}

/* Display identity — DriverDesc + the Enum names. Written LAST (after the final
 * enable), because a disable/enable does NOT reset it but a driver *install*
 * does; by this point every install is finished. No cycle needed after. */
static void dev_set_identity(Dev *d)
{
    wchar_t path[512];
    HKEY k;
    _snwprintf(path, 512, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", d->classkey);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        reg_set_sz(k, L"DriverDesc", DEV_DESC_W);
        RegCloseKey(k);
    }
    _snwprintf(path, 512, L"SYSTEM\\CurrentControlSet\\Enum\\%s", d->instance);
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &k) == ERROR_SUCCESS) {
        reg_set_sz(k, L"FriendlyName", DEV_DESC_W);
        reg_set_sz(k, L"DeviceDesc",   DEV_DESC_W);
        reg_set_sz(k, L"Mfg",          DEV_VENDOR_W);
        RegCloseKey(k);
    }
}

/* Is the identity in the registry ours right now? (registry = the truth; the
 * IP Helper Description lags a re-registration for a second or two.) */
static BOOL identity_ok(Dev *d)
{
    wchar_t path[512], val[256];
    _snwprintf(path, 512, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", d->classkey);
    if (reg_get_sz(path, L"DriverDesc", val, 256)) return wcscmp(val, DEV_DESC_W) == 0;
    return FALSE;
}

/* Disable then enable to make the driver re-read the identity. PnP-unsafe. */
static BOOL dev_cycle(Dev *d)
{
    SP_PROPCHANGE_PARAMS pcp;
    int pass;
    for (pass = 0; pass < 2; pass++) {
        pcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        pcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        pcp.StateChange = pass == 0 ? DICS_DISABLE : DICS_ENABLE;
        pcp.Scope = DICS_FLAG_GLOBAL;
        pcp.HwProfile = 0;
        if (!SetupDiSetClassInstallParamsW(d->hdi, &d->did, &pcp.ClassInstallHeader, sizeof(pcp)) ||
            !SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, d->hdi, &d->did)) {
            logf(d->n, "cycle %s err %lu", pass ? "enable" : "disable", GetLastError());
            return FALSE;
        }
    }
    return TRUE;
}

/* ----------------------------------------------- live status by GUID */
/* Fills *up (OperStatus==Up) and desc; returns FALSE if the adapter is not
 * found yet. Read straight from IP Helper, the same view the OS shows. */
static BOOL live(const wchar_t *guid, int *up, char *desc, size_t desccap)
{
    ULONG sz = 0, r;
    IP_ADAPTER_ADDRESSES *aa, *p;
    BOOL found = FALSE;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST,
                         NULL, NULL, &sz);
    if (!sz) return FALSE;
    aa = (IP_ADAPTER_ADDRESSES*)malloc(sz);
    if (!aa) return FALSE;
    r = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST,
                             NULL, aa, &sz);
    if (r == NO_ERROR) {
        wchar_t want[64]; wcsncpy(want, guid, 63); want[63]=0;
        for (p = aa; p; p = p->Next) {
            wchar_t an[64]; int i;
            /* AdapterName is ASCII GUID with braces */
            for (i = 0; p->AdapterName[i] && i < 63; i++) an[i] = (wchar_t)p->AdapterName[i];
            an[i] = 0;
            if (_wcsicmp(an, want) == 0) {
                if (up) *up = (p->OperStatus == IfOperStatusUp);
                if (desc && desccap) WideCharToMultiByte(CP_UTF8,0,p->Description,-1,desc,(int)desccap,NULL,NULL);
                found = TRUE; break;
            }
        }
    }
    free(aa);
    return found;
}

static BOOL wait_up(const wchar_t *guid, int ms)
{
    int waited = 0, up = 0;
    while (waited < ms) {
        if (live(guid, &up, NULL, 0) && up) return TRUE;
        Sleep(150); waited += 150;
    }
    return FALSE;
}

/* Wait until the adapter is BOTH up AND showing our identity. Filters out the
 * transient where GetAdaptersAddresses briefly reports the INF default right
 * after an enable/rename, which is what made the old log look like a revert. */
static BOOL settle(const wchar_t *guid, int ms, char *descOut, size_t cap, int *upOut)
{
    int waited = 0, up = 0;
    char desc[256];
    while (waited < ms) {
        if (live(guid, &up, desc, sizeof(desc)) && up && strcmp(desc, DEV_DESC) == 0) {
            if (descOut && cap) { strncpy(descOut, desc, cap - 1); descOut[cap - 1] = 0; }
            if (upOut) *upOut = up;
            return TRUE;
        }
        Sleep(150); waited += 150;
    }
    live(guid, &up, desc, sizeof(desc));
    if (descOut && cap) { strncpy(descOut, desc, cap - 1); descOut[cap - 1] = 0; }
    if (upOut) *upOut = up;
    return FALSE;
}

/* --------------------------------------------------------------- IP */
static BOOL configure_ip(const wchar_t *guid, int n)
{
    GUID g; NET_LUID luid;
    MIB_UNICASTIPADDRESS_ROW row;
    MIB_IPINTERFACE_ROW iface;
    MIB_IPFORWARD_ROW2 route;
    MIB_UNICASTIPADDRESS_TABLE *tab = NULL;
    ULONG i;

    if (CLSIDFromString(guid, &g) != NOERROR) { logf(n, "bad guid"); return FALSE; }
    if (ConvertInterfaceGuidToLuid(&g, &luid) != NO_ERROR) { logf(n, "guid->luid failed"); return FALSE; }

    /* clear any addresses we (or a previous run) left on this interface */
    if (GetUnicastIpAddressTable(AF_INET, &tab) == NO_ERROR && tab) {
        for (i = 0; i < tab->NumEntries; i++)
            if (tab->Table[i].InterfaceLuid.Value == luid.Value)
                DeleteUnicastIpAddressEntry(&tab->Table[i]);
        FreeMibTable(tab);
    }

    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.Address.si_family = AF_INET;
    row.Address.Ipv4.sin_family = AF_INET;
    row.Address.Ipv4.sin_addr.S_un.S_addr = htonl(0xC0A80000u | ((unsigned)n << 8) | 100u); /* 192.168.N.100 */
    row.OnLinkPrefixLength = 24;
    row.DadState = IpDadStatePreferred;
    if (CreateUnicastIpAddressEntry(&row) != NO_ERROR) { logf(n, "set IP failed %lu", GetLastError()); return FALSE; }

    /* interface metric 5000 — must be high so the virtual adapter can never win
     * the default route and swallow the box's outbound / remote-management. */
    memset(&iface, 0, sizeof(iface));
    iface.Family = AF_INET; iface.InterfaceLuid = luid;
    if (GetIpInterfaceEntry(&iface) == NO_ERROR) {
        iface.UseAutomaticMetric = FALSE;
        iface.Metric = 5000;
        iface.SitePrefixLength = 0;
        SetIpInterfaceEntry(&iface);
    }

    /* default route via 192.168.N.1, also metric 5000 (dead until the tunnel,
     * harmless because of the metric). */
    InitializeIpForwardEntry(&route);
    route.InterfaceLuid = luid;
    route.DestinationPrefix.Prefix.si_family = AF_INET;
    route.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    route.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr = 0;
    route.DestinationPrefix.PrefixLength = 0;
    route.NextHop.si_family = AF_INET;
    route.NextHop.Ipv4.sin_family = AF_INET;
    route.NextHop.Ipv4.sin_addr.S_un.S_addr = htonl(0xC0A80001u | ((unsigned)n << 8)); /* 192.168.N.1 */
    route.Metric = 5000;
    CreateIpForwardEntry2(&route);   /* best effort */
    return TRUE;
}

/* ---------------------------------------------------- PowerShell helper */
static void run_ps(const char *utf8)
{
    int wl = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    wchar_t *w = (wchar_t*)malloc((size_t)wl * sizeof(wchar_t));
    int b64len; char *b64; DWORD outn = 0;
    if (!w) return;
    MultiByteToWideChar(CP_UTF8, 0, utf8, -1, w, wl);
    /* base64 of UTF-16LE (drop trailing NUL) for powershell -EncodedCommand */
    {
        DWORD raw = (DWORD)((wl - 1) * sizeof(wchar_t));
        CryptBinaryToStringA((const BYTE*)w, raw, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outn);
        b64 = (char*)malloc(outn + 1);
        if (b64 && CryptBinaryToStringA((const BYTE*)w, raw, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64, &outn)) {
            char cmd[8192];
            STARTUPINFOA si; PROCESS_INFORMATION pi;
            b64len = (int)outn; b64[b64len] = 0;
            snprintf(cmd, sizeof(cmd),
                     "powershell -NoProfile -NonInteractive -EncodedCommand %s", b64);
            memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 15000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        }
        free(b64);
    }
    free(w);
}

static void set_conn_name(const wchar_t *guid, int n)
{
    char script[512];
    char gutf[64]; WideCharToMultiByte(CP_UTF8,0,guid,-1,gutf,sizeof(gutf),NULL,NULL);
    snprintf(script, sizeof(script),
        "$a=Get-NetAdapter -EA 0|?{$_.InterfaceGuid -eq '%s'};"
        "if($a){Rename-NetAdapter -Name $a.Name -NewName 'Ethernet %d' -EA 0}", gutf, n);
    run_ps(script);
}

/* -------------------------------------------------- finish (parallel) */
/* Runs after the device already exists (created serially in main). Everything
 * here is either per-adapter registry (safe) or a disable/enable cycle (taken
 * under the lock). Crucially there is NO driver install here, so writing the
 * identity last makes it stick even with many adapters in flight. */
static DWORD WINAPI finish(LPVOID arg)
{
    Dev *d = (Dev*)arg;
    int k;

    dev_set_mac(d);                                   /* MAC before the cycle */
    EnterCriticalSection(&g_pnp); dev_cycle(d); LeaveCriticalSection(&g_pnp);
    wait_up(d->guid, 15000);

    /* write the display identity last; confirm against the registry (truth). */
    for (k = 0; k < 4; k++) { dev_set_identity(d); if (identity_ok(d)) break; Sleep(250); }

    if (!configure_ip(d->guid, d->n)) logf(d->n, "warn: IP config failed");
    set_conn_name(d->guid, d->n);
    dev_set_identity(d);                               /* re-assert after rename */

    {
        wchar_t path[512], reg[256]; int up = 0;
        live(d->guid, &up, NULL, 0);
        _snwprintf(path, 512, L"SYSTEM\\CurrentControlSet\\Control\\Class\\%s", d->classkey);
        reg_get_sz(path, L"DriverDesc", reg, 256);
        logf(d->n, "%s name='Ethernet %d' ip=192.168.%d.100 metric=5000 up=%d desc='%ls'",
             identity_ok(d) ? "DONE" : "PARTIAL", d->n, d->n, up, reg);
    }
    SetupDiDestroyDeviceInfoList(d->hdi);
    InterlockedIncrement(&g_ok);
    return 0;
}

/* ------------------------------------------------------------ list/del */
static int enum_ours(void (*cb)(HDEVINFO, SP_DEVINFO_DATA*, const wchar_t*, void*), void *ctx)
{
    HDEVINFO hdi = SetupDiGetClassDevsW(&GUID_NET, NULL, NULL, DIGCF_PRESENT);
    SP_DEVINFO_DATA did; DWORD i; int count = 0;
    if (hdi == INVALID_HANDLE_VALUE) return 0;
    did.cbSize = sizeof(did);
    for (i = 0; SetupDiEnumDeviceInfo(hdi, i, &did); i++) {
        wchar_t hw[256] = {0}, inst[256] = {0}; DWORD req = 0;
        SetupDiGetDeviceRegistryPropertyW(hdi, &did, SPDRP_HARDWAREID, NULL, (BYTE*)hw, sizeof(hw), &req);
        SetupDiGetDeviceInstanceIdW(hdi, &did, inst, 256, &req);
        if (_wcsicmp(hw, TAP_HWID) == 0 && wcsncmp(inst, L"ROOT\\NET\\", 9) == 0) {
            count++;
            if (cb) cb(hdi, &did, inst, ctx);
        }
    }
    SetupDiDestroyDeviceInfoList(hdi);
    return count;
}
static void cb_list(HDEVINFO hdi, SP_DEVINFO_DATA *did, const wchar_t *inst, void *ctx)
{
    wchar_t desc[256] = {0}; DWORD req = 0; (void)ctx;
    SetupDiGetDeviceRegistryPropertyW(hdi, did, SPDRP_FRIENDLYNAME, NULL, (BYTE*)desc, sizeof(desc), &req);
    wprintf(L"  %-24s %s\n", inst, desc);
}
static void cb_del(HDEVINFO hdi, SP_DEVINFO_DATA *did, const wchar_t *inst, void *ctx)
{
    (void)ctx;
    EnterCriticalSection(&g_pnp);
    if (SetupDiCallClassInstaller(DIF_REMOVE, hdi, did)) wprintf(L"  removed %s\n", inst);
    else wprintf(L"  remove failed %s (err %lu)\n", inst, GetLastError());
    LeaveCriticalSection(&g_pnp);
}

/* ------------------------------------------------------------ main */
int main(int argc, char **argv)
{
    InitializeCriticalSection(&g_pnp);

    if (argc >= 2 && strcmp(argv[1], "list") == 0) {
        printf("virtual TAP adapters (ROOT\\NET, tap0901):\n");
        int c = enum_ours(cb_list, NULL);
        printf("total: %d\n", c);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "del") == 0) {
        if (argc >= 3 && strcmp(argv[2], "all") == 0) { enum_ours(cb_del, NULL); return 0; }
        printf("del: only 'del all' implemented for now\n"); return 1;
    }

    /* default action: add */
    {
        int first = (argc >= 2 && strcmp(argv[1], "add") == 0) ? 2 : 1;
        int i, nd = 0;
        static Dev devs[64];
        HANDLE th[64];

        if (argc <= first) {
            printf("usage: mkadapter add <N> [N2 ...] | list | del all\n");
            return 1;
        }
        if (!find_inf()) { printf("ERROR: no INF listing tap0901 found\n"); return 1; }
        wprintf(L"using INF: %s\n", g_inf);

        /* Phase 1 — create + install, SERIALISED. UpdateDriverForPlugAndPlayDevices
         * re-installs the driver on EVERY tap0901 device, which wipes the identity
         * of adapters already finished; so all installs must complete before any
         * disguise is written. This is the fix for the multithread revert. */
        for (i = first; i < argc && nd < 64; i++) {
            int n = atoi(argv[i]);
            if (n < 1 || n > 254) { printf("skip '%s' (need 1..254)\n", argv[i]); continue; }
            if (n == 1) { printf("skip 1 (192.168.1.0/24 is the host LAN)\n"); InterlockedIncrement(&g_fail); continue; }
            memset(&devs[nd], 0, sizeof(Dev)); devs[nd].n = n;
            EnterCriticalSection(&g_pnp);
            if (dev_create(&devs[nd])) nd++;
            else { if (devs[nd].hdi && devs[nd].hdi != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(devs[nd].hdi);
                   InterlockedIncrement(&g_fail); }
            LeaveCriticalSection(&g_pnp);
        }

        /* Phase 2 — finish each in parallel: MAC, cycle, wait-up, IP, rename. */
        for (i = 0; i < nd; i++) th[i] = CreateThread(NULL, 0, finish, &devs[i], 0, NULL);
        if (nd) WaitForMultipleObjects((DWORD)nd, th, TRUE, INFINITE);
        for (i = 0; i < nd; i++) if (th[i]) CloseHandle(th[i]);

        printf("\n==== summary: ok=%ld fail=%ld ====\n", (long)g_ok, (long)g_fail);
        return g_fail ? 2 : 0;
    }
}
