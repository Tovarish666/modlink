/* modlink-agent — TAP-устройство, см. tap.h */
#include "tap.h"
#include <winioctl.h>
#include <string.h>
#include <stdio.h>

/* Коды взяты из официального include/tap-windows.h пакета tap-windows6, а не
 * выведены на глаз: ошибиться здесь легко, а диагностика была бы невнятной. */
#define TAP_WIN_CONTROL_CODE(request, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)
#define TAP_WIN_IOCTL_GET_MAC          TAP_WIN_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_WIN_IOCTL_SET_MEDIA_STATUS TAP_WIN_CONTROL_CODE(6, METHOD_BUFFERED)

#define ADAPTER_KEY "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define CONN_KEY    "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define TAP_COMPONENT_ID "tap0901"

/* ------------------------------------------------------------- реестр */
static BOOL reg_str(HKEY root, const char *path, const char *name, char *out, DWORD cap)
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

int tap_enumerate(TapAdapter *out, int cap)
{
    HKEY k;
    DWORD i = 0;
    int found = 0;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTER_KEY, 0, KEY_READ, &k) != ERROR_SUCCESS)
        return 0;

    for (;; i++) {
        char sub[64], path[512], cid[128];
        DWORD sublen = sizeof(sub);

        if (RegEnumKeyExA(k, i, sub, &sublen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (found >= cap) break;

        snprintf(path, sizeof(path), "%s\\%s", ADAPTER_KEY, sub);
        if (!reg_str(HKEY_LOCAL_MACHINE, path, "ComponentId", cid, sizeof(cid))) continue;
        if (_stricmp(cid, TAP_COMPONENT_ID) != 0) continue;

        {
            TapAdapter *a = &out[found];
            memset(a, 0, sizeof(*a));
            if (!reg_str(HKEY_LOCAL_MACHINE, path, "NetCfgInstanceId", a->guid, sizeof(a->guid)))
                continue;
            reg_str(HKEY_LOCAL_MACHINE, path, "DriverDesc", a->desc, sizeof(a->desc));
            ml_strlcpy(a->regkey, sub, sizeof(a->regkey));
            {   /* человекочитаемое имя лежит в другой ветке */
                char cpath[512];
                snprintf(cpath, sizeof(cpath), "%s\\%s\\Connection", CONN_KEY, a->guid);
                reg_str(HKEY_LOCAL_MACHINE, cpath, "Name", a->name, sizeof(a->name));
            }
            found++;
        }
    }
    RegCloseKey(k);
    return found;
}

BOOL tap_find_by_guid(const char *guid, TapAdapter *out)
{
    TapAdapter all[64];
    int n = tap_enumerate(all, 64), i;
    for (i = 0; i < n; i++) {
        if (!_stricmp(all[i].guid, guid)) { *out = all[i]; return TRUE; }
    }
    return FALSE;
}

/* ------------------------------------------------------------- устройство */
HANDLE tap_open(const char *guid, char *err, size_t errcap)
{
    char path[256];
    HANDLE h;
    ULONG status = 1;
    DWORD ret = 0;

    if (err && errcap) err[0] = 0;
    snprintf(path, sizeof(path), "\\\\.\\Global\\%s.tap", guid);

    /* FILE_FLAG_OVERLAPPED обязателен: без него чтение кадра заблокирует поток
     * навсегда, если трафика нет, и остановить агента будет нечем. */
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (err) {
            if (e == ERROR_FILE_NOT_FOUND)
                snprintf(err, errcap, "адаптер %s не найден", guid);
            else if (e == ERROR_ACCESS_DENIED || e == ERROR_SHARING_VIOLATION)
                snprintf(err, errcap, "адаптер %s уже занят другим процессом", guid);
            else
                snprintf(err, errcap, "не удалось открыть %s (ошибка %lu)", guid, e);
        }
        return INVALID_HANDLE_VALUE;
    }

    /* «Подключить кабель». Без этого система считает адаптер отключённым и не
     * отправит в него ни одного пакета. */
    if (!DeviceIoControl(h, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                         &status, sizeof(status), &status, sizeof(status), &ret, NULL)) {
        if (err) snprintf(err, errcap, "не удалось поднять линк (ошибка %lu)", GetLastError());
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

void tap_close(HANDLE h)
{
    ULONG status = 0;
    DWORD ret = 0;
    if (h == INVALID_HANDLE_VALUE || !h) return;
    DeviceIoControl(h, TAP_WIN_IOCTL_SET_MEDIA_STATUS,
                    &status, sizeof(status), &status, sizeof(status), &ret, NULL);
    CloseHandle(h);
}

BOOL tap_get_mac(HANDLE h, unsigned char mac[6])
{
    DWORD ret = 0;
    return DeviceIoControl(h, TAP_WIN_IOCTL_GET_MAC, mac, 6, mac, 6, &ret, NULL) && ret == 6;
}

/* ------------------------------------------------------------- обмен */
BOOL tap_read_begin(HANDLE h, void *buf, int cap, OVERLAPPED *ov, BOOL *completed)
{
    DWORD got = 0;
    HANDLE ev = ov->hEvent;

    *completed = FALSE;
    memset(ov, 0, sizeof(*ov));
    ov->hEvent = ev;
    ResetEvent(ev);

    if (ReadFile(h, buf, (DWORD)cap, &got, ov)) {
        *completed = TRUE;          /* успело синхронно */
        return TRUE;
    }
    return GetLastError() == ERROR_IO_PENDING;
}

BOOL tap_read_end(HANDLE h, OVERLAPPED *ov, int *got)
{
    DWORD n = 0;
    if (!GetOverlappedResult(h, ov, &n, FALSE)) {
        *got = 0;
        return GetLastError() == ERROR_IO_INCOMPLETE;
    }
    *got = (int)n;
    return TRUE;
}

void tap_read_cancel(HANDLE h, OVERLAPPED *ov)
{
    DWORD n = 0;
    CancelIoEx(h, ov);
    GetOverlappedResult(h, ov, &n, TRUE);
}

BOOL tap_write(HANDLE h, const void *buf, int len)
{
    OVERLAPPED ov;
    DWORD wrote = 0;
    BOOL ok;

    memset(&ov, 0, sizeof(ov));
    ov.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ov.hEvent) return FALSE;

    ok = WriteFile(h, buf, (DWORD)len, &wrote, &ov);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = (WaitForSingleObject(ov.hEvent, 5000) == WAIT_OBJECT_0) &&
             GetOverlappedResult(h, &ov, &wrote, FALSE);
        if (!ok) CancelIoEx(h, &ov);
    }
    CloseHandle(ov.hEvent);
    return ok && wrote == (DWORD)len;
}
