/* modlink — entry point. */
#include "common.h"
#include <winsock2.h>

/* A second instance would fight the first for the proxy ports, so raise the
 * existing window instead of starting over. */
static BOOL already_running(void)
{
    HANDLE mtx = CreateMutexA(NULL, TRUE, "Global\\modlink_single_instance");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND prev = FindWindowW(L"ModlinkMain", NULL);
        if (prev) {
            if (IsIconic(prev)) ShowWindow(prev, SW_RESTORE);
            SetForegroundWindow(prev);
        }
        return TRUE;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int nCmdShow)
{
    WSADATA wsa;
    int rc;

    (void)hPrev; (void)cmd;

    if (already_running()) return 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(NULL, L"Не удалось инициализировать Winsock.", L"modlink",
                    MB_ICONERROR | MB_OK);
        return 1;
    }

    ml_ensure_dirs();
    ml_log("---- modlink starting ----");
    p3_extract_binary();

    rc = ui_run(hInst, nCmdShow);

    ml_log("---- modlink exiting ----");
    WSACleanup();
    return rc;
}
