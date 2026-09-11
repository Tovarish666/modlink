/* modlink — точка входа. Одно окно, две вкладки: «Сервер» и «Агент».
 * Серверу права администратора не нужны; агенту (создание адаптеров, реестр)
 * нужны. Поэтому запуск с --agent сразу открывает вкладку агента и, если прав
 * нет, перезапускает себя с повышением. Обычный запуск — вкладка сервера без
 * повышения; переключиться на агента можно и там, но операции с адаптерами
 * попросят администратора. */
#include "common.h"
#include "ui.h"
#include <winsock2.h>
#include <shellapi.h>

extern int g_start_agent;   /* из ui_main: стартовать на вкладке агента */

static BOOL is_elevated(void)
{
    HANDLE tok = NULL; TOKEN_ELEVATION el; DWORD len = 0; BOOL r = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len))
            r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

static BOOL relaunch_elevated(const char *args)
{
    char self[ML_PATH_LEN];
    SHELLEXECUTEINFOA sei;
    if (!GetModuleFileNameA(NULL, self, sizeof(self))) return FALSE;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";
    sei.lpFile = self;
    sei.lpParameters = args;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExA(&sei);
}

static BOOL already_running(void)
{
    HANDLE mtx = CreateMutexA(NULL, TRUE, "Global\\modlink_single_instance");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND prev = FindWindowW(L"ModlinkMain", NULL);
        if (prev) { if (IsIconic(prev)) ShowWindow(prev, SW_RESTORE); SetForegroundWindow(prev); }
        return TRUE;
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int nCmdShow)
{
    WSADATA wsa;
    BOOL agent = cmd && strstr(cmd, "--agent") != NULL;
    int rc;
    (void)hPrev;

    /* Запуск с --agent без прав — перезапускаемся с повышением. */
    if (agent && !is_elevated()) {
        if (relaunch_elevated("--agent")) return 0;
        MessageBoxW(NULL, L"Режим агента требует прав администратора.",
                    L"modlink", MB_ICONWARNING | MB_OK);
        return 1;
    }

    if (already_running()) return 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(NULL, L"Не удалось инициализировать Winsock.", L"modlink",
                    MB_ICONERROR | MB_OK);
        return 1;
    }

    ml_ensure_dirs();
    ml_log("---- modlink starting ----");
    if (agent) g_start_agent = 1;

    /* 3proxy распаковываем только под сервер; агенту он не нужен. */
    if (!agent) p3_extract_binary();

    rc = ui_run(hInst, nCmdShow);

    ml_log("---- modlink exiting ----");
    WSACleanup();
    return rc;
}
