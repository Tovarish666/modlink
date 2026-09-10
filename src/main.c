/* modlink — точка входа. Два режима в одном exe:
 *   без аргументов  — панель сервера (3proxy, модемы);
 *   --agent         — панель агента (виртуальные модемы на этой машине).
 * Агенту нужны права администратора; если их нет, перезапускаем себя с
 * повышением. Сервер прав не требует и остаётся asInvoker. */
#include "common.h"
#include "ui.h"
#include <winsock2.h>
#include <shellapi.h>

int ui_agent_run(HINSTANCE hInst, int nCmdShow);

static BOOL is_agent(LPSTR cmd)
{
    return cmd && strstr(cmd, "--agent") != NULL;
}

static BOOL is_elevated(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD len = 0;
    BOOL r = FALSE;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len))
            r = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return r;
}

/* Перезапуск себя с запросом прав администратора (диалог UAC). */
static BOOL relaunch_elevated(const char *args)
{
    char self[ML_PATH_LEN];
    SHELLEXECUTEINFOA sei;
    if (!GetModuleFileNameA(NULL, self, sizeof(self))) return FALSE;
    memset(&sei, 0, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.lpVerb = "runas";              /* просит повышение */
    sei.lpFile = self;
    sei.lpParameters = args;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExA(&sei);
}

/* Второй экземпляр того же режима не нужен — поднимаем окно первого. */
static BOOL already_running(BOOL agent)
{
    const char *name = agent ? "Global\\modlink_agent_instance"
                             : "Global\\modlink_server_instance";
    HANDLE mtx = CreateMutexA(NULL, TRUE, name);
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND prev = FindWindowW(agent ? L"ModlinkAgent" : L"ModlinkMain", NULL);
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
    BOOL agent;
    int rc;

    (void)hPrev;
    agent = is_agent(cmd);

    /* Агент без прав — перезапускаемся с повышением и выходим. */
    if (agent && !is_elevated()) {
        if (relaunch_elevated("--agent")) return 0;
        MessageBoxW(NULL, L"Режим агента требует прав администратора.",
                    L"modlink", MB_ICONWARNING | MB_OK);
        return 1;
    }

    if (already_running(agent)) return 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        MessageBoxW(NULL, L"Не удалось инициализировать Winsock.", L"modlink",
                    MB_ICONERROR | MB_OK);
        return 1;
    }

    ml_ensure_dirs();
    ml_log(agent ? "---- modlink agent starting ----" : "---- modlink server starting ----");

    if (agent) {
        rc = ui_agent_run(hInst, nCmdShow);
    } else {
        p3_extract_binary();
        rc = ui_run(hInst, nCmdShow);
    }

    ml_log("---- modlink exiting ----");
    WSACleanup();
    return rc;
}
