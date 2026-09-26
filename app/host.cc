/* modlink — WebView2 host.
 *
 * The whole window is one WebView2 control rendering app/ui.html. There is no
 * owner-draw, no GDI, no theming code — the look lives entirely in HTML/CSS,
 * which is exactly why this replaces the old native panel.
 *
 * Bridge model: each pv_* function from bridge.h is bound to a global JS
 * function of the same name. The UI calls `await pv_apply()` etc. and gets the
 * parsed JSON object straight back (webview splices the returned JSON into the
 * promise resolve). Fast operations answer on the UI thread; slow ones
 * (apply/test/reconnect/reboot touch the network or start a process) run on a
 * worker thread and marshal the reply back with webview_dispatch.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <string>
#include <thread>
#include <vector>
#include <cstring>

#include "webview.h"

extern "C" {
#include "bridge.h"
int worker_run(void);   /* src/worker.c — background engine, no window */
}

typedef char *(*bridge_fn)(const char *);

struct Binding { webview_t w; bridge_fn fn; };
static std::vector<Binding *> g_bindings;   /* live for the whole process */

/* ---- returning a reply to JS ---------------------------------------- */
static void reply(webview_t w, const char *seq, char *result)
{
    /* status 0 => the promise resolves with the value; non-zero => rejects. */
    webview_return(w, seq, result ? 0 : 1, result ? result : "{\"ok\":false}");
    free(result);
}

/* Fast path: compute on the UI thread, answer immediately. */
static void sync_cb(const char *seq, const char *req, void *arg)
{
    Binding *b = static_cast<Binding *>(arg);
    reply(b->w, seq, b->fn(req));
}

/* Slow path: compute on a worker, then hop back to the UI thread to answer. */
struct RetData { webview_t w; std::string seq; std::string result; int status; };

static void ret_on_ui(webview_t w, void *p)
{
    RetData *d = static_cast<RetData *>(p);
    webview_return(w, d->seq.c_str(), d->status, d->result.c_str());
    delete d;
}

static void async_cb(const char *seq, const char *req, void *arg)
{
    Binding *b = static_cast<Binding *>(arg);
    std::string s = seq ? seq : "";
    std::string r = req ? req : "[]";
    webview_t w = b->w;
    bridge_fn fn = b->fn;
    std::thread([w, fn, s, r]() {
        char *out = fn(r.c_str());
        RetData *d = new RetData{ w, s,
            out ? std::string(out) : std::string("{\"ok\":false}"),
            out ? 0 : 1 };
        free(out);
        webview_dispatch(w, ret_on_ui, d);
    }).detach();
}

static void reg(webview_t w, const char *name, bridge_fn fn, bool async)
{
    Binding *b = new Binding{ w, fn };
    g_bindings.push_back(b);
    webview_bind(w, name, async ? async_cb : sync_cb, b);
}

/* ---- UI html from the embedded RCDATA resource (id 201) ------------- */
#define IDR_UI_HTML 201

static char *load_ui_html()
{
    HRSRC res = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_UI_HTML), RT_RCDATA);
    if (!res) return nullptr;
    DWORD size = SizeofResource(nullptr, res);
    HGLOBAL glob = LoadResource(nullptr, res);
    if (!glob || !size) return nullptr;
    const void *data = LockResource(glob);
    if (!data) return nullptr;
    char *html = static_cast<char *>(malloc(size + 1));
    if (!html) return nullptr;
    memcpy(html, data, size);
    html[size] = 0;
    return html;
}

/* ---- single instance ------------------------------------------------- */
static bool already_running()
{
    HANDLE mtx = CreateMutexA(nullptr, TRUE, "Global\\modlink_single_instance");
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) {
        HWND prev = FindWindowW(L"Chrome_WidgetWin_0", nullptr); /* best effort */
        if (prev) { if (IsIconic(prev)) ShowWindow(prev, SW_RESTORE); SetForegroundWindow(prev); }
        return true;
    }
    return false;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int nCmdShow)
{
    (void)hInst; (void)hPrev; (void)nCmdShow;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    /* Background engine: no window, no GUI. Owns 3proxy + reconnect + watchdog. */
    if (cmd && strstr(cmd, "--worker")) {
        int rc = worker_run();
        WSACleanup();
        return rc;
    }

    if (already_running()) { WSACleanup(); return 0; }

    pv_init();

    webview_t w = webview_create(0 /* set to 1 to enable devtools */, nullptr);
    if (!w) {
        MessageBoxW(nullptr,
            L"Не удалось создать WebView2.\n\nНужен компонент «WebView2 Runtime» "
            L"(входит в Windows 10/11 и Microsoft Edge).",
            L"modlink", MB_ICONERROR | MB_OK);
        WSACleanup();
        return 1;
    }

    webview_set_title(w, "modlink");
    webview_set_size(w, 900, 560, WEBVIEW_HINT_MIN);
    webview_set_size(w, 1060, 700, WEBVIEW_HINT_NONE);

    /* Window icon, if one is embedded (resource id 1). Optional. */
    HWND hwnd = static_cast<HWND>(webview_get_window(w));
    if (hwnd) {
        HICON ic = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(1));
        if (ic) {
            SendMessageW(hwnd, WM_SETICON, ICON_BIG,   (LPARAM)ic);
            SendMessageW(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)ic);
        }
    }

    reg(w, "pv_get_state",    pv_get_state,    false);
    reg(w, "pv_status",       pv_status,       false);
    reg(w, "pv_checks",       pv_checks,       false);
    reg(w, "pv_log_modlink",  pv_log_modlink,  false);
    reg(w, "pv_log_3proxy",   pv_log_3proxy,   false);
    reg(w, "pv_clip",         pv_clip,         false);
    reg(w, "pv_save_network", pv_save_network, false);
    reg(w, "pv_add_modem",    pv_add_modem,    false);
    reg(w, "pv_set_mode",     pv_set_mode,     false);
    reg(w, "pv_update_modem", pv_update_modem, false);
    reg(w, "pv_delete_modem", pv_delete_modem, false);
    reg(w, "pv_stop",         pv_stop,         false);
    reg(w, "pv_apply",        pv_apply,        true);
    reg(w, "pv_test",         pv_test,         true);
    reg(w, "pv_reconnect",    pv_reconnect,    true);
    reg(w, "pv_reboot",       pv_reboot,       true);
    reg(w, "pv_speedtest",    pv_speedtest,    true);

    char *html = load_ui_html();
    if (html) { webview_set_html(w, html); free(html); }
    else       webview_set_html(w, "<h1 style='font:16px sans-serif;padding:2rem'>UI resource missing</h1>");

    webview_run(w);
    webview_destroy(w);

    pv_shutdown();
    WSACleanup();
    return 0;
}
