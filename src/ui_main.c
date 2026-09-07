/* modlink — main window, adaptive layout, background operations.
 *
 * Layout: every modem is a child window of a scrolling list. The row lays its
 * own controls out through the flex helper, and the set of lines it feeds the
 * helper depends on the current width mode. Narrowing the window past a
 * breakpoint reflows a single-line table into a stacked card — the native
 * equivalent of a CSS media query. */
#include "ui.h"
#include "json.h"
#include <windowsx.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <shellapi.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------- breakpoints */
enum { MODE_WIDE, MODE_MID, MODE_NARROW };
#define BP_WIDE 1150      /* unscaled dp */
#define BP_MID   880

#define ROW_LINE_H 26
#define ROW_GAP     6
#define ROW_PAD     6
#define HDR_H      52
#define BAR_H      46
#define COLHDR_H   26
#define TOOL_H     48
#define STATUS_H   24

/* ------------------------------------------------------------- ids */
enum {
    IDC_WANIP = 100, IDC_WANAUTO, IDC_LANIP, IDC_LANAUTO, IDC_BASEPORT,
    IDC_ADD, IDC_APPLY, IDC_COPY, IDC_LOGS, IDC_LIST,

    IDC_R_EN = 200, IDC_R_NAME, IDC_R_LOGIN, IDC_R_PASS, IDC_R_GEN,
    IDC_R_PORT, IDC_R_LANIP, IDC_R_MODEMIP, IDC_R_RPORT, IDC_R_INT,
    IDC_R_TEST, IDC_R_RECONN, IDC_R_REBOOT, IDC_R_LOG, IDC_R_DEL
};

#define WM_APP_TESTDONE   (WM_APP + 1)
#define WM_APP_ACTDONE    (WM_APP + 2)
#define WM_APP_APPLYDONE  (WM_APP + 3)
#define WM_APP_IPDONE     (WM_APP + 4)
#define WM_APP_STATUS     (WM_APP + 5)
#define WM_APP_RELAYOUT   (WM_APP + 6)

/* ------------------------------------------------------------- state */
typedef struct {
    int  modem_id;
    HWND en, num, login, pass, gen, port, lanip, modemip, rport, intv;
    HWND test, reconn, reboot, logbtn, del;
    BOOL enabled;
    int  test_state;              /* ML_TEST_* */
    char test_text[96];
} RowData;

static Config    g_cfg;
static HINSTANCE g_inst;
static HWND      g_main, g_list;
static HWND      g_wanip, g_lanip, g_baseport;
static HWND      g_btn_wanauto, g_btn_lanauto, g_btn_add, g_btn_apply, g_btn_copy, g_btn_logs;
static HWND      g_rows[ML_MAX_MODEMS];
static int       g_nrows = 0;
static int       g_mode = MODE_WIDE;
static int       g_scroll = 0, g_content_h = 0;
static char      g_status[512] = "готов";
static COLORREF  g_status_col;
static volatile LONG g_busy = 0;

static void relayout(void);
static void rows_rebuild(void);
static void collect_ui_into_config(void);

/* ------------------------------------------------------------- status */
static void status_set(const char *msg, COLORREF col)
{
    ml_strlcpy(g_status, msg, sizeof(g_status));
    g_status_col = col;
    if (g_main) InvalidateRect(g_main, NULL, FALSE);
}

/* Worker threads cannot touch the UI, so they post a heap copy instead. */
static void status_post(const char *msg, COLORREF col)
{
    char *dup = _strdup(msg);
    if (dup) PostMessageW(g_main, WM_APP_STATUS, (WPARAM)col, (LPARAM)dup);
}

/* ------------------------------------------------------------- clipboard */
static void clipboard_put(const char *utf8)
{
    wchar_t *w = ml_utf8_to_w(utf8);
    size_t bytes;
    HGLOBAL mem;
    if (!w) return;
    bytes = (wcslen(w) + 1) * sizeof(wchar_t);
    mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (mem) {
        void *p = GlobalLock(mem);
        memcpy(p, w, bytes);
        GlobalUnlock(mem);
        if (OpenClipboard(g_main)) {
            EmptyClipboard();
            SetClipboardData(CF_UNICODETEXT, mem);
            CloseClipboard();
        } else {
            GlobalFree(mem);
        }
    }
    free(w);
}

/* ------------------------------------------------------------- workers */
typedef struct { int modem_id; char host[ML_ADDR_LEN]; char login[ML_LOGIN_LEN];
                 char pass[ML_PASS_LEN]; int port;
                 /* Where to reach the proxy. NOT loopback: 3proxy binds -i to
                  * the host's LAN address, so 127.0.0.1 would refuse the
                  * connection and every test would read "нет ответа". */
                 char proxy[ML_ADDR_LEN]; } TestJob;
typedef struct { int modem_id; char text[96]; int state; } TestResult;
typedef struct { int modem_id; char host[ML_ADDR_LEN]; char login[ML_LOGIN_LEN];
                 int reboot; } ActJob;

static DWORD WINAPI test_thread(LPVOID arg)
{
    TestJob *j = (TestJob *)arg;
    TestResult *res = (TestResult *)calloc(1, sizeof(TestResult));
    HttpResp r;
    char exit_ip[ML_ADDR_LEN] = {0};
    BOOL huawei = FALSE;

    if (!res) { free(j); return 0; }
    res->modem_id = j->modem_id;

    /* Exit IP as seen from outside, fetched through this modem's own port —
     * this is the check that proves -e actually pinned the right interface. */
    if (http_get_via_proxy("http://api.ipify.org", j->proxy, j->port,
                           j->login, j->pass, 9000, &r) && r.status == 200 && r.body) {
        char *p = r.body, *w = exit_ip;
        while (*p == ' ' || *p == '\n' || *p == '\r') p++;
        while (*p && *p != '\n' && *p != '\r' && (size_t)(w - exit_ip) < sizeof(exit_ip) - 1)
            *w++ = *p++;
        *w = 0;
    }
    http_free(&r);

    if (j->host[0]) {
        char url[ML_URL_LEN];
        snprintf(url, sizeof(url), "http://%s/api/webserver/SesTokInfo", j->host);
        if (http_get_via_proxy(url, j->proxy, j->port, j->login, j->pass, 8000, &r) &&
            r.body && strstr(r.body, "SesInfo"))
            huawei = TRUE;
        http_free(&r);
    }

    if (ml_is_ipv4(exit_ip)) {
        res->state = ML_TEST_OK;
        snprintf(res->text, sizeof(res->text), "%s%s", exit_ip, huawei ? "  H OK" : "");
    } else {
        res->state = ML_TEST_FAIL;
        ml_strlcpy(res->text, "нет ответа", sizeof(res->text));
    }

    PostMessageW(g_main, WM_APP_TESTDONE, (WPARAM)res->modem_id, (LPARAM)res);
    free(j);
    return 0;
}

static DWORD WINAPI act_thread(LPVOID arg)
{
    ActJob *j = (ActJob *)arg;
    char msg[256] = {0};
    double dt = 0;
    BOOL ok;
    char out[512];

    if (j->reboot) {
        ok = hilink_reboot(j->host, msg, sizeof(msg));
        snprintf(out, sizeof(out), "%s: %s", j->login, msg);
        reconn_log_append(j->modem_id, out);
    } else {
        ok = hilink_reconnect(j->host, msg, sizeof(msg), &dt);
        snprintf(out, sizeof(out), "%s | manual | %.2fs | %s | %s",
                 j->login, dt, ok ? "ok" : "fail", msg);
        reconn_log_append(j->modem_id, out);
        snprintf(out, sizeof(out), "%s: %s (%.1f с)", j->login, msg, dt);
    }
    status_post(out, ok ? C_SUCCESS : C_ERROR);
    PostMessageW(g_main, WM_APP_ACTDONE, (WPARAM)j->modem_id, 0);
    free(j);
    return 0;
}

/* Works on its own copy: the user can keep editing (or add/remove rows) while
 * 3proxy restarts, and that must not change the config mid-apply. */
static DWORD WINAPI apply_thread(LPVOID arg)
{
    Config *snap = (Config *)arg;
    char err[1024] = {0};
    BOOL ok;

    ok = p3_apply(snap, err, sizeof(err));
    if (ok) {
        reconn_rebuild(snap);
        status_post("применено — 3proxy запущен", C_SUCCESS);
    } else {
        status_post(err[0] ? err : "не удалось применить", C_ERROR);
    }
    free(snap);
    InterlockedExchange(&g_busy, 0);
    PostMessageW(g_main, WM_APP_APPLYDONE, (WPARAM)ok, 0);
    return 0;
}

static DWORD WINAPI ip_thread(LPVOID arg)
{
    char ip[ML_ADDR_LEN] = {0};
    BOOL ok = net_fetch_external_ip(ip, sizeof(ip));
    (void)arg;
    if (ok) {
        char *dup = _strdup(ip);
        PostMessageW(g_main, WM_APP_IPDONE, 0, (LPARAM)dup);
    } else {
        status_post("не удалось определить внешний IP", C_ERROR);
        PostMessageW(g_main, WM_APP_IPDONE, 0, 0);
    }
    return 0;
}

/* ------------------------------------------------------------- row window */
static RowData *row_data(HWND h) { return (RowData *)GetWindowLongPtrW(h, GWLP_USERDATA); }

static void row_load(HWND row, const Modem *m)
{
    RowData *d = row_data(row);
    if (!d) return;
    d->modem_id = m->id;
    d->enabled  = m->enabled;
    edit_set_int(d->num,  m->n);
    edit_set(d->login,    m->login);
    edit_set(d->pass,     m->pass);
    edit_set(d->lanip,    m->lan_ip);
    edit_set(d->modemip,  m->modem_ip);
    edit_set_int(d->port,  m->proxy_port);
    edit_set_int(d->rport, m->reconn_port);
    edit_set_int(d->intv,  m->interval_min);
    SetWindowTextW(d->en, d->enabled ? L"\x2611" : L"\x2610");
}

static void row_store(HWND row, Modem *m)
{
    RowData *d = row_data(row);
    if (!d) return;
    m->n = edit_get_int(d->num);
    edit_get(d->login,   m->login,    sizeof(m->login));
    edit_get(d->pass,    m->pass,     sizeof(m->pass));
    edit_get(d->lanip,   m->lan_ip,   sizeof(m->lan_ip));
    edit_get(d->modemip, m->modem_ip, sizeof(m->modem_ip));
    m->proxy_port   = edit_get_int(d->port);
    m->reconn_port  = edit_get_int(d->rport);
    m->interval_min = edit_get_int(d->intv);
    m->enabled      = d->enabled;
}

/* Height of a row in the current mode — the list needs it before laying out. */
static int row_height(int mode)
{
    int lines = (mode == MODE_WIDE) ? 1 : (mode == MODE_MID) ? 2 : 4;
    return S(ROW_PAD) * 2 + lines * S(ROW_LINE_H) + (lines - 1) * S(ROW_GAP);
}

static void row_layout(HWND row)
{
    RowData *d = row_data(row);
    RECT rc;
    FlexLine L;
    int x, y, w, lh = S(ROW_LINE_H);

    if (!d) return;
    GetClientRect(row, &rc);
    x = S(ROW_PAD);
    y = S(ROW_PAD);
    w = rc.right - rc.left - S(ROW_PAD) * 2;

    if (g_mode == MODE_WIDE) {
        flex_reset(&L);
        flex_add(&L, d->en,      26,  0, 0);
        flex_add(&L, d->num,     44,  0, 0);
        flex_add(&L, d->modemip,108,  1, 0);
        flex_add(&L, d->lanip,  108,  1, 0);
        flex_add(&L, d->port,    58,  0, 0);
        flex_add(&L, d->login,   92,  1, 0);
        flex_add(&L, d->pass,   104,  1, 0);
        flex_add(&L, d->gen,     26,  0, 0);
        flex_add(&L, d->rport,   58,  0, 0);
        flex_add(&L, d->intv,    46,  0, 0);
        /* Weight 2: the exit IP is what gets read after every reconnect, so
         * spare width goes here first. A v4 address plus the Huawei marker
         * needs ~150dp before it starts eliding. */
        flex_add(&L, NULL,      150,  2, 0);
        flex_add(&L, d->test,    56,  0, 0);
        flex_add(&L, d->reconn,  26,  0, 0);
        flex_add(&L, d->reboot,  26,  0, 0);
        flex_add(&L, d->logbtn,  26,  0, 0);
        flex_add(&L, d->del,     26,  0, 0);
        flex_apply(&L, x, y, w, lh, ROW_GAP);
    } else if (g_mode == MODE_MID) {
        flex_reset(&L);
        flex_add(&L, d->en,      26,  0, 0);
        flex_add(&L, d->num,     44,  0, 0);
        flex_add(&L, d->modemip,108,  1, 0);
        flex_add(&L, d->lanip,  108,  1, 0);
        flex_add(&L, d->port,    58,  0, 0);
        flex_add(&L, d->login,   92,  1, 0);
        y = flex_apply(&L, x, y, w, lh, ROW_GAP) + S(ROW_GAP);

        flex_reset(&L);
        flex_add(&L, NULL,       26,  0, 0);
        flex_add(&L, d->pass,   104,  1, 0);
        flex_add(&L, d->gen,     26,  0, 0);
        flex_add(&L, d->rport,   58,  0, 0);
        flex_add(&L, d->intv,    46,  0, 0);
        flex_add(&L, NULL,      130,  2, 0);      /* test result */
        flex_add(&L, d->test,    56,  0, 0);
        flex_add(&L, d->reconn,  26,  0, 0);
        flex_add(&L, d->reboot,  26,  0, 0);
        flex_add(&L, d->logbtn,  26,  0, 0);
        flex_add(&L, d->del,     26,  0, 0);
        flex_apply(&L, x, y, w, lh, ROW_GAP);
    } else {
        flex_reset(&L);
        flex_add(&L, d->en,      26,  0, 0);
        flex_add(&L, d->num,     44,  0, 0);
        flex_add(&L, d->login,   90,  1, 0);
        flex_add(&L, d->port,    58,  0, 0);
        y = flex_apply(&L, x, y, w, lh, ROW_GAP) + S(ROW_GAP);

        flex_reset(&L);
        flex_add(&L, d->modemip, 96,  1, 0);
        flex_add(&L, d->lanip,   96,  1, 0);
        y = flex_apply(&L, x, y, w, lh, ROW_GAP) + S(ROW_GAP);

        flex_reset(&L);
        flex_add(&L, d->pass,    96,  2, 0);
        flex_add(&L, d->gen,     26,  0, 0);
        flex_add(&L, d->rport,   54,  1, 0);
        flex_add(&L, d->intv,    44,  0, 0);
        y = flex_apply(&L, x, y, w, lh, ROW_GAP) + S(ROW_GAP);

        flex_reset(&L);
        flex_add(&L, NULL,      120,  1, 0);      /* test result */
        flex_add(&L, d->test,    56,  0, 0);
        flex_add(&L, d->reconn,  26,  0, 0);
        flex_add(&L, d->reboot,  26,  0, 0);
        flex_add(&L, d->logbtn,  26,  0, 0);
        flex_add(&L, d->del,     26,  0, 0);
        flex_apply(&L, x, y, w, lh, ROW_GAP);
    }
}

/* The test-result cell has no control of its own; the row paints it so the
 * spinner/colour can change without recreating anything. */
static void row_paint_result(HWND row, HDC dc)
{
    RowData *d = row_data(row);
    RECT rc, cell;
    wchar_t *w;
    COLORREF col;
    int lh = S(ROW_LINE_H);

    if (!d || !d->test) return;
    GetClientRect(row, &rc);
    GetWindowRect(d->test, &cell);
    MapWindowPoints(NULL, row, (POINT *)&cell, 2);

    /* the result sits immediately left of the Test button */
    cell.right = cell.left - S(ROW_GAP);
    cell.left  = cell.right - S(g_mode == MODE_WIDE ? 150 :
                                g_mode == MODE_MID  ? 130 : 120);
    if (cell.left < S(ROW_PAD)) cell.left = S(ROW_PAD);
    cell.top    = cell.top + (cell.bottom - cell.top - lh) / 2;
    cell.bottom = cell.top + lh;

    switch (d->test_state) {
    case ML_TEST_OK:      col = C_SUCCESS; break;
    case ML_TEST_FAIL:    col = C_ERROR;   break;
    case ML_TEST_PENDING: col = C_MUTED;   break;
    default:              return;
    }
    w = ml_utf8_to_w(d->test_text);
    if (w) {
        theme_text(dc, &cell, w, g_th.f_mono, col,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        free(w);
    }
}

static LRESULT CALLBACK RowProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    RowData *d = row_data(h);

    switch (msg) {
    case WM_CREATE: {
        RowData *nd = (RowData *)calloc(1, sizeof(RowData));
        if (!nd) return -1;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)nd);
        nd->en      = btn_create(h, L"\x2611", IDC_R_EN, BTN_ICON);
        nd->num     = edit_create(h, IDC_R_NAME,    TRUE,  FALSE);
        nd->login   = edit_create(h, IDC_R_LOGIN,   TRUE,  FALSE);
        nd->pass    = edit_create(h, IDC_R_PASS,    TRUE,  FALSE);
        nd->gen     = btn_create(h, L"\x21ba", IDC_R_GEN, BTN_ICON);
        nd->port    = edit_create(h, IDC_R_PORT,    TRUE,  FALSE);
        nd->lanip   = edit_create(h, IDC_R_LANIP,   TRUE,  FALSE);
        nd->modemip = edit_create(h, IDC_R_MODEMIP, TRUE,  FALSE);
        nd->rport   = edit_create(h, IDC_R_RPORT,   TRUE,  FALSE);
        nd->intv    = edit_create(h, IDC_R_INT,     TRUE,  FALSE);
        nd->test    = btn_create(h, L"Test",   IDC_R_TEST,   BTN_NORMAL);
        nd->reconn  = btn_create(h, L"\x27f3", IDC_R_RECONN, BTN_ICON);
        nd->reboot  = btn_create(h, L"\x21bb", IDC_R_REBOOT, BTN_WARN);
        nd->logbtn  = btn_create(h, L"\x2261", IDC_R_LOG,    BTN_ICON);
        nd->del     = btn_create(h, L"\x2715", IDC_R_DEL,    BTN_DANGER);
        return 0;
    }
    case WM_DESTROY:
        free(d);
        SetWindowLongPtrW(h, GWLP_USERDATA, 0);
        return 0;

    case WM_SIZE:
        row_layout(h);
        return 0;

    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        RECT rc, line;
        GetClientRect(h, &rc);
        theme_fill(dc, &rc, g_th.br_surface);
        line = rc; line.top = line.bottom - 1;
        theme_fill(dc, &line, g_th.br_border);
        row_paint_result(h, dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        wchar_t label[32];
        GetWindowTextW(di->hwndItem, label, 31);
        btn_draw(di, btn_style_of(di->hwndItem), label);
        return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_BG);
        return (LRESULT)g_th.br_bg;
    }
    case WM_COMMAND:
        /* Row buttons are handled centrally; forward with the row handle so the
         * main window knows which modem was clicked. */
        if (HIWORD(wp) == BN_CLICKED || HIWORD(wp) == EN_CHANGE)
            SendMessageW(g_main, WM_COMMAND, wp, (LPARAM)h);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- list */
static void list_update_scroll(void)
{
    RECT rc;
    SCROLLINFO si;
    int rh, page;

    GetClientRect(g_list, &rc);
    rh   = row_height(g_mode);
    page = rc.bottom - rc.top;
    g_content_h = g_cfg.count * rh;

    if (g_scroll > g_content_h - page) g_scroll = g_content_h - page;
    if (g_scroll < 0) g_scroll = 0;

    memset(&si, 0, sizeof(si));
    si.cbSize = sizeof(si);
    si.fMask  = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMin   = 0;
    si.nMax   = g_content_h > 0 ? g_content_h - 1 : 0;
    si.nPage  = (UINT)page;
    si.nPos   = g_scroll;
    SetScrollInfo(g_list, SB_VERT, &si, TRUE);
}

static void list_layout(void)
{
    RECT rc;
    int i, rh, y;
    HWND child;
    HDWP dwp;

    GetClientRect(g_list, &rc);
    rh = row_height(g_mode);
    y  = -g_scroll;

    dwp = BeginDeferWindowPos(g_nrows);
    for (i = 0; i < g_nrows; i++) {
        child = g_rows[i];
        if (dwp && child)
            dwp = DeferWindowPos(dwp, child, NULL, 0, y, rc.right - rc.left, rh,
                                 SWP_NOZORDER | SWP_NOACTIVATE);
        y += rh;
    }
    if (dwp) EndDeferWindowPos(dwp);
    list_update_scroll();
}

static LRESULT CALLBACK ListProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_ERASEBKGND: {
        RECT rc;
        HDC dc = (HDC)wp;
        GetClientRect(h, &rc);
        theme_fill(dc, &rc, g_th.br_bg);
        return 1;
    }
    case WM_SIZE:
        list_layout();
        return 0;

    case WM_VSCROLL: {
        SCROLLINFO si;
        int old = g_scroll;
        RECT rc;
        GetClientRect(h, &rc);
        memset(&si, 0, sizeof(si));
        si.cbSize = sizeof(si);
        si.fMask  = SIF_ALL;
        GetScrollInfo(h, SB_VERT, &si);

        switch (LOWORD(wp)) {
        case SB_LINEUP:    g_scroll -= S(ROW_LINE_H); break;
        case SB_LINEDOWN:  g_scroll += S(ROW_LINE_H); break;
        case SB_PAGEUP:    g_scroll -= si.nPage;      break;
        case SB_PAGEDOWN:  g_scroll += si.nPage;      break;
        case SB_THUMBTRACK:
        case SB_THUMBPOSITION: g_scroll = si.nTrackPos; break;
        }
        if (g_scroll != old) list_layout();
        return 0;
    }
    case WM_MOUSEWHEEL: {
        int delta = GET_WHEEL_DELTA_WPARAM(wp);
        g_scroll -= delta * S(ROW_LINE_H) * 3 / WHEEL_DELTA;
        list_layout();
        return 0;
    }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- rows */
/* Row order is tracked explicitly. Walking the child z-order would NOT work:
 * CreateWindow puts each new child at the TOP of the sibling z-order, so
 * GW_CHILD/GW_HWNDNEXT hands back the rows newest-first, and every index would
 * address the wrong modem. */
static HWND row_at(int index)
{
    return (index >= 0 && index < g_nrows) ? g_rows[index] : NULL;
}

static HWND row_by_id(int modem_id)
{
    int i;
    for (i = 0; i < g_nrows; i++) {
        RowData *d = row_data(g_rows[i]);
        if (d && d->modem_id == modem_id) return g_rows[i];
    }
    return NULL;
}

static int row_index_of(HWND row)
{
    int i;
    for (i = 0; i < g_nrows; i++) if (g_rows[i] == row) return i;
    return -1;
}

static void rows_rebuild(void)
{
    int i;

    for (i = 0; i < g_nrows; i++) if (g_rows[i]) DestroyWindow(g_rows[i]);
    g_nrows = 0;

    for (i = 0; i < g_cfg.count; i++) {
        HWND row = CreateWindowExW(0, L"ModlinkRow", L"", WS_CHILD | WS_VISIBLE,
                                   0, 0, 10, 10, g_list, NULL, g_inst, NULL);
        if (row) {
            row_load(row, &g_cfg.modems[i]);
            row_layout(row);
            g_rows[g_nrows++] = row;
        }
    }
    list_layout();
    InvalidateRect(g_list, NULL, TRUE);
}

static void collect_ui_into_config(void)
{
    int i;
    char t[64];

    edit_get(g_wanip, g_cfg.wan_ip, sizeof(g_cfg.wan_ip));
    edit_get(g_lanip, g_cfg.lan_ip, sizeof(g_cfg.lan_ip));
    edit_get(g_baseport, t, sizeof(t));
    if (atoi(t) > 0) g_cfg.base_port = atoi(t);

    for (i = 0; i < g_cfg.count && i < g_nrows; i++) {
        HWND row = row_at(i);
        if (row) row_store(row, &g_cfg.modems[i]);
    }
}

/* ------------------------------------------------------------- copy */
/* Produces the client-side lines: IP:PORT:LOGIN:PASS plus the reconnect URL,
 * using the WAN IP when set and falling back to the LAN one. */
static void do_copy_credentials(void)
{
    JBuf b;
    const char *ip;
    int i, n = 0;

    collect_ui_into_config();
    ip = g_cfg.wan_ip[0] ? g_cfg.wan_ip : g_cfg.lan_ip;

    jb_init(&b);
    for (i = 0; i < g_cfg.count; i++) {
        const Modem *m = &g_cfg.modems[i];
        char line[512];
        if (!m->enabled) continue;
        snprintf(line, sizeof(line), "%s:%d:%s:%s\thttp://%s:%d/reconnect\r\n",
                 ip, m->proxy_port, m->login, m->pass, ip, m->reconn_port);
        jb_raw(&b, line);
        n++;
    }
    if (n && b.buf) {
        char msg[64];
        clipboard_put(b.buf);
        snprintf(msg, sizeof(msg), "скопировано строк: %d", n);
        status_set(msg, C_SUCCESS);
    } else {
        status_set("нет активных модемов", C_ERROR);
    }
    jb_free(&b);
}

/* ------------------------------------------------------------- log window */
static HWND g_logwnd, g_logedit;
static int  g_log_modem = -1;      /* -1 = 3proxy log, otherwise a modem id */

static void log_refresh(void)
{
    char **lines = NULL;
    int n, i;
    JBuf b;

    if (!g_logedit) return;
    jb_init(&b);

    if (g_log_modem < 0) n = ml_tail_file(ml_path_3plog(), 300, &lines);
    else                 n = reconn_log_read(g_log_modem, 200, &lines);

    for (i = 0; i < n; i++) { jb_raw(&b, lines[i]); jb_raw(&b, "\r\n"); }
    ml_free_lines(lines, n);

    edit_set(g_logedit, b.buf && b.len ? b.buf : "(пусто)");
    jb_free(&b);
    SendMessageW(g_logedit, EM_SETSEL, (WPARAM)-1, -1);
    SendMessageW(g_logedit, EM_SCROLLCARET, 0, 0);
}

static LRESULT CALLBACK LogProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_SIZE: {
        RECT rc;
        GetClientRect(h, &rc);
        if (g_logedit)
            MoveWindow(g_logedit, S(8), S(8),
                       rc.right - S(16), rc.bottom - S(16), TRUE);
        return 0;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_BG);
        return (LRESULT)g_th.br_bg;
    }
    case WM_ERASEBKGND: {
        RECT rc; HDC dc = (HDC)wp;
        GetClientRect(h, &rc);
        theme_fill(dc, &rc, g_th.br_surface);
        return 1;
    }
    case WM_CLOSE:
        ShowWindow(h, SW_HIDE);
        return 0;
    case WM_DESTROY:
        g_logwnd = g_logedit = NULL;
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static void log_show(int modem_id, const char *title)
{
    wchar_t *wt;

    g_log_modem = modem_id;
    if (!g_logwnd) {
        g_logwnd = CreateWindowExW(0, L"ModlinkLog", L"", WS_OVERLAPPEDWINDOW,
                                   CW_USEDEFAULT, CW_USEDEFAULT, S(900), S(520),
                                   g_main, NULL, g_inst, NULL);
        if (!g_logwnd) return;
        theme_dark_titlebar(g_logwnd);
        g_logedit = CreateWindowExW(0, L"EDIT", L"",
                                    WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                    ES_READONLY | ES_AUTOVSCROLL,
                                    0, 0, 10, 10, g_logwnd, NULL, g_inst, NULL);
        SendMessageW(g_logedit, WM_SETFONT, (WPARAM)g_th.f_mono, TRUE);
    }
    wt = ml_utf8_to_w(title);
    if (wt) { SetWindowTextW(g_logwnd, wt); free(wt); }
    log_refresh();
    ShowWindow(g_logwnd, SW_SHOW);
    SetForegroundWindow(g_logwnd);
}

/* ------------------------------------------------------------- actions */
static void action_test(HWND row)
{
    RowData *d = row_data(row);
    int idx = row_index_of(row);
    TestJob *j;
    Modem *m;

    if (!d || idx < 0) return;
    collect_ui_into_config();
    m = &g_cfg.modems[idx];

    if (!ml_port_valid(m->proxy_port)) { status_set("некорректный порт", C_ERROR); return; }
    if (!p3_running()) { status_set("3proxy не запущен — нажми «Применить»", C_WARN); return; }

    j = (TestJob *)calloc(1, sizeof(TestJob));
    if (!j) return;
    j->modem_id = m->id;
    j->port     = m->proxy_port;
    ml_strlcpy(j->host,  m->modem_ip, sizeof(j->host));
    ml_strlcpy(j->login, m->login,    sizeof(j->login));
    ml_strlcpy(j->pass,  m->pass,     sizeof(j->pass));
    /* Match whatever went into -i; empty means 3proxy bound every interface,
     * and then loopback is reachable again. */
    ml_strlcpy(j->proxy, g_cfg.lan_ip[0] ? g_cfg.lan_ip : "127.0.0.1", sizeof(j->proxy));

    d->test_state = ML_TEST_PENDING;
    ml_strlcpy(d->test_text, "...", sizeof(d->test_text));
    EnableWindow(d->test, FALSE);
    InvalidateRect(row, NULL, FALSE);

    CloseHandle(CreateThread(NULL, 0, test_thread, j, 0, NULL));
}

static void action_reconnect(HWND row, BOOL reboot)
{
    RowData *d = row_data(row);
    int idx = row_index_of(row);
    ActJob *j;
    Modem *m;

    if (!d || idx < 0) return;
    collect_ui_into_config();
    m = &g_cfg.modems[idx];

    if (!m->modem_ip[0]) { status_set("не задан IP модема", C_ERROR); return; }

    if (reboot) {
        wchar_t q[256];
        _snwprintf(q, 255, L"Перезагрузить модем на %hs?\n\n"
                           L"Он будет недоступен примерно 30-60 секунд.", m->modem_ip);
        if (MessageBoxW(g_main, q, L"modlink", MB_ICONWARNING | MB_YESNO) != IDYES) return;
    }

    j = (ActJob *)calloc(1, sizeof(ActJob));
    if (!j) return;
    j->modem_id = m->id;
    j->reboot   = reboot;
    ml_strlcpy(j->host,  m->modem_ip, sizeof(j->host));
    ml_strlcpy(j->login, m->login,    sizeof(j->login));

    EnableWindow(d->reconn, FALSE);
    EnableWindow(d->reboot, FALSE);
    status_set(reboot ? "перезагрузка модема..." : "реконнект...", C_ACCENT);

    CloseHandle(CreateThread(NULL, 0, act_thread, j, 0, NULL));
}

static void action_apply(void)
{
    char err[512];
    int bad;

    if (InterlockedCompareExchange(&g_busy, 1, 0) != 0) return;

    collect_ui_into_config();
    bad = cfg_validate(&g_cfg, err, sizeof(err));
    if (bad != -1) {
        status_set(err, C_ERROR);
        InterlockedExchange(&g_busy, 0);
        return;
    }
    if (!cfg_save(&g_cfg)) {
        status_set("не удалось сохранить config.json", C_ERROR);
        InterlockedExchange(&g_busy, 0);
        return;
    }

    {
        Config *snap = (Config *)malloc(sizeof(Config));
        if (!snap) { InterlockedExchange(&g_busy, 0); return; }
        memcpy(snap, &g_cfg, sizeof(Config));
        EnableWindow(g_btn_apply, FALSE);
        status_set("применяю...", C_ACCENT);
        CloseHandle(CreateThread(NULL, 0, apply_thread, snap, 0, NULL));
    }
}

/* ------------------------------------------------------------- main layout */
static void relayout(void)
{
    RECT rc;
    int w, y, mode_before = g_mode;
    int bw = S(96), bh = S(28), gap = S(8);
    int x;

    if (!g_main) return;
    GetClientRect(g_main, &rc);
    w = rc.right - rc.left;

    /* The breakpoint check is the whole adaptive story: pick a mode from the
     * width, and every row reflows itself when it changes. */
    if      (w >= S(BP_WIDE)) g_mode = MODE_WIDE;
    else if (w >= S(BP_MID))  g_mode = MODE_MID;
    else                      g_mode = MODE_NARROW;

    y = S(HDR_H);

    /* config bar */
    {
        int fx = S(12);
        int fy = y + (S(BAR_H) - bh) / 2;
        int field = S(g_mode == MODE_NARROW ? 108 : 150);

        MoveWindow(g_wanip, fx + S(78), fy, field, bh, TRUE);
        MoveWindow(g_btn_wanauto, fx + S(78) + field + S(4), fy, S(52), bh, TRUE);
        fx += S(78) + field + S(60);

        MoveWindow(g_lanip, fx + S(64), fy, field, bh, TRUE);
        MoveWindow(g_btn_lanauto, fx + S(64) + field + S(4), fy, S(52), bh, TRUE);
        fx += S(64) + field + S(60);

        MoveWindow(g_baseport, fx + S(76), fy, S(70), bh, TRUE);
    }
    y += S(BAR_H);
    if (g_mode == MODE_WIDE) y += S(COLHDR_H);

    /* list */
    MoveWindow(g_list, 0, y, w, rc.bottom - y - S(TOOL_H) - S(STATUS_H), TRUE);

    /* toolbar */
    y = rc.bottom - S(TOOL_H) - S(STATUS_H) + (S(TOOL_H) - bh) / 2;
    x = S(12);
    MoveWindow(g_btn_add,  x, y, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_btn_logs, x, y, bw, bh, TRUE);

    x = w - S(12) - bw;
    MoveWindow(g_btn_apply, x, y, bw, bh, TRUE); x -= bw + gap;
    MoveWindow(g_btn_copy,  x, y, bw, bh, TRUE);

    if (mode_before != g_mode) {
        int i;
        for (i = 0; i < g_nrows; i++) row_layout(g_rows[i]);
    }
    list_layout();
    InvalidateRect(g_main, NULL, FALSE);
}

static void paint_main(HWND h, HDC dc)
{
    RECT rc, r;
    wchar_t buf[256];
    int y;
    BOOL running = p3_running();

    GetClientRect(h, &rc);
    theme_fill(dc, &rc, g_th.br_bg);

    /* --- header --- */
    r = rc; r.bottom = S(HDR_H);
    theme_fill(dc, &r, g_th.br_surface);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }

    r.left = S(14); r.right = S(240);
    theme_text(dc, &r, L"modlink", g_th.f_title, C_WHITE, DT_VCENTER | DT_SINGLELINE);
    r.left = S(14) + S(78);
    theme_text(dc, &r, L"server", g_th.f_ui, C_MUTED, DT_VCENTER | DT_SINGLELINE);

    /* status chips, right-aligned */
    r = rc; r.bottom = S(HDR_H); r.right -= S(14); r.left = r.right - S(150);
    _snwprintf(buf, 255, L"%s  %d модем(ов)",
               running ? L"\x25cf active" : L"\x25cf stopped", g_cfg.count);
    theme_text(dc, &r, buf, g_th.f_ui, running ? C_SUCCESS : C_MUTED,
               DT_RIGHT | DT_VCENTER | DT_SINGLELINE);

    /* --- config bar labels --- */
    y = S(HDR_H);
    r = rc; r.top = y; r.bottom = y + S(BAR_H);
    theme_fill(dc, &r, g_th.br_surface);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }
    {
        int fx = S(12);
        int field = S(g_mode == MODE_NARROW ? 108 : 150);
        RECT lr = r;
        lr.left = fx; lr.right = fx + S(74);
        theme_text(dc, &lr, L"WAN IP", g_th.f_small, C_MUTED, DT_VCENTER | DT_SINGLELINE);
        fx += S(78) + field + S(60);
        lr.left = fx; lr.right = fx + S(60);
        theme_text(dc, &lr, L"LAN IP", g_th.f_small, C_MUTED, DT_VCENTER | DT_SINGLELINE);
        fx += S(64) + field + S(60);
        lr.left = fx; lr.right = fx + S(72);
        theme_text(dc, &lr, L"БАЗА ПОРТ", g_th.f_small, C_MUTED, DT_VCENTER | DT_SINGLELINE);
    }
    y += S(BAR_H);

    /* --- column header (wide mode only) --- */
    if (g_mode == MODE_WIDE) {
        /* Must mirror the WIDE flex line in row_layout() exactly. */
        static const wchar_t *H[] = { L"", L"№", L"IP МОДЕМА", L"LAN IP (-e)", L"ПОРТ",
                                      L"ЛОГИН", L"ПАРОЛЬ", L"", L"РЕК.ПОРТ", L"ИНТ",
                                      L"ТЕСТ", L"", L"", L"", L"", L"" };
        static const int W[] = { 26, 44, 108, 108, 58, 92, 104, 26, 58, 46, 150, 56, 26, 26, 26, 26 };
        static const int F[] = {  0,  0,   1,   1,  0,  1,   1,  0,  0,  0,   2,  0,  0,  0,  0,  0 };
        int i, total_min = 0, weight = 0, avail, leftover, cx;

        r = rc; r.top = y; r.bottom = y + S(COLHDR_H);
        theme_fill(dc, &r, g_th.br_bg);
        { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }

        for (i = 0; i < 16; i++) { total_min += S(W[i]); weight += F[i]; }
        total_min += S(ROW_GAP) * 15;
        avail = rc.right - S(ROW_PAD) * 2;
        leftover = avail - total_min;
        if (leftover < 0) leftover = 0;

        cx = S(ROW_PAD);
        for (i = 0; i < 16; i++) {
            int cw = S(W[i]) + (F[i] && weight ? leftover * F[i] / weight : 0);
            if (H[i][0]) {
                RECT cr = r;
                cr.left = cx; cr.right = cx + cw;
                cr.top += S(4);
                theme_text(dc, &cr, H[i], g_th.f_small, C_MUTED,
                           DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            cx += cw + S(ROW_GAP);
        }
    }

    /* --- toolbar + status strip --- */
    r = rc; r.top = rc.bottom - S(TOOL_H) - S(STATUS_H); r.bottom = rc.bottom - S(STATUS_H);
    theme_fill(dc, &r, g_th.br_surface);
    { RECT ln = r; ln.bottom = ln.top + 1; theme_fill(dc, &ln, g_th.br_border); }

    r = rc; r.top = rc.bottom - S(STATUS_H);
    theme_fill(dc, &r, g_th.br_bg);
    {
        wchar_t *w = ml_utf8_to_w(g_status);
        if (w) {
            RECT sr = r; sr.left = S(14); sr.right -= S(14);
            theme_text(dc, &sr, w, g_th.f_small,
                       g_status_col ? g_status_col : C_MUTED,
                       DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            free(w);
        }
    }
}

/* ------------------------------------------------------------- main proc */
static LRESULT CALLBACK MainProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_main = h;
        theme_dark_titlebar(h);

        g_list = CreateWindowExW(0, L"ModlinkList", L"",
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL,
                                 0, 0, 10, 10, h, (HMENU)IDC_LIST, g_inst, NULL);
        SetWindowTheme(g_list, L"DarkMode_Explorer", NULL);

        g_wanip       = edit_create(h, IDC_WANIP, TRUE, FALSE);
        g_lanip       = edit_create(h, IDC_LANIP, TRUE, FALSE);
        g_baseport    = edit_create(h, IDC_BASEPORT, TRUE, FALSE);
        g_btn_wanauto = btn_create(h, L"Авто", IDC_WANAUTO, BTN_NORMAL);
        g_btn_lanauto = btn_create(h, L"Авто", IDC_LANAUTO, BTN_NORMAL);
        g_btn_add     = btn_create(h, L"+ Добавить",  IDC_ADD,   BTN_NORMAL);
        g_btn_logs    = btn_create(h, L"Логи 3proxy", IDC_LOGS,  BTN_NORMAL);
        g_btn_copy    = btn_create(h, L"Копировать",  IDC_COPY,  BTN_NORMAL);
        g_btn_apply   = btn_create(h, L"Применить",   IDC_APPLY, BTN_PRIMARY);

        edit_set(g_wanip, g_cfg.wan_ip);
        edit_set(g_lanip, g_cfg.lan_ip);
        edit_set_int(g_baseport, g_cfg.base_port);
        return 0;

    case WM_SIZE:
        relayout();
        return 0;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lp;
        mmi->ptMinTrackSize.x = S(620);
        mmi->ptMinTrackSize.y = S(400);
        return 0;
    }
    case WM_DPICHANGED: {
        RECT *nr = (RECT *)lp;
        g_dpi = HIWORD(wp);
        theme_free();
        theme_init(h);
        SetWindowPos(h, NULL, nr->left, nr->top,
                     nr->right - nr->left, nr->bottom - nr->top,
                     SWP_NOZORDER | SWP_NOACTIVATE);
        rows_rebuild();
        relayout();
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(h, &ps);
        paint_main(h, dc);
        EndPaint(h, &ps);
        return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        wchar_t label[64];
        GetWindowTextW(di->hwndItem, label, 63);
        btn_draw(di, btn_style_of(di->hwndItem), label);
        return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        SetTextColor(dc, C_TEXT);
        SetBkColor(dc, C_BG);
        return (LRESULT)g_th.br_bg;
    }

    case WM_APP_STATUS: {
        char *text = (char *)lp;      /* heap copy from a worker thread */
        if (text) { status_set(text, (COLORREF)wp); free(text); }
        return 0;
    }
    case WM_APP_TESTDONE: {
        TestResult *r = (TestResult *)lp;
        HWND row;
        if (r) {
            row = row_by_id(r->modem_id);
            if (row) {
                RowData *d = row_data(row);
                d->test_state = r->state;
                ml_strlcpy(d->test_text, r->text, sizeof(d->test_text));
                EnableWindow(d->test, TRUE);
                InvalidateRect(row, NULL, FALSE);
            }
            free(r);
        }
        return 0;
    }
    case WM_APP_ACTDONE: {
        HWND row = row_by_id((int)wp);
        if (row) {
            RowData *d = row_data(row);
            EnableWindow(d->reconn, TRUE);
            EnableWindow(d->reboot, TRUE);
        }
        return 0;
    }
    case WM_APP_APPLYDONE:
        EnableWindow(g_btn_apply, TRUE);
        InvalidateRect(h, NULL, FALSE);
        return 0;

    case WM_APP_IPDONE: {
        char *ip = (char *)lp;
        if (ip) {
            edit_set(g_wanip, ip);
            ml_strlcpy(g_cfg.wan_ip, ip, sizeof(g_cfg.wan_ip));
            status_set("внешний IP определён", C_SUCCESS);
            free(ip);
        }
        EnableWindow(g_btn_wanauto, TRUE);
        return 0;
    }

    case WM_COMMAND: {
        int id  = LOWORD(wp);
        HWND src = (HWND)lp;

        /* Row controls arrive with the row handle in lParam. */
        if (id >= IDC_R_EN && id <= IDC_R_DEL && src && GetParent(src) == g_list) {
            HWND row = src;
            RowData *d = row_data(row);
            int idx = row_index_of(row);
            if (!d || idx < 0) return 0;

            switch (id) {
            case IDC_R_EN:
                d->enabled = !d->enabled;
                SetWindowTextW(d->en, d->enabled ? L"\x2611" : L"\x2610");
                InvalidateRect(d->en, NULL, TRUE);
                break;
            case IDC_R_GEN: {
                char p[ML_PASS_LEN];
                ml_rand_pass(p, sizeof(p), 10);
                edit_set(d->pass, p);
                break;
            }
            case IDC_R_TEST:   action_test(row); break;
            case IDC_R_RECONN: action_reconnect(row, FALSE); break;
            case IDC_R_REBOOT: action_reconnect(row, TRUE);  break;
            case IDC_R_LOG: {
                char title[128];
                collect_ui_into_config();
                snprintf(title, sizeof(title), "Лог реконнектов — %s",
                         g_cfg.modems[idx].login);
                log_show(g_cfg.modems[idx].id, title);
                break;
            }
            case IDC_R_DEL:
                collect_ui_into_config();
                cfg_remove_modem(&g_cfg, idx);
                rows_rebuild();
                status_set("модем удалён (не забудь «Применить»)", C_WARN);
                break;
            }
            return 0;
        }

        switch (id) {
        case IDC_ADD: {
            int idx;
            collect_ui_into_config();
            idx = cfg_add_modem(&g_cfg);
            if (idx < 0) { status_set("достигнут лимит модемов", C_ERROR); return 0; }
            rows_rebuild();
            g_scroll = g_content_h;
            list_layout();
            status_set("модем добавлен (не забудь «Применить»)", C_WARN);
            return 0;
        }
        case IDC_APPLY: action_apply(); return 0;
        case IDC_COPY:  do_copy_credentials(); return 0;
        case IDC_LOGS:  log_show(-1, "Лог 3proxy"); return 0;

        case IDC_WANAUTO:
            EnableWindow(g_btn_wanauto, FALSE);
            status_set("определяю внешний IP...", C_ACCENT);
            CloseHandle(CreateThread(NULL, 0, ip_thread, NULL, 0, NULL));
            return 0;

        case IDC_LANAUTO: {
            char ip[ML_ADDR_LEN];
            ml_detect_lan_ip(ip, sizeof(ip));
            edit_set(g_lanip, ip);
            ml_strlcpy(g_cfg.lan_ip, ip, sizeof(g_cfg.lan_ip));
            status_set("LAN IP определён", C_SUCCESS);
            return 0;
        }
        }
        return 0;
    }

    case WM_CLOSE:
        collect_ui_into_config();
        cfg_save(&g_cfg);
        DestroyWindow(h);
        return 0;

    case WM_DESTROY:
        reconn_shutdown();
        p3_stop();
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- entry */
static void register_classes(void)
{
    WNDCLASSEXW wc;

    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.hInstance     = g_inst;
    wc.hCursor       = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.style         = CS_HREDRAW | CS_VREDRAW;

    wc.lpfnWndProc   = MainProc;
    wc.lpszClassName = L"ModlinkMain";
    wc.hIcon         = LoadIconW(NULL, MAKEINTRESOURCEW(32512)); /* IDI_APPLICATION */
    wc.hIconSm       = wc.hIcon;
    RegisterClassExW(&wc);

    wc.lpfnWndProc   = RowProc;
    wc.lpszClassName = L"ModlinkRow";
    wc.hIcon = wc.hIconSm = NULL;
    RegisterClassExW(&wc);

    wc.lpfnWndProc   = ListProc;
    wc.lpszClassName = L"ModlinkList";
    RegisterClassExW(&wc);

    wc.lpfnWndProc   = LogProc;
    wc.lpszClassName = L"ModlinkLog";
    RegisterClassExW(&wc);
}

int ui_run(HINSTANCE hInst, int nCmdShow)
{
    MSG msg;
    HWND hwnd;
    INITCOMMONCONTROLSEX icc;

    g_inst = hInst;
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    /* DPI is read once here; WM_DPICHANGED refreshes it if the window moves to
     * a monitor with a different scale. */
    {
        HDC dc = GetDC(NULL);
        g_dpi = GetDeviceCaps(dc, LOGPIXELSX);
        ReleaseDC(NULL, dc);
    }

    theme_init(NULL);
    register_classes();

    cfg_load(&g_cfg);
    if (g_cfg.lan_auto && !g_cfg.lan_ip[0])
        ml_detect_lan_ip(g_cfg.lan_ip, sizeof(g_cfg.lan_ip));

    hwnd = CreateWindowExW(0, L"ModlinkMain", L"modlink",
                           WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, S(1280), S(700),
                           NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    rows_rebuild();
    relayout();
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    /* Bring the proxy up with whatever was last saved, so a restart of the app
     * restores service without the user pressing anything. */
    if (g_cfg.count > 0) {
        char err[512];
        if (p3_apply(&g_cfg, err, sizeof(err))) {
            reconn_rebuild(&g_cfg);
            status_set("3proxy запущен", C_SUCCESS);
        } else {
            status_set(err, C_ERROR);
        }
        InvalidateRect(hwnd, NULL, FALSE);
    } else {
        status_set("модемов нет — нажми «+ Добавить»", C_MUTED);
    }

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    theme_free();
    return 0;
}
