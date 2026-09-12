/* modlink — вид «агент»: виртуальные модемы на этой машине.
 *
 * Встраивается как дочернее окно в общую оболочку (одно приложение, вкладки
 * «Сервер»/«Агент»). Каждая строка — виртуальный интерфейс: по номеру N
 * считаются адрес 192.168.N.100 и шлюз 192.168.N.1, прокси задаётся одной
 * строкой IP:port:login:pass. «Применить» создаёт для новых строк TAP-адаптеры
 * (winnet), настраивает адреса и поднимает туннели; lwIP один на процесс,
 * поэтому применение — полный перезапуск связки.
 *
 * Операции с адаптерами требуют прав администратора; их запрашивает оболочка. */
#include "ui.h"
#include "agentcfg.h"
#include "tunnel.h"
#include "winnet.h"
#include "socks5.h"
#include "tap.h"
#include <windowsx.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <string.h>
#include <stdlib.h>

#define A_ROW_H     30
#define A_GAP        6
#define A_PAD       10
#define A_BAR_H     46
#define A_COLHDR_H  24
#define A_STATUS_H  24

enum {
    IDC_A_ADD = 300, IDC_A_APPLY, IDC_A_START, IDC_A_STOP, IDC_A_RESCAN, IDC_A_LIST,
    IDC_AR_NUM = 360, IDC_AR_NAME, IDC_AR_REAL, IDC_AR_PROXY, IDC_AR_DEL
};

#define WM_A_APPLYDONE (WM_APP + 20)
#define WM_A_STATUS    (WM_APP + 21)

typedef struct {
    char  guid[TAP_GUID_LEN];     /* пусто → адаптер ещё не создан */
    BOOL  preexisting;            /* уже был в системе, не из конфига */
    char  test[64];               /* статус, рисуется */
    int   test_col;               /* 0 нет, 1 ok, 2 fail, 3 pending */
    HWND  num, name, real, proxy, del;
} ARow;

static HINSTANCE  g_inst;
static HWND       g_view, g_alist;          /* g_view — дочернее окно вида */
static HWND       g_btn_add, g_btn_apply, g_btn_start, g_btn_stop, g_btn_rescan;
static HWND       g_arows[TUNNEL_MAX_IFACES];
static int        g_narows = 0;
static int        g_ascroll = 0, g_acontent = 0;
static char       g_astatus[400] = "";
static COLORREF   g_astatus_col;
static BOOL       g_running = FALSE;
static volatile LONG g_abusy = 0;

int  agent_is_running(void) { return g_running; }
int  agent_iface_rows(void) { return g_narows; }

static void a_status(const char *m, COLORREF c)
{
    ml_strlcpy(g_astatus, m, sizeof(g_astatus));
    g_astatus_col = c;
    if (g_view) InvalidateRect(g_view, NULL, FALSE);
}
static void a_status_post(const char *m, COLORREF c)
{
    char *d = _strdup(m);
    if (d) PostMessageW(g_view, WM_A_STATUS, (WPARAM)c, (LPARAM)d);
}

/* ------------------------------------------------------------- строки */
static ARow *arow(HWND h) { return (ARow *)GetWindowLongPtrW(h, GWLP_USERDATA); }

static int arow_index(HWND row)
{
    int i;
    for (i = 0; i < g_narows; i++) if (g_arows[i] == row) return i;
    return -1;
}

static int arow_num(HWND row)
{
    char t[16];
    edit_get(arow(row)->num, t, sizeof(t));
    return atoi(t);
}

/* Первый свободный номер, начиная с 1. */
static int next_free_no(void)
{
    int n, i;
    for (n = 1; n <= 254; n++) {
        BOOL taken = FALSE;
        for (i = 0; i < g_narows; i++) if (arow_num(g_arows[i]) == n) { taken = TRUE; break; }
        if (!taken) return n;
    }
    return 0;
}

static void arow_layout(HWND row)
{
    ARow *d = arow(row);
    RECT rc;
    FlexLine L;
    int x, y, w, lh = S(A_ROW_H - 4);
    if (!d) return;
    GetClientRect(row, &rc);
    x = S(A_PAD); y = S(2); w = rc.right - rc.left - S(A_PAD) * 2;

    flex_reset(&L);
    flex_add(&L, d->num,    44, 0, 0);
    flex_add(&L, d->name,   96, 1, 0);
    flex_add(&L, d->real,  116, 1, 0);          /* IP модема (real) */
    flex_add(&L, d->proxy, 240, 3, 0);          /* IP:port:login:pass */
    flex_add(&L, NULL,     120, 1, 0);          /* статус, рисуется */
    flex_add(&L, d->del,    26, 0, 0);
    flex_apply(&L, x, y, w, lh, A_GAP);
}

/* Рисуем статус в свободной ячейке слева от ✕. */
static void arow_paint_status(HWND row, HDC dc)
{
    ARow *d = arow(row);
    RECT rc, cell;
    wchar_t *w;
    COLORREF col;
    int lh = S(A_ROW_H - 4);
    if (!d || !d->del || !d->test[0]) return;
    GetClientRect(row, &rc);
    GetWindowRect(d->del, &cell);
    MapWindowPoints(NULL, row, (POINT *)&cell, 2);
    cell.right = cell.left - S(A_GAP);
    cell.left  = cell.right - S(120);
    if (cell.left < S(A_PAD)) cell.left = S(A_PAD);
    cell.top = cell.top + (cell.bottom - cell.top - lh) / 2;
    cell.bottom = cell.top + lh;
    switch (d->test_col) {
    case 1: col = C_SUCCESS; break;
    case 2: col = C_ERROR;   break;
    case 3: col = C_ACCENT;  break;
    default: col = C_MUTED;
    }
    w = ml_utf8_to_w(d->test);
    if (w) { theme_text(dc, &cell, w, g_th.f_mono, col,
                        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS); free(w); }
}

/* № → адрес/шлюз показываем сразу в статусе строки (в реальную настройку
 * попадут при «Применить»). */
static void arow_reflect_no(HWND row)
{
    ARow *d = arow(row);
    int n = arow_num(row);
    if (n >= 1 && n <= 254 && !d->guid[0]) {
        snprintf(d->test, sizeof(d->test), "192.168.%d.100", n);
        d->test_col = 0;
    }
    InvalidateRect(row, NULL, FALSE);
}

static LRESULT CALLBACK ARowProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    ARow *d = arow(h);
    switch (msg) {
    case WM_CREATE: {
        ARow *nd = (ARow *)calloc(1, sizeof(ARow));
        if (!nd) return -1;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)nd);
        nd->num   = edit_create(h, IDC_AR_NUM,  TRUE,  FALSE);   /* № редактируемый */
        nd->name  = edit_create(h, IDC_AR_NAME, FALSE, FALSE);
        nd->real  = edit_create(h, IDC_AR_REAL, TRUE,  FALSE);
        nd->proxy = edit_create(h, IDC_AR_PROXY,TRUE,  FALSE);
        nd->del   = btn_create (h, L"\x2715", IDC_AR_DEL, BTN_DANGER);
        return 0;
    }
    case WM_DESTROY: free(d); SetWindowLongPtrW(h, GWLP_USERDATA, 0); return 0;
    case WM_SIZE: arow_layout(h); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        RECT rc, ln; GetClientRect(h, &rc);
        theme_fill(dc, &rc, d && d->preexisting ? g_th.br_surface2 : g_th.br_surface);
        ln = rc; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border);
        arow_paint_status(h, dc);
        EndPaint(h, &ps); return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        wchar_t lbl[32]; GetWindowTextW(di->hwndItem, lbl, 31);
        btn_draw(di, btn_style_of(di->hwndItem), lbl);
        return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: { HDC dc=(HDC)wp; SetTextColor(dc,C_TEXT); SetBkColor(dc,C_BG); return (LRESULT)g_th.br_bg; }
    case WM_COMMAND:
        if (HIWORD(wp) == EN_CHANGE && LOWORD(wp) == IDC_AR_NUM) arow_reflect_no(h);
        if (HIWORD(wp) == BN_CLICKED)
            SendMessageW(g_view, WM_COMMAND, wp, (LPARAM)h);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- список */
static void alist_layout(void)
{
    RECT rc; int i, y; SCROLLINFO si; HDWP dwp; int rh = S(A_ROW_H);
    GetClientRect(g_alist, &rc);
    y = -g_ascroll;
    dwp = BeginDeferWindowPos(g_narows);
    for (i = 0; i < g_narows; i++) {
        if (dwp) dwp = DeferWindowPos(dwp, g_arows[i], NULL, 0, y, rc.right - rc.left, rh,
                                      SWP_NOZORDER | SWP_NOACTIVATE);
        y += rh;
    }
    if (dwp) EndDeferWindowPos(dwp);
    g_acontent = g_narows * rh;
    memset(&si, 0, sizeof(si)); si.cbSize = sizeof(si);
    si.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
    si.nMax = g_acontent > 0 ? g_acontent - 1 : 0;
    si.nPage = (UINT)(rc.bottom - rc.top); si.nPos = g_ascroll;
    SetScrollInfo(g_alist, SB_VERT, &si, TRUE);
}

static LRESULT CALLBACK AListProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_ERASEBKGND: { RECT rc; GetClientRect(h, &rc); theme_fill((HDC)wp, &rc, g_th.br_bg); return 1; }
    case WM_SIZE: alist_layout(); return 0;
    case WM_MOUSEWHEEL:
        g_ascroll -= GET_WHEEL_DELTA_WPARAM(wp) * S(A_ROW_H) * 3 / WHEEL_DELTA;
        if (g_ascroll < 0) g_ascroll = 0;
        alist_layout(); return 0;
    case WM_VSCROLL: {
        SCROLLINFO si; int old = g_ascroll; memset(&si,0,sizeof(si));
        si.cbSize=sizeof(si); si.fMask=SIF_ALL; GetScrollInfo(h,SB_VERT,&si);
        switch (LOWORD(wp)) {
        case SB_LINEUP: g_ascroll -= S(A_ROW_H); break;
        case SB_LINEDOWN: g_ascroll += S(A_ROW_H); break;
        case SB_PAGEUP: g_ascroll -= si.nPage; break;
        case SB_PAGEDOWN: g_ascroll += si.nPage; break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: g_ascroll = si.nTrackPos; break;
        }
        if (g_ascroll < 0) g_ascroll = 0;
        if (g_ascroll != old) alist_layout();
        return 0;
    }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static HWND arow_add(int modem_no)
{
    HWND row; char t[16];
    if (g_narows >= TUNNEL_MAX_IFACES) return NULL;
    row = CreateWindowExW(0, L"ModlinkARow", L"", WS_CHILD | WS_VISIBLE,
                          0, 0, 10, 10, g_alist, NULL, g_inst, NULL);
    if (!row) return NULL;
    snprintf(t, sizeof(t), "%d", modem_no);
    edit_set(arow(row)->num, t);
    arow_reflect_no(row);
    arow_layout(row);
    g_arows[g_narows++] = row;
    return row;
}

/* Разбор строки прокси IP:port[:login[:pass]] */
static void parse_proxy(const char *in, TunnelCfg *t)
{
    char buf[256], *p = buf, *tok;
    ml_strlcpy(buf, in, sizeof(buf));
    tok = p; p = strchr(p, ':'); if (p) *p++ = 0;
    ml_strlcpy(t->proxy_ip, tok, sizeof(t->proxy_ip));
    if (!p) return;
    tok = p; p = strchr(p, ':'); if (p) *p++ = 0;
    t->proxy_port = atoi(tok);
    if (!p) return;
    tok = p; p = strchr(p, ':'); if (p) *p++ = 0;
    ml_strlcpy(t->user, tok, sizeof(t->user));
    if (!p) return;
    ml_strlcpy(t->pass, p, sizeof(t->pass));
}

/* Строка → TunnelCfg. Адрес/шлюз считаются из №. FALSE — нет №, real или прокси. */
static BOOL arow_to_cfg(HWND row, TunnelCfg *t)
{
    ARow *d = arow(row);
    char proxy[256] = {0};
    int n = arow_num(row);
    memset(t, 0, sizeof(*t));
    if (n < 1 || n > 254) return FALSE;
    edit_get(d->name,  t->label,   sizeof(t->label));
    edit_get(d->real,  t->real_ip, sizeof(t->real_ip));
    edit_get(d->proxy, proxy,      sizeof(proxy));
    ml_strlcpy(t->guid, d->guid, sizeof(t->guid));
    ml_strlcpy(t->netmask, "255.255.255.0", sizeof(t->netmask));
    snprintf(t->virt_ip, sizeof(t->virt_ip), "192.168.%d.1", n);   /* шлюз/морда из № */
    if (!t->label[0]) snprintf(t->label, sizeof(t->label), "modem%d", n);
    parse_proxy(proxy, t);
    return t->proxy_ip[0] && t->proxy_port;
}

/* ------------------------------------------------------------- применение */
static DWORD WINAPI apply_thread(LPVOID arg)
{
    int i, made = 0;
    char err[512];
    (void)arg;

    tunnel_stop();

    for (i = 0; i < g_narows; i++) {
        HWND row = g_arows[i];
        ARow *d = arow(row);
        int n = arow_num(row);
        char host_ip[ML_ADDR_LEN], virt[ML_ADDR_LEN];
        if (n < 1 || n > 254) continue;
        snprintf(host_ip, sizeof(host_ip), "192.168.%d.100", n);
        snprintf(virt,    sizeof(virt),    "192.168.%d.1",   n);

        /* GUID из конфига мог остаться от удалённого адаптера — проверяем, что
         * он ещё живой, иначе создаём заново. Без этого «Применить» пытается
         * поднять туннель на несуществующий адаптер и падает с «не найден». */
        if (d->guid[0]) {
            TapAdapter chk;
            if (!tap_find_by_guid(d->guid, &chk)) d->guid[0] = 0;
        }

        if (!d->guid[0]) {
            char inf[ML_PATH_LEN], mac[16];
            snprintf(inf, sizeof(inf), "%s\\OemVista.inf", ml_dir_data());
            if (!winnet_create_adapter(inf, d->guid, sizeof(d->guid), err, sizeof(err))) {
                char m[600];
                snprintf(m, sizeof(m), "%s%s", err,
                         strstr(err, "дминистратор") ? "" :
                         " — запусти modlink от имени администратора");
                a_status_post(m, C_ERROR);
                continue;
            }
            snprintf(mac, sizeof(mac), "021E10%02X%02X%02X",
                     (n >> 4) & 0xFF, n & 0xFF, (n * 7) & 0xFF);
            winnet_disguise(d->guid, "Remote NDIS based Internet Sharing Device",
                            mac, "Huawei Technologies Co., Ltd.", err, sizeof(err));
            /* Имя подключения не трогаем — Windows назовёт по-своему (Ethernet N),
             * как обычные адаптеры. Состояние станет «Сеть N» само, когда через
             * интерфейс пойдёт трафик. */
            winnet_cycle(d->guid, err, sizeof(err));
            made++;
        }
        winnet_configure(d->guid, host_ip, 24, virt, virt, 5000, err, sizeof(err));
    }

    {
        static TunnelCfg list[TUNNEL_MAX_IFACES];
        int nlist = 0;
        for (i = 0; i < g_narows; i++) {
            TunnelCfg t;
            if (arow_to_cfg(g_arows[i], &t) && t.guid[0]) list[nlist++] = t;
        }
        agentcfg_save(agentcfg_path(), list, nlist);
        if (nlist > 0) {
            if (tunnel_start(list, nlist, err, sizeof(err))) {
                char msg[300];
                int bad = -1, i2;
                g_running = TRUE;
                /* Быстрая проверка: каждый прокси должен отвечать по SOCKS5.
                 * Частая ошибка — вписать порт реконнекта вместо порта прокси;
                 * тогда рукопожатие возвращает не то, и интернета нет. */
                for (i2 = 0; i2 < nlist; i2++) {
                    char e2[128];
                    SOCKET s2 = socks5_connect(list[i2].proxy_ip, list[i2].proxy_port,
                                               list[i2].user, list[i2].pass,
                                               "1.1.1.1", 80, 6000, e2, sizeof(e2));
                    if (s2 == INVALID_SOCKET) { bad = i2; }
                    else closesocket(s2);
                }
                if (bad >= 0)
                    snprintf(msg, sizeof(msg),
                        "интерфейсы подняты, но прокси %s:%d не отвечает по SOCKS5 — "
                        "проверь порт (нужен «Порт», а не «Рек.порт»)",
                        list[bad].proxy_ip, list[bad].proxy_port);
                else
                    snprintf(msg, sizeof(msg), "применено: интерфейсов %d, создано новых %d",
                             tunnel_iface_count(), made);
                a_status_post(msg, bad >= 0 ? C_WARN : C_SUCCESS);
            } else { g_running = FALSE; a_status_post(err, C_ERROR); }
        } else {
            a_status_post("нет готовых строк — заполни номер и прокси", C_WARN);
        }
    }
    InterlockedExchange(&g_abusy, 0);
    PostMessageW(g_view, WM_A_APPLYDONE, 0, 0);
    return 0;
}

static void do_apply(void)
{
    if (InterlockedCompareExchange(&g_abusy, 1, 0) != 0) return;
    EnableWindow(g_btn_apply, FALSE);
    a_status("применяю: создаю адаптеры и поднимаю туннели…", C_ACCENT);
    CloseHandle(CreateThread(NULL, 0, apply_thread, NULL, 0, NULL));
}

static void do_remove(HWND row)
{
    ARow *d = arow(row);
    int idx = arow_index(row);
    char err[256];
    if (idx < 0) return;
    if (d->guid[0]) {
        tunnel_stop();
        g_running = FALSE;
        if (!winnet_remove_adapter(d->guid, err, sizeof(err)))
            a_status(err, C_ERROR);
        else
            a_status("адаптер удалён — «Применить» перезапустит остальные", C_WARN);
    }
    DestroyWindow(row);
    memmove(&g_arows[idx], &g_arows[idx + 1], sizeof(HWND) * (size_t)(g_narows - idx - 1));
    g_narows--;
    alist_layout();
}

/* Показать все TAP-адаптеры системы: строки из конфига плюс «осиротевшие»,
 * которых в конфиге нет, — чтобы их можно было удалить из панели. */
static void load_rows(void)
{
    TunnelCfg loaded[TUNNEL_MAX_IFACES];
    TapAdapter taps[64];
    int nloaded, ntap, i, j;
    char err[256];

    nloaded = agentcfg_load(agentcfg_path(), loaded, TUNNEL_MAX_IFACES, err, sizeof(err));
    for (i = 0; i < nloaded; i++) {
        int n = 0, a, b, c, dd;
        if (sscanf(loaded[i].virt_ip, "%d.%d.%d.%d", &a, &b, &c, &dd) == 4) n = c;
        HWND row = arow_add(n ? n : next_free_no());
        if (row) {
            ARow *r = arow(row);
            char pr[256];
            {
                TapAdapter chk;
                if (loaded[i].guid[0] && tap_find_by_guid(loaded[i].guid, &chk))
                    ml_strlcpy(r->guid, loaded[i].guid, sizeof(r->guid));
                /* иначе оставляем guid пустым — адаптера нет, строка новая */
            }
            edit_set(r->name, loaded[i].label);
            edit_set(r->real, loaded[i].real_ip);
            snprintf(pr, sizeof(pr), "%s:%d:%s:%s",
                     loaded[i].proxy_ip, loaded[i].proxy_port, loaded[i].user, loaded[i].pass);
            edit_set(r->proxy, pr);
        }
    }

    /* осиротевшие адаптеры — те, чей GUID не встретился в конфиге */
    ntap = tap_enumerate(taps, 64);
    for (i = 0; i < ntap; i++) {
        BOOL known = FALSE;
        for (j = 0; j < g_narows; j++)
            if (!_stricmp(arow(g_arows[j])->guid, taps[i].guid)) { known = TRUE; break; }
        if (known) continue;
        {
            HWND row = arow_add(next_free_no());
            if (row) {
                ARow *r = arow(row);
                ml_strlcpy(r->guid, taps[i].guid, sizeof(r->guid));
                r->preexisting = TRUE;
                edit_set(r->name, taps[i].name[0] ? taps[i].name : "(адаптер)");
                ml_strlcpy(r->test, "существующий — ✕ удалит", sizeof(r->test));
                r->test_col = 0;
            }
        }
    }
}

/* ------------------------------------------------------------- раскладка вида */
static void aview_layout(void)
{
    RECT rc; int y, bw = S(104), bh = S(28), gap = S(8), x;
    if (!g_view) return;
    GetClientRect(g_view, &rc);
    y = S(A_BAR_H) + S(A_COLHDR_H);
    MoveWindow(g_alist, 0, y, rc.right, rc.bottom - y - S(A_STATUS_H), TRUE);

    y = (S(A_BAR_H) - bh) / 2; x = S(12);
    MoveWindow(g_btn_add,    x, y, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_btn_rescan, x, y, bw, bh, TRUE);
    x = rc.right - S(12) - bw;
    MoveWindow(g_btn_apply,  x, y, bw, bh, TRUE); x -= bw + gap;
    MoveWindow(g_btn_stop,   x, y, bw, bh, TRUE); x -= bw + gap;
    MoveWindow(g_btn_start,  x, y, bw, bh, TRUE);
    alist_layout();
    InvalidateRect(g_view, NULL, FALSE);
}

static void aview_paint(HWND h, HDC dc)
{
    RECT rc, r; GetClientRect(h, &rc);
    theme_fill(dc, &rc, g_th.br_bg);

    /* панель кнопок */
    r = rc; r.bottom = S(A_BAR_H); theme_fill(dc, &r, g_th.br_surface);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }

    /* шапка колонок */
    r = rc; r.top = S(A_BAR_H); r.bottom = r.top + S(A_COLHDR_H);
    theme_fill(dc, &r, g_th.br_bg);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }
    {
        static const wchar_t *H[] = { L"№", L"ИМЯ", L"IP МОДЕМА", L"ПРОКСИ  (IP:порт:логин:пароль)", L"АДРЕС / СТАТУС", L"" };
        static const int W[] = { 44, 96, 116, 240, 120, 26 };
        static const int F[] = {  0,  1,   1,   3,   1,  0 };
        int i, tot = 0, wt = 0, cx = S(A_PAD), avail, left;
        for (i = 0; i < 6; i++) { tot += S(W[i]); wt += F[i]; }
        tot += S(A_GAP) * 5;
        avail = rc.right - S(A_PAD) * 2;
        left = avail - tot; if (left < 0) left = 0;
        for (i = 0; i < 6; i++) {
            int cw = S(W[i]) + (F[i] && wt ? left * F[i] / wt : 0);
            if (H[i][0]) {
                RECT cr = r; cr.left = cx; cr.right = cx + cw; cr.top += S(3);
                theme_text(dc, &cr, H[i], g_th.f_small, C_MUTED,
                           DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            }
            cx += cw + S(A_GAP);
        }
    }

    /* строка состояния */
    r = rc; r.top = rc.bottom - S(A_STATUS_H); theme_fill(dc, &r, g_th.br_bg);
    if (g_astatus[0]) {
        wchar_t *w = ml_utf8_to_w(g_astatus);
        if (w) {
            RECT sr = r; sr.left = S(14); sr.right -= S(14);
            theme_text(dc, &sr, w, g_th.f_small, g_astatus_col ? g_astatus_col : C_MUTED,
                       DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            free(w);
        }
    }
}

static LRESULT CALLBACK AViewProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_view = h;
        g_alist = CreateWindowExW(0, L"ModlinkAList", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL,
                                  0, 0, 10, 10, h, (HMENU)IDC_A_LIST, g_inst, NULL);
        SetWindowTheme(g_alist, L"DarkMode_Explorer", NULL);
        g_btn_add    = btn_create(h, L"+ Добавить", IDC_A_ADD,    BTN_NORMAL);
        g_btn_rescan = btn_create(h, L"Обновить",   IDC_A_RESCAN, BTN_NORMAL);
        g_btn_start  = btn_create(h, L"Старт",      IDC_A_START,  BTN_NORMAL);
        g_btn_stop   = btn_create(h, L"Стоп",       IDC_A_STOP,   BTN_NORMAL);
        g_btn_apply  = btn_create(h, L"Применить",  IDC_A_APPLY,  BTN_PRIMARY);
        load_rows();
        a_status(g_narows ? "готово — заполни строки и «Применить»" : "интерфейсов нет — «+ Добавить»", C_MUTED);
        return 0;
    case WM_SIZE: aview_layout(); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: { PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); aview_paint(h, dc); EndPaint(h, &ps); return 0; }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        wchar_t lbl[32]; GetWindowTextW(di->hwndItem, lbl, 31);
        btn_draw(di, btn_style_of(di->hwndItem), lbl); return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: { HDC dc=(HDC)wp; SetTextColor(dc,C_TEXT); SetBkColor(dc,C_BG); return (LRESULT)g_th.br_bg; }
    case WM_A_STATUS: { char *t=(char*)lp; if(t){a_status(t,(COLORREF)wp); free(t);} return 0; }
    case WM_A_APPLYDONE: EnableWindow(g_btn_apply, TRUE); InvalidateRect(GetParent(h), NULL, FALSE); return 0;
    case WM_COMMAND: {
        int id = LOWORD(wp);
        HWND src = (HWND)lp;
        if (id == IDC_AR_DEL && src && GetParent(src) == g_alist) { do_remove(src); return 0; }
        switch (id) {
        case IDC_A_ADD: {
            int no = next_free_no();
            if (!no) { a_status("свободных номеров нет", C_ERROR); return 0; }
            arow_add(no);
            g_ascroll = g_acontent; alist_layout();
            a_status("строка добавлена — впиши IP модема и прокси, затем «Применить»", C_WARN);
            return 0;
        }
        case IDC_A_APPLY:
        case IDC_A_START: do_apply(); return 0;
        case IDC_A_STOP: tunnel_stop(); g_running = FALSE; a_status("туннели остановлены", C_WARN); return 0;
        case IDC_A_RESCAN: {
            int i;
            for (i = 0; i < g_narows; i++) DestroyWindow(g_arows[i]);
            g_narows = 0;
            load_rows(); alist_layout(); InvalidateRect(h, NULL, TRUE);
            a_status("список обновлён", C_MUTED);
            return 0;
        }
        }
        return 0;
    }
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- API оболочки */
void ui_agent_register(HINSTANCE inst)
{
    WNDCLASSEXW wc;
    g_inst = inst;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc); wc.hInstance = inst;
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.style = CS_HREDRAW | CS_VREDRAW;
    wc.lpfnWndProc = AViewProc; wc.lpszClassName = L"ModlinkAgentView"; RegisterClassExW(&wc);
    wc.lpfnWndProc = ARowProc;  wc.lpszClassName = L"ModlinkARow";      RegisterClassExW(&wc);
    wc.lpfnWndProc = AListProc; wc.lpszClassName = L"ModlinkAList";     RegisterClassExW(&wc);
}

HWND ui_agent_create(HWND parent)
{
    return CreateWindowExW(0, L"ModlinkAgentView", L"",
                           WS_CHILD | WS_CLIPCHILDREN, 0, 0, 10, 10,
                           parent, NULL, g_inst, NULL);
}

void ui_agent_stop_all(void) { tunnel_stop(); g_running = FALSE; }
