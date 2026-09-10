/* modlink — режим «агент»: виртуальные модемы на этой машине.
 *
 * Отдельное окно рядом с серверной панелью, но та же тёмная тема и flex.
 * Каждая строка — один виртуальный интерфейс. «Применить» создаёт для новых
 * строк TAP-адаптеры (winnet), сохраняет agent.json и перезапускает туннели;
 * lwIP один на процесс, поэтому применение — это полный перезапуск связки.
 *
 * Режиму нужны права администратора (создание адаптеров, запись в реестр);
 * повышение прав делает main.c до открытия этого окна. */
#include "ui.h"
#include "agentcfg.h"
#include "tunnel.h"
#include "winnet.h"
#include "tap.h"
#include <windowsx.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <string.h>
#include <stdlib.h>

#define A_ROW_H     30
#define A_GAP        6
#define A_PAD       10
#define A_HDR_H     52
#define A_BAR_H     46
#define A_COLHDR_H  24
#define A_STATUS_H  24

enum {
    IDC_A_ADD = 300, IDC_A_APPLY, IDC_A_START, IDC_A_STOP, IDC_A_LOGS, IDC_A_LIST,
    IDC_AR_NUM = 360, IDC_AR_NAME, IDC_AR_REAL, IDC_AR_VIRT,
    IDC_AR_PROXY, IDC_AR_USER, IDC_AR_PASS, IDC_AR_DEL
};

#define WM_A_APPLYDONE (WM_APP + 20)
#define WM_A_STATUS    (WM_APP + 21)

typedef struct {
    int   modem_no;               /* № для метки/подсети */
    char  guid[TAP_GUID_LEN];     /* пусто → адаптер ещё не создан */
    char  applied_virt[ML_ADDR_LEN];
    HWND  num, name, real, virt, proxy, user, pass, del;
} ARow;

static Config    *g_scfg;         /* серверный конфиг — для переключения назад */
static HINSTANCE  g_inst;
static HWND       g_awnd, g_alist;
static HWND       g_btn_add, g_btn_apply, g_btn_start, g_btn_stop, g_btn_logs;
static HWND       g_arows[TUNNEL_MAX_IFACES];
static int        g_narows = 0;
static int        g_ascroll = 0, g_acontent = 0;
static char       g_astatus[400] = "готов";
static COLORREF   g_astatus_col;
static BOOL       g_running = FALSE;
static volatile LONG g_abusy = 0;

static void a_status(const char *m, COLORREF c)
{
    ml_strlcpy(g_astatus, m, sizeof(g_astatus));
    g_astatus_col = c;
    if (g_awnd) InvalidateRect(g_awnd, NULL, FALSE);
}
static void a_status_post(const char *m, COLORREF c)
{
    char *d = _strdup(m);
    if (d) PostMessageW(g_awnd, WM_A_STATUS, (WPARAM)c, (LPARAM)d);
}

/* ------------------------------------------------------------- строки */
static ARow *arow(HWND h) { return (ARow *)GetWindowLongPtrW(h, GWLP_USERDATA); }

static int arow_index(HWND row)
{
    int i;
    for (i = 0; i < g_narows; i++) if (g_arows[i] == row) return i;
    return -1;
}

/* Следующий свободный номер модема: подсеть 192.168.N.x, N не занят строками. */
static int next_free_no(void)
{
    int n, i;
    for (n = 50; n <= 254; n++) {
        BOOL taken = FALSE;
        for (i = 0; i < g_narows; i++) if (arow(g_arows[i])->modem_no == n) { taken = TRUE; break; }
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
    flex_add(&L, d->num,    40, 0, 0);
    flex_add(&L, d->name,   90, 1, 0);
    flex_add(&L, d->real,  104, 1, 0);   /* IP модема (real) */
    flex_add(&L, d->virt,  104, 1, 0);   /* шлюз/морда (virt) */
    flex_add(&L, d->proxy, 150, 2, 0);   /* ip:port:… */
    flex_add(&L, d->user,   84, 1, 0);
    flex_add(&L, d->pass,  104, 1, 0);
    flex_add(&L, d->del,    26, 0, 0);
    flex_apply(&L, x, y, w, lh, A_GAP);
}

static LRESULT CALLBACK ARowProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    ARow *d = arow(h);
    switch (msg) {
    case WM_CREATE: {
        ARow *nd = (ARow *)calloc(1, sizeof(ARow));
        if (!nd) return -1;
        SetWindowLongPtrW(h, GWLP_USERDATA, (LONG_PTR)nd);
        nd->num   = edit_create(h, IDC_AR_NUM,  TRUE,  TRUE);   /* № только чтение */
        nd->name  = edit_create(h, IDC_AR_NAME, FALSE, FALSE);
        nd->real  = edit_create(h, IDC_AR_REAL, TRUE,  FALSE);
        nd->virt  = edit_create(h, IDC_AR_VIRT, TRUE,  TRUE);   /* шлюз считается из № */
        nd->proxy = edit_create(h, IDC_AR_PROXY,TRUE,  FALSE);
        nd->user  = edit_create(h, IDC_AR_USER, TRUE,  FALSE);
        nd->pass  = edit_create(h, IDC_AR_PASS, TRUE,  FALSE);
        nd->del   = btn_create (h, L"\x2715", IDC_AR_DEL, BTN_DANGER);
        return 0;
    }
    case WM_DESTROY: free(d); SetWindowLongPtrW(h, GWLP_USERDATA, 0); return 0;
    case WM_SIZE: arow_layout(h); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: {
        PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
        RECT rc, ln; GetClientRect(h, &rc);
        theme_fill(dc, &rc, g_th.br_surface);
        ln = rc; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border);
        EndPaint(h, &ps); return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        wchar_t lbl[32]; GetWindowTextW(di->hwndItem, lbl, 31);
        btn_draw(di, btn_style_of(di->hwndItem), lbl);
        return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp; SetTextColor(dc, C_TEXT); SetBkColor(dc, C_BG);
        return (LRESULT)g_th.br_bg;
    }
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED || HIWORD(wp) == EN_CHANGE)
            SendMessageW(g_awnd, WM_COMMAND, wp, (LPARAM)h);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* № → адреса: virt-шлюз 192.168.N.1, адрес хоста 192.168.N.100. */
static void arow_fill_from_no(HWND row)
{
    ARow *d = arow(row);
    char t[64];
    snprintf(t, sizeof(t), "%d", d->modem_no);              edit_set(d->num, t);
    snprintf(t, sizeof(t), "192.168.%d.1", d->modem_no);    edit_set(d->virt, t);
    if (!d->name) return;
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
    HWND row;
    if (g_narows >= TUNNEL_MAX_IFACES) return NULL;
    row = CreateWindowExW(0, L"ModlinkARow", L"", WS_CHILD | WS_VISIBLE,
                          0, 0, 10, 10, g_alist, NULL, g_inst, NULL);
    if (!row) return NULL;
    arow(row)->modem_no = modem_no;
    arow_fill_from_no(row);
    arow_layout(row);
    g_arows[g_narows++] = row;
    return row;
}

/* Собирает строку в TunnelCfg. FALSE — строка неполная (нет real/proxy). */
static BOOL arow_to_cfg(HWND row, TunnelCfg *t)
{
    ARow *d = arow(row);
    char proxy[128] = {0};
    memset(t, 0, sizeof(*t));
    edit_get(d->name,  t->label,   sizeof(t->label));
    edit_get(d->real,  t->real_ip, sizeof(t->real_ip));
    edit_get(d->virt,  t->virt_ip, sizeof(t->virt_ip));
    edit_get(d->proxy, proxy,      sizeof(proxy));
    edit_get(d->user,  t->user,    sizeof(t->user));
    edit_get(d->pass,  t->pass,    sizeof(t->pass));
    ml_strlcpy(t->guid, d->guid, sizeof(t->guid));
    ml_strlcpy(t->netmask, "255.255.255.0", sizeof(t->netmask));
    if (!t->label[0]) snprintf(t->label, sizeof(t->label), "modem%d", d->modem_no);
    {   /* proxy → ip:port */
        char *colon = strchr(proxy, ':');
        if (colon) { *colon = 0; ml_strlcpy(t->proxy_ip, proxy, sizeof(t->proxy_ip)); t->proxy_port = atoi(colon+1); }
    }
    return t->real_ip[0] && t->proxy_ip[0] && t->proxy_port;
}

/* ------------------------------------------------------------- применение */
static DWORD WINAPI apply_thread(LPVOID arg)
{
    int i;
    int made = 0, ok = 0;
    char err[512];
    (void)arg;

    /* lwIP один — глушим туннели перед пересозданием адаптеров. */
    tunnel_stop();

    for (i = 0; i < g_narows; i++) {
        ARow *d = arow(g_arows[i]);
        char virt[ML_ADDR_LEN];
        snprintf(virt, sizeof(virt), "192.168.%d.1", d->modem_no);

        if (!d->guid[0]) {
            /* новая строка — создаём и маскируем адаптер */
            char inf[ML_PATH_LEN], mac[16], name[64];
            snprintf(inf, sizeof(inf), "%s\\OemVista.inf", ml_dir_data());
            if (!winnet_create_adapter(inf, d->guid, sizeof(d->guid), err, sizeof(err))) {
                a_status_post(err, C_ERROR);
                continue;
            }
            snprintf(mac, sizeof(mac), "021E10%02X%02X%02X",
                     (d->modem_no >> 4) & 0xFF, d->modem_no & 0xFF, (d->modem_no * 7) & 0xFF);
            winnet_disguise(d->guid, "Remote NDIS based Internet Sharing Device",
                            mac, "Huawei Technologies Co., Ltd.", err, sizeof(err));
            snprintf(name, sizeof(name), "\xd1\x81\xd0\xb5\xd1\x82\xd1\x8c""%d", d->modem_no);
            winnet_rename(d->guid, name, err, sizeof(err));
            winnet_cycle(d->guid, err, sizeof(err));
            made++;
        }
        /* адрес хоста .100, шлюз .1, DNS = шлюз, метрика 5000 */
        {
            char host_ip[ML_ADDR_LEN];
            snprintf(host_ip, sizeof(host_ip), "192.168.%d.100", d->modem_no);
            winnet_configure(d->guid, host_ip, 24, virt, virt, 5000, err, sizeof(err));
        }
        ml_strlcpy(d->applied_virt, virt, sizeof(d->applied_virt));
        ok++;
    }

    /* собираем и поднимаем туннели */
    {
        static TunnelCfg list[TUNNEL_MAX_IFACES];
        int n = 0;
        for (i = 0; i < g_narows; i++) {
            TunnelCfg t;
            if (arow_to_cfg(g_arows[i], &t) && t.guid[0]) list[n++] = t;
        }
        agentcfg_save(agentcfg_path(), list, n);
        if (n > 0) {
            if (tunnel_start(list, n, err, sizeof(err))) {
                g_running = TRUE;
                {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "применено: интерфейсов %d, создано новых %d",
                             tunnel_iface_count(), made);
                    a_status_post(msg, C_SUCCESS);
                }
            } else {
                g_running = FALSE;
                a_status_post(err, C_ERROR);
            }
        } else {
            a_status_post("нет готовых интерфейсов — заполни IP модема и прокси", C_WARN);
        }
    }
    (void)ok;
    InterlockedExchange(&g_abusy, 0);
    PostMessageW(g_awnd, WM_A_APPLYDONE, 0, 0);
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
        tunnel_stop();                         /* освободить адаптер */
        g_running = FALSE;
        winnet_remove_adapter(d->guid, err, sizeof(err));
    }
    DestroyWindow(row);
    memmove(&g_arows[idx], &g_arows[idx + 1], sizeof(HWND) * (size_t)(g_narows - idx - 1));
    g_narows--;
    alist_layout();
    a_status("адаптер удалён — нажми «Применить», чтобы перезапустить остальные", C_WARN);
}

/* ------------------------------------------------------------- раскладка окна */
static void arelayout(void)
{
    RECT rc; int y, bw = S(104), bh = S(28), gap = S(8), x;
    if (!g_awnd) return;
    GetClientRect(g_awnd, &rc);
    y = S(A_HDR_H) + S(A_BAR_H) + S(A_COLHDR_H);
    MoveWindow(g_alist, 0, y, rc.right, rc.bottom - y - S(A_STATUS_H), TRUE);

    y = S(A_HDR_H) + (S(A_BAR_H) - bh) / 2;
    x = S(12);
    MoveWindow(g_btn_add,   x, y, bw, bh, TRUE); x += bw + gap;
    MoveWindow(g_btn_logs,  x, y, bw, bh, TRUE);
    x = rc.right - S(12) - bw;
    MoveWindow(g_btn_apply, x, y, bw, bh, TRUE); x -= bw + gap;
    MoveWindow(g_btn_stop,  x, y, bw, bh, TRUE); x -= bw + gap;
    MoveWindow(g_btn_start, x, y, bw, bh, TRUE);
    alist_layout();
    InvalidateRect(g_awnd, NULL, FALSE);
}

static void apaint(HWND h, HDC dc)
{
    RECT rc, r; GetClientRect(h, &rc);
    theme_fill(dc, &rc, g_th.br_bg);

    /* заголовок */
    r = rc; r.bottom = S(A_HDR_H); theme_fill(dc, &r, g_th.br_surface);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }
    r.left = S(14); r.right = S(320);
    theme_text(dc, &r, L"modlink", g_th.f_title, C_WHITE, DT_VCENTER | DT_SINGLELINE);
    r.left = S(14) + S(78);
    theme_text(dc, &r, L"агент — виртуальные модемы", g_th.f_ui, C_MUTED, DT_VCENTER | DT_SINGLELINE);
    r = rc; r.bottom = S(A_HDR_H); r.right -= S(14); r.left = r.right - S(200);
    {
        wchar_t st[128];
        _snwprintf(st, 127, L"%s  %d интерфейс(ов)",
                   g_running ? L"\x25cf работает" : L"\x25cf остановлено", g_narows);
        theme_text(dc, &r, st, g_th.f_ui, g_running ? C_SUCCESS : C_MUTED,
                   DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
    }

    /* панель настроек-подсказка */
    r = rc; r.top = S(A_HDR_H); r.bottom = r.top + S(A_BAR_H);
    theme_fill(dc, &r, g_th.br_surface);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }

    /* шапка колонок */
    r = rc; r.top = S(A_HDR_H) + S(A_BAR_H); r.bottom = r.top + S(A_COLHDR_H);
    theme_fill(dc, &r, g_th.br_bg);
    { RECT ln = r; ln.top = ln.bottom - 1; theme_fill(dc, &ln, g_th.br_border); }
    {
        static const wchar_t *H[] = { L"№", L"ИМЯ", L"IP МОДЕМА", L"ШЛЮЗ/МОРДА", L"ПРОКСИ", L"ЛОГИН", L"ПАРОЛЬ", L"" };
        static const int W[] = { 40, 90, 104, 104, 150, 84, 104, 26 };
        static const int F[] = {  0,  1,   1,   1,   2,  1,   1,  0 };
        int i, tot = 0, wt = 0, cx = S(A_PAD), avail, left;
        for (i = 0; i < 8; i++) { tot += S(W[i]); wt += F[i]; }
        tot += S(A_GAP) * 7;
        avail = rc.right - S(A_PAD) * 2;
        left = avail - tot; if (left < 0) left = 0;
        for (i = 0; i < 8; i++) {
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
    {
        wchar_t *w = ml_utf8_to_w(g_astatus);
        if (w) {
            RECT sr = r; sr.left = S(14); sr.right -= S(14);
            theme_text(dc, &sr, w, g_th.f_small, g_astatus_col ? g_astatus_col : C_MUTED,
                       DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            free(w);
        }
    }
}

static LRESULT CALLBACK AMainProc(HWND h, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE:
        g_awnd = h;
        theme_dark_titlebar(h);
        g_alist = CreateWindowExW(0, L"ModlinkAList", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL,
                                  0, 0, 10, 10, h, (HMENU)IDC_A_LIST, g_inst, NULL);
        SetWindowTheme(g_alist, L"DarkMode_Explorer", NULL);
        g_btn_add   = btn_create(h, L"+ Добавить", IDC_A_ADD,   BTN_NORMAL);
        g_btn_logs  = btn_create(h, L"Логи",       IDC_A_LOGS,  BTN_NORMAL);
        g_btn_start = btn_create(h, L"Старт",      IDC_A_START, BTN_NORMAL);
        g_btn_stop  = btn_create(h, L"Стоп",       IDC_A_STOP,  BTN_NORMAL);
        g_btn_apply = btn_create(h, L"Применить",  IDC_A_APPLY, BTN_PRIMARY);
        return 0;
    case WM_SIZE: arelayout(); return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *m = (MINMAXINFO *)lp;
        m->ptMinTrackSize.x = S(720); m->ptMinTrackSize.y = S(360); return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_PAINT: { PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); apaint(h, dc); EndPaint(h, &ps); return 0; }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT di = (LPDRAWITEMSTRUCT)lp;
        wchar_t lbl[32]; GetWindowTextW(di->hwndItem, lbl, 31);
        btn_draw(di, btn_style_of(di->hwndItem), lbl); return TRUE;
    }
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORSTATIC: { HDC dc=(HDC)wp; SetTextColor(dc,C_TEXT); SetBkColor(dc,C_BG); return (LRESULT)g_th.br_bg; }
    case WM_A_STATUS: { char *t=(char*)lp; if(t){a_status(t,(COLORREF)wp); free(t);} return 0; }
    case WM_A_APPLYDONE: EnableWindow(g_btn_apply, TRUE); InvalidateRect(h, NULL, FALSE); return 0;
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
            a_status("строка добавлена — заполни IP модема и прокси, затем «Применить»", C_WARN);
            return 0;
        }
        case IDC_A_APPLY: do_apply(); return 0;
        case IDC_A_STOP:  tunnel_stop(); g_running = FALSE; a_status("туннели остановлены", C_WARN); InvalidateRect(h,NULL,FALSE); return 0;
        case IDC_A_START: do_apply(); return 0;
        }
        return 0;
    }
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: tunnel_stop(); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

/* ------------------------------------------------------------- запуск */
static void a_register(void)
{
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc); wc.hInstance = g_inst;
    wc.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(32512));
    wc.style = CS_HREDRAW | CS_VREDRAW;

    wc.lpfnWndProc = AMainProc; wc.lpszClassName = L"ModlinkAgent";
    wc.hIcon = LoadIconW(NULL, MAKEINTRESOURCEW(32512));
    RegisterClassExW(&wc);
    wc.lpfnWndProc = ARowProc;  wc.lpszClassName = L"ModlinkARow"; wc.hIcon = NULL;
    RegisterClassExW(&wc);
    wc.lpfnWndProc = AListProc; wc.lpszClassName = L"ModlinkAList";
    RegisterClassExW(&wc);
}

int ui_agent_run(HINSTANCE hInst, int nCmdShow)
{
    MSG msg; HWND hwnd;
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    TunnelCfg loaded[TUNNEL_MAX_IFACES];
    int nloaded, i;
    char err[256];

    g_inst = hInst;
    (void)g_scfg;
    InitCommonControlsEx(&icc);
    { HDC dc = GetDC(NULL); g_dpi = GetDeviceCaps(dc, LOGPIXELSX); ReleaseDC(NULL, dc); }
    theme_init(NULL);
    a_register();

    hwnd = CreateWindowExW(0, L"ModlinkAgent", L"modlink — агент",
                           WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
                           S(1120), S(600), NULL, NULL, hInst, NULL);
    if (!hwnd) return 1;

    /* восстанавливаем строки из agent.json */
    nloaded = agentcfg_load(agentcfg_path(), loaded, TUNNEL_MAX_IFACES, err, sizeof(err));
    for (i = 0; i < nloaded; i++) {
        int no = 0;
        { const char *p = loaded[i].virt_ip; int a,b,c,d; if (sscanf(p,"%d.%d.%d.%d",&a,&b,&c,&d)==4) no=c; }
        HWND row = arow_add(no ? no : next_free_no());
        if (row) {
            ARow *r = arow(row);
            ml_strlcpy(r->guid, loaded[i].guid, sizeof(r->guid));
            edit_set(r->name, loaded[i].label);
            edit_set(r->real, loaded[i].real_ip);
            { char pr[128]; snprintf(pr,sizeof(pr),"%s:%d",loaded[i].proxy_ip,loaded[i].proxy_port); edit_set(r->proxy, pr); }
            edit_set(r->user, loaded[i].user);
            edit_set(r->pass, loaded[i].pass);
        }
    }
    arelayout();
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    /* если что-то загрузили — сразу поднимаем */
    if (nloaded > 0) { a_status("восстановлено из конфига — нажми «Применить» для запуска", C_MUTED); }
    else a_status("интерфейсов нет — «+ Добавить»", C_MUTED);

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    }
    theme_free();
    return 0;
}
