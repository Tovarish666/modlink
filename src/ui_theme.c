/* modlink — dark theme primitives, owner-draw controls, flex layout. */
#include "ui.h"
#include <uxtheme.h>
#include <dwmapi.h>
#include <string.h>
#include <stdlib.h>

int   g_dpi = 96;
Theme g_th;

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif

/* --------------------------------------------------------------- theme */
static HFONT mkfont(const wchar_t *face, int pt, int weight)
{
    return CreateFontW(-MulDiv(pt, g_dpi, 72), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, face);
}

void theme_init(HWND hwnd)
{
    (void)hwnd;
    g_th.br_bg       = CreateSolidBrush(C_BG);
    g_th.br_surface  = CreateSolidBrush(C_SURFACE);
    g_th.br_surface2 = CreateSolidBrush(C_SURFACE2);
    g_th.br_border   = CreateSolidBrush(C_BORDER);
    g_th.br_accent   = CreateSolidBrush(C_ACCENT);
    g_th.pen_border  = CreatePen(PS_SOLID, 1, C_BORDER);

    g_th.f_ui    = mkfont(L"Segoe UI", 9,  FW_NORMAL);
    g_th.f_bold  = mkfont(L"Segoe UI", 9,  FW_SEMIBOLD);
    g_th.f_small = mkfont(L"Segoe UI", 7,  FW_NORMAL);
    g_th.f_title = mkfont(L"Segoe UI", 12, FW_SEMIBOLD);
    /* Consolas for anything the user copies verbatim: IPs, ports, passwords. */
    g_th.f_mono  = mkfont(L"Consolas", 9,  FW_NORMAL);
}

void theme_free(void)
{
    DeleteObject(g_th.br_bg);      DeleteObject(g_th.br_surface);
    DeleteObject(g_th.br_surface2);DeleteObject(g_th.br_border);
    DeleteObject(g_th.br_accent);  DeleteObject(g_th.pen_border);
    DeleteObject(g_th.f_ui);       DeleteObject(g_th.f_mono);
    DeleteObject(g_th.f_small);    DeleteObject(g_th.f_title);
    DeleteObject(g_th.f_bold);
    memset(&g_th, 0, sizeof(g_th));
}

/* Win10 1809+ paints the title bar dark when asked; older builds just ignore
 * the attribute, which is why the return value is not checked. */
void theme_dark_titlebar(HWND hwnd)
{
    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    SetWindowTheme(hwnd, L"DarkMode_Explorer", NULL);
}

void theme_fill(HDC dc, const RECT *r, HBRUSH b) { FillRect(dc, r, b); }

void theme_frame(HDC dc, const RECT *r, COLORREF c)
{
    HBRUSH b = CreateSolidBrush(c);
    FrameRect(dc, r, b);
    DeleteObject(b);
}

void theme_rounded(HDC dc, const RECT *r, COLORREF fill, COLORREF border, int radius)
{
    HBRUSH hb = CreateSolidBrush(fill);
    HPEN   hp = CreatePen(PS_SOLID, 1, border);
    HGDIOBJ ob = SelectObject(dc, hb);
    HGDIOBJ op = SelectObject(dc, hp);
    RoundRect(dc, r->left, r->top, r->right, r->bottom, radius, radius);
    SelectObject(dc, ob); SelectObject(dc, op);
    DeleteObject(hb); DeleteObject(hp);
}

void theme_text(HDC dc, const RECT *r, const wchar_t *s, HFONT f, COLORREF col, UINT fmt)
{
    HGDIOBJ of = SelectObject(dc, f);
    RECT rr = *r;
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, col);
    DrawTextW(dc, s, -1, &rr, fmt);
    SelectObject(dc, of);
}

/* --------------------------------------------------------------- buttons */
/* Style is stashed in the window's user data so WM_DRAWITEM can find it. */
HWND btn_create(HWND parent, const wchar_t *label, int id, int style)
{
    HWND h = CreateWindowExW(0, L"BUTTON", label,
                             WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_OWNERDRAW,
                             0, 0, 10, 10, parent, (HMENU)(INT_PTR)id,
                             (HINSTANCE)GetWindowLongPtrW(parent, GWLP_HINSTANCE), NULL);
    if (h) SetWindowLongPtrW(h, GWLP_USERDATA, style);
    return h;
}

int btn_style_of(HWND h) { return (int)GetWindowLongPtrW(h, GWLP_USERDATA); }

void btn_draw(LPDRAWITEMSTRUCT di, int style, const wchar_t *label)
{
    RECT r = di->rcItem;
    BOOL hot      = (di->itemState & ODS_FOCUS) != 0;
    BOOL pressed  = (di->itemState & ODS_SELECTED) != 0;
    BOOL disabled = (di->itemState & ODS_DISABLED) != 0;
    COLORREF fill = C_SURFACE, border = C_BORDER, text = C_TEXT;

    switch (style) {
    case BTN_PRIMARY: fill = C_ACCENT;  border = C_ACCENT; text = RGB(0,0,0); break;
    case BTN_DANGER:  if (hot) { border = C_ERROR;   text = C_ERROR;   } break;
    case BTN_WARN:    if (hot) { border = C_WARN;    text = C_WARN;    } break;
    case BTN_ICON:
    case BTN_NORMAL:  if (hot) { border = C_ACCENT;  text = C_ACCENT;  } break;
    }
    if (pressed) {
        if (style == BTN_PRIMARY) fill = RGB(0x79, 0xb8, 0xff);
        else                      fill = C_SURFACE2;
    }
    if (disabled) { text = C_MUTED; border = C_BORDER; if (style == BTN_PRIMARY) fill = C_SURFACE2; }

    theme_rounded(di->hDC, &r, fill, border, S(6));
    theme_text(di->hDC, &r, label,
               style == BTN_PRIMARY ? g_th.f_bold : g_th.f_ui,
               text, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
}

/* --------------------------------------------------------------- edits */
HWND edit_create(HWND parent, int id, BOOL mono, BOOL readonly)
{
    DWORD st = WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_LEFT;
    HWND h;
    if (readonly) st |= ES_READONLY;
    h = CreateWindowExW(0, L"EDIT", L"", st, 0, 0, 10, 10, parent,
                        (HMENU)(INT_PTR)id,
                        (HINSTANCE)GetWindowLongPtrW(parent, GWLP_HINSTANCE), NULL);
    if (h) {
        SendMessageW(h, WM_SETFONT, (WPARAM)(mono ? g_th.f_mono : g_th.f_ui), TRUE);
        SendMessageW(h, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN,
                     MAKELPARAM(S(5), S(3)));
    }
    return h;
}

void edit_set(HWND h, const char *utf8)
{
    wchar_t *w = ml_utf8_to_w(utf8 ? utf8 : "");
    if (w) { SetWindowTextW(h, w); free(w); }
}

void edit_get(HWND h, char *out, size_t cap)
{
    wchar_t buf[1024];
    char *a;
    out[0] = 0;
    GetWindowTextW(h, buf, 1023);
    a = ml_w_to_utf8(buf);
    if (a) { ml_strlcpy(out, a, cap); free(a); }
}

int edit_get_int(HWND h)
{
    char t[32];
    edit_get(h, t, sizeof(t));
    return atoi(t);
}

void edit_set_int(HWND h, int v)
{
    char t[32];
    snprintf(t, sizeof(t), "%d", v);
    edit_set(h, t);
}

/* --------------------------------------------------------------- flex */
void flex_reset(FlexLine *l) { l->n = 0; }

void flex_add(FlexLine *l, HWND h, int min_w, int weight, int height)
{
    FlexCell *c;
    if (l->n >= FLEX_MAX_CELLS) return;
    c = &l->cell[l->n++];
    c->hwnd   = h;
    c->min_w  = min_w;
    c->weight = weight;
    c->height = height;
}

int flex_min_width(const FlexLine *l, int gap)
{
    int i, w = 0;
    for (i = 0; i < l->n; i++) w += S(l->cell[i].min_w) + (i ? S(gap) : 0);
    return w;
}

int flex_apply(FlexLine *l, int x, int y, int width, int line_h, int gap)
{
    int i, used = 0, total_weight = 0, leftover, cx;
    HDWP dwp;

    if (l->n == 0) return y;

    for (i = 0; i < l->n; i++) {
        used += S(l->cell[i].min_w);
        total_weight += l->cell[i].weight;
    }
    used += S(gap) * (l->n - 1);
    leftover = width - used;
    if (leftover < 0) leftover = 0;      /* below the minimum: just clip */

    dwp = BeginDeferWindowPos(l->n);
    cx = x;
    for (i = 0; i < l->n; i++) {
        FlexCell *c = &l->cell[i];
        int w = S(c->min_w);
        int h = c->height ? S(c->height) : line_h;
        int cy = y + (line_h - h) / 2;

        if (c->weight > 0 && total_weight > 0) {
            /* Give the last flexible cell the rounding remainder so the row
             * ends exactly on the right edge instead of a pixel short. */
            int share = leftover * c->weight / total_weight;
            w += share;
        }
        if (c->hwnd && dwp)
            dwp = DeferWindowPos(dwp, c->hwnd, NULL, cx, cy, w, h,
                                 SWP_NOZORDER | SWP_NOACTIVATE);
        cx += w + S(gap);
    }
    if (dwp) EndDeferWindowPos(dwp);

    return y + line_h;
}
