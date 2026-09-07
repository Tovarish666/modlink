/* modlink — shared UI declarations: palette, DPI scaling, flex layout. */
#ifndef MODLINK_UI_H
#define MODLINK_UI_H

#include "common.h"

/* Palette lifted verbatim from the Python panel's CSS so the native window
 * keeps the same identity as the web panel it replaces. */
#define C_BG       RGB(0x0e, 0x11, 0x17)
#define C_SURFACE  RGB(0x16, 0x1b, 0x22)
#define C_SURFACE2 RGB(0x1c, 0x21, 0x28)
#define C_BORDER   RGB(0x21, 0x26, 0x2d)
#define C_ACCENT   RGB(0x58, 0xa6, 0xff)
#define C_SUCCESS  RGB(0x3f, 0xb9, 0x50)
#define C_ERROR    RGB(0xf8, 0x51, 0x49)
#define C_WARN     RGB(0xd2, 0x99, 0x22)
#define C_TEXT     RGB(0xc9, 0xd1, 0xd9)
#define C_MUTED    RGB(0x8b, 0x94, 0x9e)
#define C_WHITE    RGB(0xff, 0xff, 0xff)

/* ------------------------------------------------------------------ dpi */
extern int g_dpi;
#define S(x)  MulDiv((x), g_dpi, 96)      /* scale a 96-dpi design value */

/* ------------------------------------------------------------------ theme */
typedef struct {
    HBRUSH br_bg, br_surface, br_surface2, br_border, br_accent;
    HFONT  f_ui, f_mono, f_small, f_title, f_bold;
    HPEN   pen_border;
} Theme;

extern Theme g_th;

void theme_init(HWND hwnd);
void theme_free(void);
void theme_dark_titlebar(HWND hwnd);
void theme_fill(HDC dc, const RECT *r, HBRUSH b);
void theme_frame(HDC dc, const RECT *r, COLORREF c);
void theme_rounded(HDC dc, const RECT *r, COLORREF fill, COLORREF border, int radius);
void theme_text(HDC dc, const RECT *r, const wchar_t *s, HFONT f, COLORREF col, UINT fmt);

/* Owner-draw button styles. */
enum { BTN_NORMAL = 0, BTN_PRIMARY, BTN_ICON, BTN_DANGER, BTN_WARN };
void   btn_draw(LPDRAWITEMSTRUCT di, int style, const wchar_t *label);
HWND   btn_create(HWND parent, const wchar_t *label, int id, int style);
int    btn_style_of(HWND h);

/* Dark-themed single-line edit. */
HWND   edit_create(HWND parent, int id, BOOL mono, BOOL readonly);
void   edit_set(HWND h, const char *utf8);
void   edit_get(HWND h, char *out, size_t cap);
int    edit_get_int(HWND h);
void   edit_set_int(HWND h, int v);

/* ------------------------------------------------------------------ flex */
/* A one-dimensional flex distributor. This is what makes the layout adaptive:
 * each cell states a minimum width and a stretch weight, and the row hands out
 * whatever space it has. When the window narrows past a breakpoint the caller
 * simply feeds a different set of lines. */
#define FLEX_MAX_CELLS 24

typedef struct {
    HWND hwnd;        /* control to place (NULL = spacer) */
    int  min_w;       /* unscaled minimum width */
    int  weight;      /* 0 = fixed at min_w, >0 = share of the leftover */
    int  height;      /* unscaled height, 0 = full line height */
} FlexCell;

typedef struct {
    FlexCell cell[FLEX_MAX_CELLS];
    int      n;
} FlexLine;

void flex_reset(FlexLine *l);
void flex_add(FlexLine *l, HWND h, int min_w, int weight, int height);
/* Places the line inside `area` (already in device pixels) and returns the
 * y of the next line. `gap` is unscaled. */
int  flex_apply(FlexLine *l, int x, int y, int width, int line_h, int gap);
int  flex_min_width(const FlexLine *l, int gap);

#endif
