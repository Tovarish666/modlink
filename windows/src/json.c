/* modlink — minimal JSON DOM (see json.h). */
#include "json.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------- parsing */
typedef struct { const char *p; int depth; } JP;

static JVal *pv(JP *s);

static void skip_ws(JP *s)
{
    while (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r') s->p++;
}

static JVal *jnew(JType t)
{
    JVal *v = (JVal *)calloc(1, sizeof(JVal));
    if (v) v->type = t;
    return v;
}

/* Encode one code point as UTF-8; returns bytes written. */
static int utf8_put(char *out, unsigned cp)
{
    if (cp < 0x80)    { out[0] = (char)cp; return 1; }
    if (cp < 0x800)   { out[0] = (char)(0xC0 | (cp >> 6));
                        out[1] = (char)(0x80 | (cp & 0x3F)); return 2; }
    if (cp < 0x10000) { out[0] = (char)(0xE0 | (cp >> 12));
                        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        out[2] = (char)(0x80 | (cp & 0x3F)); return 3; }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

static int hex4(const char *p, unsigned *out)
{
    unsigned v = 0; int i;
    for (i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if      (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return 0;
    }
    *out = v;
    return 1;
}

/* Parses a JSON string literal starting at the opening quote. */
static char *pstr(JP *s)
{
    const char *p = s->p;
    char *out, *w;
    size_t cap;

    if (*p != '"') return NULL;
    p++;
    cap = strlen(p) + 1;              /* escapes only ever shrink the result */
    out = (char *)malloc(cap);
    if (!out) return NULL;
    w = out;

    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case 'n': *w++ = '\n'; p++; break;
            case 't': *w++ = '\t'; p++; break;
            case 'r': *w++ = '\r'; p++; break;
            case 'b': *w++ = '\b'; p++; break;
            case 'f': *w++ = '\f'; p++; break;
            case '/': *w++ = '/';  p++; break;
            case '\\':*w++ = '\\'; p++; break;
            case '"': *w++ = '"';  p++; break;
            case 'u': {
                unsigned cp = 0, lo = 0;
                p++;
                if (!hex4(p, &cp)) { free(out); return NULL; }
                p += 4;
                /* surrogate pair */
                if (cp >= 0xD800 && cp <= 0xDBFF && p[0] == '\\' && p[1] == 'u' &&
                    hex4(p + 2, &lo) && lo >= 0xDC00 && lo <= 0xDFFF) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    p += 6;
                }
                w += utf8_put(w, cp);
                break;
            }
            default: free(out); return NULL;
            }
        } else {
            *w++ = *p++;
        }
    }
    if (*p != '"') { free(out); return NULL; }
    *w = 0;
    s->p = p + 1;
    return out;
}

static JVal *pv(JP *s)
{
    JVal *v;

    if (s->depth > 64) return NULL;          /* refuse pathological nesting */
    skip_ws(s);

    if (*s->p == '"') {
        char *str = pstr(s);
        if (!str) return NULL;
        v = jnew(J_STR);
        if (!v) { free(str); return NULL; }
        v->str = str;
        return v;
    }
    if (*s->p == '{' || *s->p == '[') {
        int is_obj = (*s->p == '{');
        char close = is_obj ? '}' : ']';
        JVal *tail = NULL;
        v = jnew(is_obj ? J_OBJ : J_ARR);
        if (!v) return NULL;
        s->p++; s->depth++;
        skip_ws(s);
        if (*s->p == close) { s->p++; s->depth--; return v; }
        for (;;) {
            JVal *item;
            char *key = NULL;
            skip_ws(s);
            if (is_obj) {
                key = pstr(s);
                if (!key) { json_free(v); return NULL; }
                skip_ws(s);
                if (*s->p != ':') { free(key); json_free(v); return NULL; }
                s->p++;
            }
            item = pv(s);
            if (!item) { free(key); json_free(v); return NULL; }
            item->key = key;
            if (tail) tail->next = item; else v->child = item;
            tail = item;
            skip_ws(s);
            if (*s->p == ',') { s->p++; continue; }
            if (*s->p == close) { s->p++; s->depth--; return v; }
            json_free(v);
            return NULL;
        }
    }
    if (!strncmp(s->p, "true", 4))  { s->p += 4; v = jnew(J_BOOL); if (v) v->bval = 1; return v; }
    if (!strncmp(s->p, "false", 5)) { s->p += 5; v = jnew(J_BOOL); if (v) v->bval = 0; return v; }
    if (!strncmp(s->p, "null", 4))  { s->p += 4; return jnew(J_NULL); }

    /* number */
    {
        char *end = NULL;
        double d = strtod(s->p, &end);
        if (end == s->p) return NULL;
        s->p = end;
        v = jnew(J_NUM);
        if (v) v->num = d;
        return v;
    }
}

JVal *json_parse(const char *text)
{
    JP s;
    JVal *v;
    if (!text) return NULL;
    s.p = text; s.depth = 0;
    /* tolerate a UTF-8 BOM — Notepad adds one if the user hand-edits the file */
    if ((unsigned char)s.p[0] == 0xEF && (unsigned char)s.p[1] == 0xBB &&
        (unsigned char)s.p[2] == 0xBF) s.p += 3;
    v = pv(&s);
    if (!v) return NULL;
    skip_ws(&s);
    return v;
}

void json_free(JVal *v)
{
    while (v) {
        JVal *next = v->next;
        json_free(v->child);
        free(v->str);
        free(v->key);
        free(v);
        v = next;
    }
}

const JVal *json_get(const JVal *obj, const char *key)
{
    const JVal *c;
    if (!obj || obj->type != J_OBJ) return NULL;
    for (c = obj->child; c; c = c->next)
        if (c->key && !strcmp(c->key, key)) return c;
    return NULL;
}

const char *json_str(const JVal *obj, const char *key, const char *fallback)
{
    const JVal *v = json_get(obj, key);
    return (v && v->type == J_STR && v->str) ? v->str : fallback;
}

double json_num(const JVal *obj, const char *key, double fallback)
{
    const JVal *v = json_get(obj, key);
    return (v && v->type == J_NUM) ? v->num : fallback;
}

int json_bool(const JVal *obj, const char *key, int fallback)
{
    const JVal *v = json_get(obj, key);
    if (!v) return fallback;
    if (v->type == J_BOOL) return v->bval;
    if (v->type == J_NUM)  return v->num != 0;
    return fallback;
}

int json_arr_len(const JVal *arr)
{
    const JVal *c;
    int n = 0;
    if (!arr || arr->type != J_ARR) return 0;
    for (c = arr->child; c; c = c->next) n++;
    return n;
}

/* ------------------------------------------------------------- emitting */
void jb_init(JBuf *b) { b->buf = NULL; b->len = 0; b->cap = 0; }
void jb_free(JBuf *b) { free(b->buf); jb_init(b); }

static void jb_need(JBuf *b, size_t extra)
{
    size_t want = b->len + extra + 1;
    if (want <= b->cap) return;
    if (b->cap == 0) b->cap = 1024;
    while (b->cap < want) b->cap *= 2;
    b->buf = (char *)realloc(b->buf, b->cap);
}

void jb_raw(JBuf *b, const char *s)
{
    size_t n;
    if (!s) return;
    n = strlen(s);
    jb_need(b, n);
    if (!b->buf) return;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    b->buf[b->len] = 0;
}

void jb_str(JBuf *b, const char *s)
{
    if (!s) s = "";
    jb_need(b, strlen(s) * 6 + 2);
    if (!b->buf) return;
    b->buf[b->len++] = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  memcpy(b->buf + b->len, "\\\"", 2); b->len += 2; break;
        case '\\': memcpy(b->buf + b->len, "\\\\", 2); b->len += 2; break;
        case '\n': memcpy(b->buf + b->len, "\\n",  2); b->len += 2; break;
        case '\r': memcpy(b->buf + b->len, "\\r",  2); b->len += 2; break;
        case '\t': memcpy(b->buf + b->len, "\\t",  2); b->len += 2; break;
        default:
            if (c < 0x20) { b->len += (size_t)sprintf(b->buf + b->len, "\\u%04x", c); }
            else          { b->buf[b->len++] = (char)c; }
        }
    }
    b->buf[b->len++] = '"';
    b->buf[b->len] = 0;
}

void jb_kv_str(JBuf *b, const char *k, const char *v)
{
    jb_str(b, k); jb_raw(b, ": "); jb_str(b, v);
}

void jb_kv_int(JBuf *b, const char *k, int v)
{
    char t[32];
    jb_str(b, k); jb_raw(b, ": ");
    snprintf(t, sizeof(t), "%d", v);
    jb_raw(b, t);
}

void jb_kv_bool(JBuf *b, const char *k, int v)
{
    jb_str(b, k); jb_raw(b, ": "); jb_raw(b, v ? "true" : "false");
}

void jb_comma(JBuf *b) { jb_raw(b, ",\n"); }
