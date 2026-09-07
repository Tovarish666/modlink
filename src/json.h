/* modlink — minimal JSON DOM. Enough for config.json; no external deps.
 * Parses objects, arrays, strings (with \u escapes -> UTF-8), numbers,
 * true/false/null. Emitting is done with JBuf, a growable text buffer. */
#ifndef MODLINK_JSON_H
#define MODLINK_JSON_H

#include <stddef.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JVal JVal;
struct JVal {
    JType  type;
    double num;
    int    bval;
    char  *str;         /* J_STR: value.  Object members: key is in `key`. */
    char  *key;         /* set when this value is a member of an object    */
    JVal  *child;       /* first child (J_ARR / J_OBJ) */
    JVal  *next;        /* next sibling                */
};

JVal       *json_parse(const char *text);
void        json_free(JVal *v);
const JVal *json_get(const JVal *obj, const char *key);
const char *json_str(const JVal *obj, const char *key, const char *fallback);
double      json_num(const JVal *obj, const char *key, double fallback);
int         json_bool(const JVal *obj, const char *key, int fallback);
int         json_arr_len(const JVal *arr);

/* ------------------------------------------------------------- emitting */
typedef struct { char *buf; size_t len, cap; } JBuf;

void  jb_init(JBuf *b);
void  jb_free(JBuf *b);
void  jb_raw(JBuf *b, const char *s);
void  jb_str(JBuf *b, const char *s);          /* quoted + escaped */
void  jb_kv_str(JBuf *b, const char *k, const char *v);
void  jb_kv_int(JBuf *b, const char *k, int v);
void  jb_kv_bool(JBuf *b, const char *k, int v);
void  jb_comma(JBuf *b);

#endif
