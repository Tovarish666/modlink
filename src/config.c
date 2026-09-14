/* modlink — config load/save/validate.
 *
 * On-disk format is JSON (config.json), replacing the whitespace-separated
 * modems.conf of the Python version. The old file is imported once if present,
 * so an existing install keeps its modems and passwords. */
#include "common.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>

#define CFG_DEFAULT_BASE_PORT 15000

void cfg_defaults(Config *c)
{
    memset(c, 0, sizeof(*c));
    c->base_port = CFG_DEFAULT_BASE_PORT;
    c->wan_auto  = TRUE;
    c->lan_auto  = TRUE;
    ml_detect_lan_ip(c->lan_ip, sizeof(c->lan_ip));
}

/* ------------------------------------------------------------- port picking */
static BOOL port_taken(const Config *c, int port, int skip_idx)
{
    int i;
    for (i = 0; i < c->count; i++) {
        if (i == skip_idx) continue;
        if (c->modems[i].proxy_port  == port) return TRUE;
        if (c->modems[i].reconn_port == port) return TRUE;
    }
    return FALSE;
}

/* Suggests the next free port for a NEW row. Only a convenience — nothing is
 * recomputed for existing rows, which is the whole point of the rewrite. */
int cfg_suggest_port(const Config *c, BOOL reconnect_port)
{
    int p = c->base_port > 0 ? c->base_port : CFG_DEFAULT_BASE_PORT;
    if (reconnect_port) p++;
    while (p < 65535 && port_taken(c, p, -1)) p++;
    return p;
}

/* ------------------------------------------------------------- add / remove */
int cfg_add_modem(Config *c)
{
    Modem *m;
    int i, max_id = 0, max_n = 0;

    if (c->count >= ML_MAX_MODEMS) return -1;

    for (i = 0; i < c->count; i++) {
        if (c->modems[i].id > max_id) max_id = c->modems[i].id;
        if (c->modems[i].n  > max_n)  max_n  = c->modems[i].n;
    }

    m = &c->modems[c->count];
    memset(m, 0, sizeof(*m));
    m->id = max_id + 1;
    m->n  = max_n + 1;
    snprintf(m->login, sizeof(m->login), "modem%d", m->n);
    ml_rand_pass(m->pass, sizeof(m->pass), 10);

    /* Address suggestions follow the old 192.168.N.x convention so the fields
     * start out sensible, but they are plain editable text from here on. */
    snprintf(m->lan_ip,   sizeof(m->lan_ip),   "192.168.%d.100", m->n);
    snprintf(m->modem_ip, sizeof(m->modem_ip), "192.168.%d.1",   m->n);

    m->proxy_port   = cfg_suggest_port(c, FALSE);
    c->count++;                               /* count first so the reconnect  */
    m->reconn_port  = cfg_suggest_port(c, FALSE);  /* port avoids the proxy one */
    c->count--;

    m->interval_min = 0;
    m->enabled      = TRUE;

    c->count++;
    return c->count - 1;
}

void cfg_remove_modem(Config *c, int idx)
{
    if (idx < 0 || idx >= c->count) return;
    if (idx < c->count - 1)
        memmove(&c->modems[idx], &c->modems[idx + 1],
                sizeof(Modem) * (size_t)(c->count - idx - 1));
    c->count--;
}

Modem *cfg_find_by_id(Config *c, int id)
{
    int i;
    for (i = 0; i < c->count; i++)
        if (c->modems[i].id == id) return &c->modems[i];
    return NULL;
}

/* ------------------------------------------------------------- validation */
int cfg_validate(const Config *c, char *err, size_t errcap)
{
    int i, j;

    if (err && errcap) err[0] = 0;
    if (c->count == 0) {
        if (err) ml_strlcpy(err, "Список модемов пуст", errcap);
        return -2;
    }

    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        if (!m->enabled) continue;

        if (!m->login[0]) {
            snprintf(err, errcap, "Строка %d: пустой логин", i + 1);
            return i;
        }
        /* 3proxy's users line is whitespace-separated, so a login or password
         * containing spaces or a colon would silently corrupt the config. */
        if (strpbrk(m->login, " \t:\"'")) {
            snprintf(err, errcap, "Строка %d: логин не может содержать пробел, : или кавычки", i + 1);
            return i;
        }
        if (!m->pass[0]) {
            snprintf(err, errcap, "Строка %d (%s): пустой пароль", i + 1, m->login);
            return i;
        }
        if (strpbrk(m->pass, " \t\"'")) {
            snprintf(err, errcap, "Строка %d (%s): пароль не может содержать пробел или кавычки", i + 1, m->login);
            return i;
        }
        if (!ml_port_valid(m->proxy_port)) {
            snprintf(err, errcap, "Строка %d (%s): некорректный порт прокси", i + 1, m->login);
            return i;
        }
        if (m->reconn_port != 0 && !ml_port_valid(m->reconn_port)) {
            snprintf(err, errcap, "Строка %d (%s): некорректный порт реконнекта", i + 1, m->login);
            return i;
        }
        if (m->proxy_port == m->reconn_port) {
            snprintf(err, errcap, "Строка %d (%s): порт прокси и порт реконнекта совпадают (%d)",
                     i + 1, m->login, m->proxy_port);
            return i;
        }
        if (m->lan_ip[0] && !ml_is_ipv4(m->lan_ip)) {
            snprintf(err, errcap, "Строка %d (%s): LAN IP «%s» — не IPv4", i + 1, m->login, m->lan_ip);
            return i;
        }
        if (m->modem_ip[0] && !ml_is_ipv4(m->modem_ip)) {
            snprintf(err, errcap, "Строка %d (%s): IP модема «%s» — не IPv4", i + 1, m->login, m->modem_ip);
            return i;
        }
        /* Cross-row collisions. Hand-entered ports make these a real risk, so
         * they are hard errors rather than something 3proxy discovers at bind. */
        for (j = 0; j < c->count; j++) {
            const Modem *o = &c->modems[j];
            if (j == i || !o->enabled) continue;
            if (o->proxy_port == m->proxy_port || o->reconn_port == m->proxy_port) {
                snprintf(err, errcap, "Порт %d занят дважды: строки %d и %d",
                         m->proxy_port, i + 1, j + 1);
                return i;
            }
            if (m->reconn_port &&
                (o->proxy_port == m->reconn_port || o->reconn_port == m->reconn_port)) {
                snprintf(err, errcap, "Порт %d занят дважды: строки %d и %d",
                         m->reconn_port, i + 1, j + 1);
                return i;
            }
            if (j > i && !strcmp(o->login, m->login)) {
                snprintf(err, errcap, "Логин «%s» повторяется: строки %d и %d",
                         m->login, i + 1, j + 1);
                return i;
            }
        }
    }
    return -1;
}

/* ------------------------------------------------------------- load / save */
static void modem_from_json(Modem *m, const JVal *o, int fallback_id)
{
    memset(m, 0, sizeof(*m));
    m->id = (int)json_num(o, "id", fallback_id);
    m->n  = (int)json_num(o, "n",  fallback_id);
    ml_strlcpy(m->login,     json_str(o, "login",     ""),        sizeof(m->login));
    ml_strlcpy(m->pass,      json_str(o, "pass",      ""),        sizeof(m->pass));
    ml_strlcpy(m->lan_ip,    json_str(o, "lan_ip",    ""),        sizeof(m->lan_ip));
    ml_strlcpy(m->modem_ip,  json_str(o, "modem_ip",  ""),        sizeof(m->modem_ip));
    m->proxy_port   = (int)json_num(o, "proxy_port",   0);
    m->reconn_port  = (int)json_num(o, "reconn_port",  0);
    m->interval_min = (int)json_num(o, "interval_min", 0);
    m->enabled      =      json_bool(o, "enabled",     1);
    if (!m->login[0]) snprintf(m->login, sizeof(m->login), "modem%d", m->n);
}

/* One-time import of the Python panel's modems.conf ("N password [interval]").
 * Fields it never had are filled from the old derivation rules. */
static BOOL import_legacy(Config *c)
{
    char path[ML_PATH_LEN], *buf = NULL, *line, *save = NULL;
    size_t len = 0;
    int imported = 0;

    snprintf(path, sizeof(path), "%s\\modems.conf", ml_dir_data());
    if (!ml_read_file(path, &buf, &len) || !buf) return FALSE;

    for (line = strtok_s(buf, "\r\n", &save); line; line = strtok_s(NULL, "\r\n", &save)) {
        char *tok, *ts = NULL;
        int n, idx;
        Modem *m;

        while (*line == ' ' || *line == '\t') line++;
        if (!*line || *line == '#') continue;

        tok = strtok_s(line, " \t", &ts);
        if (!tok) continue;
        n = atoi(tok);
        if (n < 1 || n > 254) continue;

        idx = cfg_add_modem(c);
        if (idx < 0) break;
        m = &c->modems[idx];

        m->n = n;
        snprintf(m->login,    sizeof(m->login),    "modem%d",       n);
        snprintf(m->lan_ip,   sizeof(m->lan_ip),   "192.168.%d.100", n);
        snprintf(m->modem_ip, sizeof(m->modem_ip), "192.168.%d.1",   n);

        tok = strtok_s(NULL, " \t", &ts);
        if (tok) ml_strlcpy(m->pass, tok, sizeof(m->pass));
        tok = strtok_s(NULL, " \t", &ts);
        if (tok) m->interval_min = atoi(tok);

        /* Old port formula: base + sorted_index*2 (proxy) and +1 (reconnect).
         * Reproduced only so an upgrade keeps working credentials — from now on
         * these are stored values that never move on their own. */
        m->proxy_port  = c->base_port + imported * 2;
        m->reconn_port = c->base_port + imported * 2 + 1;
        imported++;
    }
    free(buf);

    if (imported) {
        ml_log("imported %d modems from legacy modems.conf", imported);
        MoveFileExA(path, "modems.conf.imported", MOVEFILE_REPLACE_EXISTING);
    }
    return imported > 0;
}

BOOL cfg_load(Config *c)
{
    char *text = NULL;
    size_t len = 0;
    JVal *root;
    const JVal *arr, *it;
    int i = 0;

    cfg_defaults(c);

    if (!ml_read_file(ml_path_config(), &text, &len) || !text) {
        /* No config yet — try to inherit from a Python-era install. */
        if (import_legacy(c)) { cfg_save(c); return TRUE; }
        return FALSE;
    }

    root = json_parse(text);
    free(text);
    if (!root) {
        ml_log("config.json is not valid JSON — starting from defaults");
        return FALSE;
    }

    ml_strlcpy(c->wan_ip, json_str(root, "wan_ip", ""), sizeof(c->wan_ip));
    ml_strlcpy(c->lan_ip, json_str(root, "lan_ip", c->lan_ip), sizeof(c->lan_ip));
    c->wan_auto        = json_bool(root, "wan_auto", 1);
    c->lan_auto        = json_bool(root, "lan_auto", 1);
    c->base_port       = (int)json_num(root, "base_port", CFG_DEFAULT_BASE_PORT);
    c->autostart       = json_bool(root, "autostart", 0);
    c->start_minimized = json_bool(root, "start_minimized", 0);
    if (!ml_port_valid(c->base_port)) c->base_port = CFG_DEFAULT_BASE_PORT;

    arr = json_get(root, "modems");
    if (arr && arr->type == J_ARR) {
        for (it = arr->child; it && c->count < ML_MAX_MODEMS; it = it->next) {
            if (it->type != J_OBJ) continue;
            modem_from_json(&c->modems[c->count], it, ++i);
            c->count++;
        }
    }

    json_free(root);
    ml_log("config loaded: %d modems", c->count);
    return TRUE;
}

BOOL cfg_save(const Config *c)
{
    JBuf b;
    int i;
    BOOL ok;

    ml_ensure_dirs();
    jb_init(&b);
    jb_raw(&b, "{\n  ");
    jb_kv_str (&b, "wan_ip", c->wan_ip);          jb_comma(&b); jb_raw(&b, "  ");
    jb_kv_str (&b, "lan_ip", c->lan_ip);          jb_comma(&b); jb_raw(&b, "  ");
    jb_kv_bool(&b, "wan_auto", c->wan_auto);      jb_comma(&b); jb_raw(&b, "  ");
    jb_kv_bool(&b, "lan_auto", c->lan_auto);      jb_comma(&b); jb_raw(&b, "  ");
    jb_kv_int (&b, "base_port", c->base_port);    jb_comma(&b); jb_raw(&b, "  ");
    jb_kv_bool(&b, "autostart", c->autostart);    jb_comma(&b); jb_raw(&b, "  ");
    jb_kv_bool(&b, "start_minimized", c->start_minimized); jb_comma(&b); jb_raw(&b, "  ");
    jb_str(&b, "modems"); jb_raw(&b, ": [");

    for (i = 0; i < c->count; i++) {
        const Modem *m = &c->modems[i];
        jb_raw(&b, i ? ",\n    {" : "\n    {");
        jb_kv_int (&b, "id",           m->id);           jb_raw(&b, ", ");
        jb_kv_int (&b, "n",            m->n);            jb_raw(&b, ", ");
        jb_kv_str (&b, "login",        m->login);        jb_raw(&b, ", ");
        jb_kv_str (&b, "pass",         m->pass);         jb_raw(&b, ",\n     ");
        jb_kv_str (&b, "lan_ip",       m->lan_ip);       jb_raw(&b, ", ");
        jb_kv_str (&b, "modem_ip",     m->modem_ip);     jb_raw(&b, ", ");
        jb_raw(&b, "\n     ");
        jb_kv_int (&b, "proxy_port",   m->proxy_port);   jb_raw(&b, ", ");
        jb_kv_int (&b, "reconn_port",  m->reconn_port);  jb_raw(&b, ", ");
        jb_kv_int (&b, "interval_min", m->interval_min); jb_raw(&b, ", ");
        jb_kv_bool(&b, "enabled",      m->enabled);
        jb_raw(&b, "}");
    }
    jb_raw(&b, c->count ? "\n  ]\n}\n" : "]\n}\n");

    ok = b.buf ? ml_write_file_atomic(ml_path_config(), b.buf, b.len) : FALSE;
    jb_free(&b);
    if (!ok) ml_log("cfg_save FAILED (%s)", ml_path_config());
    return ok;
}
