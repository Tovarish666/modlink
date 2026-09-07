/* modlink — common types and shared declarations.
 *
 * Port of https://github.com/Tovarish666/modlink to a native Windows .exe.
 * Proxy engine: 3proxy (service type `auto` = HTTP CONNECT + SOCKS5 on one port).
 *
 * Design note: in the Python original every per-modem value was DERIVED from the
 * modem number N (login = "modem{N}", bind = 192.168.{N}.100, web UI =
 * 192.168.{N}.1, port = base + sorted_index*2). Here every one of those is a
 * stored, user-editable field. Nothing is derived at runtime, so adding a modem
 * can never renumber the ports of the modems already deployed to clients.
 */
#ifndef MODLINK_COMMON_H
#define MODLINK_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

/* ---------------------------------------------------------------- limits */
#define ML_MAX_MODEMS     256
#define ML_NAME_LEN        64
#define ML_LOGIN_LEN       64
#define ML_PASS_LEN        64
#define ML_ADDR_LEN        46      /* fits IPv6 text form */
#define ML_PATH_LEN       512
#define ML_URL_LEN        512

/* ---------------------------------------------------------------- modem */
typedef struct {
    int   id;                       /* stable, never reused, not shown to user */
    int   n;                        /* modem number — label only, no longer load-bearing */
    char  name  [ML_NAME_LEN];      /* free-text label */
    char  login [ML_LOGIN_LEN];     /* proxy username        — editable */
    char  pass  [ML_PASS_LEN];      /* proxy password        — editable */
    char  lan_ip[ML_ADDR_LEN];      /* 3proxy -e : outbound bind = modem iface on host */
    char  modem_ip[ML_ADDR_LEN];    /* Huawei HiLink web UI host (was 192.168.N.1)     */
    char  listen_ip[ML_ADDR_LEN];   /* 3proxy -i : listen address, default 0.0.0.0     */
    int   proxy_port;               /* 3proxy `auto` service port */
    int   reconn_port;              /* our own reconnect HTTP listener port */
    int   interval_min;             /* auto-reconnect period, 0 = off */
    BOOL  enabled;

    /* --- runtime only, never persisted --- */
    char  last_exit_ip[ML_ADDR_LEN];
    int   last_test;                /* ML_TEST_* */
    BOOL  huawei_ok;
} Modem;

enum { ML_TEST_NONE = 0, ML_TEST_PENDING, ML_TEST_OK, ML_TEST_FAIL };

/* ---------------------------------------------------------------- config */
typedef struct {
    char  wan_ip[ML_ADDR_LEN];      /* external IP: manual or auto-detected */
    char  lan_ip[ML_ADDR_LEN];      /* host LAN IP: manual or auto-detected */
    BOOL  wan_auto;                 /* re-detect WAN on startup */
    BOOL  lan_auto;                 /* re-detect LAN on startup */
    int   base_port;                /* only SUGGESTS ports for newly added rows */
    BOOL  autostart;                /* register in HKCU Run */
    BOOL  start_minimized;

    Modem modems[ML_MAX_MODEMS];
    int   count;
} Config;

/* ---------------------------------------------------------------- paths */
const char *ml_dir_data(void);      /* %ProgramData%\modlink            */
const char *ml_dir_bin(void);       /* %ProgramData%\modlink\bin        */
const char *ml_dir_logs(void);      /* %ProgramData%\modlink\logs       */
const char *ml_path_config(void);   /* ...\config.json                  */
const char *ml_path_3pcfg(void);    /* ...\3proxy.cfg                   */
const char *ml_path_3pexe(void);    /* ...\bin\3proxy.exe               */
const char *ml_path_3plog(void);    /* ...\logs\3proxy.log              */
BOOL        ml_ensure_dirs(void);

/* ---------------------------------------------------------------- util */
void   ml_log(const char *fmt, ...);          /* app log -> logs\modlink.log */
char  *ml_strlcpy(char *dst, const char *src, size_t cap);
BOOL   ml_is_ipv4(const char *s);
BOOL   ml_port_valid(int p);
void   ml_rand_pass(char *out, size_t cap, int len);
wchar_t *ml_utf8_to_w(const char *s);         /* caller frees */
char    *ml_w_to_utf8(const wchar_t *s);      /* caller frees */
BOOL   ml_read_file(const char *path, char **out, size_t *len);
BOOL   ml_write_file_atomic(const char *path, const char *data, size_t len);
void   ml_detect_lan_ip(char *out, size_t cap);
int    ml_tail_file(const char *path, int max_lines, char ***out_lines);
void   ml_free_lines(char **lines, int n);

/* ---------------------------------------------------------------- config io */
void   cfg_defaults(Config *c);
BOOL   cfg_load(Config *c);
BOOL   cfg_save(const Config *c);
int    cfg_add_modem(Config *c);              /* returns index, -1 if full */
void   cfg_remove_modem(Config *c, int idx);
Modem *cfg_find_by_id(Config *c, int id);
/* Validation: fills err (cap ML_PATH_LEN) and returns index of offending row,
 * or -1 when the whole config is coherent. Catches port collisions, which
 * matter now that ports are hand-entered. */
int    cfg_validate(const Config *c, char *err, size_t errcap);
int    cfg_suggest_port(const Config *c, BOOL reconnect_port);

/* ---------------------------------------------------------------- 3proxy */
BOOL   p3_extract_binary(void);               /* unpack embedded 3proxy.exe */
BOOL   p3_write_config(const Config *c, char *err, size_t errcap);
BOOL   p3_start(char *err, size_t errcap);
void   p3_stop(void);
BOOL   p3_running(void);
BOOL   p3_apply(const Config *c, char *err, size_t errcap);  /* write + restart */

/* ---------------------------------------------------------------- net */
/* All HTTP goes through WinHTTP: it speaks TLS and proxies natively, so we
 * never need OpenSSL or a bundled cert store. */
typedef struct {
    int    status;
    char  *body;        /* NUL-terminated, caller frees */
    size_t len;
    char   err[256];
} HttpResp;

void   http_free(HttpResp *r);
BOOL   http_get(const char *url, int timeout_ms, HttpResp *out);
BOOL   http_get_via_proxy(const char *url, const char *proxy_host, int proxy_port,
                          const char *user, const char *pass,
                          int timeout_ms, HttpResp *out);
BOOL   http_post_xml(const char *url, const char *body,
                     const char *const *hdrs, int nhdrs,
                     int timeout_ms, HttpResp *out);
BOOL   net_fetch_external_ip(char *out, size_t cap);

/* ---------------------------------------------------------------- hilink */
/* Huawei HiLink API (E3372h and friends): token dance, then the same
 * dataswitch/net-mode sequence the Python panel used to force a new IP. */
BOOL   hilink_reconnect(const char *host, char *msg, size_t msgcap, double *secs);
BOOL   hilink_reboot(const char *host, char *msg, size_t msgcap);
BOOL   hilink_probe(const char *host, int timeout_ms);   /* SesTokInfo reachable? */

/* ---------------------------------------------------------------- reconnect */
BOOL   reconn_rebuild(const Config *c);   /* sync listeners + timers to config */
void   reconn_shutdown(void);
void   reconn_log_append(int modem_id, const char *line);
int    reconn_log_read(int modem_id, int max_lines, char ***out);

/* ---------------------------------------------------------------- ui */
int    ui_run(HINSTANCE hInst, int nCmdShow);

#endif /* MODLINK_COMMON_H */
