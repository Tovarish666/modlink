/* ProxyVeth — bridge between the WebView2 UI (JS) and the C server backend.
 *
 * Every function returns a freshly malloc'd, NUL-terminated UTF-8 JSON string
 * that the caller must free(). The host (host.cc) binds each of these to a
 * global JS function; the UI calls them and gets the JSON back as a Promise.
 *
 * Kept deliberately free of <windows.h> so it can be included from the C++
 * host next to webview.h / WebView2.h without header clashes.
 */
#ifndef PROXYVETH_BRIDGE_H
#define PROXYVETH_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Called once at startup (loads config.json, ensures dirs, unpacks 3proxy). */
void  pv_init(void);
/* Called once at shutdown (stops 3proxy and reconnect listeners). */
void  pv_shutdown(void);

/* --- read (req ignored, kept for a uniform binding signature) --------- */
char *pv_get_state(const char *req);   /* {network:{...}, modems:[...], running} */
char *pv_status(const char *req);      /* {running:bool} — cheap poll            */
char *pv_clip(const char *req);        /* req[0] = text -> Windows clipboard      */

/* --- mutate (fast, run on the UI thread) ------------------------------ */
char *pv_save_network(const char *req);/* req[0] = {lan_ip, base_port}  -> state */
char *pv_add_modem(const char *req);   /* -> state (with the new row)            */
char *pv_set_mode(const char *req);    /* req[0]=mode(0/1); refills ports -> state */
char *pv_update_modem(const char *req);/* req[0] = full modem object    -> state */
char *pv_delete_modem(const char *req);/* req[0] = id (number)          -> state */
char *pv_stop(const char *req);        /* stop 3proxy                   -> {ok}  */

/* --- slow (network / process start; host runs these on a worker) ------ */
char *pv_apply(const char *req);       /* validate, write cfg, (re)start 3proxy  */
char *pv_test(const char *req);        /* req[0] = id -> {ok, exit_ip, huawei}   */
char *pv_reconnect(const char *req);   /* req[0] = id -> {ok, msg, secs}         */
char *pv_reboot(const char *req);      /* req[0] = id -> {ok, msg}               */

#ifdef __cplusplus
}
#endif

#endif /* PROXYVETH_BRIDGE_H */
