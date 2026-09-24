/* modlink — background worker.
 *
 * `modlink.exe --worker` runs this: a windowless process that owns 3proxy, the
 * reconnect listeners and a watchdog. The GUI never runs 3proxy itself — it
 * saves config.json and signals the worker, so closing the window leaves the
 * proxies running. Nothing is shown: no console (the exe is a GUI subsystem
 * binary and never creates a window here), no tray.
 *
 * IPC is deliberately tiny and session-local (GUI and worker are the same user
 * in the same session, whether the worker was spawned by the GUI or by the
 * logon autostart):
 *   - a mutex marks "a worker is running";
 *   - three auto-reset events drive it: reload (re-read config + apply), stop
 *     (stop 3proxy, keep watching), quit (exit);
 *   - status.json carries {running, err} back to the GUI.
 */
#include "common.h"
#include "json.h"
#include <string.h>

#define EV_RELOAD "Local\\modlink_reload"
#define EV_STOP   "Local\\modlink_stop"
#define EV_QUIT   "Local\\modlink_quit"
#define MTX_WORK  "Local\\modlink_worker_mtx"

static void write_status(BOOL running, const char *err)
{
    char path[ML_PATH_LEN];
    JBuf b;
    snprintf(path, sizeof(path), "%s\\status.json", ml_dir_data());
    jb_init(&b);
    jb_raw(&b, "{");
    jb_kv_bool(&b, "running", running);
    jb_raw(&b, ",");
    jb_kv_str(&b, "err", err ? err : "");
    jb_raw(&b, "}\n");
    if (b.buf) ml_write_file_atomic(path, b.buf, b.len);
    jb_free(&b);
}

/* Load config into *cfg, validate, (re)start 3proxy + reconnect. Returns TRUE if
 * the proxy is meant to be running afterwards; fills err on failure. *cfg is
 * always populated (the periodic checks read it even when validation fails). */
static BOOL apply_now(Config *cfg, char *err, size_t errcap)
{
    int bad;
    if (err && errcap) err[0] = 0;
    if (!cfg_load(cfg)) { cfg_defaults(cfg); }
    bad = cfg_validate(cfg, err, errcap);
    if (bad != -1) return FALSE;
    if (!p3_apply(cfg, err, errcap)) return FALSE;
    reconn_rebuild(cfg);
    return TRUE;
}

int worker_run(void)
{
    HANDLE mtx, ev_reload, ev_stop, ev_quit, waits[3];
    BOOL run;
    char err[ML_PATH_LEN];
    Config cfg;                 /* last loaded config; the checks read it */

    /* single worker only */
    mtx = CreateMutexA(NULL, TRUE, MTX_WORK);
    if (mtx && GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    ml_ensure_dirs();
    ml_log("---- worker starting ----");
    p3_extract_binary();

    ev_reload = CreateEventA(NULL, FALSE, FALSE, EV_RELOAD);
    ev_stop   = CreateEventA(NULL, FALSE, FALSE, EV_STOP);
    ev_quit   = CreateEventA(NULL, FALSE, FALSE, EV_QUIT);

    run = apply_now(&cfg, err, sizeof(err));
    write_status(run && p3_running(), run ? "" : err);

    waits[0] = ev_reload; waits[1] = ev_stop; waits[2] = ev_quit;
    for (;;) {
        DWORD w = WaitForMultipleObjects(3, waits, FALSE, 3000);
        if (w == WAIT_OBJECT_0) {                 /* reload */
            run = apply_now(&cfg, err, sizeof(err));
            if (!run) p3_stop();
        } else if (w == WAIT_OBJECT_0 + 1) {      /* stop */
            p3_stop();
            reconn_shutdown();
            run = FALSE;
            err[0] = 0;
        } else if (w == WAIT_OBJECT_0 + 2) {      /* quit */
            break;
        } else {                                  /* timeout — watchdog */
            if (run && !p3_running()) {
                ml_log("watchdog: 3proxy died, restarting");
                run = apply_now(&cfg, err, sizeof(err));
            }
        }
        /* Periodic WAN / speed probes; a no-op until one comes due. */
        checks_tick(&cfg, run && p3_running());
        write_status(run && p3_running(), run ? "" : err);
    }

    p3_stop();
    reconn_shutdown();
    write_status(FALSE, "");
    ml_log("---- worker exiting ----");
    return 0;
}
