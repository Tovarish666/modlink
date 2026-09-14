/* modlink-agent — конфиг интерфейсов, см. agentcfg.h */
#include "agentcfg.h"
#include "json.h"
#include <string.h>
#include <stdlib.h>

const char *agentcfg_path(void)
{
    static char path[ML_PATH_LEN];
    snprintf(path, sizeof(path), "%s\\agent.json", ml_dir_data());
    return path;
}

/* «ip:port:user:pass» из строки прокси — тот же формат, что копирует сервер. */
static void split_proxy(const char *proxy, TunnelCfg *t)
{
    const char *colon;
    if (!proxy || !proxy[0]) return;
    colon = strchr(proxy, ':');
    if (!colon) { ml_strlcpy(t->proxy_ip, proxy, sizeof(t->proxy_ip)); return; }
    {
        size_t k = (size_t)(colon - proxy);
        if (k >= sizeof(t->proxy_ip)) k = sizeof(t->proxy_ip) - 1;
        memcpy(t->proxy_ip, proxy, k);
        t->proxy_ip[k] = 0;
    }
    t->proxy_port = atoi(colon + 1);
}

int agentcfg_load(const char *path, TunnelCfg *out, int cap, char *err, size_t errcap)
{
    char *text = NULL;
    size_t len = 0;
    JVal *root;
    const JVal *arr, *it;
    int n = 0;

    if (err && errcap) err[0] = 0;
    if (!ml_read_file(path, &text, &len) || !text) return 0;   /* нет файла — пусто */

    root = json_parse(text);
    free(text);
    if (!root) { if (err) snprintf(err, errcap, "%s — не валидный JSON", path); return -1; }

    arr = json_get(root, "interfaces");
    if (arr && arr->type == J_ARR) {
        for (it = arr->child; it && n < cap; it = it->next) {
            TunnelCfg *t;
            if (it->type != J_OBJ) continue;
            t = &out[n];
            memset(t, 0, sizeof(*t));
            ml_strlcpy(t->guid,    json_str(it, "tap",   ""),              sizeof(t->guid));
            ml_strlcpy(t->virt_ip, json_str(it, "virt",  ""),              sizeof(t->virt_ip));
            ml_strlcpy(t->netmask, json_str(it, "mask",  "255.255.255.0"), sizeof(t->netmask));
            ml_strlcpy(t->real_ip, json_str(it, "real",  ""),              sizeof(t->real_ip));
            ml_strlcpy(t->user,    json_str(it, "user",  ""),              sizeof(t->user));
            ml_strlcpy(t->pass,    json_str(it, "pass",  ""),              sizeof(t->pass));
            ml_strlcpy(t->dns_ip,  json_str(it, "dns",   ""),              sizeof(t->dns_ip));
            ml_strlcpy(t->label,   json_str(it, "label", ""),              sizeof(t->label));
            split_proxy(json_str(it, "proxy", ""), t);
            if (!t->label[0]) ml_strlcpy(t->label, t->virt_ip, sizeof(t->label));
            n++;
        }
    }
    json_free(root);
    return n;
}

BOOL agentcfg_save(const char *path, const TunnelCfg *list, int count)
{
    JBuf b;
    int i;
    BOOL ok;

    ml_ensure_dirs();
    jb_init(&b);
    jb_raw(&b, "{\n  \"interfaces\": [");
    for (i = 0; i < count; i++) {
        const TunnelCfg *t = &list[i];
        char proxy[128];
        snprintf(proxy, sizeof(proxy), "%s:%d", t->proxy_ip, t->proxy_port);
        jb_raw(&b, i ? ",\n    {" : "\n    {");
        jb_kv_str(&b, "label", t->label);   jb_raw(&b, ", ");
        jb_kv_str(&b, "tap",   t->guid);    jb_raw(&b, ",\n     ");
        jb_kv_str(&b, "virt",  t->virt_ip); jb_raw(&b, ", ");
        jb_kv_str(&b, "mask",  t->netmask); jb_raw(&b, ", ");
        jb_kv_str(&b, "real",  t->real_ip); jb_raw(&b, ",\n     ");
        jb_kv_str(&b, "proxy", proxy);      jb_raw(&b, ", ");
        jb_kv_str(&b, "user",  t->user);    jb_raw(&b, ", ");
        jb_kv_str(&b, "pass",  t->pass);    jb_raw(&b, ", ");
        jb_kv_str(&b, "dns",   t->dns_ip);
        jb_raw(&b, "}");
    }
    jb_raw(&b, count ? "\n  ]\n}\n" : "]\n}\n");
    ok = b.buf ? ml_write_file_atomic(path, b.buf, b.len) : FALSE;
    jb_free(&b);
    return ok;
}
