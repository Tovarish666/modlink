/* modlink-agent — правка HTTP-заголовков, см. httprw.h */
#include "httprw.h"
#include <string.h>

int hrw_find_ci(const char *hay, size_t hlen, const char *needle)
{
    size_t nlen = strlen(needle), i, j;
    if (nlen == 0 || nlen > hlen) return -1;
    for (i = 0; i + nlen <= hlen; i++) {
        for (j = 0; j < nlen; j++) {
            char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
        }
        if (j == nlen) return (int)i;
    }
    return -1;
}

int hrw_headers_end(const char *buf, int len)
{
    int p = hrw_find_ci(buf, (size_t)len, "\r\n\r\n");
    return p < 0 ? -1 : p + 4;
}

int hrw_rewrite_header(char *buf, int len, int cap,
                       const char *name, const char *from, const char *to)
{
    int pos = 0;
    while (pos < len) {
        int line_end = -1, i;
        for (i = pos; i + 1 < len; i++)
            if (buf[i] == '\r' && buf[i + 1] == '\n') { line_end = i; break; }
        if (line_end < 0 || line_end == pos) break;   /* конец заголовков */

        if (hrw_find_ci(buf + pos, (size_t)(line_end - pos), name) == 0) {
            int fpos = hrw_find_ci(buf + pos, (size_t)(line_end - pos), from);
            if (fpos >= 0) {
                int abs   = pos + fpos;
                int flen  = (int)strlen(from);
                int tlen  = (int)strlen(to);
                int delta = tlen - flen;
                if (len + delta >= cap) return len;   /* не влезает — оставляем */
                memmove(buf + abs + tlen, buf + abs + flen, (size_t)(len - abs - flen));
                memcpy(buf + abs, to, (size_t)tlen);
                len += delta;
            }
            return len;
        }
        pos = line_end + 2;
    }
    return len;
}

int hrw_force_close(char *buf, int len, int cap)
{
    static const char CL[] = "Connection: close\r\n";
    int clen = (int)sizeof(CL) - 1;
    int eol  = hrw_find_ci(buf, (size_t)len, "\r\n");
    if (eol < 0 || len + clen >= cap) return len;
    memmove(buf + eol + 2 + clen, buf + eol + 2, (size_t)(len - eol - 2));
    memcpy(buf + eol + 2, CL, (size_t)clen);
    return len + clen;
}
