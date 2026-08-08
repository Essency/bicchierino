#include "jsonw.h"

#include <stdio.h>

void json_escape_into(const char *src, char *dst, size_t dst_sz) {
    size_t di = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && di + 1 < dst_sz; p++) {
        if (*p == '"' || *p == '\\') {
            if (di + 2 >= dst_sz) break;
            dst[di++] = '\\';
            dst[di++] = (char)*p;
        } else if (*p == '\n' || *p == '\r' || *p == '\t') {
            if (di + 2 >= dst_sz) break;
            dst[di++] = '\\';
            dst[di++] = *p == '\n' ? 'n' : (*p == '\r' ? 'r' : 't');
        } else if (*p < 0x20) {
            if (di + 6 >= dst_sz) break;
            di += (size_t)snprintf(dst + di, dst_sz - di, "\\u%04x", *p);
        } else {
            dst[di++] = (char)*p;
        }
    }
    dst[di] = '\0';
}
