#include "jsonw.h"

#include <stdio.h>

bool json_escape_into(const char *src, char *dst, size_t dst_sz) {
    /* Nowhere to write, not even the terminator — the loop below would
     * skip and then `dst[0] = '\0'` past the end of a zero-sized buffer. */
    if (dst_sz == 0) return false;

    size_t di = 0;
    const unsigned char *p = (const unsigned char *)src;
    for (; *p && di + 1 < dst_sz; p++) {
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
    /* Every exit above — the `break`s and the loop's own room check —
     * leaves `p` on the first byte that did not fit. Reaching the
     * terminator instead means all of `src` is in `dst`. */
    return *p == '\0';
}
