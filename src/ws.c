#include "ws.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void ws_reader_init(struct ws_reader *r) {
    memset(r, 0, sizeof(*r));
}

void ws_reader_free(struct ws_reader *r) {
    free(r->buf);
    free(r->msg);
    memset(r, 0, sizeof(*r));
}

/* Make room for `extra` more bytes, reclaiming the consumed prefix first.
 * Compacting before growing is what keeps a long-lived connection from
 * walking its buffer off into memory it never reuses. */
static bool buf_reserve(struct ws_reader *r, size_t extra) {
    if (r->off && r->len - r->off + extra > r->cap) {
        memmove(r->buf, r->buf + r->off, r->len - r->off);
        r->len -= r->off;
        r->off = 0;
    }
    if (r->len + extra <= r->cap) return true;
    size_t cap = r->cap ? r->cap : 4096;
    while (cap < r->len + extra) {
        if (cap > WS_MAX_MESSAGE) return false;
        cap *= 2;
    }
    unsigned char *next = realloc(r->buf, cap);
    if (!next) return false;
    r->buf = next;
    r->cap = cap;
    return true;
}

bool ws_reader_feed(struct ws_reader *r, const void *bytes, size_t n) {
    if (!n) return true;
    if (!buf_reserve(r, n)) return false;
    memcpy(r->buf + r->len, bytes, n);
    r->len += n;
    return true;
}

static bool msg_append(struct ws_reader *r, const unsigned char *p, size_t n) {
    if (r->msg_len + n > WS_MAX_MESSAGE) return false;
    if (r->msg_len + n + 1 > r->msg_cap) {
        size_t cap = r->msg_cap ? r->msg_cap : 4096;
        while (cap < r->msg_len + n + 1) cap *= 2;
        unsigned char *next = realloc(r->msg, cap);
        if (!next) return false;
        r->msg = next;
        r->msg_cap = cap;
    }
    memcpy(r->msg + r->msg_len, p, n);
    r->msg_len += n;
    return true;
}

/* Hand the reassembled message to the caller and reset for the next one. */
static ws_result msg_yield(struct ws_reader *r, char **payload, size_t *len) {
    if (!r->msg) {
        /* An empty message is still a message. */
        if (!msg_append(r, (const unsigned char *)"", 0)) return WS_ERROR;
    }
    r->msg[r->msg_len] = 0;
    if (payload) *payload = (char *)r->msg;
    else free(r->msg);
    if (len) *len = r->msg_len;
    r->msg = NULL;
    r->msg_len = 0;
    r->msg_cap = 0;
    r->msg_open = false;
    r->msg_discard = false;
    return WS_TEXT;
}

/* A control frame's payload, copied out for the caller (ping → pong). */
static ws_result control_yield(const unsigned char *p, size_t n, char **payload, size_t *len,
                               ws_result kind) {
    if (payload) {
        char *copy = malloc(n + 1);
        if (!copy) return WS_ERROR;
        memcpy(copy, p, n);
        copy[n] = 0;
        *payload = copy;
    }
    if (len) *len = n;
    return kind;
}

ws_result ws_reader_take(struct ws_reader *r, char **payload, size_t *len) {
    for (;;) {
        size_t avail = r->len - r->off;
        if (avail < 2) return WS_NEED_MORE;
        const unsigned char *f = r->buf + r->off;
        bool fin = (f[0] & 0x80) != 0;
        /* Reserved bits set means an extension was negotiated. None was:
         * this client offers none, so a frame using them is unreadable
         * rather than merely unexpected. */
        if (f[0] & 0x70) return WS_ERROR;
        int opcode = f[0] & 0x0f;
        bool masked = (f[1] & 0x80) != 0;
        uint64_t plen = f[1] & 0x7f;
        size_t hdr = 2;

        if (plen == 126) {
            if (avail < 4) return WS_NEED_MORE;
            plen = ((uint64_t)f[2] << 8) | f[3];
            hdr = 4;
        } else if (plen == 127) {
            if (avail < 10) return WS_NEED_MORE;
            plen = 0;
            for (int i = 0; i < 8; i++) plen = (plen << 8) | f[2 + i];
            hdr = 10;
        }
        if (plen > WS_MAX_MESSAGE) return WS_ERROR;
        /* Control frames carry at most 125 bytes and are never
         * fragmented (RFC 6455 §5.5) — anything else is a broken peer,
         * not a big message. */
        bool control = (opcode & 0x8) != 0;
        if (control && (plen > 125 || !fin)) return WS_ERROR;
        if (masked) hdr += 4;

        /* THE point of the buffer: an incomplete frame consumes nothing,
         * so the bytes already read stay where the next feed can finish
         * them. The old reader dropped them here, which desynchronised
         * the stream for everything that followed. */
        if (avail < hdr + plen) return WS_NEED_MORE;

        unsigned char *body = r->buf + r->off + hdr;
        if (masked) {
            const unsigned char *mask = r->buf + r->off + hdr - 4;
            for (uint64_t i = 0; i < plen; i++) body[i] ^= mask[i % 4];
        }
        r->off += hdr + (size_t)plen;

        switch (opcode) {
        case 0x8:
            return WS_CLOSED;
        case 0x9:
            return control_yield(body, (size_t)plen, payload, len, WS_PING);
        case 0xA:
            continue; /* pong: nothing to do, look for the next frame */
        case 0x0:
            /* A continuation with nothing to continue is a stream we
             * have lost the shape of. */
            if (!r->msg_open) return WS_ERROR;
            if (!r->msg_discard && !msg_append(r, body, (size_t)plen)) return WS_ERROR;
            if (!fin) continue;
            if (r->msg_discard) {
                r->msg_open = false;
                r->msg_discard = false;
                continue;
            }
            return msg_yield(r, payload, len);
        case 0x1:
        case 0x2: {
            if (r->msg_open) return WS_ERROR; /* a new message inside one */
            bool discard = opcode == 0x2;     /* grappa speaks text; binary is not ours */
            if (!discard && !msg_append(r, body, (size_t)plen)) return WS_ERROR;
            if (!fin) {
                r->msg_open = true;
                r->msg_discard = discard;
                continue;
            }
            if (discard) continue;
            return msg_yield(r, payload, len);
        }
        default:
            return WS_ERROR; /* an opcode this protocol does not define */
        }
    }
}
