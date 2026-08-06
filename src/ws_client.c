#include "ws_client.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp — POSIX, but not implicitly pulled in by string.h */
#include <unistd.h>

#include "http.h"

/* Hand-rolled instead of the GNU extension `memmem`: not declared under
 * strict POSIX feature-test macros everywhere, and portability to BSD
 * (CLAUDE.md's own reason for `poll()` over `epoll`) is exactly the kind
 * of thing worth not gambling on for five lines of code. */
static const void *buf_find(const void *haystack, size_t haystack_len, const void *needle,
                             size_t needle_len) {
    if (needle_len == 0 || needle_len > haystack_len) return NULL;
    const unsigned char *h = haystack;
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        if (memcmp(h + i, needle, needle_len) == 0) return h + i;
    }
    return NULL;
}

#define WS_HANDSHAKE_MAX 4096
#define WS_MAGIC_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" /* RFC 6455 §1.3, fixed */

/* Standard base64 (RFC 4648 §4 — `+`/`/`, WITH padding). Used for the
 * RFC 6455 handshake's own Sec-WebSocket-Key/-Accept, which the RFC
 * itself specifies in exactly this alphabet — unrelated to the
 * Phoenix-specific encoding below, and not to be confused with it. */
static char *base64_encode(const unsigned char *buf, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3) + 1;
    char *out = malloc(out_len);
    if (!out) return NULL;
    int n = EVP_EncodeBlock((unsigned char *)out, buf, (int)len);
    out[n] = '\0';
    return out;
}

/* The auth-token encoding Phoenix's own websocket transport expects —
 * verified directly against lib/phoenix/transports/websocket.ex at the
 * exact tag grappa's mix.lock pins (v1.8.9), not assumed: despite the
 * `@auth_token_prefix "base64url.bearer.phx."` constant's name, the
 * decode side is `Base.decode64!(encoded_token, padding: false)` —
 * STANDARD base64 (`+`/`/`), not the URL-safe alphabet, just with
 * padding stripped. (shottino's own client encodes this with the true
 * base64url alphabet — `-`/`_` — which appears to be a latent mismatch
 * that happens not to manifest for grappa's particular token shape,
 * not a second confirmed-correct convention. Not followed here.) */
static char *base64_nopad_encode(const unsigned char *buf, size_t len) {
    char *out = base64_encode(buf, len);
    if (!out) return NULL;
    char *pad = strchr(out, '=');
    if (pad) *pad = '\0';
    return out;
}

static bool parse_upgrade_response(const char *response, size_t response_len,
                                    const char *expected_accept, size_t *header_len_out) {
    if (strncmp(response, "HTTP/1.1 101", 12) != 0) return false;

    const unsigned char *sep = buf_find(response, response_len, "\r\n\r\n", 4);
    if (!sep) return false;
    *header_len_out = (size_t)((const char *)sep - response) + 4;

    /* Sec-WebSocket-Accept is case-insensitive by header-name convention
     * but its VALUE must match byte-for-byte (RFC 6455 §4.2.2 step 5.4) —
     * find the header line, then compare the value exactly. */
    const char *needle = "Sec-WebSocket-Accept:";
    const char *pos = response;
    const char *header_end = response + *header_len_out;
    while (pos < header_end) {
        if (strncasecmp(pos, needle, strlen(needle)) == 0) {
            const char *val = pos + strlen(needle);
            while (*val == ' ') val++;
            size_t expected_len = strlen(expected_accept);
            return strncmp(val, expected_accept, expected_len) == 0 &&
                   (val[expected_len] == '\r' || val[expected_len] == '\n');
        }
        const char *nl = memchr(pos, '\n', (size_t)(header_end - pos));
        if (!nl) break;
        pos = nl + 1;
    }
    return false;
}

bool ws_client_connect(const char *grappa_url, const char *bearer_token, struct ws_client *out) {
    memset(out, 0, sizeof(*out));

    char host[256];
    if (!https_tls_connect(grappa_url, &out->ctx, &out->ssl, &out->fd, host, sizeof(host)))
        return false;

    unsigned char key_bytes[16];
    RAND_bytes(key_bytes, sizeof(key_bytes));
    char *ws_key = base64_encode(key_bytes, sizeof(key_bytes));
    if (!ws_key) {
        ws_client_close(out);
        return false;
    }

    char *token_b64 = base64_nopad_encode((const unsigned char *)bearer_token,
                                           strlen(bearer_token));
    if (!token_b64) {
        free(ws_key);
        ws_client_close(out);
        return false;
    }

    /* Expected Sec-WebSocket-Accept, computed now so it's ready the
     * moment the response headers are in (RFC 6455 §4.2.2 step 5.4):
     * base64(SHA1(key + magic GUID)). */
    char accept_input[128];
    snprintf(accept_input, sizeof(accept_input), "%s%s", ws_key, WS_MAGIC_GUID);
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)accept_input, strlen(accept_input), sha1);
    char *expected_accept = base64_encode(sha1, sizeof(sha1));

    bool ok = ws_key && token_b64 && expected_accept;

    if (ok) {
        char request[WS_HANDSHAKE_MAX];
        int req_len = snprintf(request, sizeof(request),
                                "GET /socket/websocket HTTP/1.1\r\n"
                                "Host: %s\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Key: %s\r\n"
                                "Sec-WebSocket-Version: 13\r\n"
                                "Sec-WebSocket-Protocol: base64url.bearer.phx.%s\r\n"
                                "\r\n",
                                host, ws_key, token_b64);
        ok = req_len > 0 && (size_t)req_len < sizeof(request) &&
             SSL_write(out->ssl, request, req_len) > 0;
    }

    free(ws_key);
    free(token_b64);

    char response[WS_HANDSHAKE_MAX];
    size_t response_len = 0;
    size_t header_len = 0;

    if (ok) {
        /* Read until the header terminator shows up. A real handshake
         * response is a few hundred bytes — this bounds it generously
         * without needing a growable buffer, unlike http.c's response
         * reader (which has to handle an arbitrary JSON body; this
         * doesn't). */
        for (;;) {
            if (response_len >= sizeof(response) - 1) {
                ok = false;
                break;
            }
            int n = SSL_read(out->ssl, response + response_len,
                              (int)(sizeof(response) - 1 - response_len));
            if (n <= 0) {
                ok = false;
                break;
            }
            response_len += (size_t)n;
            response[response_len] = '\0';
            if (buf_find(response, response_len, "\r\n\r\n", 4)) break;
        }
    }

    if (ok)
        ok = parse_upgrade_response(response, response_len, expected_accept, &header_len);

    free(expected_accept);

    if (!ok) {
        ws_client_close(out);
        return false;
    }

    ws_reader_init(&out->reader);
    /* Bytes past the header terminator are already websocket frames —
     * TCP has no message boundaries, the peer's first frame(s) may have
     * arrived in the same segment as the 101 response. Feed them in
     * rather than discard them. */
    if (response_len > header_len) {
        if (!ws_reader_feed(&out->reader, response + header_len, response_len - header_len)) {
            ws_client_close(out);
            return false;
        }
    }

    return true;
}

bool ws_client_send_text(struct ws_client *wsc, const char *text) {
    size_t len = strlen(text);

    unsigned char header[14];
    size_t header_len = 0;
    header[header_len++] = 0x81; /* FIN=1, opcode=0x1 (text) */

    const unsigned char mask_bit = 0x80;
    if (len < 126) {
        header[header_len++] = mask_bit | (unsigned char)len;
    } else if (len <= 0xFFFF) {
        header[header_len++] = mask_bit | 126;
        header[header_len++] = (unsigned char)((len >> 8) & 0xFF);
        header[header_len++] = (unsigned char)(len & 0xFF);
    } else {
        header[header_len++] = mask_bit | 127;
        for (int i = 7; i >= 0; i--)
            header[header_len++] = (unsigned char)((len >> (i * 8)) & 0xFF);
    }

    unsigned char mask_key[4];
    RAND_bytes(mask_key, sizeof(mask_key));
    memcpy(header + header_len, mask_key, sizeof(mask_key));
    header_len += sizeof(mask_key);

    if (SSL_write(wsc->ssl, header, (int)header_len) <= 0) return false;

    /* RFC 6455 §5.3: every client-to-server frame MUST be masked —
     * this is the one thing ws.c (receive-side, server frames are never
     * masked) never had to do, so it's the one thing bicchierino writes
     * itself rather than reusing the vendored code for. */
    unsigned char *masked = malloc(len);
    if (!masked) return false;
    for (size_t i = 0; i < len; i++)
        masked[i] = ((unsigned char)text[i]) ^ mask_key[i % sizeof(mask_key)];
    bool ok = len == 0 || SSL_write(wsc->ssl, masked, (int)len) > 0;
    free(masked);
    return ok;
}

ws_result ws_client_recv(struct ws_client *wsc, char **payload, size_t *len) {
    ws_result r = ws_reader_take(&wsc->reader, payload, len);
    if (r != WS_NEED_MORE) return r;

    unsigned char chunk[4096];
    int n = SSL_read(wsc->ssl, chunk, sizeof(chunk));
    if (n == 0) return WS_CLOSED;
    if (n < 0) return WS_ERROR;
    if (!ws_reader_feed(&wsc->reader, chunk, (size_t)n)) return WS_ERROR;

    return ws_reader_take(&wsc->reader, payload, len);
}

void ws_client_close(struct ws_client *wsc) {
    ws_reader_free(&wsc->reader);
    if (wsc->ssl) {
        SSL_shutdown(wsc->ssl);
        SSL_free(wsc->ssl);
    }
    if (wsc->ctx) SSL_CTX_free(wsc->ctx);
    if (wsc->fd >= 0) close(wsc->fd);
    memset(wsc, 0, sizeof(*wsc));
}
