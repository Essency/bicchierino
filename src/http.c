#include "http.h"

#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp — HTTP header names are case-insensitive */
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define GRAPPA_URL_PREFIX "https://"
/* Timeout for the initial TCP connect() — bounds how long we wait if
 * grappa's host is unreachable or blackholes SYNs. */
#define HTTP_CONNECT_TIMEOUT_SEC 30
/* Timeout for all subsequent I/O (SSL_read / SSL_write) on a connected
 * socket — ensures an unresponsive server can't park the thread forever
 * in SSL_read.  A timed-out read returns an error and the caller's
 * existing reconnect-and-retry path handles it cleanly. */
#define HTTP_IO_TIMEOUT_SEC 30
#define HTTP_READ_CHUNK 4096
#define HTTP_REQUEST_MAX 8192
#define HTTP_HEADER_MAX 8192 /* grappa's own response headers are a few
                               * hundred bytes at most; generous bound,
                               * not a real limit */
#define HTTP_MAX_RESPONSE (4 * 1024 * 1024) /* any of bicchierino's own
                                              * responses are a few KB at
                                              * most; this is a
                                              * hostile-server backstop,
                                              * not a real limit */

struct parsed_url {
    char host[256];
    char port[8];
};

/* grappa_url is config, not attacker input, but the parse still fails
 * closed on anything unexpected — a malformed config should error out
 * loudly (CLAUDE.md's own "no silent-swallow" spirit), not connect to
 * whatever str[8..] happened to contain. */
static bool parse_grappa_url(const char *url, struct parsed_url *out) {
    size_t prefix_len = strlen(GRAPPA_URL_PREFIX);
    if (strncmp(url, GRAPPA_URL_PREFIX, prefix_len) != 0) return false;
    const char *rest = url + prefix_len;
    if (*rest == '\0') return false;

    const char *colon = strchr(rest, ':');
    const char *slash = strchr(rest, '/');
    const char *host_end = slash && (!colon || slash < colon) ? slash : colon;
    if (!host_end) host_end = rest + strlen(rest);

    size_t host_len = (size_t)(host_end - rest);
    if (host_len == 0 || host_len >= sizeof(out->host)) return false;
    memcpy(out->host, rest, host_len);
    out->host[host_len] = '\0';

    if (colon && (!slash || colon < slash)) {
        const char *port_start = colon + 1;
        const char *port_end = slash ? slash : port_start + strlen(port_start);
        size_t port_len = (size_t)(port_end - port_start);
        if (port_len == 0 || port_len >= sizeof(out->port)) return false;
        memcpy(out->port, port_start, port_len);
        out->port[port_len] = '\0';
    } else {
        snprintf(out->port, sizeof(out->port), "443");
    }

    return true;
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        /* Bound the connect() call — without this, a host that blackholes
         * SYNs stalls here for the kernel's full TCP connect timeout
         * (~130 s on Linux) while the IRC client waits for its 001. */
        struct timeval connect_tv = { .tv_sec = HTTP_CONNECT_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &connect_tv, sizeof(connect_tv));
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* TLS connect + verify (chain of trust + hostname — ARCHITECTURE.md's
 * "OpenSSL, two distinct roles" client role, never skipped). Shared by
 * every caller in this file, and by ws_client.c via https_tls_connect
 * below — the persistent websocket connection needs the exact same
 * verification posture as a one-shot REST call, only what happens to
 * the connection afterwards differs. On success the caller owns
 * *ssl_out, *ctx_out and *fd_out, and must tear all three down. */
static bool tls_connect(const struct parsed_url *pu, SSL_CTX **ctx_out, SSL **ssl_out,
                         int *fd_out) {
    int fd = tcp_connect(pu->host, pu->port);
    if (fd < 0) return false;

    /* Override the connect-phase SO_SNDTIMEO with the I/O timeout and
     * also arm SO_RCVTIMEO — from this point on any SSL_read or
     * SSL_write that blocks past HTTP_IO_TIMEOUT_SEC returns an error
     * rather than parking the thread forever.  Both paths through this
     * function (http_client_connect for REST, https_tls_connect for the
     * WebSocket leg) need this: an unresponsive grappa must not pin the
     * connection thread indefinitely regardless of how it was opened. */
    struct timeval io_tv = { .tv_sec = HTTP_IO_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &io_tv, sizeof(io_tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &io_tv, sizeof(io_tv));

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        close(fd);
        return false;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(ctx);
    /* TLS 1.2 minimum — matches what any grappa deployment worth talking
     * to will negotiate anyway, and refuses to silently downgrade. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        close(fd);
        return false;
    }

    /* Both SNI (which server sends its cert) and hostname verification
     * (which cert we'll accept) need the hostname — they are not the
     * same OpenSSL call and it's easy to set one and forget the other. */
    SSL_set_tlsext_host_name(ssl, pu->host);
    SSL_set1_host(ssl, pu->host);
    SSL_set_fd(ssl, fd);

    if (SSL_connect(ssl) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return false;
    }

    *ctx_out = ctx;
    *ssl_out = ssl;
    *fd_out = fd;
    return true;
}

bool https_tls_connect(const char *grappa_url, SSL_CTX **ctx_out, SSL **ssl_out, int *fd_out,
                        char *host_out, size_t host_out_sz) {
    struct parsed_url pu;
    if (!parse_grappa_url(grappa_url, &pu)) return false;
    if (host_out && host_out_sz > 0) snprintf(host_out, host_out_sz, "%s", pu.host);
    return tls_connect(&pu, ctx_out, ssl_out, fd_out);
}

/* Growing buffer, same shape as connection.c's line reader: a read() call
 * is not a message, keep appending until the peer closes. */
struct growbuf {
    char *data;
    size_t len;
    size_t cap;
};

static bool growbuf_append(struct growbuf *gb, const char *bytes, size_t n) {
    if (gb->len + n > HTTP_MAX_RESPONSE) return false;
    if (gb->len + n > gb->cap) {
        size_t new_cap = gb->cap ? gb->cap * 2 : HTTP_READ_CHUNK;
        while (new_cap < gb->len + n) new_cap *= 2;
        char *grown = realloc(gb->data, new_cap);
        if (!grown) return false;
        gb->data = grown;
        gb->cap = new_cap;
    }
    memcpy(gb->data + gb->len, bytes, n);
    gb->len += n;
    return true;
}

static bool parse_status_line(const char *response, int *status) {
    /* "HTTP/1.1 200 OK\r\n..." — only the numeric code matters here. */
    const char *sp = strchr(response, ' ');
    if (!sp) return false;
    *status = atoi(sp + 1);
    return *status >= 100 && *status < 600;
}

void http_client_init(struct http_client *hc) { memset(hc, 0, sizeof(*hc)); }

static void http_client_disconnect(struct http_client *hc) {
    if (!hc->connected) return;
    SSL_shutdown(hc->ssl);
    SSL_free(hc->ssl);
    SSL_CTX_free(hc->ctx);
    close(hc->fd);
    hc->ssl = NULL;
    hc->ctx = NULL;
    hc->fd = -1;
    hc->connected = false;
}

void http_client_close(struct http_client *hc) { http_client_disconnect(hc); }

static bool http_client_connect(struct http_client *hc, const char *grappa_url) {
    if (hc->connected) return true;
    struct parsed_url pu;
    if (!parse_grappa_url(grappa_url, &pu)) return false;
    snprintf(hc->host, sizeof(hc->host), "%s", pu.host);
    if (!tls_connect(&pu, &hc->ctx, &hc->ssl, &hc->fd)) return false;
    hc->connected = true;
    /* One line per ACTUAL new TCP+TLS handshake — the whole point of
     * this file is that this should fire once per connection's life,
     * not once per REST call. Cheap ops signal for exactly that. */
    fprintf(stderr, "bicchierino: http: new keep-alive connection to %s\n", hc->host);
    return true;
}

/* Case-insensitive header lookup within the raw, not-yet-split header
 * block (`headers[0..header_len)`, no NUL assumed past it). HTTP header
 * names are case-insensitive by spec; grappa's own server may spell it
 * either way depending on framework version. */
static bool find_content_length(const char *headers, size_t header_len, long *out) {
    static const char needle[] = "Content-Length:";
    size_t needle_len = sizeof(needle) - 1;
    const char *pos = headers;
    const char *end = headers + header_len;
    while (pos < end) {
        if ((size_t)(end - pos) >= needle_len && strncasecmp(pos, needle, needle_len) == 0) {
            const char *val = pos + needle_len;
            while (val < end && *val == ' ') val++;
            *out = atol(val);
            return true;
        }
        const char *nl = memchr(pos, '\n', (size_t)(end - pos));
        if (!nl) break;
        pos = nl + 1;
    }
    return false;
}

/* One request/response over an already-connected `hc` — no reconnect
 * logic here, that's http_client_request()'s job. Reads the header
 * block bounded (same read-until-terminator shape as ws_client.c's
 * handshake reader — headers are always small and arrive in one or two
 * TCP segments), then reads exactly Content-Length body bytes: unlike
 * the old one-shot-connection model, this can NOT just "read until the
 * peer closes" — the whole point is that the peer does NOT close, the
 * connection outlives this one exchange. A 204 (DELETE /auth/logout)
 * is the one case allowed an absent Content-Length — RFC 7230 says a
 * 204 carries no body regardless. Any other status without
 * Content-Length is a hard failure: grappa's JSON responses are always
 * fully-buffered, so a real one always sets it, and a persistent
 * connection can't safely guess. */
static bool http_client_exchange_once(struct http_client *hc, const char *request,
                                       size_t request_len, struct http_response *out) {
    if (SSL_write(hc->ssl, request, (int)request_len) <= 0) return false;

    char header_buf[HTTP_HEADER_MAX];
    size_t header_len = 0;
    const char *sep = NULL;
    for (;;) {
        if (header_len >= sizeof(header_buf) - 1) return false;
        int n = SSL_read(hc->ssl, header_buf + header_len,
                          (int)(sizeof(header_buf) - 1 - header_len));
        if (n <= 0) return false;
        header_len += (size_t)n;
        header_buf[header_len] = '\0';
        sep = strstr(header_buf, "\r\n\r\n");
        if (sep) break;
    }
    size_t headers_end = (size_t)(sep - header_buf) + 4;

    int status;
    if (!parse_status_line(header_buf, &status)) return false;

    long content_length = 0;
    bool have_cl = find_content_length(header_buf, headers_end, &content_length);
    if (!have_cl) {
        if (status != 204) return false;
    } else if (content_length < 0) {
        return false;
    }

    /* Body: whatever came bundled past the header terminator in the
     * SAME reads (TCP/TLS records don't respect our header/body split
     * any more than they respect message boundaries elsewhere in this
     * codebase), plus more SSL_read calls until content_length bytes
     * are in hand. */
    struct growbuf body = {0};
    size_t already = header_len - headers_end;
    if (already > 0 && !growbuf_append(&body, header_buf + headers_end, already)) return false;
    while (body.len < (size_t)content_length) {
        char chunk[HTTP_READ_CHUNK];
        size_t want = (size_t)content_length - body.len;
        int n = SSL_read(hc->ssl, chunk, (int)(want < sizeof(chunk) ? want : sizeof(chunk)));
        if (n <= 0) {
            free(body.data);
            return false;
        }
        if (!growbuf_append(&body, chunk, (size_t)n)) {
            free(body.data);
            return false;
        }
    }

    out->status = status;
    out->body = malloc(body.len + 1);
    if (!out->body) {
        free(body.data);
        return false;
    }
    memcpy(out->body, body.data, body.len);
    out->body[body.len] = '\0';
    out->body_len = body.len;
    free(body.data);
    return true;
}

bool http_client_request(struct http_client *hc, const char *grappa_url, const char *method,
                          const char *path, const char *bearer_token, const char *json_body,
                          struct http_response *out) {
    memset(out, 0, sizeof(*out));

    struct parsed_url pu;
    if (!parse_grappa_url(grappa_url, &pu)) return false;

    /* No `Connection: close` — the entire point of this file is that
     * the connection is NOT torn down after one exchange. HTTP/1.1
     * defaults to keep-alive; omitting the header is enough. */
    char request[HTTP_REQUEST_MAX];
    int req_len;
    if (json_body) {
        req_len = snprintf(request, sizeof(request),
                            "%s %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "%s%s%s"
                            "Content-Type: application/json\r\n"
                            "Content-Length: %zu\r\n"
                            "\r\n"
                            "%s",
                            method, path, pu.host, bearer_token ? "Authorization: Bearer " : "",
                            bearer_token ? bearer_token : "", bearer_token ? "\r\n" : "",
                            strlen(json_body), json_body);
    } else {
        req_len = snprintf(request, sizeof(request),
                            "%s %s HTTP/1.1\r\n"
                            "Host: %s\r\n"
                            "%s%s%s"
                            "\r\n",
                            method, path, pu.host, bearer_token ? "Authorization: Bearer " : "",
                            bearer_token ? bearer_token : "", bearer_token ? "\r\n" : "");
    }
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) return false;

    if (!http_client_connect(hc, grappa_url)) return false;

    if (http_client_exchange_once(hc, request, (size_t)req_len, out)) return true;

    /* The pooled connection may simply have gone stale — a server-side
     * keep-alive idle timeout racing with reuse is routine for
     * HTTP/1.1, not a hostile-input case. Reconnect fresh and retry
     * exactly once before reporting grappa unreachable. */
    http_client_disconnect(hc);
    http_response_free(out);
    if (!http_client_connect(hc, grappa_url)) return false;
    return http_client_exchange_once(hc, request, (size_t)req_len, out);
}

void http_response_free(struct http_response *resp) {
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
