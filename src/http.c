#include "http.h"

#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define GRAPPA_URL_PREFIX "https://"
#define HTTP_READ_CHUNK 4096
#define HTTP_MAX_RESPONSE (4 * 1024 * 1024) /* a login response is a few
                                              * hundred bytes; this is a
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
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
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

bool https_post_login(const char *grappa_url, const char *json_body, struct http_response *out) {
    memset(out, 0, sizeof(*out));

    struct parsed_url pu;
    if (!parse_grappa_url(grappa_url, &pu)) return false;

    int fd = tcp_connect(pu.host, pu.port);
    if (fd < 0) return false;

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
    SSL_set_tlsext_host_name(ssl, pu.host);
    SSL_set1_host(ssl, pu.host);
    SSL_set_fd(ssl, fd);

    bool ok = true;
    if (SSL_connect(ssl) != 1) ok = false;

    struct growbuf response = {0};

    if (ok) {
        char request[HTTP_READ_CHUNK];
        int req_len = snprintf(request, sizeof(request),
                                "POST /auth/login HTTP/1.1\r\n"
                                "Host: %s\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "Connection: close\r\n"
                                "\r\n"
                                "%s",
                                pu.host, strlen(json_body), json_body);
        if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
            ok = false;
        } else if (SSL_write(ssl, request, req_len) <= 0) {
            ok = false;
        }
    }

    if (ok) {
        char chunk[HTTP_READ_CHUNK];
        for (;;) {
            int n = SSL_read(ssl, chunk, sizeof(chunk));
            if (n <= 0) break; /* clean close (Connection: close) or error;
                                 * either way, response is done or unusable */
            if (!growbuf_append(&response, chunk, (size_t)n)) {
                ok = false;
                break;
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);

    if (!ok || response.len == 0) {
        free(response.data);
        return false;
    }

    /* NUL-terminate so string functions below can work on it directly —
     * the body may legitimately contain no embedded NULs (it's grappa's
     * own JSON, per WIRE.md's own contract that this wire is text). */
    if (!growbuf_append(&response, "", 1)) {
        free(response.data);
        return false;
    }

    char *sep = strstr(response.data, "\r\n\r\n");
    if (!sep) {
        free(response.data);
        return false;
    }

    if (!parse_status_line(response.data, &out->status)) {
        free(response.data);
        return false;
    }

    const char *body_start = sep + 4;
    size_t body_len = response.len - 1 - (size_t)(body_start - response.data);
    out->body = malloc(body_len + 1);
    if (!out->body) {
        free(response.data);
        return false;
    }
    memcpy(out->body, body_start, body_len);
    out->body[body_len] = '\0';
    out->body_len = body_len;

    free(response.data);
    return true;
}

void http_response_free(struct http_response *resp) {
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
