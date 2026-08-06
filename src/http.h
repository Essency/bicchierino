/* http.h — the one HTTPS call bicchierino ever makes: POST /auth/login.
 *
 * Not a general HTTP client. WIRE.md §2.5: after login, a session never
 * makes another HTTP request — everything else is a push on the already-
 * open websocket. So this only needs to do one thing, blocking, once per
 * connection thread (CLAUDE.md §3: that's exactly why connections are
 * threads, not multiplexed on one poll() loop).
 */
#ifndef BICCHIERINO_HTTP_H
#define BICCHIERINO_HTTP_H

#include <stdbool.h>
#include <stddef.h>

struct http_response {
    int status;
    char *body; /* heap-allocated, NUL-terminated; owned by the caller */
    size_t body_len;
};

/* Blocking HTTPS POST of `json_body` to `<grappa_url>/auth/login`.
 * `grappa_url` must start with "https://" — TLS to grappa is mandatory,
 * never optional (ARCHITECTURE.md's "OpenSSL, two distinct roles").
 *
 * Returns true when an HTTP exchange actually completed — the caller
 * checks `out->status`, 401 is a normal, expected outcome here, not a
 * transport failure. Returns false only when grappa could not be reached
 * at all (DNS, connect, TLS handshake, malformed response) — this is
 * CLAUDE.md §3.3's "grappa not reachable" case, not a credentials one. */
bool https_post_login(const char *grappa_url, const char *json_body, struct http_response *out);

void http_response_free(struct http_response *resp);

#endif /* BICCHIERINO_HTTP_H */
