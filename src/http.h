/* http.h — the small, fixed set of HTTPS calls bicchierino ever makes:
 * login, the bootstrap discovery GETs (WIRE.md §1.5), and logout.
 *
 * Not a general HTTP client. WIRE.md §2.5: once bootstrap is done, a
 * session never makes another HTTP request — everything else is a push
 * on the already-open websocket. Every call here is blocking, one-shot,
 * no connection reuse between them — that's fine precisely because none
 * of this repeats within a session (CLAUDE.md §3: it's also why
 * connections are threads, not multiplexed on one poll() loop — a
 * blocking call here only ever stalls its own connection).
 */
#ifndef BICCHIERINO_HTTP_H
#define BICCHIERINO_HTTP_H

#include <openssl/ssl.h>
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

/* Blocking authenticated HTTPS GET of `<grappa_url><path>`, bearer auth.
 * Same return-value contract as https_post_login. Used for the
 * post-login bootstrap discovery calls (WIRE.md §1.5): GET /networks and
 * GET /networks/:slug/channels — both blocking, both one-shot, no
 * connection reuse between them (WIRE.md §2.5: nothing here is frequent
 * enough to need it). */
bool https_get_bearer(const char *grappa_url, const char *path, const char *bearer_token,
                       struct http_response *out);

/* Blocking authenticated HTTPS DELETE of `<grappa_url><path>`, bearer
 * auth. Same return-value contract as https_post_login. Used for
 * `DELETE /auth/logout` when the downstream client goes away — revokes
 * bicchierino's own token. Confirmed safe for a registered-user session
 * (WIRE.md, auth_controller.ex's own #126 comment): this detaches, it
 * does NOT tear down the real upstream IRC connection — that lives in
 * grappa's own Session.Server, keyed by (user, network), independent of
 * any WS client. Best-effort by the caller: nothing meaningful to do if
 * this fails, the connection is already tearing down either way. */
bool https_delete_bearer(const char *grappa_url, const char *path, const char *bearer_token,
                          struct http_response *out);

/* Opens a verified TLS connection (same posture as every call above —
 * chain of trust + hostname, never skipped) to `<grappa_url>`'s host:port
 * and leaves it OPEN — unlike every function above, which owns the whole
 * request/response exchange and tears the connection down before
 * returning. For ws_client.c: the websocket connection is persistent
 * (WIRE.md §2), so it needs the TLS setup without the one-shot
 * request/close lifecycle. Caller owns *ssl_out, *ctx_out and *fd_out,
 * and must tear down all three (SSL_shutdown, SSL_free, SSL_CTX_free,
 * close) when done.
 *
 * `host_out` receives the parsed hostname (NUL-terminated, truncated to
 * `host_out_sz` in the pathological case) — a caller building its own
 * request needs it for the `Host:` header, and this is the one place
 * the URL is parsed, not duplicated per caller. */
bool https_tls_connect(const char *grappa_url, SSL_CTX **ctx_out, SSL **ssl_out, int *fd_out,
                        char *host_out, size_t host_out_sz);

void http_response_free(struct http_response *resp);

#endif /* BICCHIERINO_HTTP_H */
