/* http.h — one persistent HTTP/1.1 (keep-alive) client per bicchierino
 * connection, reused for every REST call grappa needs: login, the
 * bootstrap discovery GETs (WIRE.md §1.5), sending a PRIVMSG (WIRE.md
 * §2.5's corrected text — this is REST, not a websocket push), and the
 * final logout DELETE.
 *
 * NOT one-shot-connection-per-call (an earlier version of this file was)
 * — flagged live as a real cost: a fresh TCP+TLS handshake per outbound
 * chat line is 2-3 network round trips paid on every single PRIVMSG,
 * the one REST call that happens far more than once per connection.
 * cicchetto (the browser client) never pays this because the browser's
 * own HTTP stack keeps the connection open across requests by default —
 * this is bicchierino doing the same thing explicitly, since nothing
 * does it for a hand-rolled C client. One `struct http_client` opened
 * lazily on first use and kept alive for the whole IRC connection's
 * life, torn down only at final cleanup.
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

struct http_client {
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
    bool connected;
    char host[256];
};

/* Zeroes `hc` — not yet connected. Connecting is lazy, on the first
 * http_client_request() call, same as every other "open on first use"
 * resource in this codebase (config validated once, connected once). */
void http_client_init(struct http_client *hc);

/* Sends one request over `hc`'s persistent connection — reconnects
 * (once, transparently) if not yet connected, or if the pooled
 * connection turned out stale (a server-side keep-alive idle timeout
 * racing with reuse is routine for HTTP/1.1, not a hostile-input case:
 * every real keep-alive client retries exactly like this). `method` is
 * a literal like `"GET"`/`"POST"`/`"DELETE"`. `bearer_token` and
 * `json_body` may be NULL — no `Authorization` header / no body,
 * respectively (the one bearer-less call is `/auth/login` itself).
 *
 * Same return-value contract every call in this codebase already used:
 * true when an HTTP exchange actually completed (the caller checks
 * `out->status` — 401/404/429/etc. are normal outcomes here, not
 * transport failures); false only when grappa could not be reached at
 * all even after the one retry — the "grappa not reachable" case,
 * reported to the downstream client and never retried internally. */
bool http_client_request(struct http_client *hc, const char *grappa_url, const char *method,
                          const char *path, const char *bearer_token, const char *json_body,
                          struct http_response *out);

/* Tears down the persistent connection — call once, at the IRC
 * connection's own teardown (`cleanup:`), not between individual REST
 * calls (that would defeat the entire point of this file). */
void http_client_close(struct http_client *hc);

/* Opens a verified TLS connection (same posture as every REST call
 * above — chain of trust + hostname, never skipped) to `<grappa_url>`'s
 * host:port and leaves it OPEN — for ws_client.c: the websocket
 * connection is persistent too (WIRE.md §2), but speaks WS framing, not
 * HTTP/1.1 keep-alive, so it needs the bare TLS setup, not
 * http_client_request's request/response machinery. Caller owns
 * *ssl_out, *ctx_out and *fd_out, and must tear down all three
 * (SSL_shutdown, SSL_free, SSL_CTX_free, close) when done.
 *
 * `host_out` receives the parsed hostname (NUL-terminated, truncated to
 * `host_out_sz` in the pathological case) — a caller building its own
 * request needs it for the `Host:` header, and this is the one place
 * the URL is parsed, not duplicated per caller. */
bool https_tls_connect(const char *grappa_url, SSL_CTX **ctx_out, SSL **ssl_out, int *fd_out,
                        char *host_out, size_t host_out_sz);

void http_response_free(struct http_response *resp);

#endif /* BICCHIERINO_HTTP_H */
