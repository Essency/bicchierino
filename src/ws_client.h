/* ws_client.h — the persistent websocket connection to grappa.
 *
 * Owns the HTTP Upgrade handshake (RFC 6455 §4) and the connection's
 * whole lifetime after that — unlike http.c's one-shot exchanges, this
 * stays open for as long as the bridge does (WIRE.md §2-5).
 *
 * Reuses the vendored ws.c/ws.h for RECEIVE-side frame parsing
 * (ws_reader — buffer, don't assume a read is a message). ws.c has no
 * send side at all (shottino never needed one on this leg the same
 * way — it's a receive-focused reader by its own header's admission),
 * so the client-to-server direction — which RFC 6455 §5.3 requires to
 * be MASKED, unlike server frames — is this file's own, small addition.
 */
#ifndef BICCHIERINO_WS_CLIENT_H
#define BICCHIERINO_WS_CLIENT_H

#include <openssl/ssl.h>
#include <stdbool.h>
#include <stddef.h>

#include "ws.h"

struct ws_client {
    int fd;
    SSL_CTX *ctx;
    SSL *ssl;
    struct ws_reader reader;
};

/* Performs the full handshake: TLS connect (https_tls_connect, same
 * verification posture as every REST call), HTTP Upgrade request with
 * the bearer riding Sec-WebSocket-Protocol as
 * `base64url.bearer.phx.<token>` (WIRE.md §2 — NOT the query string,
 * that path is gone server-side), verifies the `101 Switching
 * Protocols` response and its Sec-WebSocket-Accept per RFC 6455 §4.2.2.
 * Any websocket frame bytes that arrived packed into the same TCP
 * segment as the HTTP response (a real possibility, TCP has no message
 * boundaries) are fed into the reader before this returns, not
 * discarded.
 *
 * Returns false on any failure — TLS, HTTP-level, or a handshake that
 * didn't verify. CLAUDE.md §3.3's "grappa not reachable" territory,
 * same as every other connect failure in this codebase. */
bool ws_client_connect(const char *grappa_url, const char *bearer_token, struct ws_client *out);

/* Encodes and sends `text` as a single masked text frame (RFC 6455
 * §5.2, §5.3). Not chunked — every message this codebase sends
 * (phx_join, pushes) is small JSON, never worth fragmenting. */
bool ws_client_send_text(struct ws_client *wsc, const char *text);

/* One blocking SSL_read, fed into the reader, then one ws_reader_take.
 * Meant to be called after poll() reports the fd readable — a single
 * call may or may not yield a complete message (TCP framing, again),
 * so the caller loops on WS_NEED_MORE at the poll() level, not by
 * spinning here. Answers a PING with a PONG internally (the reader
 * surfaces WS_PING so the caller COULD, but grappa doesn't need
 * anything else observed about it, and answering here means every
 * caller gets it right instead of every caller having to remember). */
ws_result ws_client_recv(struct ws_client *wsc, char **payload, size_t *len);

void ws_client_close(struct ws_client *wsc);

#endif /* BICCHIERINO_WS_CLIENT_H */
