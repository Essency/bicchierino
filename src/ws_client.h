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
 * didn't verify. This is "grappa not reachable" territory, same as
 * every other connect failure in this codebase: the caller reports
 * `ERROR :...` to the downstream client and closes, never retries
 * internally. */
bool ws_client_connect(const char *grappa_url, const char *bearer_token, struct ws_client *out);

/* Encodes and sends `text` as a single masked text frame (RFC 6455
 * §5.2, §5.3). Not chunked — every message this codebase sends
 * (phx_join, pushes) is small JSON, never worth fragmenting. */
bool ws_client_send_text(struct ws_client *wsc, const char *text);

/* Encodes and sends `payload`/`len` as a single masked PONG frame (RFC
 * 6455 §5.5.2/§5.3) — the required reply to a WS_PING the reader
 * surfaced. `payload` must be echoed byte-for-byte from the PING that
 * prompted it (the RFC's own requirement), so this takes an explicit
 * length rather than assuming a NUL-terminated C string the way
 * `ws_client_send_text` does. */
bool ws_client_send_pong(struct ws_client *wsc, const char *payload, size_t len);

/* First tries a pure buffer peek (never touches the network); only if
 * that yields WS_NEED_MORE does this fall through to one blocking
 * SSL_read, fed into the reader, then one more peek. Meant to be called
 * ONCE per poll()-reported-readable wakeup on the fd — that first
 * network read is safe to block on (poll() promised data is coming),
 * but a caller wanting to drain several already-buffered frames from
 * the same wakeup should re-peek the reader directly rather than call
 * this again, which could trigger a second SSL_read poll() never
 * promised would return promptly. Does NOT answer PING with PONG
 * automatically — the reader surfaces WS_PING, left for the caller
 * (`connection.c`'s Phase 2 drain loop calls `ws_client_send_pong`
 * itself the moment it sees one). */
ws_result ws_client_recv(struct ws_client *wsc, char **payload, size_t *len);

void ws_client_close(struct ws_client *wsc);

#endif /* BICCHIERINO_WS_CLIENT_H */
