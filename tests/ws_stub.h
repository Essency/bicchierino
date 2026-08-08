/* ws_stub.h — test-side control surface for the fake websocket peer.
 * See ws_stub.c. */
#ifndef BICCHIERINO_WS_STUB_H
#define BICCHIERINO_WS_STUB_H

#include <stddef.h>

#include "../src/ws_client.h"

/* Drops every queued and recorded frame. Call at the top of each TEST —
 * a suite that shares state between cases reports the previous case's
 * frames as this one's. */
void ws_stub_reset(void);

/* Queues one frame for ws_client_recv to return, in call order.
 * `payload` may be NULL for the results that carry none. */
void ws_stub_queue(ws_result result, const char *payload);

/* What bridge.c sent, in order. */
size_t ws_stub_sent_count(void);
const char *ws_stub_sent(size_t i);

/* Queued-but-not-yet-consumed frames — lets a test assert that a join
 * stopped reading when it found its answer instead of draining. */
size_t ws_stub_unread(void);

#endif /* BICCHIERINO_WS_STUB_H */
