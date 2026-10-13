/* http_stub.h — test-side control surface for the fake grappa REST peer.
 * See http_stub.c. */
#ifndef BICCHIERINO_HTTP_STUB_H
#define BICCHIERINO_HTTP_STUB_H

#include <stddef.h>

#include "../src/http.h"

/* Drops every queued response and recorded request. Call at the top of
 * each TEST, same reason as ws_stub_reset. */
void http_stub_reset(void);

/* Queues one response for http_client_request to return, in call order.
 * A request with nothing queued answers false: "grappa not reachable". */
void http_stub_queue(int status, const char *body);

/* The paths requested, in order. */
size_t http_stub_request_count(void);
const char *http_stub_request(size_t i);

#endif /* BICCHIERINO_HTTP_STUB_H */
