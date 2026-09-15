/* ws_stub.c — a websocket peer that never touches a socket.
 *
 * bridge.c's whole job is the shape of what it SENDS and which of the
 * frames it RECEIVES it treats as an answer. Both are decidable without
 * a network, so this replaces ws_client.c at link time: the tests queue
 * the frames grappa would push and then read back exactly what bridge.c
 * put on the wire.
 *
 * Only the four entry points bridge.c calls are provided. ws_reader_take
 * is deliberately NOT stubbed — bridge_recv_buffered forwards straight to
 * the real ws.c reader, and stubbing it would test the stub.
 */
#include "ws_stub.h"

#include <stdlib.h>
#include <string.h>

#define STUB_MAX_FRAMES 64

static char *stub_sent[STUB_MAX_FRAMES];
static size_t stub_sent_count;

static char *stub_inbox[STUB_MAX_FRAMES];
static ws_result stub_inbox_result[STUB_MAX_FRAMES];
static size_t stub_inbox_count;
static size_t stub_inbox_pos;

void ws_stub_reset(void) {
    for (size_t i = 0; i < stub_sent_count; i++) free(stub_sent[i]);
    for (size_t i = stub_inbox_pos; i < stub_inbox_count; i++) free(stub_inbox[i]);
    stub_sent_count = 0;
    stub_inbox_count = 0;
    stub_inbox_pos = 0;
}

void ws_stub_queue(ws_result result, const char *payload) {
    if (stub_inbox_count >= STUB_MAX_FRAMES) abort();
    stub_inbox_result[stub_inbox_count] = result;
    stub_inbox[stub_inbox_count] = payload ? strdup(payload) : NULL;
    stub_inbox_count++;
}

size_t ws_stub_sent_count(void) { return stub_sent_count; }

const char *ws_stub_sent(size_t i) { return i < stub_sent_count ? stub_sent[i] : NULL; }

size_t ws_stub_unread(void) { return stub_inbox_count - stub_inbox_pos; }

/* ── the symbols bridge.c links against ──────────────────────────── */

bool ws_client_connect(const char *grappa_url, const char *bearer_token, struct ws_client *out) {
    (void)grappa_url;
    (void)bearer_token;
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    ws_reader_init(&out->reader);
    return true;
}

bool ws_client_send_text(struct ws_client *wsc, const char *text) {
    (void)wsc;
    if (stub_sent_count >= STUB_MAX_FRAMES) abort();
    stub_sent[stub_sent_count++] = strdup(text);
    return true;
}

bool ws_client_send_pong(struct ws_client *wsc, const char *payload, size_t len) {
    (void)wsc;
    (void)payload;
    (void)len;
    return true;
}

/* Hands back the queued frames in order. Past the end it reports
 * WS_CLOSED rather than looping — a bridge_join that keeps reading after
 * the script ran out has to terminate, not spin. */
ws_result ws_client_recv(struct ws_client *wsc, char **payload, size_t *len) {
    (void)wsc;
    if (stub_inbox_pos >= stub_inbox_count) {
        *payload = NULL;
        *len = 0;
        return WS_CLOSED;
    }
    size_t i = stub_inbox_pos++;
    /* bridge.c frees whatever comes back, so hand over the copy. */
    *payload = stub_inbox[i];
    *len = stub_inbox[i] ? strlen(stub_inbox[i]) : 0;
    stub_inbox[i] = NULL;
    return stub_inbox_result[i];
}

void ws_client_close(struct ws_client *wsc) { ws_reader_free(&wsc->reader); }
