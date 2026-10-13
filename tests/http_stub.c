/* http_stub.c — a grappa REST peer that never touches a socket.
 *
 * Replaces http.c at link time, the way ws_stub.c replaces ws_client.c:
 * a suite queues the bodies grappa would answer and reads back the paths
 * connection.c asked for. Only the http.h entry points connection.c and
 * bridge.c call are provided; the transport half (grappa_transport_connect,
 * conn_read/conn_write) belongs to ws_client.c, which these suites do not
 * link either. */
#include "http_stub.h"

#include <stdlib.h>
#include <string.h>

#define STUB_MAX 64

static char *stub_bodies[STUB_MAX];
static int stub_status[STUB_MAX];
static size_t stub_count;
static size_t stub_pos;

static char *stub_paths[STUB_MAX];
static size_t stub_path_count;

void http_stub_reset(void) {
    for (size_t i = stub_pos; i < stub_count; i++) free(stub_bodies[i]);
    for (size_t i = 0; i < stub_path_count; i++) free(stub_paths[i]);
    stub_count = stub_pos = stub_path_count = 0;
}

void http_stub_queue(int status, const char *body) {
    if (stub_count >= STUB_MAX) abort();
    stub_status[stub_count] = status;
    stub_bodies[stub_count] = strdup(body ? body : "");
    stub_count++;
}

size_t http_stub_request_count(void) { return stub_path_count; }

const char *http_stub_request(size_t i) { return i < stub_path_count ? stub_paths[i] : NULL; }

/* ── the symbols connection.c and bridge.c link against ──────────── */

void http_client_init(struct http_client *hc) { memset(hc, 0, sizeof(*hc)); }

void http_client_close(struct http_client *hc) { (void)hc; }

bool http_client_request(struct http_client *hc, const char *grappa_url, const char *method,
                          const char *path, const char *bearer_token, const char *json_body,
                          struct http_response *out) {
    (void)hc;
    (void)grappa_url;
    (void)method;
    (void)bearer_token;
    (void)json_body;
    if (stub_path_count >= STUB_MAX) abort();
    stub_paths[stub_path_count++] = strdup(path);
    if (stub_pos >= stub_count) return false;
    out->status = stub_status[stub_pos];
    out->body = stub_bodies[stub_pos];
    out->body_len = strlen(out->body);
    stub_pos++;
    return true;
}

void http_response_free(struct http_response *resp) {
    free(resp->body);
    resp->body = NULL;
    resp->body_len = 0;
}
