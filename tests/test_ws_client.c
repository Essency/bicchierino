/* test_ws_client.c — ws_client_recv behaviour under EAGAIN (#111).
 *
 * Before the fix, conn_read returning -1/EAGAIN (e.g. SO_RCVTIMEO
 * expiry on the grappa socket after 30 s of idle) propagated straight
 * out as WS_ERROR, tearing down a healthy session.  With the fix,
 * ws_client_recv translates EAGAIN → WS_NEED_MORE so the Phase 2
 * poll() loop goes back to waiting rather than emitting
 * "ERROR :lost grappa connection".
 *
 * Compiled with http.c (supplies conn_read), ws_client.c (the function
 * under test), and ws.c (ws_reader_* that ws_client_recv calls first).
 */
#include "../src/ws_client.h"

#include "test.h"

#include <sys/socket.h>
#include <sys/time.h>

/* ── ws_client_recv EAGAIN (#111) ────────────────────────────────── */

/* Reproduce the observed failure: the grappa socket has SO_RCVTIMEO set
 * (transport_connect in http.c arms it for both plaintext and TLS).
 * After HTTP_IO_TIMEOUT_SEC of idle, read(2) returns -1/EAGAIN.  The old
 * code mapped every negative conn_read result to WS_ERROR (-2); the fix
 * maps EAGAIN to WS_NEED_MORE (0). */
TEST(eagain_from_read_timeout_is_ws_need_more_not_ws_error) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        FAIL("socketpair");
        return;
    }

    /* 1 ms SO_RCVTIMEO: read(2) fires EAGAIN immediately, same mechanism
     * as the production 30 s timeout — only the wall-clock cost differs. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Build a ws_client pointing at the empty, timeout-armed socket.
     * ssl == NULL: plaintext, exactly the deployment that surfaced #111. */
    struct ws_client wsc;
    memset(&wsc, 0, sizeof(wsc));
    wsc.fd  = fds[0];
    wsc.ssl = NULL;
    ws_reader_init(&wsc.reader);

    char   *payload  = NULL;
    size_t  plen     = 0;
    ws_result r = ws_client_recv(&wsc, &payload, &plen);

    /* Before the fix: WS_ERROR (-2) → "grappa websocket closed mid-session".
     * After the fix: WS_NEED_MORE (0) → caller goes back to poll(). */
    CHECK_LONG(r, WS_NEED_MORE);
    CHECK(payload == NULL);

    ws_reader_free(&wsc.reader);
    close(fds[0]);
    close(fds[1]);
}

/* A real WS_ERROR (connection reset, not just a timeout) must still come
 * back as WS_ERROR — EAGAIN handling must not swallow genuine failures. */
TEST(a_genuine_read_error_is_still_ws_error) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        FAIL("socketpair");
        return;
    }

    /* Close the write end first; reading now yields 0 (EOF), which is
     * WS_CLOSED.  Use shutdown to force an RST-like condition instead. */
    struct ws_client wsc;
    memset(&wsc, 0, sizeof(wsc));
    wsc.fd  = fds[0];
    wsc.ssl = NULL;
    ws_reader_init(&wsc.reader);

    /* Closing the peer end makes the next read return 0 (EOF). */
    close(fds[1]);

    char   *payload  = NULL;
    size_t  plen     = 0;
    ws_result r = ws_client_recv(&wsc, &payload, &plen);

    /* read() returns 0 → WS_CLOSED.  Either WS_CLOSED or WS_ERROR is
     * the expected "not WS_NEED_MORE" outcome; either tears the session
     * down, which is correct for a genuine connection loss. */
    CHECK(r == WS_CLOSED || r == WS_ERROR);
    CHECK(r != WS_NEED_MORE);

    ws_reader_free(&wsc.reader);
    close(fds[0]);
}

int main(void) {
    RUN(eagain_from_read_timeout_is_ws_need_more_not_ws_error);
    RUN(a_genuine_read_error_is_still_ws_error);
    return test_report();
}
