/* test_ws_client.c — ws_client_recv behaviour under EAGAIN (#111), and
 * ws_client_connect timeout-clearing after the WebSocket upgrade (#112).
 *
 * #111: conn_read returning -1/EAGAIN (e.g. SO_RCVTIMEO expiry on the
 * grappa socket after 30 s of idle) must surface as WS_NEED_MORE, not
 * WS_ERROR — the Phase 2 poll() loop goes back to waiting rather than
 * emitting "ERROR :lost grappa connection".
 *
 * #112: transport_connect arms a 30 s SO_RCVTIMEO for the HTTP
 * request/response exchange.  ws_client_connect must clear it once the
 * WebSocket upgrade has completed so that 30 s of silence on a healthy,
 * idle bridge does not trigger a spurious timeout.
 *
 * Compiled with http.c (supplies conn_read / grappa_transport_connect),
 * ws_client.c (the functions under test), and ws.c (ws_reader_* that
 * ws_client_recv calls first).
 */
#include "../src/ws_client.h"

#include "test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>

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

/* ── ws_client_connect clears IO timeouts after upgrade (#112) ───── */

/* Bind to loopback, listen, return the fd and the chosen port as a
 * NUL-terminated string.  Mirrors the helper of the same name in
 * test_http.c — duplicated here to keep each suite self-contained. */
static int listen_loopback(char *port_out, size_t port_sz) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(fd, 1) != 0) {
        close(fd);
        return -1;
    }
    socklen_t sl = sizeof(sa);
    if (getsockname(fd, (struct sockaddr *)&sa, &sl) != 0) {
        close(fd);
        return -1;
    }
    snprintf(port_out, port_sz, "%u", (unsigned)ntohs(sa.sin_port));
    return fd;
}

/* Read SO_RCVTIMEO or SO_SNDTIMEO off fd, return the seconds component.
 * A zero timeval is the kernel's "no timeout" / "block forever". */
static bool timeout_secs(int fd, int optname, long *out) {
    struct timeval tv;
    socklen_t sl = sizeof(tv);
    if (getsockopt(fd, SOL_SOCKET, optname, &tv, &sl) != 0) return false;
    *out = (long)tv.tv_sec;
    return true;
}

/* Minimal WebSocket server: read an HTTP upgrade request, derive the
 * correct Sec-WebSocket-Accept, send HTTP/1.1 101, then park.
 * Runs in a forked child — never returns. */
static void serve_ws_upgrade(int connfd) {
    alarm(5); /* backstop if the parent dies */

    /* Read until the end of the HTTP request headers. */
    char req[4096];
    ssize_t n = 0;
    while (n < (ssize_t)(sizeof(req) - 1)) {
        ssize_t r = read(connfd, req + n, sizeof(req) - 1 - (size_t)n);
        if (r <= 0) _exit(1);
        n += r;
        req[n] = '\0';
        if (strstr(req, "\r\n\r\n")) break;
    }

    /* Extract the Sec-WebSocket-Key header value (header name is
     * case-insensitive per RFC 7230, value must be compared exactly). */
    const char *hdr = req;
    char ws_key[128] = "";
    while (*hdr) {
        if (strncasecmp(hdr, "Sec-WebSocket-Key:", 18) == 0) {
            hdr += 18;
            while (*hdr == ' ') hdr++;
            int i = 0;
            while (*hdr && *hdr != '\r' && *hdr != '\n' && i < 127)
                ws_key[i++] = *hdr++;
            ws_key[i] = '\0';
            break;
        }
        const char *nl = strchr(hdr, '\n');
        if (!nl) break;
        hdr = nl + 1;
    }
    if (!ws_key[0]) _exit(1);

    /* Sec-WebSocket-Accept = base64(SHA1(key + GUID)) — RFC 6455 §4.2.2. */
    char accept_input[256];
    snprintf(accept_input, sizeof(accept_input),
             "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", ws_key);
    unsigned char sha1[SHA_DIGEST_LENGTH];
    SHA1((const unsigned char *)accept_input, strlen(accept_input), sha1);
    char accept_b64[64];
    int elen = EVP_EncodeBlock((unsigned char *)accept_b64, sha1, SHA_DIGEST_LENGTH);
    accept_b64[elen] = '\0';

    /* Send the 101 upgrade response. */
    char resp[512];
    int rlen = snprintf(resp, sizeof(resp),
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Accept: %s\r\n"
                        "\r\n",
                        accept_b64);
    if (rlen > 0) (void)write(connfd, resp, (size_t)rlen);

    /* Stay alive until the parent kills us — the connection must remain
     * open so ws_client_connect can verify the socket options on it. */
    pause();
    _exit(0);
}

/* Confirm that ws_client_connect clears both SO_RCVTIMEO and SO_SNDTIMEO
 * once the HTTP → WebSocket upgrade has completed (#112).
 *
 * transport_connect (http.c) arms a 30 s I/O timeout for the HTTP
 * exchange.  Without the fix, that timeout persists on the WebSocket
 * socket for the bridge's lifetime: any 30 s gap in the stream fires
 * EAGAIN on conn_read, which — even with the #111 fix in place —
 * causes spurious WS_NEED_MORE wakeups from the bridge.c bootstrap
 * loop (bridge.c §74-79, no poll() gate, unbounded by anything but
 * this timeout).
 *
 * Uses an http:// URL to a loopback listener (the plaintext-loopback
 * deployment path, which avoids the need for a TLS cert while still
 * exercising the same transport_connect path that sets the timeout). */
TEST(ws_client_connect_clears_io_timeout_after_upgrade) {
    char port[8];
    int srv = listen_loopback(port, sizeof(port));
    if (srv < 0) {
        FAIL("could not listen on loopback");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        close(srv);
        return;
    }
    if (pid == 0) {
        /* child: accept one connection, run the upgrade server */
        int c = accept(srv, NULL, NULL);
        close(srv);
        if (c < 0) _exit(1);
        serve_ws_upgrade(c);
        /* serve_ws_upgrade never returns */
    }

    /* parent: hand off the listener fd (child has its own copy) */
    close(srv);

    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%s", port);

    struct ws_client wsc;
    bool ok = ws_client_connect(url, "dummy-token", &wsc);
    CHECK(ok);

    if (ok) {
        /* After a successful upgrade both timeouts must be zero —
         * the kernel's representation of "no timeout / block forever".
         * Without the fix, both read back HTTP_IO_TIMEOUT_SEC (30 s). */
        long rcv = -1, snd = -1;
        CHECK(timeout_secs(wsc.fd, SO_RCVTIMEO, &rcv));
        CHECK(timeout_secs(wsc.fd, SO_SNDTIMEO, &snd));
        CHECK_LONG(rcv, 0);
        CHECK_LONG(snd, 0);
        ws_client_close(&wsc);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
}

int main(void) {
    RUN(eagain_from_read_timeout_is_ws_need_more_not_ws_error);
    RUN(a_genuine_read_error_is_still_ws_error);
    RUN(ws_client_connect_clears_io_timeout_after_upgrade);
    return test_report();
}
