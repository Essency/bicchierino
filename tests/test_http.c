/* test_http.c — the HTTP client's parsing, without a network.
 *
 * The functions that matter here are static: URL parsing, the status
 * line, Content-Length lookup, and the growing response buffer. They are
 * pure (bytes in, values out) and they are the ones fed by a server that
 * may not be behaving, so they get compiled straight into the suite —
 * the same trick shottino's test_layout uses to reach its own statics.
 *
 * http_client_request is NOT exercised: it needs a real grappa, and that
 * is the Phase B testnet's job, not this suite's. tcp_connect and
 * tls_connect ARE, but only for the socket timeouts they arm — see the
 * last section, which stands up a peer on loopback for exactly that.
 */
#include "test.h"

/* Reaches the statics. http.c's own quoted includes resolve relative to
 * its directory, so this needs no extra -I. */
#include "../src/http.c"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>

/* ── parse_grappa_url ────────────────────────────────────────────── */

TEST(a_plain_https_url_parses_to_host_and_default_port) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://grappa.example.net", &pu));
    CHECK_STR(pu.host, "grappa.example.net");
    CHECK_STR(pu.port, "443");
}

TEST(an_explicit_port_is_taken) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://grappa.example.net:4000", &pu));
    CHECK_STR(pu.host, "grappa.example.net");
    CHECK_STR(pu.port, "4000");
}

TEST(a_path_ends_the_host_and_is_discarded) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://grappa.example.net/api/v1", &pu));
    CHECK_STR(pu.host, "grappa.example.net");
    CHECK_STR(pu.port, "443");

    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://grappa.example.net:4000/api", &pu));
    CHECK_STR(pu.host, "grappa.example.net");
    CHECK_STR(pu.port, "4000");

    /* A colon AFTER the first slash is part of the path, not a port. */
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://grappa.example.net/a:b", &pu));
    CHECK_STR(pu.host, "grappa.example.net");
    CHECK_STR(pu.port, "443");
}

/* RFC 3986 §3.2.2: a bracketed IPv6 literal is stripped of its brackets
 * before being stored — getaddrinfo / tcp_connect take bare literals. */
TEST(a_bracketed_ipv6_literal_parses_to_bare_host_and_default_port) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://[2001:db8::1]", &pu));
    CHECK_STR(pu.host, "2001:db8::1");
    CHECK_STR(pu.port, "443");

    /* The loopback address is the most common test case. */
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://[::1]", &pu));
    CHECK_STR(pu.host, "::1");
    CHECK_STR(pu.port, "443");
}

TEST(a_bracketed_ipv6_literal_with_explicit_port_is_taken) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://[2001:db8::1]:4000", &pu));
    CHECK_STR(pu.host, "2001:db8::1");
    CHECK_STR(pu.port, "4000");

    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://[::1]:443", &pu));
    CHECK_STR(pu.host, "::1");
    CHECK_STR(pu.port, "443");
}

TEST(a_bracketed_ipv6_literal_with_a_path_is_accepted) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://[::1]/api/v1", &pu));
    CHECK_STR(pu.host, "::1");
    CHECK_STR(pu.port, "443");

    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://[2001:db8::1]:4000/api", &pu));
    CHECK_STR(pu.host, "2001:db8::1");
    CHECK_STR(pu.port, "4000");
}

TEST(a_malformed_bracketed_host_is_refused) {
    struct parsed_url pu;
    /* Opening bracket with no closing bracket. */
    CHECK(!parse_grappa_url("https://[::1", &pu));
    /* Empty brackets — no host. */
    CHECK(!parse_grappa_url("https://[]", &pu));
    CHECK(!parse_grappa_url("https://[]:4000", &pu));
    /* Junk character immediately after the closing bracket. */
    CHECK(!parse_grappa_url("https://[::1]junk", &pu));
    /* Empty port after the colon that follows ']'. */
    CHECK(!parse_grappa_url("https://[::1]:", &pu));
}

/* Fails closed on anything unexpected — the header says so, and the
 * dangerous alternative is connecting to whatever the tail happened to
 * hold.
 *
 * http:// is NOT refused here any more: the parser recognises it and
 * reports it via pu.tls, and whether such a URL is allowed at all is
 * decided in config.c, at startup, where the loopback rule lives (see
 * a_plaintext_grappa_url_is_loopback_only in tests/test_config.c). Two
 * different questions — "is this a URL I can parse" and "is this a URL
 * you are allowed to point me at" — and they belong to different
 * layers: only config.c can see --insecure. */
TEST(anything_that_is_not_a_known_scheme_is_refused) {
    struct parsed_url pu;
    CHECK(!parse_grappa_url("ws://grappa.example.net", &pu));
    CHECK(!parse_grappa_url("grappa.example.net", &pu));
    CHECK(!parse_grappa_url("", &pu));
    CHECK(!parse_grappa_url("https://", &pu));      /* prefix, no host */
    CHECK(!parse_grappa_url("https:///path", &pu)); /* empty host */
    CHECK(!parse_grappa_url("https://:4000", &pu)); /* port, no host */
    CHECK(!parse_grappa_url("http://", &pu));       /* same, plaintext */
    CHECK(!parse_grappa_url("http:///path", &pu));
    CHECK(!parse_grappa_url("http://:4000", &pu));
}

/* The plaintext scheme parses like the TLS one, differing only in the
 * default port and in the flag the transport layer reads. */
TEST(a_plaintext_url_parses_and_defaults_to_port_80) {
    struct parsed_url pu;
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("http://127.0.0.1", &pu));
    CHECK_STR(pu.host, "127.0.0.1");
    CHECK_STR(pu.port, "80");
    CHECK(pu.tls == false);

    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("http://127.0.0.1:4000/api", &pu));
    CHECK_STR(pu.host, "127.0.0.1");
    CHECK_STR(pu.port, "4000");
    CHECK(pu.tls == false);

    /* The TLS default is unchanged, and so is its flag. */
    memset(&pu, 0, sizeof(pu));
    CHECK(parse_grappa_url("https://grappa.example.net", &pu));
    CHECK_STR(pu.port, "443");
    CHECK(pu.tls == true);
}

TEST(an_empty_or_oversized_port_is_refused) {
    struct parsed_url pu;
    CHECK(!parse_grappa_url("https://host:", &pu));
    CHECK(!parse_grappa_url("https://host:/path", &pu));
    /* port[8], so 8+ digits cannot fit and must fail rather than truncate
     * into a different port number than the operator wrote. */
    CHECK(!parse_grappa_url("https://host:123456789", &pu));
}

TEST(an_oversized_host_is_refused_not_truncated) {
    char url[512];
    char host[400];
    memset(host, 'h', sizeof(host) - 1);
    host[sizeof(host) - 1] = '\0';
    snprintf(url, sizeof(url), "https://%s", host);

    struct parsed_url pu;
    CHECK(!parse_grappa_url(url, &pu));
}

/* ── parse_status_line ───────────────────────────────────────────── */

TEST(status_codes_across_the_valid_range_are_read) {
    int st = 0;
    CHECK(parse_status_line("HTTP/1.1 200 OK\r\n\r\n", &st));
    CHECK_LONG(st, 200);

    CHECK(parse_status_line("HTTP/1.1 404 Not Found\r\n", &st));
    CHECK_LONG(st, 404);

    CHECK(parse_status_line("HTTP/1.1 401 Unauthorized\r\n", &st));
    CHECK_LONG(st, 401);

    CHECK(parse_status_line("HTTP/1.1 429 Too Many Requests\r\n", &st));
    CHECK_LONG(st, 429);

    /* The boundaries the range check names. */
    CHECK(parse_status_line("HTTP/1.1 100 Continue\r\n", &st));
    CHECK_LONG(st, 100);
    CHECK(parse_status_line("HTTP/1.1 599 Whatever\r\n", &st));
    CHECK_LONG(st, 599);

    /* No reason phrase at all is legal HTTP. */
    CHECK(parse_status_line("HTTP/1.1 204\r\n", &st));
    CHECK_LONG(st, 204);
}

TEST(a_status_line_that_is_not_one_is_refused) {
    int st = 0;
    CHECK(!parse_status_line("", &st));
    CHECK(!parse_status_line("HTTP/1.1", &st));            /* no space */
    CHECK(!parse_status_line("HTTP/1.1 sideways\r\n", &st)); /* not a number */
    CHECK(!parse_status_line("HTTP/1.1 99 Too Small\r\n", &st));
    CHECK(!parse_status_line("HTTP/1.1 600 Too Big\r\n", &st));
    CHECK(!parse_status_line("HTTP/1.1 0 Zero\r\n", &st));
    CHECK(!parse_status_line("HTTP/1.1 -200 Negative\r\n", &st));
}

/* ── find_content_length ─────────────────────────────────────────── */

/* The header block is passed as a length-delimited region with, per its
 * own comment, "no NUL assumed past it". Every case here therefore builds
 * the region so the bytes after header_len are NOT part of the number —
 * under ASan, a read past `end` shows up here. */
TEST(content_length_is_found_in_either_case) {
    long len = -1;
    const char *h1 = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\nX: y\r\n";
    CHECK(find_content_length(h1, strlen(h1), &len));
    CHECK_LONG(len, 42);

    len = -1;
    const char *h2 = "HTTP/1.1 200 OK\r\ncontent-length: 7\r\n";
    CHECK(find_content_length(h2, strlen(h2), &len));
    CHECK_LONG(len, 7);

    len = -1;
    const char *h3 = "HTTP/1.1 200 OK\r\nCONTENT-LENGTH: 1234\r\n";
    CHECK(find_content_length(h3, strlen(h3), &len));
    CHECK_LONG(len, 1234);
}

TEST(content_length_tolerates_the_spacing_servers_actually_send) {
    long len = -1;
    const char *none = "HTTP/1.1 200 OK\r\nContent-Length:99\r\n";
    CHECK(find_content_length(none, strlen(none), &len));
    CHECK_LONG(len, 99);

    len = -1;
    const char *many = "HTTP/1.1 200 OK\r\nContent-Length:    5\r\n";
    CHECK(find_content_length(many, strlen(many), &len));
    CHECK_LONG(len, 5);

    len = -1;
    const char *zero = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n";
    CHECK(find_content_length(zero, strlen(zero), &len));
    CHECK_LONG(len, 0);
}

TEST(a_response_without_the_header_says_so) {
    long len = -1;
    const char *h = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX: y\r\n";
    CHECK(!find_content_length(h, strlen(h), &len));

    CHECK(!find_content_length("", 0, &len));

    /* A truncated header name is not a match. */
    const char *partial = "HTTP/1.1 200 OK\r\nContent-Len";
    CHECK(!find_content_length(partial, strlen(partial), &len));
}

TEST(the_search_stops_at_header_len) {
    /* The Content-Length lives PAST the length we hand in: it must not be
     * found. A parser that trusted NUL termination instead of the bound
     * would read it and return true. */
    const char *buf = "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n";
    size_t cut = strlen("HTTP/1.1 200 OK\r\n");
    long len = -1;
    CHECK(!find_content_length(buf, cut, &len));
}

/* ── growbuf_append ──────────────────────────────────────────────── */

TEST(the_buffer_grows_across_many_small_appends) {
    struct growbuf gb;
    memset(&gb, 0, sizeof(gb));

    for (int i = 0; i < 1000; i++) CHECK(growbuf_append(&gb, "0123456789", 10));

    CHECK_LONG(gb.len, 10000);
    CHECK(gb.cap >= gb.len);
    CHECK(memcmp(gb.data, "0123456789", 10) == 0);
    CHECK(memcmp(gb.data + 9990, "0123456789", 10) == 0);
    free(gb.data);
}

TEST(a_zero_length_append_is_a_no_op) {
    struct growbuf gb;
    memset(&gb, 0, sizeof(gb));
    CHECK(growbuf_append(&gb, "", 0));
    CHECK_LONG(gb.len, 0);
    free(gb.data);
}

/* The backstop against a server that would otherwise make this process
 * allocate without bound. Rejected BEFORE any copy, so passing a huge n
 * with a small source is safe. */
TEST(a_response_past_the_cap_is_refused) {
    struct growbuf gb;
    memset(&gb, 0, sizeof(gb));
    char small[16] = {0};

    CHECK(!growbuf_append(&gb, small, (size_t)HTTP_MAX_RESPONSE + 1));
    CHECK_LONG(gb.len, 0);

    /* And the cap holds across appends, not just within one. */
    CHECK(growbuf_append(&gb, small, 16));
    CHECK(!growbuf_append(&gb, small, (size_t)HTTP_MAX_RESPONSE));
    CHECK_LONG(gb.len, 16);
    free(gb.data);
}

/* ── Transfer-Encoding: chunked ──────────────────────────────────────── */

/* The chunked decoder arrived with #19 and is the newest hostile-input
 * surface in this file: grappa behind any reverse proxy speaks it, so
 * these bytes come from the network on every deployment that is not a
 * direct connection.
 *
 * chunkbuf_readline and chunkbuf_read_into fall back to SSL_read when the
 * buffer runs dry, so every case here pre-seeds enough bytes that the
 * fallback is never reached — `ssl` stays NULL, and a test that reached it
 * would crash rather than quietly pass against a live socket. */

static void seed(struct chunkbuf *cb, const char *bytes, size_t n) {
    memset(cb, 0, sizeof(*cb));
    cb->ssl = NULL;
    memcpy(cb->buf, bytes, n);
    cb->len = n;
}

TEST(chunked_is_detected_case_insensitively) {
    const char *h1 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n";
    CHECK(find_chunked_encoding(h1, strlen(h1)));

    const char *h2 = "HTTP/1.1 200 OK\r\ntransfer-encoding: CHUNKED\r\n";
    CHECK(find_chunked_encoding(h2, strlen(h2)));

    /* Tabs are legal whitespace after the colon, and no space at all is
     * what several proxies actually send. */
    const char *h3 = "HTTP/1.1 200 OK\r\nTransfer-Encoding:chunked\r\n";
    CHECK(find_chunked_encoding(h3, strlen(h3)));

    const char *h4 = "HTTP/1.1 200 OK\r\nTransfer-Encoding:\t chunked\r\n";
    CHECK(find_chunked_encoding(h4, strlen(h4)));
}

TEST(a_response_that_is_not_chunked_says_so) {
    const char *h1 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n";
    CHECK(!find_chunked_encoding(h1, strlen(h1)));

    CHECK(!find_chunked_encoding("", 0));

    /* Another transfer coding is not chunked. */
    const char *h2 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n";
    CHECK(!find_chunked_encoding(h2, strlen(h2)));

    /* Truncated header name, and truncated value. */
    const char *h3 = "HTTP/1.1 200 OK\r\nTransfer-Enc";
    CHECK(!find_chunked_encoding(h3, strlen(h3)));
    const char *h4 = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chun";
    CHECK(!find_chunked_encoding(h4, strlen(h4)));
}

/* The bound is honoured: a header past header_len is not there. */
TEST(the_chunked_search_stops_at_header_len) {
    const char *buf = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n";
    size_t cut = strlen("HTTP/1.1 200 OK\r\n");
    CHECK(!find_chunked_encoding(buf, cut));
}

/* DOCUMENTED GAP, pinned rather than fixed.
 *
 * RFC 9112 requires chunked to be the FINAL coding, so `gzip, chunked` is
 * a chunked response — and this returns false for it, then the caller
 * reads the body as if it were not chunked. Not reachable through grappa
 * today (nothing in front of it applies a second coding), which is why
 * this records the behaviour instead of asserting the right one: flipping
 * it is a decode change, not a parse change, and wants its own commit. */
TEST(a_stacked_coding_is_not_recognised_today) {
    const char *h = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n";
    CHECK(!find_chunked_encoding(h, strlen(h)));
}

TEST(readline_splits_on_crlf_and_consumes_it) {
    struct chunkbuf cb;
    char line[64];

    seed(&cb, "1a\r\nrest of the buffer\r\n", 24);
    CHECK(chunkbuf_readline(&cb, line, sizeof(line)));
    CHECK_STR(line, "1a");
    /* The CRLF is consumed too, so the next line starts clean. */
    CHECK(chunkbuf_readline(&cb, line, sizeof(line)));
    CHECK_STR(line, "rest of the buffer");
    CHECK_LONG(cb.len, 0);
}

/* A zero-length line is what terminates the chunk list, so it has to come
 * back as an empty string rather than as a failure. */
TEST(readline_returns_the_empty_line) {
    struct chunkbuf cb;
    char line[64];

    seed(&cb, "\r\nx\r\n", 5);
    CHECK(chunkbuf_readline(&cb, line, sizeof(line)));
    CHECK_STR(line, "");
    CHECK(chunkbuf_readline(&cb, line, sizeof(line)));
    CHECK_STR(line, "x");
}

/* A lone CR or a lone LF is not a terminator: only the pair is. A parser
 * that accepted either would resynchronise on the wrong byte and read the
 * rest of the stream shifted by one. */
TEST(readline_does_not_split_on_a_lone_cr_or_lf) {
    struct chunkbuf cb;
    char line[64];

    seed(&cb, "a\rb\nc\r\n", 7);
    CHECK(chunkbuf_readline(&cb, line, sizeof(line)));
    CHECK_STR(line, "a\rb\nc");
}

/* out_cap is a hard bound: a line that does not fit must fail, not
 * truncate into a chunk size that is a prefix of the real one — "10000"
 * truncated to "10" is a valid hex length and a silently wrong body. */
TEST(readline_refuses_a_line_that_does_not_fit) {
    struct chunkbuf cb;
    char small[4];

    seed(&cb, "10000\r\n", 7);
    CHECK(!chunkbuf_readline(&cb, small, sizeof(small)));

    /* Exactly-fits is allowed: 3 chars plus the terminator in 4 bytes. */
    char exact[4];
    seed(&cb, "abc\r\n", 5);
    CHECK(chunkbuf_readline(&cb, exact, sizeof(exact)));
    CHECK_STR(exact, "abc");
}

TEST(read_into_copies_exactly_n_bytes) {
    struct chunkbuf cb;
    struct growbuf gb;
    memset(&gb, 0, sizeof(gb));

    seed(&cb, "HELLOWORLD", 10);
    CHECK(chunkbuf_read_into(&cb, &gb, 5));
    CHECK_LONG(gb.len, 5);
    CHECK(memcmp(gb.data, "HELLO", 5) == 0);
    /* The rest is still buffered, shifted to the front. */
    CHECK_LONG(cb.len, 5);
    CHECK(memcmp(cb.buf, "WORLD", 5) == 0);

    CHECK(chunkbuf_read_into(&cb, &gb, 5));
    CHECK_LONG(gb.len, 10);
    CHECK(memcmp(gb.data, "HELLOWORLD", 10) == 0);
    free(gb.data);
}

TEST(read_into_zero_is_a_no_op) {
    struct chunkbuf cb;
    struct growbuf gb;
    memset(&gb, 0, sizeof(gb));

    seed(&cb, "ABC", 3);
    CHECK(chunkbuf_read_into(&cb, &gb, 0));
    CHECK_LONG(gb.len, 0);
    CHECK_LONG(cb.len, 3); /* nothing consumed */
    free(gb.data);
}

/* Asking for more than the buffer holds falls through to SSL_read, which
 * is NULL here. That is deliberately not exercised — the point of this
 * note is that the untested path exists, so nobody reads the suite as
 * covering a short read from the network. */

/* ── conn_read EAGAIN / EINTR handling (#111) ────────────────────── */

/* conn_read must translate EAGAIN (SO_RCVTIMEO expiry) into -1 with
 * errno preserved, so ws_client_recv can return WS_NEED_MORE rather
 * than WS_ERROR and avoid tearing down a healthy session.
 *
 * A socketpair with a sub-millisecond SO_RCVTIMEO triggers the condition
 * without burning HTTP_IO_TIMEOUT_SEC of wall clock. */
TEST(conn_read_preserves_eagain_errno_on_read_timeout) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        FAIL("socketpair");
        return;
    }

    /* 1 ms timeout: read(2) returns -1/EAGAIN immediately when nothing
     * has been written to the other end — the same mechanism that fires
     * after HTTP_IO_TIMEOUT_SEC on the real grappa socket. */
    struct timeval tv = { .tv_sec = 0, .tv_usec = 1000 };
    setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[16];
    int n = conn_read(NULL, fds[0], buf, sizeof(buf));

    /* Must return -1 with errno EAGAIN or EWOULDBLOCK — NOT any other
     * value that ws_client_recv would interpret as WS_ERROR. */
    CHECK_LONG(n, -1);
    CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

    close(fds[0]);
    close(fds[1]);
}

/* conn_read must retry transparently when read(2) is interrupted by a
 * signal (EINTR) — the rest of the codebase (connection.c:1533,
 * main.c:165) handles EINTR the same way around poll(). */
static volatile sig_atomic_t g_eintr_test_fired;
static void eintr_test_handler(int sig) { (void)sig; g_eintr_test_fired = 1; }

TEST(conn_read_retries_eintr_and_delivers_the_data) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        FAIL("socketpair");
        return;
    }

    /* Install a SIGUSR1 handler WITHOUT SA_RESTART so the signal
     * interrupts read(2) and produces EINTR rather than being
     * transparently restarted by the kernel. */
    struct sigaction sa, old;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = eintr_test_handler;
    /* sa_flags deliberately omits SA_RESTART */
    sigaction(SIGUSR1, &sa, &old);
    g_eintr_test_fired = 0;

    /* Fork a child that: sends SIGUSR1 to the parent (causing EINTR on
     * the blocked read), then immediately writes data so conn_read's
     * retry loop finds data waiting. */
    pid_t pid = fork();
    if (pid < 0) {
        FAIL("fork");
        sigaction(SIGUSR1, &old, NULL);
        close(fds[0]);
        close(fds[1]);
        return;
    }
    if (pid == 0) {
        close(fds[0]);
        kill(getppid(), SIGUSR1);
        /* Short sleep so the parent is likely blocked in read() before
         * the write arrives — nanosleep is POSIX 2008, usleep is not. */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5000000 }; /* 5 ms */
        nanosleep(&ts, NULL);
        const char data[] = "hi";
        ssize_t nw = write(fds[1], data, sizeof(data) - 1);
        (void)nw; /* in the child, losing the write is not a test failure */
        _exit(0);
    }
    close(fds[1]);

    char buf[16];
    int n = conn_read(NULL, fds[0], buf, sizeof(buf));

    /* Whether EINTR fired before or after the write, conn_read must
     * deliver the data (if the signal arrived after the write, read
     * returned immediately — both outcomes are correct for this test). */
    CHECK(n > 0);
    if (n > 0) CHECK(memcmp(buf, "hi", (size_t)n) == 0);

    waitpid(pid, NULL, 0);
    sigaction(SIGUSR1, &old, NULL);
    close(fds[0]);
}

/* ── socket timeouts on the grappa leg ───────────────────────────── */

/* Unlike everything above, these need a peer: the property under test is
 * a socket option, and the only honest way to read one is off a real fd.
 * It earns the peer. Without these bounds a grappa that stops answering
 * parks the connection thread in SSL_read for the process lifetime,
 * holding the fd while the IRC client sits in front of a socket that
 * will never say anything again (#5).
 *
 * What is asserted: the fd each function hands back carries the bound.
 * What is NOT: that a blocked call then actually returns. Observing that
 * costs HTTP_IO_TIMEOUT_SEC of wall clock per case and what it would
 * demonstrate is that the kernel implements SO_RCVTIMEO, not anything
 * about this file.
 */

/* Bound to 127.0.0.1, never a wildcard: a unit suite has no business
 * opening a port to the network for the seconds it runs. */
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

static bool timeout_secs(int fd, int optname, long *out) {
    struct timeval tv;
    socklen_t sl = sizeof(tv);
    if (getsockopt(fd, SOL_SOCKET, optname, &tv, &sl) != 0) return false;
    *out = (long)tv.tv_sec;
    return true;
}

TEST(tcp_connect_bounds_the_connect_itself) {
    /* A zero timeval is the kernel's "block forever", so a bound of zero
     * would satisfy the comparison below while being no bound at all. */
    CHECK(HTTP_CONNECT_TIMEOUT_SEC > 0);

    char port[8];
    int srv = listen_loopback(port, sizeof(port));
    if (srv < 0) {
        FAIL("could not listen on loopback");
        return;
    }

    int fd = tcp_connect("127.0.0.1", port);
    CHECK(fd >= 0);
    if (fd >= 0) {
        long sec = -1;
        CHECK(timeout_secs(fd, SO_SNDTIMEO, &sec));
        CHECK_LONG(sec, HTTP_CONNECT_TIMEOUT_SEC);

        /* Reads are still unbounded here, and that is precisely why the
         * next test matters: nothing between this fd and the first
         * SSL_read arms SO_RCVTIMEO except tls_connect. */
        sec = -1;
        CHECK(timeout_secs(fd, SO_RCVTIMEO, &sec));
        CHECK_LONG(sec, 0);
        close(fd);
    }
    close(srv);
}

/* tls_connect verifies the chain AND the hostname, with no way to ask it
 * not to — that is the point of it. So the peer is made verifiable
 * rather than the client weakened: a self-signed cert naming localhost,
 * handed to the client as its only trust anchor through SSL_CERT_FILE,
 * which is the file SSL_CTX_set_default_verify_paths consults. */
static EVP_PKEY *generate_key(void) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!pctx) return NULL;
    EVP_PKEY *key = NULL;
    if (EVP_PKEY_keygen_init(pctx) != 1 || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) != 1 ||
        EVP_PKEY_keygen(pctx, &key) != 1)
        key = NULL;
    EVP_PKEY_CTX_free(pctx);
    return key;
}

static X509 *self_signed_localhost(EVP_PKEY *key) {
    X509 *x = X509_new();
    if (!x) return NULL;
    X509_set_version(x, 2); /* v3, so the SAN below is honoured */
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), -3600);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);

    X509_NAME *nm = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1,
                               0);
    X509_set_issuer_name(x, nm); /* self-signed: issuer is the subject */

    /* SSL_set1_host checks names, not the CN, so the SAN is what makes
     * the handshake pass. CA:TRUE because this same cert is the trust
     * anchor the client is given. */
    static const struct {
        int nid;
        const char *value;
    } exts[] = { { NID_subject_alt_name, "DNS:localhost" },
                 { NID_basic_constraints, "critical,CA:TRUE" } };
    for (size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        X509_EXTENSION *e = X509V3_EXT_conf_nid(NULL, NULL, exts[i].nid, exts[i].value);
        if (!e) {
            X509_free(x);
            return NULL;
        }
        X509_add_ext(x, e, -1);
        X509_EXTENSION_free(e);
    }

    if (X509_sign(x, key, EVP_sha256()) == 0) {
        X509_free(x);
        return NULL;
    }
    return x;
}

static bool write_pem(X509 *cert, char *path_out, size_t path_sz) {
    snprintf(path_out, path_sz, "/tmp/bicchierino-test-ca-XXXXXX");
    int fd = mkstemp(path_out);
    if (fd < 0) return false;
    FILE *f = fdopen(fd, "w");
    if (!f) {
        close(fd);
        return false;
    }
    bool ok = PEM_write_X509(f, cert) == 1;
    fclose(f);
    return ok;
}

/* A forked child, not a thread: the handshake needs both ends live at
 * once, and a separate process keeps the server's OpenSSL state — and
 * anything it does wrong — out of the suite's address space. The child
 * never returns; the parent kills it once it has read the options. */
static pid_t serve_one_tls(int srv, X509 *cert, EVP_PKEY *key) {
    pid_t pid = fork();
    if (pid != 0) return pid;

    alarm(30); /* backstop, in case the parent dies before the kill */
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx || SSL_CTX_use_certificate(ctx, cert) != 1 || SSL_CTX_use_PrivateKey(ctx, key) != 1)
        _exit(1);
    int c = accept(srv, NULL, NULL);
    if (c < 0) _exit(1);
    SSL *ssl = SSL_new(ctx);
    if (!ssl) _exit(1);
    SSL_set_fd(ssl, c);
    if (SSL_accept(ssl) != 1) _exit(1);
    char scratch[64];
    SSL_read(ssl, scratch, sizeof(scratch)); /* parks until the client goes */
    _exit(0);
}

TEST(tls_connect_bounds_reads_and_writes) {
    CHECK(HTTP_IO_TIMEOUT_SEC > 0); /* same reasoning as the connect bound */

    char port[8];
    int srv = listen_loopback(port, sizeof(port));
    if (srv < 0) {
        FAIL("could not listen on loopback");
        return;
    }

    EVP_PKEY *key = generate_key();
    X509 *cert = key ? self_signed_localhost(key) : NULL;
    char ca_path[64];
    if (!cert || !write_pem(cert, ca_path, sizeof(ca_path))) {
        FAIL("could not build the test server's certificate");
        X509_free(cert);
        EVP_PKEY_free(key);
        close(srv);
        return;
    }
    setenv("SSL_CERT_FILE", ca_path, 1);

    pid_t pid = serve_one_tls(srv, cert, key);
    if (pid < 0) {
        FAIL("fork");
        goto done;
    }

    /* "localhost", not the literal 127.0.0.1: the cert carries a DNS SAN
     * and hostname verification matches names. tcp_connect tries every
     * address getaddrinfo returns, so the listener above is still reached
     * on a host that resolves localhost to ::1 first (this one does). */
    char url[64];
    snprintf(url, sizeof(url), "https://localhost:%s", port);

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1;
    char host[256] = { 0 };
    if (!grappa_transport_connect(url, &ctx, &ssl, &fd, host, sizeof(host))) {
        FAIL("grappa_transport_connect to the local test server failed");
    } else {
        CHECK_STR(host, "localhost");

        /* Both directions, because both block: a write into a full
         * window stalls as readily as a read from a silent peer, and #5
         * was about the thread, not about which syscall pinned it. */
        long sec = -1;
        CHECK(timeout_secs(fd, SO_RCVTIMEO, &sec));
        CHECK_LONG(sec, HTTP_IO_TIMEOUT_SEC);
        sec = -1;
        CHECK(timeout_secs(fd, SO_SNDTIMEO, &sec));
        CHECK_LONG(sec, HTTP_IO_TIMEOUT_SEC);

        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
    }

    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);

done:
    unsetenv("SSL_CERT_FILE");
    unlink(ca_path);
    X509_free(cert);
    EVP_PKEY_free(key);
    close(srv);
}

int main(void) {
    RUN(a_plain_https_url_parses_to_host_and_default_port);
    RUN(an_explicit_port_is_taken);
    RUN(a_path_ends_the_host_and_is_discarded);
    RUN(a_bracketed_ipv6_literal_parses_to_bare_host_and_default_port);
    RUN(a_bracketed_ipv6_literal_with_explicit_port_is_taken);
    RUN(a_bracketed_ipv6_literal_with_a_path_is_accepted);
    RUN(a_malformed_bracketed_host_is_refused);
    RUN(anything_that_is_not_a_known_scheme_is_refused);
    RUN(a_plaintext_url_parses_and_defaults_to_port_80);
    RUN(an_empty_or_oversized_port_is_refused);
    RUN(an_oversized_host_is_refused_not_truncated);
    RUN(status_codes_across_the_valid_range_are_read);
    RUN(a_status_line_that_is_not_one_is_refused);
    RUN(content_length_is_found_in_either_case);
    RUN(content_length_tolerates_the_spacing_servers_actually_send);
    RUN(a_response_without_the_header_says_so);
    RUN(the_search_stops_at_header_len);
    RUN(the_buffer_grows_across_many_small_appends);
    RUN(a_zero_length_append_is_a_no_op);
    RUN(a_response_past_the_cap_is_refused);
    RUN(chunked_is_detected_case_insensitively);
    RUN(a_response_that_is_not_chunked_says_so);
    RUN(the_chunked_search_stops_at_header_len);
    RUN(a_stacked_coding_is_not_recognised_today);
    RUN(readline_splits_on_crlf_and_consumes_it);
    RUN(readline_returns_the_empty_line);
    RUN(readline_does_not_split_on_a_lone_cr_or_lf);
    RUN(readline_refuses_a_line_that_does_not_fit);
    RUN(read_into_copies_exactly_n_bytes);
    RUN(read_into_zero_is_a_no_op);
    RUN(conn_read_preserves_eagain_errno_on_read_timeout);
    RUN(conn_read_retries_eintr_and_delivers_the_data);
    RUN(tcp_connect_bounds_the_connect_itself);
    RUN(tls_connect_bounds_reads_and_writes);
    return test_report();
}
