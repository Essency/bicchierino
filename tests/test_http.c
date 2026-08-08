/* test_http.c — the HTTP client's parsing, without a network.
 *
 * The functions that matter here are static: URL parsing, the status
 * line, Content-Length lookup, and the growing response buffer. They are
 * pure (bytes in, values out) and they are the ones fed by a server that
 * may not be behaving, so they get compiled straight into the suite —
 * the same trick shottino's test_layout uses to reach its own statics.
 *
 * The connecting parts (tcp_connect, tls_connect, http_client_request)
 * are NOT exercised: they need a real peer, and that is the Phase B
 * testnet's job, not this suite's.
 */
#include "test.h"

/* Reaches the statics. http.c's own quoted includes resolve relative to
 * its directory, so this needs no extra -I. */
#include "../src/http.c"

#include <string.h>

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

/* Fails closed on anything unexpected — the header says so, and the
 * dangerous alternative is connecting to whatever the tail happened to
 * hold. Note http:// is refused outright: every grappa leg is TLS. */
TEST(anything_that_is_not_https_is_refused) {
    struct parsed_url pu;
    CHECK(!parse_grappa_url("http://grappa.example.net", &pu));
    CHECK(!parse_grappa_url("ws://grappa.example.net", &pu));
    CHECK(!parse_grappa_url("grappa.example.net", &pu));
    CHECK(!parse_grappa_url("", &pu));
    CHECK(!parse_grappa_url("https://", &pu));      /* prefix, no host */
    CHECK(!parse_grappa_url("https:///path", &pu)); /* empty host */
    CHECK(!parse_grappa_url("https://:4000", &pu)); /* port, no host */
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

int main(void) {
    RUN(a_plain_https_url_parses_to_host_and_default_port);
    RUN(an_explicit_port_is_taken);
    RUN(a_path_ends_the_host_and_is_discarded);
    RUN(anything_that_is_not_https_is_refused);
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
    return test_report();
}
