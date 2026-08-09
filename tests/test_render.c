/* test_render.c — one line in, one line out. (#9)
 *
 * Every render arm in connection.c formats grappa-sourced strings — body,
 * channel, sender, topic, kick reason — through send_line/send_tagged_line,
 * which append CRLF and write the result to the client. A CR or LF inside
 * one of those fields therefore ends the line early and starts another
 * one, chosen by whoever controls the field. The client cannot tell that
 * apart from a line the bridge meant to send.
 *
 * This is not a live exploit today: grappa refuses \r, \n and \0 in every
 * public send helper (Grappa.IRC.Identifier.safe_line_token?/1), so such a
 * field never reaches the wire. That is the point — bicchierino's
 * correctness here rests on an invariant held by a separate codebase,
 * versioned separately, with nothing on this side asserting it. The
 * Makefile's own threat model already names "JSON/websocket frames from
 * grappa" as hostile input.
 *
 * So these assert the property directly, at the one place every arm passes
 * through: whatever goes in, exactly one line comes out.
 *
 * connection.c is compiled into the suite to reach send_line, which is
 * static — the same approach test_http uses for the parsers, and the only
 * one that does not widen a header for the tests' benefit.
 */
#include "test.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* A socketpair stands in for the client. client_write falls back to
 * write(2) whenever no TLS session is attached, which is the case here. */
static int rx = -1;

static int open_client(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair");
        return -1;
    }
    rx = sv[0];
    return sv[1];
}

static size_t drain(int tx, char *out, size_t cap) {
    close(tx);
    size_t total = 0;
    ssize_t n;
    while (total + 1 < cap && (n = read(rx, out + total, cap - total - 1)) > 0)
        total += (size_t)n;
    out[total] = '\0';
    close(rx);
    rx = -1;
    return total;
}

/* The property: the payload may be mangled, dropped or escaped — that is
 * the implementation's choice — but it must not become a second line. */
static void check_single_line(const char *what, const char *buf, size_t len) {
    size_t crlf = 0;
    for (size_t i = 0; i + 1 < len; i++)
        if (buf[i] == '\r' && buf[i + 1] == '\n') crlf++;

    if (crlf != 1) {
        fprintf(stderr, "  [%s] %zu CRLF in: %.*s\n", what, crlf, (int)len, buf);
        FAIL("payload produced more than one line");
        return;
    }
    /* And the one CRLF is the terminator, not something in the middle. */
    CHECK(len >= 2 && buf[len - 2] == '\r' && buf[len - 1] == '\n');

    /* No stray CR or LF anywhere before it either: a lone LF is a line
     * ending for plenty of clients even without the CR. */
    for (size_t i = 0; i + 2 < len; i++)
        if (buf[i] == '\r' || buf[i] == '\n') {
            fprintf(stderr, "  [%s] stray CR/LF at %zu in: %.*s\n", what, i, (int)len, buf);
            FAIL("bare CR or LF survived inside the line");
            return;
        }
}

static void one(const char *what, const char *payload) {
    char buf[2048];
    int tx = open_client();
    if (tx < 0) return;
    send_line(tx, ":nick!user@host PRIVMSG #chan :%s", payload);
    size_t len = drain(tx, buf, sizeof(buf));
    check_single_line(what, buf, len);
}

TEST(a_clean_line_is_unchanged) {
    char buf[2048];
    int tx = open_client();
    if (tx < 0) return;
    send_line(tx, ":nick!user@host PRIVMSG #chan :%s", "hello world");
    size_t len = drain(tx, buf, sizeof(buf));
    CHECK_STR(buf, ":nick!user@host PRIVMSG #chan :hello world\r\n");
    check_single_line("clean", buf, len);
}

/* The shape an injection would take: end the line, start a new one that
 * the client renders as if the bridge had sent it. */
TEST(a_crlf_in_a_field_does_not_start_a_second_line) {
    one("crlf", "hi\r\n:evil!e@e PRIVMSG #chan :forged");
}

/* Bare LF, which many clients accept as a terminator on its own, and bare
 * CR, which some do. Neither may survive. */
TEST(a_bare_lf_or_cr_does_not_start_a_second_line) {
    one("lf", "hi\n:evil!e@e PRIVMSG #chan :forged");
    one("cr", "hi\r:evil!e@e PRIVMSG #chan :forged");
}

/* A forged line that would be read as coming from the bridge itself —
 * the most useful thing to inject, since clients trust server-prefixed
 * lines differently from user ones. */
TEST(a_forged_server_line_does_not_get_through) {
    one("forged-notice", "x\r\n:bicchierino NOTICE nick :your session expired, /msg NickServ ...");
    one("forged-error",  "x\r\nERROR :Closing link");
}

/* Injection attempts placed where truncation might interact with them:
 * at the very start, at the very end, and repeated. */
TEST(injection_at_the_edges_and_repeated) {
    one("leading",  "\r\n:evil!e@e PRIVMSG #chan :forged");
    one("trailing", "hi\r\n");
    one("repeated", "a\r\nb\r\nc\r\nd");
    one("only-crlf", "\r\n");
    one("many-lf",  "a\n\n\n\nb");
}

/* A long field that fills the line budget AND carries a CRLF: the
 * truncation path and the sanitising path have to compose. */
TEST(injection_inside_an_oversized_field) {
    char big[IRC_LINE_MAX * 2];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    memcpy(big + 100, "\r\n:evil!e@e PRIVMSG #chan :forged", 33);
    one("oversized", big);
}

/* Fields other than the trailing one: a channel name or a nick is
 * interpolated into the middle of the line, where a CRLF splits it in a
 * different place. */
TEST(injection_in_a_non_trailing_field) {
    char buf[2048];
    int tx = open_client();
    if (tx < 0) return;
    send_line(tx, ":nick!user@host PRIVMSG %s :%s", "#chan\r\n:evil!e@e JOIN #other", "body");
    size_t len = drain(tx, buf, sizeof(buf));
    check_single_line("mid-field", buf, len);
}

/* NUL is called out in #9 alongside CR and LF, but it cannot arrive
 * through a %s argument: the C string ends there, so send_line never sees
 * what follows. Recorded rather than asserted, so nobody reads this suite
 * as covering a NUL that arrived some other way (a memcpy'd field, a
 * length-carrying wire value). */
TEST(a_nul_truncates_the_argument_and_cannot_inject) {
    char buf[2048];
    int tx = open_client();
    if (tx < 0) return;
    const char payload[] = "safe\0:evil!e@e PRIVMSG #chan :forged";
    send_line(tx, ":nick!user@host PRIVMSG #chan :%s", payload);
    size_t len = drain(tx, buf, sizeof(buf));
    CHECK_STR(buf, ":nick!user@host PRIVMSG #chan :safe\r\n");
    check_single_line("nul", buf, len);
}

int main(void) {
    RUN(a_clean_line_is_unchanged);
    RUN(a_crlf_in_a_field_does_not_start_a_second_line);
    RUN(a_bare_lf_or_cr_does_not_start_a_second_line);
    RUN(a_forged_server_line_does_not_get_through);
    RUN(injection_at_the_edges_and_repeated);
    RUN(injection_inside_an_oversized_field);
    RUN(injection_in_a_non_trailing_field);
    RUN(a_nul_truncates_the_argument_and_cannot_inject);
    return test_report();
}
