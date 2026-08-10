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

/* ── pending_self_channel set — issue #73 ────────────────────────────
 *
 * `remember_pending_self_channel` / `consume_pending_self_channel` are
 * the join/part analogue of `remember_pending_self_id` /
 * `consume_pending_self_id`. These tests assert:
 *
 *   1. A channel this connection issued (in the pending set) is consumed
 *      on the first matching event → own echo, suppress it.
 *   2. A channel NOT in the pending set (sibling client's event) is NOT
 *      consumed → forward it to the IRC client.
 *   3. After consuming once the entry is gone — a second identical event
 *      is NOT consumed (sibling join that happened to be the same channel
 *      after the echo was already matched).
 *   4. Join and part sets are independent — a channel in the join set is
 *      not matched by a part consume and vice versa.
 *   5. Matching is case-insensitive (folded keys): a channel recorded
 *      as "#ABC" is consumed by "#abc".
 */

/* Thin wrappers so the tests don't need to manage the raw [CAP][SZ] types
 * by hand — just a mini session with two pending sets. */
struct pending_ch_fixture {
    char join_set[PENDING_SELF_CH_CAP][PENDING_SELF_CH_SZ];
    size_t join_count;
    char part_set[PENDING_SELF_CH_CAP][PENDING_SELF_CH_SZ];
    size_t part_count;
};

static void pf_remember_join(struct pending_ch_fixture *f, const char *ch) {
    char folded[PENDING_SELF_CH_SZ];
    ascii_fold_lower(ch, folded, sizeof(folded));
    remember_pending_self_channel(f->join_set, &f->join_count, folded);
}
static void pf_remember_part(struct pending_ch_fixture *f, const char *ch) {
    char folded[PENDING_SELF_CH_SZ];
    ascii_fold_lower(ch, folded, sizeof(folded));
    remember_pending_self_channel(f->part_set, &f->part_count, folded);
}
static bool pf_consume_join(struct pending_ch_fixture *f, const char *ch) {
    char folded[PENDING_SELF_CH_SZ];
    ascii_fold_lower(ch, folded, sizeof(folded));
    return consume_pending_self_channel(f->join_set, &f->join_count, folded);
}
static bool pf_consume_part(struct pending_ch_fixture *f, const char *ch) {
    char folded[PENDING_SELF_CH_SZ];
    ascii_fold_lower(ch, folded, sizeof(folded));
    return consume_pending_self_channel(f->part_set, &f->part_count, folded);
}

/* Own echo: recorded channel IS in the pending set → consumed (suppress). */
TEST(pending_join_own_echo_is_consumed) {
    struct pending_ch_fixture f = {0};
    pf_remember_join(&f, "#bicchierino");
    CHECK(pf_consume_join(&f, "#bicchierino") == true);
    CHECK(f.join_count == 0);
}

/* Sibling event: channel NOT in the set → NOT consumed (forward). */
TEST(pending_join_sibling_event_not_consumed) {
    struct pending_ch_fixture f = {0};
    pf_remember_join(&f, "#mine");
    /* A different channel — sibling joined somewhere else. */
    CHECK(pf_consume_join(&f, "#theirs") == false);
    /* The pending entry for #mine must still be there. */
    CHECK(f.join_count == 1);
}

/* Consumed only once: a second identical event is NOT in the set any more. */
TEST(pending_join_consumed_only_once) {
    struct pending_ch_fixture f = {0};
    pf_remember_join(&f, "#once");
    CHECK(pf_consume_join(&f, "#once") == true);  /* own echo — suppress */
    CHECK(pf_consume_join(&f, "#once") == false); /* sibling join after echo — forward */
}

/* Join and part sets are independent. */
TEST(pending_join_and_part_sets_are_independent) {
    struct pending_ch_fixture f = {0};
    pf_remember_join(&f, "#chan");
    /* A part consume must NOT match what is in the join set. */
    CHECK(pf_consume_part(&f, "#chan") == false);
    CHECK(f.join_count == 1); /* join entry still present */

    pf_remember_part(&f, "#chan");
    CHECK(pf_consume_part(&f, "#chan") == true);
    CHECK(f.part_count == 0);
    /* And the join entry is still untouched. */
    CHECK(pf_consume_join(&f, "#chan") == true);
}

/* Matching is case-insensitive (folded keys). */
TEST(pending_join_matching_is_case_insensitive) {
    struct pending_ch_fixture f = {0};
    pf_remember_join(&f, "#MyChannel");
    /* Event arrives with differently-cased channel name. */
    CHECK(pf_consume_join(&f, "#mychannel") == true);
    CHECK(f.join_count == 0);
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
    RUN(pending_join_own_echo_is_consumed);
    RUN(pending_join_sibling_event_not_consumed);
    RUN(pending_join_consumed_only_once);
    RUN(pending_join_and_part_sets_are_independent);
    RUN(pending_join_matching_is_case_insensitive);
    return test_report();
}
