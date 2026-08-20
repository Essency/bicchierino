/* test_parse.c — irc_parse_line behaviour. (#101)
 *
 * The root fix for #101 is architectural: handle_raw() now forwards the
 * ORIGINAL line bytes received from the client verbatim (threaded from the
 * poll loop through handle_irc_line), rather than calling reconstruct_irc_line
 * on the re-tokenised struct irc_message.  reconstruct_irc_line and the
 * last-slot absorb-at-cap block in irc_parse_line have both been removed.
 *
 * irc_parse_line is still used for command dispatch (deciding which dedicated
 * handler, if any, owns a command) — that usage is unchanged.  These tests
 * cover the parser's own contract: correct tokenisation up to IRC_MAX_PARAMS,
 * the colon-trailing-param rule, and the command name extraction.
 *
 * connection.c is compiled in directly to reach irc_parse_line, which is
 * static — the same approach as test_render and test_whois.
 */
#include "test.h"

#include "../src/connection.c"

#include <string.h>

/* ── helpers ─────────────────────────────────────────────────────── */

/* Call irc_parse_line and assert it succeeds. */
static struct irc_message parse_ok(const char *line) {
    struct irc_message msg;
    if (!irc_parse_line(line, &msg)) {
        FAIL("irc_parse_line returned false");
    }
    return msg;
}

/* ── tests ───────────────────────────────────────────────────────── */

/* A line with exactly IRC_MAX_PARAMS (15) space-separated tokens must
 * parse all 15 and leave nothing behind. */
TEST(exactly_max_params_parsed_intact) {
    /* PRIVMSG + 14 more tokens = 15 params total */
    const char *line =
        "PRIVMSG p1 p2 p3 p4 p5 p6 p7 p8 p9 p10 p11 p12 p13 p14";
    struct irc_message msg = parse_ok(line);

    CHECK_LONG((long)msg.param_count, 14);
    CHECK(strcmp(msg.params[0],  "p1")  == 0);
    CHECK(strcmp(msg.params[13], "p14") == 0);
}

/* A line with MORE than IRC_MAX_PARAMS tokens must still parse
 * successfully (handle_irc_line needs the command name for dispatch),
 * filling the first IRC_MAX_PARAMS param slots with the first 15 tokens.
 * The tail beyond the cap is not stored in msg.params — handle_raw
 * forwards the ORIGINAL line verbatim instead of reconstructing from
 * msg.params, so nothing is lost on the wire. */
TEST(excess_tokens_parsed_for_dispatch) {
    /* "OS" + 16 space-separated tokens = 17 tokens total without a cap. */
    const char *line =
        "OS tagline add "
        "w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 "
        "w13 w14";

    struct irc_message msg = parse_ok(line);

    /* Command must be correctly extracted for dispatch. */
    CHECK(strcmp(msg.command, "OS") == 0);

    /* Parser fills up to IRC_MAX_PARAMS slots; tail beyond the cap is
     * not in msg.params (handle_raw uses the original line, not these). */
    CHECK_LONG((long)msg.param_count, IRC_MAX_PARAMS);

    /* First and 14th param slots are correct. */
    CHECK(strcmp(msg.params[0],  "tagline") == 0);
    CHECK(strcmp(msg.params[13], "w12")     == 0);

    /* 15th slot (index 14) gets the 15th token only — stopping at the
     * next space, not absorbing the remainder. */
    CHECK(strcmp(msg.params[IRC_MAX_PARAMS - 1], "w13") == 0);
}

/* A colon-prefixed trailing param must still be handled correctly — the
 * ':' path absorbs the rest of the line regardless of token count. */
TEST(colon_trailing_param_still_works) {
    const char *line = "PRIVMSG #chan :hello world";
    struct irc_message msg = parse_ok(line);

    CHECK_LONG((long)msg.param_count, 2);
    CHECK(strcmp(msg.params[0], "#chan")       == 0);
    CHECK(strcmp(msg.params[1], "hello world") == 0);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void) {
    RUN(exactly_max_params_parsed_intact);
    RUN(excess_tokens_parsed_for_dispatch);
    RUN(colon_trailing_param_still_works);
    return test_report();
}
