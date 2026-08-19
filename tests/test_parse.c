/* test_parse.c — irc_parse_line param-cap behaviour. (#101)
 *
 * A client line whose space-separated token count exceeds IRC_MAX_PARAMS
 * was silently truncated: irc_parse_line stopped at the 15th token and
 * discarded the remainder without error.  The bug was introduced here, not
 * enforced by the upstream ircd — bahamut itself assigns the entire
 * remainder of the line (spaces included) to the last argument once its
 * own cap is reached, so a direct-ircd client kept the full text while a
 * bicchierino-mediated one did not.
 *
 * The fix: when filling the last available slot and the current param does
 * NOT start with ':', absorb the rest of the line verbatim.
 * reconstruct_irc_line() already emits ':' for a trailing param that
 * contains spaces, so the rebuilt line forwarded to grappa stays
 * wire-legal.
 *
 * connection.c is compiled in directly to reach irc_parse_line and
 * reconstruct_irc_line, which are both static — the same approach as
 * test_render and test_whois.
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

/* A line with MORE than IRC_MAX_PARAMS tokens must NOT lose the tail:
 * the content from token 15 onward (including its spaces) must end up
 * verbatim in params[IRC_MAX_PARAMS-1]. */
TEST(excess_tokens_collected_into_last_param) {
    /* Command "OS" + 16 space-separated tokens = 16 params without the cap.
     * Slot 14 (index IRC_MAX_PARAMS-1 = 14) must absorb tokens 15 and 16
     * rather than stopping at the space after token 15.
     *
     * Tokens: tagline(0) add(1) w1(2)..w12(13) w13 w14(14, last slot)
     *         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     *         14 individual words then the remainder in slot 14. */
    const char *line =
        "OS tagline add "                           /* "OS" + tokens 0-1 */
        "w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 " /* tokens 2-13       */
        "w13 w14";                                  /* overflow -> slot 14 */

    struct irc_message msg = parse_ok(line);

    /* Must fill every slot. */
    CHECK_LONG((long)msg.param_count, IRC_MAX_PARAMS);

    /* params[0] = "tagline", params[13] = "w12". */
    CHECK(strcmp(msg.params[0],  "tagline") == 0);
    CHECK(strcmp(msg.params[13], "w12")     == 0);

    /* The last slot absorbs "w13 w14" — spaces intact, not just "w13". */
    CHECK(strcmp(msg.params[IRC_MAX_PARAMS - 1], "w13 w14") == 0);
}

/* A colon-prefixed trailing param before the cap is still handled
 * correctly — the ':' path should not interact with the new last-slot
 * logic. */
TEST(colon_trailing_param_still_works) {
    const char *line = "PRIVMSG #chan :hello world";
    struct irc_message msg = parse_ok(line);

    CHECK_LONG((long)msg.param_count, 2);
    CHECK(strcmp(msg.params[0], "#chan")       == 0);
    CHECK(strcmp(msg.params[1], "hello world") == 0);
}

/* reconstruct_irc_line must emit ':' for the last param when it contains
 * spaces, producing a wire-legal line even when the last slot was filled
 * by the new last-slot absorption path. */
TEST(reconstruct_adds_colon_for_spaced_last_param) {
    const char *line =
        "OS tagline add "
        "w1 w2 w3 w4 w5 w6 w7 w8 w9 w10 w11 w12 "
        "w13 w14";

    struct irc_message msg = parse_ok(line);

    char out[IRC_LINE_MAX];
    reconstruct_irc_line(&msg, out, sizeof(out));

    /* The rebuilt line must carry the excess tokens with a ':' prefix. */
    CHECK(strstr(out, ":w13 w14") != NULL);
    /* And it must NOT silently end at "w12". */
    CHECK(strstr(out, "w13") != NULL);
    CHECK(strstr(out, "w14") != NULL);
}

/* ── main ────────────────────────────────────────────────────────── */

int main(void) {
    RUN(exactly_max_params_parsed_intact);
    RUN(excess_tokens_collected_into_last_param);
    RUN(colon_trailing_param_still_works);
    RUN(reconstruct_adds_colon_for_spaced_last_param);
    return test_report();
}
