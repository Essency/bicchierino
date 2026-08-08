/* test_jsonw.c — the JSON string escaper.
 *
 * Small, but it is the ONLY thing standing between a downstream IRC
 * client's bytes and the JSON frames bicchierino builds by hand with
 * snprintf (bridge.c's phx_join/push templates interpolate its output
 * straight into a string literal). A quote or a backslash that survives
 * unescaped does not corrupt a display string — it terminates the JSON
 * string early and hands grappa a different message shape than intended.
 * So the cases here are the ones an IRC nick or channel name can legally
 * contain, plus the truncation boundaries where an escape no longer fits.
 */
#include "../src/jsonw.h"

#include "test.h"

#include <string.h>

TEST(passes_plain_text_through) {
    char dst[64];
    CHECK(json_escape_into("hello world", dst, sizeof(dst)));
    CHECK_STR(dst, "hello world");

    CHECK(json_escape_into("", dst, sizeof(dst)));
    CHECK_STR(dst, "");
}

TEST(escapes_the_two_that_break_the_string) {
    char dst[64];
    CHECK(json_escape_into("say \"hi\"", dst, sizeof(dst)));
    CHECK_STR(dst, "say \\\"hi\\\"");

    CHECK(json_escape_into("back\\slash", dst, sizeof(dst)));
    CHECK_STR(dst, "back\\\\slash");
}

TEST(escapes_the_whitespace_controls_by_name) {
    char dst[64];
    CHECK(json_escape_into("a\nb", dst, sizeof(dst)));
    CHECK_STR(dst, "a\\nb");

    CHECK(json_escape_into("a\rb", dst, sizeof(dst)));
    CHECK_STR(dst, "a\\rb");

    CHECK(json_escape_into("a\tb", dst, sizeof(dst)));
    CHECK_STR(dst, "a\\tb");
}

/* IRC carries these for real: 0x01 delimits CTCP, 0x02/0x03/0x1f are
 * bold/colour/underline. They reach grappa inside message bodies, so
 * they have to come out as \u00xx rather than raw bytes in the JSON. */
TEST(escapes_other_controls_as_u_escapes) {
    char dst[64];
    CHECK(json_escape_into("\x01" "ACTION waves\x01", dst, sizeof(dst)));
    CHECK_STR(dst, "\\u0001ACTION waves\\u0001");

    CHECK(json_escape_into("\x02" "bold\x03" "3colour", dst, sizeof(dst)));
    CHECK_STR(dst, "\\u0002bold\\u00033colour");
}

/* High-bit bytes are NOT escaped: UTF-8 passes through as-is, which is
 * what a JSON string is allowed to carry. An escaper that mangled these
 * would break every non-ASCII nick and message on the network. */
TEST(leaves_utf8_alone) {
    char dst[64];
    CHECK(json_escape_into("caffè — 日本", dst, sizeof(dst)));
    CHECK_STR(dst, "caffè — 日本");
}

/* Truncation still truncates rather than overflowing — and now SAYS so.
 * Each case below sizes dst so the escape cannot fit, and asserts the
 * false return, that the result is NUL-terminated within bounds, and that
 * no half-written escape sequence was left behind: a lone trailing
 * backslash would be worse than truncation, since it escapes the closing
 * quote the caller appends. */
TEST(truncation_is_reported_and_never_splits_an_escape) {
    char dst[8];

    /* 6 chars of room: "abcde" + NUL. The quote's 2 bytes don't fit. */
    memset(dst, 'X', sizeof(dst));
    CHECK(!json_escape_into("abcde\"fgh", dst, 6));
    CHECK_STR(dst, "abcde");
    CHECK(dst[6] == 'X'); /* nothing written past dst_sz */

    memset(dst, 'X', sizeof(dst));
    CHECK(!json_escape_into("abcde\\fgh", dst, 6));
    CHECK_STR(dst, "abcde");
    CHECK(dst[6] == 'X');

    memset(dst, 'X', sizeof(dst));
    CHECK(!json_escape_into("abcde\nfgh", dst, 6));
    CHECK_STR(dst, "abcde");
    CHECK(dst[6] == 'X');

    /* A \u00xx escape needs 6 bytes; only 4 of room here. */
    memset(dst, 'X', sizeof(dst));
    CHECK(!json_escape_into("ab\x01yz", dst, 5));
    CHECK_STR(dst, "ab");
    CHECK(dst[5] == 'X');

    /* No trailing lone backslash in ANY of the above: the last written
     * byte before the NUL is never the escape introducer. */
    json_escape_into("abcde\"fgh", dst, 6);
    size_t n = strlen(dst);
    CHECK(n == 0 || dst[n - 1] != '\\');
}

/* The boundary: exactly enough room reports success, one byte less
 * reports truncation. A predicate that is off by one here would either
 * refuse valid topics or let shortened ones through. */
TEST(the_exact_fit_succeeds_and_one_byte_less_does_not) {
    char dst[16];

    /* "ab\"cd" escapes to 6 bytes, so 7 with the terminator. */
    CHECK(json_escape_into("ab\"cd", dst, 7));
    CHECK_STR(dst, "ab\\\"cd");

    CHECK(!json_escape_into("ab\"cd", dst, 6));

    /* Plain text: 5 bytes plus terminator. */
    CHECK(json_escape_into("abcde", dst, 6));
    CHECK_STR(dst, "abcde");
    CHECK(!json_escape_into("abcde", dst, 5));
}

/* dst_sz == 1 leaves room for the NUL and nothing else — the empty input
 * still fits there, anything else does not. */
TEST(a_one_byte_buffer_holds_only_the_empty_string) {
    char dst[4];
    memset(dst, 'X', sizeof(dst));
    CHECK(!json_escape_into("anything", dst, 1));
    CHECK_STR(dst, "");
    CHECK(dst[1] == 'X');

    CHECK(json_escape_into("", dst, 1));
    CHECK_STR(dst, "");
}

/* dst_sz == 0 has nowhere to put even the terminator: it must write
 * nothing at all. Run under ASan, this is the case that catches a
 * one-past-the-end store. */
TEST(a_zero_byte_buffer_is_not_written_to) {
    char dst[4];
    memset(dst, 'X', sizeof(dst));
    CHECK(!json_escape_into("anything", dst, 0));
    CHECK(dst[0] == 'X');
    CHECK(!json_escape_into("", dst, 0));
    CHECK(dst[0] == 'X');
}

int main(void) {
    RUN(passes_plain_text_through);
    RUN(escapes_the_two_that_break_the_string);
    RUN(escapes_the_whitespace_controls_by_name);
    RUN(escapes_other_controls_as_u_escapes);
    RUN(leaves_utf8_alone);
    RUN(truncation_is_reported_and_never_splits_an_escape);
    RUN(the_exact_fit_succeeds_and_one_byte_less_does_not);
    RUN(a_one_byte_buffer_holds_only_the_empty_string);
    RUN(a_zero_byte_buffer_is_not_written_to);
    return test_report();
}
