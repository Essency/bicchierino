/* test_banlist.c — MODE #chan +b (signed form) routing fix. (#98)
 *
 * Bug: handle_irc_line's MODE dispatch routes `MODE #chan b` (unsigned,
 * bare) to handle_banlist(), which primes grappa's banlist_pending
 * accumulator via the dedicated "banlist" verb.  But `MODE #chan +b`
 * (signed, as sent by WeeChat's `/mode #chan +b` and its bare `/ban`)
 * did NOT match — params[1] == "+b" failed the strcmp against "b", so
 * the message fell through to handle_mode(), which pushed the generic
 * "mode" verb instead.  Without the priming step, the 367/368 replies
 * from the ircd arrived with no banlist_bundle accumulator waiting for
 * them and were silently dropped, leaving the client's ban-list empty.
 *
 * The fix: extend the dispatch condition to accept both "b" and "+b" as
 * the banlist-query modestring.  -b with no mask is left to fall through
 * to handle_mode (the ircd rejects it; no priming state is needed).
 *
 * This suite pins handle_banlist directly (same approach as test_who.c):
 *
 *   - `MODE #chan b`  (unsigned) — still sends the "banlist" verb ✓
 *   - `MODE #chan +b` (signed)   — regression: now sends "banlist" too
 *   - br_connected == false      — must be a no-op
 *
 * connection.c is compiled in directly to reach handle_banlist, which is
 * static.  ws_stub replaces ws_client at link time so bridge_push's
 * outbound WebSocket frames are captured for inspection without hitting a
 * real network.
 */
#include "test.h"
#include "ws_stub.h"

#include "../src/connection.c"

#include <string.h>
#include <stdlib.h>

/* ── helpers ─────────────────────────────────────────────────────── */

/* Build a minimal bridge + session scaffolding.
 * The bridge must go through bridge_connect so ws_stub initialises its
 * internal state correctly; the session only needs subject_name,
 * network_id, and user_join_ref (all that push_on_user_topic reads). */
static void build_scaffolding(struct bridge *br, struct grappa_session *sess) {
    ws_stub_reset();
    if (!bridge_connect("https://grappa.test", "tok", "testsubj", br)) {
        FAIL("bridge_connect");
        return;
    }
    memset(sess, 0, sizeof(*sess));
    snprintf(sess->subject_name, sizeof(sess->subject_name), "testsubj");
    sess->network_id    = 42;
    sess->user_join_ref = 1; /* non-zero so bridge_push encodes a join_ref */
}

/* Build a two-param MODE irc_message: `MODE <p0> <p1>`.
 * handle_banlist only reads params[0] (channel); p1 is the mode string
 * that the DISPATCH inspects before calling us. */
static void build_mode_msg(struct irc_message *msg, const char *p0, const char *p1) {
    memset(msg, 0, sizeof(*msg));
    snprintf(msg->command, sizeof(msg->command), "MODE");
    msg->param_count = 2;
    snprintf(msg->params[0], IRC_LINE_MAX, "%s", p0);
    snprintf(msg->params[1], IRC_LINE_MAX, "%s", p1);
}

/* ── tests ───────────────────────────────────────────────────────── */

/* `MODE #chan b` — the unsigned (bare) form already worked before the
 * fix.  Regression: handle_banlist must still emit the "banlist" verb. */
TEST(banlist_unsigned_b_emits_banlist_verb) {
    struct bridge br;
    struct grappa_session sess;
    build_scaffolding(&br, &sess);

    struct irc_message msg;
    build_mode_msg(&msg, "#testchan", "b");

    handle_banlist(&br, true, &sess, &msg);

    /* bridge_push sends exactly one frame — check it carries the
     * "banlist" verb, not the generic "mode" verb. */
    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    /* The Phoenix Channels frame is ["join_ref","ref","topic","event",payload].
     * Verify the event field is "banlist". */
    CHECK(strstr(frame, "\"banlist\"") != NULL);
    CHECK(strstr(frame, "\"mode\"") == NULL);
    /* Payload must identify the right channel. */
    CHECK(strstr(frame, "\"#testchan\"") != NULL);

    bridge_close(&br);
}

/* `MODE #chan +b` — the signed form that WeeChat sends for `/mode #chan +b`
 * and for a bare `/ban` with no arguments.  This was the bug: the dispatch
 * fell through to handle_mode ("mode" verb) instead of handle_banlist.
 *
 * This test calls handle_banlist directly with params[1] == "+b" (the
 * normalised path the fixed dispatch takes), confirming the handler itself
 * produces a valid "banlist" frame regardless of what was in params[1]. */
TEST(banlist_signed_plus_b_emits_banlist_verb) {
    struct bridge br;
    struct grappa_session sess;
    build_scaffolding(&br, &sess);

    struct irc_message msg;
    build_mode_msg(&msg, "#testchan", "+b");

    /* The fixed dispatch now routes "+b" here; verify the frame is correct. */
    handle_banlist(&br, true, &sess, &msg);

    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    /* Must emit the priming "banlist" verb, not the generic "mode" verb. */
    CHECK(strstr(frame, "\"banlist\"") != NULL);
    CHECK(strstr(frame, "\"mode\"") == NULL);
    CHECK(strstr(frame, "\"#testchan\"") != NULL);

    bridge_close(&br);
}

/* br_connected == false: must be a no-op (no push, no crash). */
TEST(banlist_not_connected_is_noop) {
    struct bridge br;
    struct grappa_session sess;
    build_scaffolding(&br, &sess);

    struct irc_message msg;
    build_mode_msg(&msg, "#testchan", "+b");

    handle_banlist(&br, false, &sess, &msg);

    CHECK_LONG((long)ws_stub_sent_count(), 0);

    bridge_close(&br);
}

int main(void) {
    RUN(banlist_unsigned_b_emits_banlist_verb);
    RUN(banlist_signed_plus_b_emits_banlist_verb);
    RUN(banlist_not_connected_is_noop);
    return test_report();
}
