/* test_who.c — handle_who multi-param join fix. (#67)
 *
 * Bahamut's extended-WHO syntax (/who +h *.azzurra.chat) arrives at
 * bicchierino as TWO separate params because irc_parse_line splits on
 * spaces. The bug: handle_who only read params[0], silently dropping
 * everything after it — grappa received {"channel":"+h"} and forwarded
 * a bare "WHO +h" with no mask, which the ircd rejected with a syntax
 * error.
 *
 * The fix joins params[0..n-1] with spaces before building the JSON
 * payload. This suite pins the two cases that must both work:
 *
 *   - /who #channel  (single param, must still work identically)
 *   - /who +h *.azzurra.chat  (two params, must reach grappa intact
 *     as "+h *.azzurra.chat")
 *
 * connection.c is compiled in directly (same approach as test_render,
 * test_server_window, test_grappa_admin) to reach handle_who, which is
 * static. ws_stub replaces ws_client at link time so bridge_push's
 * outbound WebSocket frames are captured for inspection rather than
 * hitting a real network.
 */
#include "test.h"
#include "ws_stub.h"

#include "../src/connection.c"

#include <string.h>
#include <stdlib.h>

/* ── helpers ─────────────────────────────────────────────────────── */

/* Build a minimal bridge + session scaffolding for handle_who tests.
 * The bridge must go through bridge_connect so ws_stub initialises its
 * internal state correctly; the session only needs subject_name,
 * network_id, and user_join_ref (all that push_on_user_topic reads). */
static void build_who_scaffolding(struct bridge *br, struct grappa_session *sess) {
    ws_stub_reset();
    /* bridge_connect calls ws_client_connect via ws_stub — always succeeds. */
    if (!bridge_connect("https://grappa.test", "tok", "testsubj", br)) {
        FAIL("bridge_connect");
        return;
    }
    memset(sess, 0, sizeof(*sess));
    snprintf(sess->subject_name, sizeof(sess->subject_name), "testsubj");
    sess->network_id   = 42;
    sess->user_join_ref = 1; /* non-zero so bridge_push uses numeric join_ref */
}

/* Build an irc_message with the given params (up to 4 for these tests). */
static void build_who_msg(struct irc_message *msg, int param_count,
                           const char *p0, const char *p1) {
    memset(msg, 0, sizeof(*msg));
    snprintf(msg->command, sizeof(msg->command), "WHO");
    msg->param_count = param_count;
    if (param_count >= 1 && p0) snprintf(msg->params[0], IRC_LINE_MAX, "%s", p0);
    if (param_count >= 2 && p1) snprintf(msg->params[1], IRC_LINE_MAX, "%s", p1);
}

/* ── tests ───────────────────────────────────────────────────────── */

/* /who #channel — single param, must still work identically after the fix. */
TEST(who_single_param_channel_sends_channel_field) {
    struct bridge br;
    struct grappa_session sess;
    build_who_scaffolding(&br, &sess);

    struct irc_message msg;
    build_who_msg(&msg, 1, "#channel", NULL);

    handle_who(&br, true, &sess, &msg);

    /* bridge_push sends exactly one frame — check it contains the
     * right channel value in the JSON payload. */
    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    CHECK(strstr(frame, "\"#channel\"") != NULL);
    /* Must NOT accidentally contain a second space-joined field. */
    CHECK(strstr(frame, "\"#channel ") == NULL);

    bridge_close(&br);
}

/* /who +h *.azzurra.chat — TWO params — the bug: params[1] was silently
 * dropped and grappa received only "+h". Fix: both params are joined with
 * a space into one "channel" field value. */
TEST(who_two_params_joined_with_space) {
    struct bridge br;
    struct grappa_session sess;
    build_who_scaffolding(&br, &sess);

    struct irc_message msg;
    build_who_msg(&msg, 2, "+h", "*.azzurra.chat");

    handle_who(&br, true, &sess, &msg);

    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    /* The complete two-token argument must appear as one JSON string. */
    CHECK(strstr(frame, "\"+h *.azzurra.chat\"") != NULL);
    /* The old (buggy) behaviour was "+h" alone — must not happen. */
    CHECK(strstr(frame, "\"+h\"") == NULL);

    bridge_close(&br);
}

/* br_connected == false: must be a no-op (no push, no crash). */
TEST(who_not_connected_is_noop) {
    struct bridge br;
    struct grappa_session sess;
    build_who_scaffolding(&br, &sess);

    struct irc_message msg;
    build_who_msg(&msg, 1, "#channel", NULL);

    handle_who(&br, false, &sess, &msg);

    CHECK_LONG((long)ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* param_count == 0: must be a no-op (no push, no crash). */
TEST(who_no_params_is_noop) {
    struct bridge br;
    struct grappa_session sess;
    build_who_scaffolding(&br, &sess);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command, sizeof(msg.command), "WHO");
    msg.param_count = 0;

    handle_who(&br, true, &sess, &msg);

    CHECK_LONG((long)ws_stub_sent_count(), 0);

    bridge_close(&br);
}

int main(void) {
    RUN(who_single_param_channel_sends_channel_field);
    RUN(who_two_params_joined_with_space);
    RUN(who_not_connected_is_noop);
    RUN(who_no_params_is_noop);
    return test_report();
}
