/* test_sibling_dm.c — sibling-client DM rendering with/without echo-message (#123).
 *
 * Bug: a DM sent from a sibling client (same grappa identity, different
 * connection — e.g. the PWA) arrived at an attached IRC client as a fabricated
 * incoming line with the sender name stuffed into the body:
 *
 *   <Peer> <me> text I actually sent from the PWA
 *
 * The rewrite was intentional for vanilla IRC clients that would otherwise drop
 * `:me PRIVMSG Peer :body` (a target they never asked about), but clients that
 * negotiated echo-message already know how to handle the real wire shape and
 * render it as an outbound message in the right query window.
 *
 * Fix: gate the rewrite on !sess->cap_echo_message.  With the cap, send the
 * real `:me PRIVMSG Peer :body` wire shape verbatim.  Without it, keep the old
 * `:Peer PRIVMSG me :<me> body` fallback exactly.
 *
 * Test structure: same as test_channel_prefix.c — compile connection.c in to
 * reach handle_grappa_message_event (static), drive it over a socketpair, and
 * inspect what the client side receives.
 */
#include "test.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static void drain(int tx, char *out, size_t cap) {
    close(tx);
    size_t total = 0;
    ssize_t n;
    while (total + 1 < cap && (n = read(rx, out + total, cap - total - 1)) > 0)
        total += (size_t)n;
    out[total] = '\0';
    close(rx);
    rx = -1;
}

/* Build a minimal session with the given own nick and optional cap flags. */
static struct grappa_session make_sess(const char *own_nick, bool echo_message) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", own_nick);
    sess.cap_echo_message = echo_message;
    return sess;
}

/* Build and parse a JSON message payload for a sibling-client DM.
 *
 * For a sibling outbound DM: sender == own nick, channel == peer nick
 * (NOT own nick and NOT a #channel), body is the message text.
 * No id is planted in pending_self_msg_ids, so consume_pending_self_id
 * returns false and the message is not suppressed as a local echo.
 *
 * Returns a heap-allocated json_doc (caller must json_free). */
static json_doc *make_sibling_dm(const char *kind, const char *own_nick,
                                  const char *peer_nick, const char *body) {
    char json[1024];
    char body_esc[256];
    json_escape_into(body, body_esc, sizeof(body_esc));

    /* id=99 — not in pending_self_msg_ids (zero-initialised), so the
     * consume_pending_self_id guard lets it through to the sibling-DM path. */
    int n = snprintf(json, sizeof(json),
        "{\"kind\":\"%s\",\"channel\":\"%s\",\"sender\":\"%s\","
        "\"body\":\"%s\",\"id\":99,\"server_time\":0,\"meta\":{}}",
        kind, peer_nick, own_nick, body_esc);

    char err[128];
    json_doc *d = json_parse(json, (size_t)n, err, sizeof(err));
    if (!d) FAIL("make_sibling_dm: parse failed");
    return d;
}

/* Renders a sibling-DM event and returns the line the client would see. */
static void render_sibling_dm(const char *kind, const char *own_nick,
                               const char *peer_nick, const char *body,
                               bool cap_echo_message,
                               char *out, size_t out_sz) {
    struct grappa_session sess = make_sess(own_nick, cap_echo_message);
    int tx = open_client();
    if (tx < 0) { out[0] = '\0'; return; }

    json_doc *d = make_sibling_dm(kind, own_nick, peer_nick, body);
    /* br=NULL is safe for privmsg/notice/action — same as test_channel_prefix. */
    handle_grappa_message_event(tx, NULL, &sess, json_root(d));
    json_free(d);
    drain(tx, out, out_sz);
}

/* ── privmsg ─────────────────────────────────────────────────────────────── */

/* Without echo-message: sibling DM is rewritten as an incoming line from the
 * peer, with the real author's nick prepended to the body as a text marker —
 * the only way to land the message in the right query window on a vanilla IRC
 * client that would otherwise ignore a `:me PRIVMSG Peer :body` line. */
TEST(sibling_dm_privmsg_without_cap_rewrites_as_incoming) {
    char buf[1024];
    render_sibling_dm("privmsg", "me", "Peer", "hello",
                      false, buf, sizeof(buf));
    CHECK_STR(buf, ":Peer PRIVMSG me :<me> hello\r\n");
}

/* With echo-message: sibling DM is delivered as the real wire shape.
 * WeeChat 4.10.0 irc-protocol.c:3232 routes `:me PRIVMSG Peer :body` into
 * the peer's query window and renders it as an outgoing message (self_msg +
 * notify_none tags, nick_self colour) — no capability beyond echo-message
 * is required. */
TEST(sibling_dm_privmsg_with_cap_sends_real_wire_shape) {
    char buf[1024];
    render_sibling_dm("privmsg", "me", "Peer", "hello",
                      true, buf, sizeof(buf));
    CHECK_STR(buf, ":me PRIVMSG Peer :hello\r\n");
}

/* ── notice ──────────────────────────────────────────────────────────────── */

TEST(sibling_dm_notice_without_cap_rewrites_as_incoming) {
    char buf[1024];
    render_sibling_dm("notice", "me", "Peer", "a notice",
                      false, buf, sizeof(buf));
    CHECK_STR(buf, ":Peer NOTICE me :<me> a notice\r\n");
}

TEST(sibling_dm_notice_with_cap_sends_real_wire_shape) {
    char buf[1024];
    render_sibling_dm("notice", "me", "Peer", "a notice",
                      true, buf, sizeof(buf));
    CHECK_STR(buf, ":me NOTICE Peer :a notice\r\n");
}

/* ── action ──────────────────────────────────────────────────────────────── */

/* Without echo-message: the body marker must land INSIDE the CTCP frame, after
 * "ACTION ", so the CTCP envelope stays intact and the client reads the action
 * as coming from the peer (not ourself). */
TEST(sibling_dm_action_without_cap_injects_marker_inside_ctcp) {
    char buf[1024];
    render_sibling_dm("action", "me", "Peer", "\x01" "ACTION waves\x01",
                      false, buf, sizeof(buf));
    CHECK_STR(buf, ":Peer PRIVMSG me :\x01" "ACTION <me> waves\x01\r\n");
}

/* With echo-message: the CTCP body is sent verbatim — no marker injection, no
 * rewrite. The client sees `:me PRIVMSG Peer :\x01ACTION waves\x01` and renders
 * it as an outgoing /me from this identity. */
TEST(sibling_dm_action_with_cap_sends_verbatim_ctcp) {
    char buf[1024];
    render_sibling_dm("action", "me", "Peer", "\x01" "ACTION waves\x01",
                      true, buf, sizeof(buf));
    CHECK_STR(buf, ":me PRIVMSG Peer :\x01" "ACTION waves\x01\r\n");
}

/* ── non-regression: incoming DMs and channel messages unaffected ─────────── */

/* An incoming DM (channel == own nick, sender == peer) is NOT a sibling DM.
 * It must not be altered by the echo-message gate regardless of cap state. */
TEST(incoming_dm_unaffected_by_echo_message_cap) {
    /* channel == own nick: this is an incoming DM path, not a sibling one */
    struct grappa_session sess = make_sess("me", true);
    int tx = open_client();
    if (tx < 0) return;

    char json[256];
    int n = snprintf(json, sizeof(json),
        "{\"kind\":\"privmsg\",\"channel\":\"me\",\"sender\":\"Peer\","
        "\"body\":\"hi there\",\"id\":2,\"server_time\":0,\"meta\":{}}");
    char err[64];
    json_doc *d = json_parse(json, (size_t)n, err, sizeof(err));
    if (!d) { FAIL("parse"); return; }

    handle_grappa_message_event(tx, NULL, &sess, json_root(d));
    json_free(d);

    char buf[512];
    drain(tx, buf, sizeof(buf));
    /* For incoming DMs, target is re-keyed to sender (WIRE.md §5) —
     * the query window is keyed by the sender nick, not own nick. */
    CHECK_STR(buf, ":Peer PRIVMSG Peer :hi there\r\n");
}

int main(void) {
    RUN(sibling_dm_privmsg_without_cap_rewrites_as_incoming);
    RUN(sibling_dm_privmsg_with_cap_sends_real_wire_shape);
    RUN(sibling_dm_notice_without_cap_rewrites_as_incoming);
    RUN(sibling_dm_notice_with_cap_sends_real_wire_shape);
    RUN(sibling_dm_action_without_cap_injects_marker_inside_ctcp);
    RUN(sibling_dm_action_with_cap_sends_verbatim_ctcp);
    RUN(incoming_dm_unaffected_by_echo_message_cap);
    return test_report();
}
