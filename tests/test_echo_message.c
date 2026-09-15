/* test_echo_message.c — own-send echo with the echo-message CAP (#133).
 *
 * Bug: bicchierino advertised `echo-message` in CAP LS but never reflected a
 * client's own PRIVMSG/NOTICE/ACTION back to that client.  A client that
 * negotiated the capability therefore never saw its own sent lines.
 *
 * Root cause: dispatch_grappa_event (via handle_grappa_message_event) always
 * returned early when `consume_pending_self_id` matched the outbound message's
 * id, regardless of whether `cap_echo_message` was set.  Clients that negotiate
 * echo-message rely on the server echo — they suppress their own local display.
 *
 * Fix: the early-return is now gated on `!sess->cap_echo_message`.  The id is
 * still consumed from the ring (so it cannot fire again), but the echo is
 * delivered when the client negotiated the capability.
 *
 * Test structure: same as test_sibling_dm.c — compile connection.c in to reach
 * handle_grappa_message_event (static), drive it over a socketpair, and inspect
 * what the client receives.  Here we also plant an id in pending_self_msg_ids to
 * simulate "this connection just sent the message via send_privmsg_rest".
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

/* Build a minimal session with the given own nick and echo-message cap flag.
 * If seed_id != 0, plant it in pending_self_msg_ids to simulate a just-sent
 * outbound message (the id the REST response would have returned). */
static struct grappa_session make_sess(const char *own_nick, bool echo_message,
                                       long seed_id) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", own_nick);
    sess.cap_echo_message = echo_message;
    if (seed_id) {
        sess.pending_self_msg_ids[0] = seed_id;
        sess.pending_self_msg_count = 1;
    }
    return sess;
}

/* Build a JSON message payload as grappa would broadcast it after accepting
 * a PRIVMSG from this client.  `sender` == own nick (is_self), `id` matches
 * the planted pending_self_msg_ids entry. */
static json_doc *make_own_msg(const char *kind, const char *own_nick,
                               const char *channel, const char *body,
                               long id) {
    char json[1024];
    char body_esc[256];
    json_escape_into(body, body_esc, sizeof(body_esc));
    int n = snprintf(json, sizeof(json),
        "{\"kind\":\"%s\",\"channel\":\"%s\",\"sender\":\"%s\","
        "\"body\":\"%s\",\"id\":%ld,\"server_time\":0,\"meta\":{}}",
        kind, channel, own_nick, body_esc, id);
    char err[128];
    json_doc *d = json_parse(json, (size_t)n, err, sizeof(err));
    if (!d) FAIL("make_own_msg: parse failed");
    return d;
}

/* Render an own-message event and return whatever the client socket receives.
 * `seed_id` is planted in pending_self_msg_ids; the JSON message carries the
 * same id, simulating the round-trip from send_privmsg_rest -> grappa -> WS. */
static void render_own_msg(const char *kind, const char *own_nick,
                            const char *channel, const char *body,
                            long seed_id, bool cap_echo_message,
                            char *out, size_t out_sz) {
    struct grappa_session sess = make_sess(own_nick, cap_echo_message, seed_id);
    int tx = open_client();
    if (tx < 0) { out[0] = '\0'; return; }
    json_doc *d = make_own_msg(kind, own_nick, channel, body, seed_id);
    handle_grappa_message_event(tx, NULL, &sess, json_root(d));
    json_free(d);
    drain(tx, out, out_sz);
}

/* ── without echo-message: own send must be suppressed ───────────────────── */

/* No echo-message: client did its own local echo when it typed.  The broadcast
 * from grappa must be swallowed — the client must NOT see a duplicate. */
TEST(own_privmsg_without_cap_is_suppressed) {
    char buf[512] = {0};
    render_own_msg("privmsg", "me", "#chan", "hello", 42, false, buf, sizeof(buf));
    /* Nothing sent to the client fd. */
    CHECK_STR(buf, "");
}

TEST(own_notice_without_cap_is_suppressed) {
    char buf[512] = {0};
    render_own_msg("notice", "me", "#chan", "a notice", 43, false, buf, sizeof(buf));
    CHECK_STR(buf, "");
}

TEST(own_action_without_cap_is_suppressed) {
    char buf[512] = {0};
    render_own_msg("action", "me", "#chan", "\x01" "ACTION waves\x01",
                   44, false, buf, sizeof(buf));
    CHECK_STR(buf, "");
}

/* ── with echo-message: own send must be echoed back ─────────────────────── */

/* echo-message negotiated: the client suppressed its local display and is
 * waiting for the server to echo the line.  The broadcast must be delivered. */
TEST(own_privmsg_with_cap_is_echoed) {
    char buf[512];
    render_own_msg("privmsg", "me", "#chan", "hello", 42, true, buf, sizeof(buf));
    /* The prefix is bare nick (no user/host in the meta object). */
    CHECK_STR(buf, ":me PRIVMSG #chan :hello\r\n");
}

TEST(own_notice_with_cap_is_echoed) {
    char buf[512];
    render_own_msg("notice", "me", "#chan", "a notice", 43, true, buf, sizeof(buf));
    CHECK_STR(buf, ":me NOTICE #chan :a notice\r\n");
}

TEST(own_action_with_cap_is_echoed) {
    char buf[512];
    render_own_msg("action", "me", "#chan", "\x01" "ACTION waves\x01",
                   44, true, buf, sizeof(buf));
    CHECK_STR(buf, ":me PRIVMSG #chan :\x01" "ACTION waves\x01\r\n");
}

/* ── id consumed even when echoed: second broadcast must not double-echo ──── */

/* After the echo fires, the id must have been removed from pending_self_msg_ids.
 * A hypothetical second broadcast of the same id would NOT be correlated and
 * would therefore fall through as a normal (non-self) render — this test
 * verifies the id was consumed, not retained. */
TEST(own_echo_consumes_id_so_duplicate_is_not_suppressed) {
    struct grappa_session sess = make_sess("me", true, 42);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }
    rx = sv[0];
    int tx = sv[1];

    json_doc *d1 = make_own_msg("privmsg", "me", "#chan", "first", 42);
    handle_grappa_message_event(tx, NULL, &sess, json_root(d1));
    json_free(d1);

    /* id 42 has been consumed.  A second event with the same id is no longer
     * in the ring, so consume_pending_self_id returns false and the message
     * falls through to normal rendering (not suppressed). */
    json_doc *d2 = make_own_msg("privmsg", "me", "#chan", "second", 42);
    handle_grappa_message_event(tx, NULL, &sess, json_root(d2));
    json_free(d2);

    char buf[1024];
    drain(tx, buf, sizeof(buf));
    /* Two echoes: the first (id consumed → echo) and the second (id gone →
     * falls through as is_self but consume returns false → still renders). */
    CHECK(strstr(buf, ":me PRIVMSG #chan :first\r\n") != NULL);
    CHECK(strstr(buf, ":me PRIVMSG #chan :second\r\n") != NULL);
}

int main(void) {
    RUN(own_privmsg_without_cap_is_suppressed);
    RUN(own_notice_without_cap_is_suppressed);
    RUN(own_action_without_cap_is_suppressed);
    RUN(own_privmsg_with_cap_is_echoed);
    RUN(own_notice_with_cap_is_echoed);
    RUN(own_action_with_cap_is_echoed);
    RUN(own_echo_consumes_id_so_duplicate_is_not_suppressed);
    return test_report();
}
