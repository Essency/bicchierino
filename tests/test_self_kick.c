/* test_self_kick.c — self-KICK clears the channel from sess->channels[] (#150).
 *
 * Bug: when a grappa `kick` message event arrives and the target is our own
 * nick, bicchierino rendered the KICK line to the IRC client but did NOT
 * remove the channel from sess->channels[].  Every subsequent JOIN for that
 * channel hit the `find_channel_index != channel_count` guard in handle_join
 * and was silently dropped — the client got no reply and grappa never heard
 * about the join.
 *
 * Fix: after rendering the KICK line, if ascii_fold_lower(target) ==
 * folded_own_nick, call remove_channel_at and push a phx_leave on the
 * channel's WS topic — the same cleanup handle_part does.
 *
 * Test structure: compile connection.c in directly (to reach
 * handle_grappa_event, which is static), use ws_stub.c to capture outbound
 * WS frames, and a socketpair for the IRC client output — same pattern as
 * test_sibling_join.c / test_banlist.c.
 */
#include "test.h"
#include "ws_stub.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── helpers ─────────────────────────────────────────────────────────────── */

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

/* Build a session with one channel already joined, plus a valid join_ref so
 * bridge_push can encode the phx_leave frame. */
static struct grappa_session make_sess_with_channel(const char *own_nick, const char *channel) {
    struct grappa_session s;
    memset(&s, 0, sizeof(s));
    snprintf(s.network_nick,  sizeof(s.network_nick),  "%s", own_nick);
    snprintf(s.subject_name,  sizeof(s.subject_name),  "testuser");
    snprintf(s.network_slug,  sizeof(s.network_slug),  "testnet");
    s.network_id    = 1;
    s.user_join_ref = 1;
    /* Pre-register the channel — simulates handle_join having already run. */
    snprintf(s.channels[0], sizeof(s.channels[0]), "%s", channel);
    s.channel_join_refs[0] = 99; /* non-zero so phx_leave carries a real join_ref */
    s.channel_count = 1;
    return s;
}

static struct bridge make_bridge(void) {
    struct bridge br;
    memset(&br, 0, sizeof(br));
    ws_client_connect("https://grappa.test", "tok", &br.wsc);
    return br;
}

/* Phoenix 5-element envelope wrapping a "message" event with the kick
 * sub-kind.  The outer kind is "message" so handle_grappa_event dispatches
 * to handle_grappa_message_event; the inner message.kind is "kick". */
static char *make_kick_envelope(const char *channel, const char *kicked_nick) {
    char *buf = malloc(2048);
    if (!buf) abort();
    snprintf(buf, 2048,
        "[\"42\",\"42\","
        "\"grappa:user:testuser/network:testnet/channel:%s\","
        "\"event\","
        "{\"kind\":\"message\","
        "\"message\":{"
            "\"kind\":\"kick\","
            "\"channel\":\"%s\","
            "\"sender\":\"Kicker\","
            "\"server_time\":0,"
            "\"id\":1,"
            "\"meta\":{\"target\":\"%s\"}"
        "}}]",
        channel, channel, kicked_nick);
    return buf;
}

/* Same but with a kick reason in the body field. */
static char *make_kick_envelope_with_reason(const char *channel,
                                             const char *kicked_nick,
                                             const char *reason) {
    char *buf = malloc(2048);
    if (!buf) abort();
    snprintf(buf, 2048,
        "[\"42\",\"42\","
        "\"grappa:user:testuser/network:testnet/channel:%s\","
        "\"event\","
        "{\"kind\":\"message\","
        "\"message\":{"
            "\"kind\":\"kick\","
            "\"channel\":\"%s\","
            "\"sender\":\"Kicker\","
            "\"server_time\":0,"
            "\"id\":2,"
            "\"meta\":{\"target\":\"%s\"},"
            "\"body\":\"%s\""
        "}}]",
        channel, channel, kicked_nick, reason);
    return buf;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

/* Core case — issue #150: a kick event whose target is our own nick must
 * remove the channel from sess->channels[] so the next JOIN is not dropped. */
TEST(self_kick_removes_channel_from_session) {
    ws_stub_reset();
    struct grappa_session sess = make_sess_with_channel("mynick", "#foo");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_kick_envelope("#foo", "mynick");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* KICK line must have been relayed to the IRC client. */
    CHECK(strstr(out, "KICK #foo mynick") != NULL);

    /* Channel must now be gone from the session — a later JOIN must not
     * hit the "already joined" guard. */
    CHECK_LONG((long)sess.channel_count, 0);
    CHECK_LONG((long)find_channel_index(&sess, "#foo"), 0); /* == channel_count == 0, i.e. "not found" */

    /* phx_leave must have been pushed for the channel's WS topic. */
    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    CHECK(strstr(frame, "phx_leave") != NULL);
    CHECK(strstr(frame, "#foo") != NULL);

    bridge_close(&br);
}

/* Kick with a reason: channel is still removed and phx_leave still fires. */
TEST(self_kick_with_reason_removes_channel) {
    ws_stub_reset();
    struct grappa_session sess = make_sess_with_channel("mynick", "#foo");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_kick_envelope_with_reason("#foo", "mynick", "misbehaving");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "KICK #foo mynick :misbehaving") != NULL);
    CHECK_LONG((long)sess.channel_count, 0);
    CHECK_LONG((long)ws_stub_sent_count(), 1);

    bridge_close(&br);
}

/* Case-insensitive: target "MYNICK" (all-caps) must still match own nick
 * "mynick" (lower-case) via ascii_fold_lower. */
TEST(self_kick_is_case_insensitive) {
    ws_stub_reset();
    struct grappa_session sess = make_sess_with_channel("mynick", "#bar");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_kick_envelope("#bar", "MYNICK");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "KICK #bar MYNICK") != NULL);
    CHECK_LONG((long)sess.channel_count, 0);
    CHECK_LONG((long)ws_stub_sent_count(), 1);

    bridge_close(&br);
}

/* A kick targeting a DIFFERENT nick must NOT remove the channel. */
TEST(other_user_kick_leaves_channel_in_session) {
    ws_stub_reset();
    struct grappa_session sess = make_sess_with_channel("mynick", "#foo");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_kick_envelope("#foo", "othernick");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* KICK line rendered — but channel must still be in the session. */
    CHECK(strstr(out, "KICK #foo othernick") != NULL);
    CHECK_LONG((long)sess.channel_count, 1);

    /* No phx_leave — we are still in the channel. */
    CHECK_LONG((long)ws_stub_sent_count(), 0);

    bridge_close(&br);
}

int main(void) {
    RUN(self_kick_removes_channel_from_session);
    RUN(self_kick_with_reason_removes_channel);
    RUN(self_kick_is_case_insensitive);
    RUN(other_user_kick_leaves_channel_in_session);
    return test_report();
}
