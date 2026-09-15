/* test_sibling_join.c — sibling-client channel join (issue #134).
 *
 * Bug: when a sibling client (e.g. the PWA) joins a channel, grappa broadcasts
 * a `window_pending` event (join in flight) followed by a `joined` event (join
 * confirmed) on the user topic.  Both were unhandled: `window_pending` logged
 * "not yet handled" and `joined` was a deliberate no-op (the optimistic-echo
 * comment applied only to joins THIS connection originated).  The IRC client
 * therefore never saw a JOIN for channels opened by a sibling.
 *
 * Fix: `handle_grappa_joined_event`:
 *   - If the channel is already in sess->channels[] (our own confirmed join),
 *     it remains a no-op — handle_join's optimistic echo already covered it.
 *   - If the channel is NOT in sess->channels[] (sibling-originated join),
 *     add it to the session, subscribe the grappa WS topic (triggering the
 *     post-join snapshot: topic/modes/members → existing handlers emit
 *     332/333/353/366), and send JOIN to the IRC client.
 *
 * `window_pending` is now an explicit no-op: the join is in flight but not
 * yet confirmed; we wait for the terminal `joined` / `join_failed` before
 * updating IRC state.
 *
 * Test structure: same as test_banlist.c / test_who.c — compile connection.c
 * in directly to reach handle_grappa_event (static), use a socketpair to
 * capture IRC output, and ws_stub.c to capture / script the bridge.
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

/* Close the write end, drain all bytes from the read end, NUL-terminate. */
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

/* Build a minimal session.  network_slug must match the `network` field in
 * the event payloads below, otherwise the per-network filter drops the event. */
static struct grappa_session make_sess(const char *own_nick) {
    struct grappa_session s;
    memset(&s, 0, sizeof(s));
    snprintf(s.network_nick,  sizeof(s.network_nick),  "%s", own_nick);
    snprintf(s.subject_name,  sizeof(s.subject_name),  "testuser");
    snprintf(s.network_slug,  sizeof(s.network_slug),  "testnet");
    s.network_id    = 1;
    s.user_join_ref = 1; /* non-zero; bridge_push uses it */
    return s;
}

/* Build a bridge connected through ws_stub.  The stub starts empty; queue
 * frames with ws_stub_queue() BEFORE this call if bridge_join will read
 * them during the connection step itself (not the case here — we queue
 * after connect, before the actual test call). */
static struct bridge make_bridge(void) {
    struct bridge br;
    memset(&br, 0, sizeof(br));
    ws_client_connect("https://grappa.test", "tok", &br.wsc);
    return br;
}

/* Build a Phoenix 5-element envelope as handle_grappa_event expects.
 * [join_ref, ref, topic, event, payload].  join_ref/ref 42/42 are
 * non-matching (not a reply to bridge_join's own ref=1) so the frame goes
 * to on_event rather than being consumed as the phx_reply. */
static char *make_event_envelope(const char *event, const char *payload_json) {
    char *buf = malloc(2048);
    if (!buf) abort();
    snprintf(buf, 2048, "[\"42\",\"42\",\"grappa:user:testuser\",\"%s\",%s]",
             event, payload_json);
    return buf;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

/* Core case — issue #134: a `joined` event for a channel NOT in the session
 * (sibling-originated join) must produce a JOIN line on the IRC client and
 * subscribe the grappa WS topic for that channel. */
TEST(sibling_joined_channel_sends_join_and_subscribes_topic) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    /* Queue the phx_reply that handle_grappa_joined_event's bridge_join call
     * will consume to confirm the per-channel topic subscription. */
    ws_stub_queue(WS_TEXT,
        "[\"1\",\"1\",\"grappa:user:testuser/network:testnet/channel:#foo\","
        "\"phx_reply\",{\"status\":\"ok\"}]");

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    /* `joined` Phoenix envelope for #foo on network testnet — NOT in sess */
    char *envelope = make_event_envelope("event",
        "{\"kind\":\"joined\",\"network\":\"testnet\",\"channel\":\"#foo\",\"state\":\"joined\"}");

    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* IRC client must see JOIN */
    CHECK(strstr(out, "JOIN :#foo") != NULL);
    CHECK(strstr(out, ":mynick!bicchierino@bicchierino JOIN :#foo") != NULL);

    /* bridge_join must have been called: exactly one phx_join frame sent */
    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    CHECK(strstr(frame, "phx_join") != NULL);
    CHECK(strstr(frame, "#foo") != NULL);

    /* Channel must now be tracked in the session */
    CHECK_LONG((long)find_channel_index(&sess, "#foo"), 0);
    CHECK_LONG((long)sess.channel_count, 1);

    bridge_close(&br);
}

/* Already-in-session channel: `joined` for a channel we already know about
 * (own join confirmed) must NOT send a second JOIN or a second phx_join.
 * handle_join's optimistic echo already covered this case. */
TEST(joined_for_own_channel_is_noop) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    /* Pre-register #foo as if handle_join already added it. */
    snprintf(sess.channels[0], sizeof(sess.channels[0]), "#foo");
    sess.channel_count = 1;
    sess.channel_join_refs[0] = 1; /* already subscribed */

    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope("event",
        "{\"kind\":\"joined\",\"network\":\"testnet\",\"channel\":\"#foo\",\"state\":\"joined\"}");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    /* No JOIN echo — handle_join's optimistic echo was the one that mattered */
    CHECK(strstr(out, "JOIN") == NULL);
    /* No extra bridge_join frame */
    CHECK_LONG((long)ws_stub_sent_count(), 0);
    /* Channel count unchanged */
    CHECK_LONG((long)sess.channel_count, 1);

    bridge_close(&br);
}

/* `window_pending` must be a recognized no-op — the join is in flight but
 * not yet confirmed; we wait for `joined` / `join_failed`.  No JOIN,
 * no bridge_join, no "not yet handled" log noise. */
TEST(window_pending_is_recognized_noop) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope("event",
        "{\"kind\":\"window_pending\",\"network\":\"testnet\","
        "\"channel\":\"#bar\",\"state\":\"pending\"}");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "JOIN") == NULL);
    CHECK_LONG((long)ws_stub_sent_count(), 0);
    /* Channel must NOT have been added to the session — we wait for `joined` */
    CHECK_LONG((long)sess.channel_count, 0);

    bridge_close(&br);
}

/* Multi-network filter: `joined` for a DIFFERENT network's channel must be
 * ignored entirely — bicchierino only handles one network per connection,
 * but the user topic fans events for all of the account's networks. */
TEST(joined_for_wrong_network_is_filtered) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope("event",
        "{\"kind\":\"joined\",\"network\":\"othernetwork\","
        "\"channel\":\"#baz\",\"state\":\"joined\"}");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "JOIN") == NULL);
    CHECK_LONG((long)ws_stub_sent_count(), 0);
    CHECK_LONG((long)sess.channel_count, 0);

    bridge_close(&br);
}

/* DM query windows use the peer's nick as the "channel" field (no '#').
 * A `joined` for such a window must not produce a spurious IRC JOIN line. */
TEST(joined_for_dm_window_is_filtered) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope("event",
        "{\"kind\":\"joined\",\"network\":\"testnet\","
        "\"channel\":\"peernick\",\"state\":\"joined\"}");
    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "JOIN") == NULL);
    CHECK_LONG((long)ws_stub_sent_count(), 0);
    CHECK_LONG((long)sess.channel_count, 0);

    bridge_close(&br);
}

int main(void) {
    RUN(sibling_joined_channel_sends_join_and_subscribes_topic);
    RUN(joined_for_own_channel_is_noop);
    RUN(window_pending_is_recognized_noop);
    RUN(joined_for_wrong_network_is_filtered);
    RUN(joined_for_dm_window_is_filtered);
    return test_report();
}
