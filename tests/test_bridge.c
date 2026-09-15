/* test_bridge.c — the Phoenix Channels envelope layer.
 *
 * Two things here already cost live bugs, both recorded in bridge.c's own
 * comments, and both are exactly what this suite pins:
 *
 *   1. A join must not mistake an EARLIER topic's after-join snapshot for
 *      its own reply. Matching on "a phx_reply arrived" instead of "a
 *      phx_reply carrying MY ref arrived" is the bug.
 *   2. A frame that isn't this join's reply must reach `on_event`, not
 *      the free() list. An entire channel's member/topic snapshot went
 *      missing that way, reproducibly.
 *
 * The websocket is stubbed (ws_stub.c), so every case is a decision about
 * bytes, with no peer involved.
 */
#include "../src/bridge.h"

#include "test.h"
#include "ws_stub.h"

#include <stdlib.h>
#include <string.h>

/* Collects whatever bridge_join decided was not its answer. Sized above
 * the 32-frame join cap: the give-up case hands every one of those to the
 * callback, and a smaller array turns that test into an abort. */
#define MAX_EVENTS 64
static char *seen_events[MAX_EVENTS];
static size_t seen_count;

static void on_event(void *ctx, const char *payload, size_t payload_len) {
    (void)ctx;
    if (seen_count >= MAX_EVENTS) abort();
    seen_events[seen_count] = strndup(payload, payload_len);
    seen_count++;
}

static void events_reset(void) {
    for (size_t i = 0; i < seen_count; i++) free(seen_events[i]);
    seen_count = 0;
}

static void fresh(struct bridge *br) {
    ws_stub_reset();
    events_reset();
    CHECK(bridge_connect("https://g.example", "tok", "subj", br));
}

/* ── bridge_join ─────────────────────────────────────────────────── */

TEST(a_join_sends_the_envelope_wire_md_describes) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");

    unsigned long ref = 0;
    CHECK(bridge_join(&br, "rooms:1", &ref, NULL, NULL));

    /* join_ref and ref are the SAME new ref on a join — WIRE.md §4. */
    CHECK_LONG(ws_stub_sent_count(), 1);
    CHECK_STR(ws_stub_sent(0), "[\"1\",\"1\",\"rooms:1\",\"phx_join\",{}]");
    CHECK_LONG(ref, 1);

    bridge_close(&br);
}

TEST(refs_increase_across_joins) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"a\",\"phx_reply\",{\"status\":\"ok\"}]");
    ws_stub_queue(WS_TEXT, "[\"2\",\"2\",\"b\",\"phx_reply\",{\"status\":\"ok\"}]");

    unsigned long r1 = 0, r2 = 0;
    CHECK(bridge_join(&br, "a", &r1, NULL, NULL));
    CHECK(bridge_join(&br, "b", &r2, NULL, NULL));
    CHECK_LONG(r1, 1);
    CHECK_LONG(r2, 2);
    CHECK_STR(ws_stub_sent(1), "[\"2\",\"2\",\"b\",\"phx_join\",{}]");

    bridge_close(&br);
}

TEST(a_topic_with_json_metacharacters_is_escaped) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"x\",\"phx_reply\",{\"status\":\"ok\"}]");

    bridge_join(&br, "rooms:\"od\\d", NULL, NULL, NULL);
    CHECK_STR(ws_stub_sent(0), "[\"1\",\"1\",\"rooms:\\\"od\\\\d\",\"phx_join\",{}]");

    bridge_close(&br);
}

TEST(a_reply_that_is_not_ok_fails_the_join) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT,
                  "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"error\","
                  "\"response\":{\"reason\":\"unauthorized\"}}]");

    unsigned long ref = 12345;
    CHECK(!bridge_join(&br, "rooms:1", &ref, NULL, NULL));
    /* The out-param is left alone on failure — a caller that ignored the
     * return value must not find a plausible-looking ref in there. */
    CHECK_LONG(ref, 12345);

    bridge_close(&br);
}

/* Bug 1. The reply to join #2 arrives AFTER join #1's leftover reply.
 * Matching on "is a phx_reply" would take the wrong one. */
TEST(a_reply_carrying_another_joins_ref_is_not_mine) {
    struct bridge br;
    fresh(&br);
    /* Burn ref 1 so the next join is ref 2. */
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"first\",\"phx_reply\",{\"status\":\"ok\"}]");
    CHECK(bridge_join(&br, "first", NULL, NULL, NULL));

    /* Now: a stale reply for ref 1, THEN the real one for ref 2. */
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"first\",\"phx_reply\",{\"status\":\"error\"}]");
    ws_stub_queue(WS_TEXT, "[\"2\",\"2\",\"second\",\"phx_reply\",{\"status\":\"ok\"}]");

    unsigned long ref = 0;
    CHECK(bridge_join(&br, "second", &ref, on_event, NULL));
    CHECK_LONG(ref, 2);
    /* The stale one was not silently dropped either — see bug 2. */
    CHECK_LONG(seen_count, 1);

    bridge_close(&br);
}

/* Bug 2. Unsolicited pushes arriving before the reply must be handed to
 * the callback, in order, and not freed into the void. */
TEST(pushes_before_the_reply_reach_the_callback_in_order) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[null,null,\"rooms:1\",\"bundle_hash\",{\"h\":\"abc\"}]");
    ws_stub_queue(WS_TEXT, "[null,null,\"rooms:1\",\"query_windows_list\",{\"w\":[]}]");
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");

    CHECK(bridge_join(&br, "rooms:1", NULL, on_event, NULL));
    CHECK_LONG(seen_count, 2);
    CHECK(strstr(seen_events[0], "bundle_hash") != NULL);
    CHECK(strstr(seen_events[1], "query_windows_list") != NULL);

    bridge_close(&br);
}

/* A join stops the moment it has its answer: anything queued behind the
 * reply is still there for the steady-state read loop. */
TEST(a_join_stops_reading_once_it_has_its_answer) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");
    ws_stub_queue(WS_TEXT, "[null,null,\"rooms:1\",\"new_message\",{}]");

    CHECK(bridge_join(&br, "rooms:1", NULL, on_event, NULL));
    CHECK_LONG(seen_count, 0);
    CHECK_LONG(ws_stub_unread(), 1);

    bridge_close(&br);
}

TEST(a_malformed_frame_is_skipped_not_fatal) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "{not json at all");
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");

    CHECK(bridge_join(&br, "rooms:1", NULL, NULL, NULL));

    bridge_close(&br);
}

/* Shapes that parse as JSON but are not a v2 envelope: too short, not an
 * array, wrong types. None may be read as a reply, and none may crash. */
TEST(frames_that_are_not_envelopes_are_not_replies) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[]");
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"t\"]");
    ws_stub_queue(WS_TEXT, "{\"status\":\"ok\"}");
    ws_stub_queue(WS_TEXT, "null");
    ws_stub_queue(WS_TEXT, "[1,2,3,4,5]");
    /* A phx_reply, but for somebody else's ref — not this join's answer. */
    ws_stub_queue(WS_TEXT, "[\"99\",\"99\",\"t\",\"phx_reply\",null]");
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");

    CHECK(bridge_join(&br, "rooms:1", NULL, on_event, NULL));
    CHECK_LONG(seen_count, 6);

    bridge_close(&br);
}

/* My ref, my event, but no payload object to read a status out of. That
 * IS this join's reply — so the join must end, and end as a failure,
 * rather than read on and take a later frame as its answer. */
TEST(my_own_reply_without_a_status_fails_the_join) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",null]");
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");

    CHECK(!bridge_join(&br, "rooms:1", NULL, on_event, NULL));
    CHECK_LONG(seen_count, 0);
    CHECK_LONG(ws_stub_unread(), 1); /* stopped at the first reply */

    bridge_close(&br);
}

TEST(a_closed_socket_fails_the_join_instead_of_spinning) {
    struct bridge br;
    fresh(&br);
    /* Nothing queued: the stub reports WS_CLOSED. */
    CHECK(!bridge_join(&br, "rooms:1", NULL, NULL, NULL));

    bridge_close(&br);
}

/* The 32-frame cap: an endlessly chatty server that never answers must
 * fail rather than block forever. */
TEST(a_server_that_never_replies_gives_up) {
    struct bridge br;
    fresh(&br);
    for (int i = 0; i < 40; i++)
        ws_stub_queue(WS_TEXT, "[null,null,\"rooms:1\",\"noise\",{}]");

    CHECK(!bridge_join(&br, "rooms:1", NULL, on_event, NULL));
    /* Stopped at the cap, did not drain all 40. */
    CHECK(ws_stub_unread() > 0);

    bridge_close(&br);
}

/* #14. A topic that does not fit must not be shortened and sent: the
 * result would not be a degraded message, it would be a join on a
 * DIFFERENT channel, reported as success. Nothing goes on the wire. */
TEST(a_topic_that_does_not_fit_is_refused_not_shortened) {
    struct bridge br;
    fresh(&br);
    char big[BRIDGE_TOPIC_MAX + 64];
    memset(big, 't', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    CHECK(!bridge_join(&br, big, NULL, NULL, NULL));
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* The bound has to fit what connection.c can legally build: a topic from
 * subject_name[128] + network_slug[64] + a folded channel[128] reaches
 * 347 bytes, and every one of those is a real join that must still work.
 * A fix that refused these would trade a silent wrong join for an
 * outright broken one. */
TEST(the_longest_topic_connection_c_can_build_still_joins) {
    struct bridge br;
    fresh(&br);

    char subject[128], network[64], channel[128];
    memset(subject, 's', sizeof(subject) - 1);
    subject[sizeof(subject) - 1] = '\0';
    memset(network, 'n', sizeof(network) - 1);
    network[sizeof(network) - 1] = '\0';
    channel[0] = '#';
    memset(channel + 1, 'c', sizeof(channel) - 2);
    channel[sizeof(channel) - 1] = '\0';

    char topic[512];
    int n = snprintf(topic, sizeof(topic), "grappa:user:%s/network:%s/channel:%s", subject, network,
                     channel);
    CHECK(n == 347); /* the number in #14 — if this moves, the bound needs revisiting */

    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"t\",\"phx_reply\",{\"status\":\"ok\"}]");
    CHECK(bridge_join(&br, topic, NULL, NULL, NULL));
    CHECK_LONG(ws_stub_sent_count(), 1);
    /* And it went out whole — the topic in the frame is the one asked for. */
    CHECK(ws_stub_sent(0) && strstr(ws_stub_sent(0), topic) != NULL);

    bridge_close(&br);
}

/* Escaping expands: a `"` costs 2 bytes, a control byte costs 6. A topic
 * that fits raw can therefore still not fit escaped, and that case has to
 * refuse for the same reason. */
TEST(a_topic_that_only_overflows_once_escaped_is_also_refused) {
    struct bridge br;
    fresh(&br);

    char big[BRIDGE_TOPIC_MAX - 32];
    for (size_t i = 0; i < sizeof(big) - 1; i++) big[i] = '"';
    big[sizeof(big) - 1] = '\0';
    CHECK(strlen(big) < BRIDGE_TOPIC_MAX); /* fits raw ... */

    CHECK(!bridge_join(&br, big, NULL, NULL, NULL)); /* ... not escaped */
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* ── bridge_push ─────────────────────────────────────────────────── */

TEST(a_push_on_a_joined_topic_carries_its_join_ref) {
    struct bridge br;
    fresh(&br);
    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"rooms:1\",\"phx_reply\",{\"status\":\"ok\"}]");
    unsigned long join_ref = 0;
    CHECK(bridge_join(&br, "rooms:1", &join_ref, NULL, NULL));

    CHECK(bridge_push(&br, "rooms:1", join_ref, "new_message", "{\"body\":\"hi\"}"));
    CHECK_STR(ws_stub_sent(1),
              "[\"1\",\"2\",\"rooms:1\",\"new_message\",{\"body\":\"hi\"}]");

    bridge_close(&br);
}

/* join_ref 0 is the "not tied to a joined topic" sentinel — encoded as
 * JSON null, not the string "0". The heartbeat push on "phoenix" uses it. */
TEST(a_push_with_no_join_ref_encodes_null_not_zero) {
    struct bridge br;
    fresh(&br);

    CHECK(bridge_push(&br, "phoenix", 0, "heartbeat", "{}"));
    CHECK_STR(ws_stub_sent(0), "[null,\"1\",\"phoenix\",\"heartbeat\",{}]");
    CHECK(strstr(ws_stub_sent(0), "\"0\"") == NULL);

    bridge_close(&br);
}

TEST(a_push_escapes_its_topic_and_event) {
    struct bridge br;
    fresh(&br);

    CHECK(bridge_push(&br, "a\"b", 0, "e\\v", "{}"));
    CHECK_STR(ws_stub_sent(0), "[null,\"1\",\"a\\\"b\",\"e\\\\v\",{}]");

    bridge_close(&br);
}

/* json_payload is interpolated raw, so it is snprintf's return value that
 * catches this one rather than the escaper — but the outcome must be the
 * same: nothing truncated goes on the wire. */
TEST(an_oversized_push_payload_fails_instead_of_sending_a_truncated_frame) {
    struct bridge br;
    fresh(&br);
    char big[BRIDGE_FRAME_MAX + 64];
    memset(big, 'p', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    CHECK(!bridge_push(&br, "rooms:1", 1, "ev", big));
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

TEST(an_oversized_push_topic_or_event_is_refused) {
    struct bridge br;
    fresh(&br);

    char big_topic[BRIDGE_TOPIC_MAX + 8];
    memset(big_topic, 't', sizeof(big_topic) - 1);
    big_topic[sizeof(big_topic) - 1] = '\0';
    CHECK(!bridge_push(&br, big_topic, 1, "ev", "{}"));

    char big_event[BRIDGE_EVENT_MAX + 8];
    memset(big_event, 'e', sizeof(big_event) - 1);
    big_event[sizeof(big_event) - 1] = '\0';
    CHECK(!bridge_push(&br, "rooms:1", 1, big_event, "{}"));

    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

int main(void) {
    RUN(a_join_sends_the_envelope_wire_md_describes);
    RUN(refs_increase_across_joins);
    RUN(a_topic_with_json_metacharacters_is_escaped);
    RUN(a_reply_that_is_not_ok_fails_the_join);
    RUN(a_reply_carrying_another_joins_ref_is_not_mine);
    RUN(pushes_before_the_reply_reach_the_callback_in_order);
    RUN(a_join_stops_reading_once_it_has_its_answer);
    RUN(a_malformed_frame_is_skipped_not_fatal);
    RUN(frames_that_are_not_envelopes_are_not_replies);
    RUN(my_own_reply_without_a_status_fails_the_join);
    RUN(a_closed_socket_fails_the_join_instead_of_spinning);
    RUN(a_server_that_never_replies_gives_up);
    RUN(a_topic_that_does_not_fit_is_refused_not_shortened);
    RUN(the_longest_topic_connection_c_can_build_still_joins);
    RUN(a_topic_that_only_overflows_once_escaped_is_also_refused);
    RUN(a_push_on_a_joined_topic_carries_its_join_ref);
    RUN(a_push_with_no_join_ref_encodes_null_not_zero);
    RUN(a_push_escapes_its_topic_and_event);
    RUN(an_oversized_push_payload_fails_instead_of_sending_a_truncated_frame);
    RUN(an_oversized_push_topic_or_event_is_refused);
    events_reset();
    ws_stub_reset();
    return test_report();
}
