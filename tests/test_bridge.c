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

/* DEFECT, pinned rather than fixed — this suite does not touch src/.
 *
 * bridge_join escapes the topic into esc_topic[256], which TRUNCATES at
 * 255 bytes, and only then checks whether the assembled frame fits
 * frame[512]. Because the escaped topic can never exceed 255, that check
 * cannot fire on topic length alone: an over-long topic is silently
 * shortened and the join is issued against a DIFFERENT topic than the
 * caller named, reporting success.
 *
 * Not known to be reachable today — topics come from grappa's own
 * discovery (`rooms:<id>`, `$server`), not from downstream client bytes.
 * The assertion below therefore records what the code does now; when the
 * truncation is made to fail closed, this test flips and should be
 * rewritten to expect the refusal. bridge_push has the same escape
 * truncation but a raw json_payload that CAN overflow 512, which is why
 * the push case below really does fail closed. */
TEST(an_oversized_topic_is_silently_truncated_today) {
    struct bridge br;
    fresh(&br);
    char big[600];
    memset(big, 't', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    ws_stub_queue(WS_TEXT, "[\"1\",\"1\",\"t\",\"phx_reply\",{\"status\":\"ok\"}]");
    bridge_join(&br, big, NULL, NULL, NULL);

    CHECK_LONG(ws_stub_sent_count(), 1);
    const char *sent = ws_stub_sent(0);
    CHECK(sent != NULL);
    /* 255 t's made it, the other 344 did not, and nothing said so. */
    CHECK(sent && strstr(sent, "\"phx_join\"") != NULL);
    CHECK(sent && strlen(sent) < 600);

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

TEST(an_oversized_push_fails_instead_of_sending_a_truncated_frame) {
    struct bridge br;
    fresh(&br);
    char big[600];
    memset(big, 'p', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    CHECK(!bridge_push(&br, "rooms:1", 1, "ev", big));
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
    RUN(an_oversized_topic_is_silently_truncated_today);
    RUN(a_push_on_a_joined_topic_carries_its_join_ref);
    RUN(a_push_with_no_join_ref_encodes_null_not_zero);
    RUN(a_push_escapes_its_topic_and_event);
    RUN(an_oversized_push_fails_instead_of_sending_a_truncated_frame);
    events_reset();
    ws_stub_reset();
    return test_report();
}
