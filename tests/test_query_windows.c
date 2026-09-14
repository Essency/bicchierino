/* test_query_windows.c — query_windows_list diff logic (#120).
 *
 * Bug: handle_grappa_query_windows_list_event was append-only.  grappa
 * broadcasts the FULL current DM window list on every change, so a
 * shrinking list is the wire signal for a closed query window.  The old
 * code only walked the incoming array to ADD newly-seen peers; it never
 * did a reverse pass to REMOVE peers that disappeared, leaving stale
 * PubSub subscriptions open and ratcheting MAX_DM_PEERS upward forever.
 *
 * Fix (also in this commit): a reverse pass after the forward pass.
 * For every entry in dm_peer_names absent from the incoming list:
 *   — push phx_leave on the peer's topic (fire-and-forget, captured by
 *     ws_stub here) and compact the slot.
 * For every entry in pending_dm_peer_names absent from the list:
 *   — just compact the slot (bridge_join never ran, no leave needed).
 *
 * Test structure follows test_server_topic_bootstrap.c: include
 * connection.c to reach the static handler, ws_stub.c at link time to
 * capture bridge_push frames without a network.
 */
#include "test.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ws_stub.h"

/* ── helpers ─────────────────────────────────────────────────────────────── */

static struct grappa_session make_sess(void) {
    struct grappa_session s = {0};
    snprintf(s.subject_name, sizeof(s.subject_name), "testuser");
    snprintf(s.network_nick,  sizeof(s.network_nick),  "testuser");
    snprintf(s.network_slug,  sizeof(s.network_slug),  "testnet");
    s.network_id = 1;
    return s;
}

static struct bridge make_bridge(void) {
    struct bridge br = {0};
    ws_client_connect("unused", "unused", &br.wsc);
    return br;
}

/* Build a query_windows_list payload for network_id=1 listing the given
 * target nicks (NULL-terminated array).  Caller must json_free() the
 * returned doc. */
static json_doc *make_list_payload(const char **nicks) {
    /* {"kind":"query_windows_list","windows":{"1":[{"target_nick":"a"},...]}}} */
    char buf[4096];
    int pos = snprintf(buf, sizeof(buf),
                       "{\"kind\":\"query_windows_list\",\"windows\":{\"1\":[");
    for (int i = 0; nicks[i] != NULL; i++) {
        char esc[128];
        json_escape_into(nicks[i], esc, sizeof(esc));
        int r = snprintf(buf + pos, sizeof(buf) - (size_t)pos,
                         "%s{\"target_nick\":\"%s\",\"network_id\":1,\"opened_at\":\"2024-01-01T00:00:00Z\"}",
                         i > 0 ? "," : "", esc);
        if (r > 0) pos += r;
    }
    snprintf(buf + pos, sizeof(buf) - (size_t)pos, "]}}");

    char err[128];
    json_doc *d = json_parse(buf, strlen(buf), err, sizeof(err));
    if (!d) FAIL("make_list_payload: parse failed");
    return d;
}

/* Convenience: call handle_grappa_query_windows_list_event with a list
 * payload for the given nicks, using the provided sess and bridge. */
static void call_handler(struct grappa_session *sess, struct bridge *br,
                          const char **nicks) {
    json_doc *d = make_list_payload(nicks);
    handle_grappa_query_windows_list_event(sess, br, json_root(d));
    json_free(d);
}

/* ── tests ─────────────────────────────────────────────────────────────────── */

/* Forward pass: a new peer in the list is queued into pending_dm_peer_names. */
TEST(new_peer_is_queued_as_pending) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    const char *nicks[] = {"alice", NULL};
    call_handler(&sess, &br, nicks);

    CHECK_LONG(sess.pending_dm_peer_count, 1);
    CHECK_STR(sess.pending_dm_peer_names[0], "alice");
    CHECK_LONG(sess.dm_peer_count, 0);
    /* No phx_leave should have been sent. */
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* Forward pass: a peer already in pending is not re-queued. */
TEST(known_pending_peer_is_not_re_queued) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    const char *nicks[] = {"alice", NULL};
    call_handler(&sess, &br, nicks);
    CHECK_LONG(sess.pending_dm_peer_count, 1);

    /* Second event with the same list — alice is still pending, must not be
     * added again. */
    call_handler(&sess, &br, nicks);
    CHECK_LONG(sess.pending_dm_peer_count, 1);
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* Reverse pass on dm_peer_names: a joined peer absent from the new list
 * must trigger phx_leave and be removed. */
TEST(closed_joined_peer_gets_phx_leave_and_is_removed) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    /* Simulate a previously bridge_join-ed peer "alice" with join_ref=42. */
    snprintf(sess.dm_peer_names[0], sizeof(sess.dm_peer_names[0]), "alice");
    sess.dm_peer_join_refs[0] = 42;
    sess.dm_peer_count = 1;

    /* New list: empty (alice closed her query window). */
    const char *empty[] = {NULL};
    call_handler(&sess, &br, empty);

    /* alice must be gone. */
    CHECK_LONG(sess.dm_peer_count, 0);

    /* phx_leave must have been pushed for alice's topic. */
    CHECK_LONG(ws_stub_sent_count(), 1);
    /* Frame format: ["<join_ref>","<ref>","<topic>","phx_leave",{}] */
    const char *frame = ws_stub_sent(0);
    CHECK(strstr(frame, "phx_leave") != NULL);
    CHECK(strstr(frame, "grappa:user:testuser/network:testnet/channel:alice") != NULL);
    /* join_ref must match the one we set. */
    CHECK(strncmp(frame, "[\"42\",", 6) == 0);

    bridge_close(&br);
}

/* Reverse pass on dm_peer_names: a peer still in the list must NOT get
 * phx_leave and must stay in dm_peer_names. */
TEST(still_open_joined_peer_stays_and_gets_no_leave) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    snprintf(sess.dm_peer_names[0], sizeof(sess.dm_peer_names[0]), "alice");
    sess.dm_peer_join_refs[0] = 7;
    sess.dm_peer_count = 1;

    const char *nicks[] = {"alice", NULL};
    call_handler(&sess, &br, nicks);

    CHECK_LONG(sess.dm_peer_count, 1);
    CHECK_STR(sess.dm_peer_names[0], "alice");
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* Reverse pass on dm_peer_names: two joined peers, one stays, one closes.
 * Only the closed one gets phx_leave; the remaining one is compacted. */
TEST(partial_close_leaves_one_and_removes_other) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    snprintf(sess.dm_peer_names[0], sizeof(sess.dm_peer_names[0]), "alice");
    sess.dm_peer_join_refs[0] = 10;
    snprintf(sess.dm_peer_names[1], sizeof(sess.dm_peer_names[1]), "bob");
    sess.dm_peer_join_refs[1] = 20;
    sess.dm_peer_count = 2;

    /* bob closed his query window — alice is still open. */
    const char *nicks[] = {"alice", NULL};
    call_handler(&sess, &br, nicks);

    CHECK_LONG(sess.dm_peer_count, 1);
    CHECK_STR(sess.dm_peer_names[0], "alice");
    CHECK_LONG(sess.dm_peer_join_refs[0], 10);

    /* Exactly one phx_leave, for bob. */
    CHECK_LONG(ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(strstr(frame, "grappa:user:testuser/network:testnet/channel:bob") != NULL);
    CHECK(strncmp(frame, "[\"20\",", 6) == 0);

    bridge_close(&br);
}

/* Reverse pass on pending_dm_peer_names: a pending peer absent from the new
 * list is silently dropped with NO phx_leave (bridge_join never ran). */
TEST(closed_pending_peer_is_dropped_without_leave) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    /* "charlie" is in pending (queued but not yet joined). */
    snprintf(sess.pending_dm_peer_names[0], sizeof(sess.pending_dm_peer_names[0]), "charlie");
    sess.pending_dm_peer_count = 1;

    /* New list is empty — charlie closed. */
    const char *empty[] = {NULL};
    call_handler(&sess, &br, empty);

    CHECK_LONG(sess.pending_dm_peer_count, 0);
    CHECK_LONG(ws_stub_sent_count(), 0);  /* no phx_leave */

    bridge_close(&br);
}

/* MAX_DM_PEERS cap is freed by removing closed peers: open N peers, close
 * all, then open N new ones — none should be dropped. */
TEST(closed_peers_release_cap_for_new_ones) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    /* Simulate MAX_DM_PEERS joined peers. */
    for (size_t i = 0; i < MAX_DM_PEERS; i++) {
        snprintf(sess.dm_peer_names[i], sizeof(sess.dm_peer_names[0]), "peer%zu", i);
        sess.dm_peer_join_refs[i] = (unsigned long)(i + 1);
    }
    sess.dm_peer_count = MAX_DM_PEERS;

    /* All windows closed — empty list. */
    const char *empty[] = {NULL};
    call_handler(&sess, &br, empty);

    CHECK_LONG(sess.dm_peer_count, 0);
    /* MAX_DM_PEERS phx_leave frames must have been sent. */
    CHECK_LONG(ws_stub_sent_count(), MAX_DM_PEERS);

    /* Reset stub so we can check the next call cleanly. */
    ws_stub_reset();

    /* Now open two brand new peers — must fit, cap was released. */
    const char *new_nicks[] = {"newpeer0", "newpeer1", NULL};
    call_handler(&sess, &br, new_nicks);

    CHECK_LONG(sess.pending_dm_peer_count, 2);
    CHECK_LONG(ws_stub_sent_count(), 0);  /* no leave for brand-new peers */

    bridge_close(&br);
}

/* Case folding: peer "Alice" in the list matches dm_peer_names slot "alice"
 * (ASCII-fold-lower), so no phx_leave and no duplicate pending entry. */
TEST(case_folding_prevents_leave_for_same_folded_nick) {
    ws_stub_reset();
    struct grappa_session sess = make_sess();
    struct bridge br = make_bridge();

    snprintf(sess.dm_peer_names[0], sizeof(sess.dm_peer_names[0]), "alice");
    sess.dm_peer_join_refs[0] = 5;
    sess.dm_peer_count = 1;

    /* List carries "Alice" (different case) — must match "alice". */
    const char *nicks[] = {"Alice", NULL};
    call_handler(&sess, &br, nicks);

    /* alice must still be present, no leave sent. */
    CHECK_LONG(sess.dm_peer_count, 1);
    CHECK_STR(sess.dm_peer_names[0], "alice");
    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

int main(void) {
    RUN(new_peer_is_queued_as_pending);
    RUN(known_pending_peer_is_not_re_queued);
    RUN(closed_joined_peer_gets_phx_leave_and_is_removed);
    RUN(still_open_joined_peer_stays_and_gets_no_leave);
    RUN(partial_close_leaves_one_and_removes_other);
    RUN(closed_pending_peer_is_dropped_without_leave);
    RUN(closed_peers_release_cap_for_new_ones);
    RUN(case_folding_prevents_leave_for_same_folded_nick);
    return test_report();
}
