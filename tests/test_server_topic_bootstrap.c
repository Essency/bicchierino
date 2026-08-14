/* test_server_topic_bootstrap.c — $server topic join for PREFIX bootstrap (#90).
 *
 * Bug: #82's fix joined `grappa:user:{subject}` (the user topic) before
 * send_welcome, expecting grappa to push `isupport_changed` in the user-topic
 * snapshot.  It never does — grappa v0.14.0's `push_user_snapshot` calls
 * `push_session_snapshot`, which pushes umodes and session identity but NOT
 * isupport.  `push_isupport_if_live` is called exclusively from
 * `push_channel_snapshot` (the per-channel-topic :after_join handler).
 *
 * Fix: Phase 2 of the bootstrap joins a channel-shaped topic — the synthetic
 * `$server` window — BEFORE send_welcome.  `await_channel_snapshot` then
 * poll()-waits (up to ~200ms) for the :after_join snapshot that carries
 * `isupport_changed`, populating the cache so send_welcome's 005 includes
 * PREFIX/CHANMODES.
 *
 * These tests verify the channel-topic path that was missing:
 *
 *   (e) joining the $server topic (channel-shaped) with a queued
 *       isupport_changed push populates the cache via bridge_join's own
 *       on_event callback — the isupport arrives as a non-reply frame WHILE
 *       bridge_join is waiting for its phx_reply, which is the fast-path
 *       exercisable with ws_stub (no poll() needed).
 *
 *   (f) after join_server_topic + await_channel_snapshot, send_welcome emits
 *       the full 005 with PREFIX exactly as case (b) in
 *       test_isupport_bootstrap.c confirms it should when the cache is set.
 *
 * Note: the poll()-wait path of await_channel_snapshot (where the snapshot
 * arrives AFTER the phx_reply, as in real grappa) is not unit-tested here
 * because poll() on ws_stub's fd=-1 is a no-op — the e2e stack tests that
 * path live.  The fd < 0 guard in await_channel_snapshot ensures the wait
 * is skipped cleanly in this environment (cache already set via on_event,
 * or legitimately empty → fallback 005, same as case (c)).
 */
#include "test.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ws_stub.h"

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

static size_t drain(int tx, char *out, size_t cap) {
    close(tx);
    size_t total = 0;
    ssize_t n;
    while (total + 1 < cap && (n = read(rx, out + total, cap - total - 1)) > 0)
        total += (size_t)n;
    out[total] = '\0';
    close(rx);
    rx = -1;
    return total;
}

static struct grappa_session make_sess(void) {
    struct grappa_session s = {0};
    snprintf(s.subject_name, sizeof(s.subject_name), "testuser");
    snprintf(s.network_nick, sizeof(s.network_nick), "testuser");
    snprintf(s.network_slug, sizeof(s.network_slug), "testnet");
    return s;
}

/* Initialise a bridge with the ws_stub (fd=-1, no real socket).
 * Caller must call ws_stub_reset() and ws_stub_queue() BEFORE calling this
 * to ensure the queue is set up before ws_client_connect resets state.
 * bridge_connect would also set br.subject but join_server_topic builds its
 * topic from sess fields directly, so that's not needed here. */
static struct bridge make_bridge(void) {
    struct bridge br = {0};
    ws_client_connect("unused", "unused", &br.wsc);
    /* br.ws_ref starts at 0; bridge_join will use ++br.ws_ref = 1 for the
     * first join.  The phx_reply frame below must carry ref="1". */
    return br;
}

/* A realistic isupport_changed push frame in Phoenix envelope format.
 * join_ref/ref are arbitrary (42/42) — bridge_join compares ref against
 * its OWN expected_ref (1), sees they don't match, and calls on_event.
 * handle_grappa_event then dispatches to handle_grappa_isupport_changed_event
 * which populates the cache. */
static const char ISUPPORT_PUSH_FRAME[] =
    "[\"42\",\"42\","
    "\"grappa:user:testuser/network:testnet/channel:$server\","
    "\"event\","
    "{\"kind\":\"isupport_changed\",\"network_id\":1,"
    "\"chanmodes_a\":[\"b\",\"z\"],"
    "\"chanmodes_b\":[],"
    "\"chanmodes_c\":[\"l\"],"
    "\"chanmodes_d\":[\"i\",\"m\",\"n\",\"p\",\"s\",\"t\"],"
    "\"prefix\":{\"o\":\"@\",\"h\":\"%\",\"v\":\"+\"}}]";

/* The phx_reply for the $server join.  ref="1" matches bridge_join's
 * expected_ref (first ws_ref ever assigned on a fresh bridge). */
static const char SERVER_JOIN_REPLY[] =
    "[\"1\",\"1\","
    "\"grappa:user:testuser/network:testnet/channel:$server\","
    "\"phx_reply\","
    "{\"status\":\"ok\",\"response\":{}}]";

/* ── tests ───────────────────────────────────────────────────────────────── */

/* (e) join_server_topic with a queued isupport push populates the cache.
 *
 * The stub delivers ISUPPORT_PUSH_FRAME before SERVER_JOIN_REPLY.
 * bridge_join sees the push first (ref=42 ≠ expected 1), calls on_event →
 * handle_grappa_event → handle_grappa_isupport_changed_event → cache set.
 * Then bridge_join finds the phx_reply (ref=1) and returns.
 * After join_server_topic returns, await_channel_snapshot short-circuits
 * (cache already set) and does not touch poll(). */
TEST(join_server_topic_populates_cache) {
    ws_stub_reset();
    ws_stub_queue(WS_TEXT, ISUPPORT_PUSH_FRAME);
    ws_stub_queue(WS_TEXT, SERVER_JOIN_REPLY);

    struct bridge br = make_bridge();
    struct grappa_session sess = make_sess();

    /* IRC client fd: join_server_topic dispatches on_event which calls
     * handle_grappa_event which may write to fd in some event kinds.
     * isupport_changed pre-welcome only caches, never writes, but open a
     * socketpair to keep fd valid and avoid SIGPIPE on any write attempt. */
    int tx = open_client();
    if (tx < 0) return;

    join_server_topic(tx, "testuser", &br, &sess);
    drain(tx, (char[4096]){0}, 4096);

    /* Cache must be populated from the isupport push. */
    CHECK(sess.cached_prefix_letters[0] != '\0');
    CHECK_STR(sess.cached_prefix_letters, "ohv");
    CHECK_STR(sess.cached_prefix_sigils,  "@%+");
    CHECK_STR(sess.cached_chanmodes,       "bz,,l,imnpst");

    /* welcome_sent is still false — join_server_topic never calls send_welcome. */
    CHECK(!sess.welcome_sent);
    CHECK(!sess.isupport_005_sent);
}

/* (f) Full pre-welcome sequence: join_server_topic then send_welcome emits
 * the full 005 with PREFIX — the correct client-visible outcome. */
TEST(server_topic_join_then_welcome_emits_full_005) {
    ws_stub_reset();
    ws_stub_queue(WS_TEXT, ISUPPORT_PUSH_FRAME);
    ws_stub_queue(WS_TEXT, SERVER_JOIN_REPLY);

    struct bridge br = make_bridge();
    struct grappa_session sess = make_sess();

    int tx = open_client();
    if (tx < 0) return;

    join_server_topic(tx, "testuser", &br, &sess);
    /* await_channel_snapshot: cache already set, returns immediately. */
    await_channel_snapshot(tx, "testuser", &br, &sess);

    char out[4096];
    send_welcome(tx, "testuser", &sess);
    drain(tx, out, sizeof(out));

    /* The 005 must include PREFIX, CHANMODES, and STATUSMSG. */
    CHECK(strstr(out, "PREFIX=(ohv)@%+") != NULL);
    CHECK(strstr(out, "CHANMODES=bz,,l,imnpst") != NULL);
    CHECK(strstr(out, "STATUSMSG=@%+") != NULL);

    CHECK(sess.welcome_sent);
    CHECK(sess.isupport_005_sent);
}

/* Regression: the user topic alone must NOT populate the cache (#90 root
 * cause).  If the bootstrap only joined the user topic (old behaviour), the
 * stub would deliver no isupport push, the cache stays empty, and
 * send_welcome would emit only the fallback 005.  This test confirms that
 * a sequence with NO isupport frame in the stub → empty cache → fallback. */
TEST(no_isupport_push_leaves_cache_empty) {
    ws_stub_reset();
    /* Queue only the user-topic phx_reply — no isupport push, simulating
     * the user topic's real snapshot which never includes isupport_changed
     * in grappa v0.14.0. */
    ws_stub_queue(WS_TEXT,
                  "[\"1\",\"1\","
                  "\"grappa:user:testuser\","
                  "\"phx_reply\","
                  "{\"status\":\"ok\",\"response\":{}}]");

    struct bridge br = make_bridge();
    struct grappa_session sess = make_sess();

    int tx = open_client();
    if (tx < 0) return;

    join_user_topic(tx, "testuser", &br, &sess);
    /* await_channel_snapshot: fd<0 guard → returns immediately; cache still empty. */
    await_channel_snapshot(tx, "testuser", &br, &sess);

    char out[4096];
    send_welcome(tx, "testuser", &sess);
    drain(tx, out, sizeof(out));

    /* Cache was never populated — must fall back to the minimal 005. */
    CHECK(sess.cached_prefix_letters[0] == '\0');
    CHECK(strstr(out, "PREFIX=") == NULL);
    CHECK(strstr(out, "CHANTYPES=#") != NULL);
    CHECK(strstr(out, "CASEMAPPING=ascii") != NULL);

    CHECK(sess.welcome_sent);
    CHECK(!sess.isupport_005_sent);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    RUN(join_server_topic_populates_cache);
    RUN(server_topic_join_then_welcome_emits_full_005);
    RUN(no_isupport_push_leaves_cache_empty);
    return test_report();
}
