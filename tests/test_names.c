/* test_names.c — explicit /NAMES double-reply fix (#147).
 *
 * Bug: grappa fires both `members_seeded` AND `names_reply` when an explicit
 * NAMES lands.  Before the fix both handlers called `render_names_353_366`,
 * giving the client two identical 353/366 pairs a few milliseconds apart.
 *
 * Fix: `handle_names` marks the channel in `sess->pending_names_channels`.
 * `handle_grappa_members_seeded_event` skips rendering when the channel is
 * listed (names_reply will answer).  `handle_grappa_names_reply_event`
 * renders normally and removes the channel from the list.
 *
 * Tests:
 *   1) members_seeded for a names-pending channel → NO 353/366 output.
 *   2) names_reply for a names-pending channel → exactly one 353/366 pair,
 *      pending mark cleared.
 *   3) members_seeded with NO pending mark (JOIN-time seed) → 353/366 still
 *      rendered.
 *
 * Compiled against connection.c directly (same as test_who, test_banlist,
 * test_sibling_join) so the static handlers are reachable.  ws_stub replaces
 * ws_client.c at link time to capture bridge frames without a real network.
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

static struct grappa_session make_sess(const char *own_nick) {
    struct grappa_session s;
    memset(&s, 0, sizeof(s));
    snprintf(s.network_nick, sizeof(s.network_nick), "%s", own_nick);
    snprintf(s.subject_name, sizeof(s.subject_name), "testuser");
    snprintf(s.network_slug, sizeof(s.network_slug), "testnet");
    s.network_id    = 1;
    s.user_join_ref = 1;
    return s;
}

static struct bridge make_bridge(void) {
    struct bridge br;
    memset(&br, 0, sizeof(br));
    ws_client_connect("https://grappa.test", "tok", &br.wsc);
    return br;
}

/* Phoenix 5-element envelope: [join_ref, ref, topic, event, payload].
 * Using join_ref/ref "42"/"42" (not the pending bridge_join's ref=1) so the
 * frame goes to the on_event path, not consumed as a phx_reply. */
static char *make_event_envelope(const char *payload_json) {
    char *buf = malloc(4096);
    if (!buf) abort();
    snprintf(buf, 4096,
             "[\"42\",\"42\",\"grappa:user:testuser\",\"event\",%s]",
             payload_json);
    return buf;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

/* 1) members_seeded with a pending NAMES mark must produce NO 353/366.
 *    names_reply will answer, so rendering here would double the reply. */
TEST(members_seeded_suppressed_when_names_pending) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    /* Simulate what handle_names does: mark #test as names-pending. */
    snprintf(sess.pending_names_channels[0], sizeof(sess.pending_names_channels[0]),
             "#test");
    sess.pending_names_count = 1;

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope(
        "{\"kind\":\"members_seeded\",\"network\":\"testnet\","
        "\"channel\":\"#test\","
        "\"members\":[{\"nick\":\"alice\",\"modes\":[\"@\"]},"
        "             {\"nick\":\"bob\",\"modes\":[]}]}");

    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* No 353 or 366 should have been sent — names_reply will answer. */
    CHECK(strstr(out, " 353 ") == NULL);
    CHECK(strstr(out, " 366 ") == NULL);

    /* Pending mark must still be there — names_reply hasn't arrived yet. */
    CHECK_LONG((long)sess.pending_names_count, 1);

    bridge_close(&br);
}

/* 2) names_reply for a names-pending channel must render exactly one 353/366
 *    pair and clear the pending mark. */
TEST(names_reply_renders_once_and_clears_pending) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    /* Pre-mark #test as names-pending. */
    snprintf(sess.pending_names_channels[0], sizeof(sess.pending_names_channels[0]),
             "#test");
    sess.pending_names_count = 1;

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope(
        "{\"kind\":\"names_reply\",\"network\":\"testnet\","
        "\"channel\":\"#test\","
        "\"members\":[{\"nick\":\"alice\",\"modes\":[\"@\"]},"
        "             {\"nick\":\"bob\",\"modes\":[]}]}");

    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* Exactly one 353 and one 366 must appear. */
    const char *p353 = strstr(out, " 353 ");
    CHECK(p353 != NULL);
    CHECK(strstr(out, " 366 ") != NULL);
    /* No second 353 after the first. */
    if (p353) CHECK(strstr(p353 + 1, " 353 ") == NULL);

    /* 353 carries both nicks; alice should have the @ sigil. */
    CHECK(strstr(out, "@alice") != NULL);
    CHECK(strstr(out, "bob") != NULL);

    /* Pending mark must have been cleared. */
    CHECK_LONG((long)sess.pending_names_count, 0);

    bridge_close(&br);
}

/* 3) members_seeded with NO pending mark (normal JOIN-time seed) must still
 *    render the 353/366 pair — the fix must not break the ordinary path. */
TEST(members_seeded_without_pending_renders_normally) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    /* No pending NAMES mark. */

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope(
        "{\"kind\":\"members_seeded\",\"network\":\"testnet\","
        "\"channel\":\"#test\","
        "\"members\":[{\"nick\":\"alice\",\"modes\":[\"@\"]},"
        "             {\"nick\":\"bob\",\"modes\":[]}]}");

    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* Normal seed: 353/366 must be present. */
    CHECK(strstr(out, " 353 ") != NULL);
    CHECK(strstr(out, " 366 ") != NULL);
    CHECK(strstr(out, "@alice") != NULL);

    bridge_close(&br);
}

/* 4) Case-insensitive pending-mark matching: a client that sends NAMES
 *    with the channel in a different case from what grappa echoes back
 *    must still suppress members_seeded. */
TEST(members_seeded_suppressed_case_insensitive) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("mynick");
    struct bridge br = make_bridge();

    /* Client sent "#TEST" (uppercase); mark it pending as-is. */
    snprintf(sess.pending_names_channels[0], sizeof(sess.pending_names_channels[0]),
             "#TEST");
    sess.pending_names_count = 1;

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    /* grappa sends back "#test" (lowercase). */
    char *envelope = make_event_envelope(
        "{\"kind\":\"members_seeded\",\"network\":\"testnet\","
        "\"channel\":\"#test\","
        "\"members\":[{\"nick\":\"alice\",\"modes\":[]}]}");

    handle_grappa_event(tx, "mynick", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[2048];
    drain(tx, out, sizeof(out));

    /* Suppressed regardless of case difference. */
    CHECK(strstr(out, " 353 ") == NULL);
    CHECK(strstr(out, " 366 ") == NULL);

    bridge_close(&br);
}
