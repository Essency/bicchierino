/* test_own_nick_changed.c — own_nick_changed grappa event (issue #155).
 *
 * Bug: `handle_grappa_event` had no case for `own_nick_changed`, so it fell
 * through to the "not yet handled" log and was dropped.  In the common case
 * (user is in channels at the time of a nick change) a per-channel
 * `nick_change` message arrives first and the client sees the NICK.  In the
 * reconnect-with-different-nick case there are no channels, so
 * `own_nick_changed` is the only signal — the client's nick stayed stale.
 *
 * Fix: `handle_grappa_own_nick_changed_event`:
 *   - Filters by `network_id` so multi-network accounts don't apply the
 *     wrong network's event.
 *   - Guards on `new_nick == sess->network_nick` — a no-op when the
 *     channel-level `nick_change` message already arrived first and updated
 *     the nick.
 *   - Sends `:<old>!bicchierino@bicchierino NICK :<new>` to the client and
 *     updates `sess->network_nick`.
 *   - Leaves the DM-listener topic (old folded nick) and sets
 *     `dm_needs_rejoin` exactly as the channel-level `nick_change` self-path
 *     does.
 *
 * Test structure: same as test_sibling_join.c / test_banlist.c — compile
 * connection.c in directly to reach handle_grappa_event (static), use a
 * socketpair to capture IRC output, ws_stub.c to capture bridge frames.
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

/* Build a Phoenix 5-element envelope [join_ref, ref, topic, event, payload].
 * join_ref/ref 42/42 are non-matching so the frame routes to on_event. */
static char *make_event_envelope(const char *payload_json) {
    char *buf = malloc(2048);
    if (!buf) abort();
    snprintf(buf, 2048,
             "[\"42\",\"42\",\"grappa:user:testuser\",\"event\",%s]",
             payload_json);
    return buf;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

/* Core case — issue #155 reconnect scenario: `own_nick_changed` with a nick
 * that differs from `sess->network_nick`.  Client must receive a NICK line
 * and `sess->network_nick` must be updated. */
TEST(own_nick_changed_sends_nick_and_updates_session) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("NickA");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope(
        "{\"kind\":\"own_nick_changed\",\"network_id\":1,\"nick\":\"NickB\"}");
    handle_grappa_event(tx, "NickA", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[1024];
    drain(tx, out, sizeof(out));

    /* Client must see the NICK line in the standard ircd shape */
    CHECK(strstr(out, "NICK :NickB") != NULL);
    CHECK(strstr(out, ":NickA!bicchierino@bicchierino NICK :NickB") != NULL);

    /* Session nick must track the new value */
    CHECK(strcmp(sess.network_nick, "NickB") == 0);

    bridge_close(&br);
}

/* Idempotent guard: `own_nick_changed` whose nick already matches
 * `sess->network_nick` (channel-level `nick_change` already ran) must be
 * a no-op — no NICK line, no session mutation. */
TEST(own_nick_changed_noop_when_nick_already_matches) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("NickA");
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    /* nick field == current network_nick → guard fires */
    char *envelope = make_event_envelope(
        "{\"kind\":\"own_nick_changed\",\"network_id\":1,\"nick\":\"NickA\"}");
    handle_grappa_event(tx, "NickA", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "NICK") == NULL);
    /* nick must be unchanged */
    CHECK(strcmp(sess.network_nick, "NickA") == 0);

    bridge_close(&br);
}

/* Multi-network filter: `own_nick_changed` for a different network_id must
 * be dropped entirely — the user topic fans events for every network the
 * account holds, same filter discipline as `isupport_changed`. */
TEST(own_nick_changed_filtered_by_network_id) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("NickA");
    /* sess.network_id == 1 (from make_sess); event carries network_id=99 */
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope(
        "{\"kind\":\"own_nick_changed\",\"network_id\":99,\"nick\":\"NickB\"}");
    handle_grappa_event(tx, "NickA", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "NICK") == NULL);
    CHECK(strcmp(sess.network_nick, "NickA") == 0);

    bridge_close(&br);
}

/* DM-listener teardown: when `dm_joined` is true, `own_nick_changed` must
 * push `phx_leave` on the old nick's DM topic and set `dm_needs_rejoin`. */
TEST(own_nick_changed_leaves_dm_topic) {
    ws_stub_reset();
    struct grappa_session sess = make_sess("NickA");
    sess.dm_joined   = true;
    sess.dm_join_ref = 7;
    struct bridge br = make_bridge();

    int tx = open_client();
    if (tx < 0) { bridge_close(&br); return; }

    char *envelope = make_event_envelope(
        "{\"kind\":\"own_nick_changed\",\"network_id\":1,\"nick\":\"NickB\"}");
    handle_grappa_event(tx, "NickA", &br, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[1024];
    drain(tx, out, sizeof(out));

    /* NICK must still be sent */
    CHECK(strstr(out, ":NickA!bicchierino@bicchierino NICK :NickB") != NULL);

    /* A phx_leave frame for the old DM topic must have been pushed */
    CHECK_LONG((long)ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(frame != NULL);
    CHECK(strstr(frame, "phx_leave") != NULL);
    /* Topic contains the OLD nick (folded) */
    CHECK(strstr(frame, "nicka") != NULL);

    /* dm_joined cleared, dm_needs_rejoin set */
    CHECK(!sess.dm_joined);
    CHECK(sess.dm_needs_rejoin);

    bridge_close(&br);
}

int main(void) {
    RUN(own_nick_changed_sends_nick_and_updates_session);
    RUN(own_nick_changed_noop_when_nick_already_matches);
    RUN(own_nick_changed_filtered_by_network_id);
    RUN(own_nick_changed_leaves_dm_topic);
    return test_report();
}
