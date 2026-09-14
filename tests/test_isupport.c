/* test_isupport.c — handle_grappa_isupport_changed_event: 005 STATUSMSG. (#83)
 *
 * Bug: bicchierino's 005 hardcoded STATUSMSG=@+ (op/voice only), silently
 * dropping halfop (%) even when the real network's PREFIX carries three
 * levels (ohv → @%+).  The fix derives STATUSMSG from the same `sigils[]`
 * array already built for PREFIX=, so both tokens stay in sync from the
 * real isupport_changed wire event.
 *
 * This suite pins the observable contract for a 3-level PREFIX (op/halfop/
 * voice, the real azzurra/bahamut shape) and the 2-level fallback (op/voice
 * only), confirming PREFIX= and STATUSMSG= always match.
 *
 * connection.c is compiled in to reach handle_grappa_isupport_changed_event,
 * which is static — the same approach test_whois and test_server_window use.
 * A socketpair provides the fd the function writes to.
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

/* Closes the write end, drains everything the function sent, returns length. */
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

/* ── helpers ─────────────────────────────────────────────────────── */

/* Invoke handle_grappa_isupport_changed_event with a JSON payload and
 * capture what the function writes.  The session starts with
 * isupport_005_sent == false so the function proceeds; the flag is set
 * true afterward (per the real code), which is why each call needs a fresh
 * session. */
static void render_005(const char *payload_json, char *out, size_t out_sz) {
    char err[128];
    json_doc *d = json_parse(payload_json, strlen(payload_json), err, sizeof(err));
    if (!d) {
        FAIL("render_005: json_parse failed");
        out[0] = '\0';
        return;
    }
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    /* welcome_sent = true: simulate the Case B path (post-welcome) so the
     * handler sends immediately rather than caching.  isupport_005_sent
     * stays false so the dedup guard does not fire. */
    sess.welcome_sent = true;

    int tx = open_client();
    if (tx < 0) {
        json_free(d);
        out[0] = '\0';
        return;
    }
    handle_grappa_isupport_changed_event(tx, "testnick", &sess, json_root(d));
    json_free(d);
    drain(tx, out, out_sz);
}

/* ── tests ───────────────────────────────────────────────────────── */

/* 3-level PREFIX (op/halfop/voice — the real azzurra/bahamut shape, captured
 * from ruby.azzurra.chat: PREFIX=(ohv)@%+).
 *
 * Before the fix: STATUSMSG=@+ (halfop % dropped).
 * After the fix:  STATUSMSG=@%+ (all three levels, matching PREFIX). */
TEST(statusmsg_matches_prefix_sigils_for_three_level_prefix) {
    char buf[1024];
    render_005("{\"chanmodes_a\":[\"b\"],\"chanmodes_b\":[\"k\"],"
               "\"chanmodes_c\":[\"l\"],\"chanmodes_d\":[\"m\",\"n\",\"t\"],"
               "\"prefix\":{\"o\":\"@\",\"h\":\"%\",\"v\":\"+\"}}",
               buf, sizeof(buf));

    /* STATUSMSG must contain the halfop sigil — this was the missing piece. */
    CHECK(strstr(buf, "STATUSMSG=@%+") != NULL);
    /* PREFIX must also carry the same three sigils. */
    CHECK(strstr(buf, "PREFIX=(ohv)@%+") != NULL);
    /* Sanity: the 005 numeric was actually sent. */
    CHECK(strstr(buf, " 005 ") != NULL);
}

/* 2-level PREFIX (op/voice only — a network without halfop).  STATUSMSG
 * must match: @+ (not @%+, not @+ hardcoded by coincidence with the old
 * bug, but dynamically matching whatever PREFIX is). */
TEST(statusmsg_matches_prefix_sigils_for_two_level_prefix) {
    char buf[1024];
    render_005("{\"chanmodes_a\":[\"b\"],\"chanmodes_b\":[\"k\"],"
               "\"chanmodes_c\":[\"l\"],\"chanmodes_d\":[\"m\",\"n\",\"t\"],"
               "\"prefix\":{\"o\":\"@\",\"v\":\"+\"}}",
               buf, sizeof(buf));

    CHECK(strstr(buf, "STATUSMSG=@+") != NULL);
    CHECK(strstr(buf, "PREFIX=(ov)@+") != NULL);
    /* Halfop must not appear anywhere in STATUSMSG. */
    const char *sm = strstr(buf, "STATUSMSG=");
    CHECK(sm != NULL);
    /* The STATUSMSG token ends at the next space; % must not be in it. */
    const char *sm_end = sm ? strchr(sm, ' ') : NULL;
    if (sm_end) {
        size_t sm_len = (size_t)(sm_end - sm);
        char sm_tok[64];
        if (sm_len < sizeof(sm_tok)) {
            memcpy(sm_tok, sm, sm_len);
            sm_tok[sm_len] = '\0';
            CHECK(strchr(sm_tok, '%') == NULL);
        }
    }
}

/* isupport_005_sent guard: a second call with the same session must not
 * send a second 005 — the guard fires after the first send. */
TEST(isupport_005_is_sent_only_once_per_session) {
    char err[128];
    const char *payload_json =
        "{\"chanmodes_a\":[\"b\"],\"chanmodes_b\":[\"k\"],"
        "\"chanmodes_c\":[\"l\"],\"chanmodes_d\":[\"m\"],"
        "\"prefix\":{\"o\":\"@\",\"h\":\"%\",\"v\":\"+\"}}";

    json_doc *d = json_parse(payload_json, strlen(payload_json), err, sizeof(err));
    if (!d) { FAIL("json_parse"); return; }

    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    /* welcome_sent = true: exercise the Case B (post-welcome) send path. */
    sess.welcome_sent = true;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); json_free(d); return; }
    rx = sv[0];
    int tx = sv[1];

    /* First call — must emit 005. */
    handle_grappa_isupport_changed_event(tx, "nick", &sess, json_root(d));
    /* Second call — isupport_005_sent is now true; must be a no-op. */
    handle_grappa_isupport_changed_event(tx, "nick", &sess, json_root(d));
    json_free(d);

    char buf[2048];
    drain(tx, buf, sizeof(buf));

    /* Only one 005 must appear in the output. */
    const char *first = strstr(buf, " 005 ");
    CHECK(first != NULL);
    const char *second = first ? strstr(first + 1, " 005 ") : NULL;
    CHECK(second == NULL);
}

/* ── network_id filter tests (#124) ─────────────────────────────── */

/* Regression for #124: on a two-network account the user topic delivers
 * isupport_changed for EVERY network the account holds.  The handler must
 * drop events whose network_id does not match sess->network_id, so the
 * first network grappa happens to iterate cannot latch the wrong 005 into
 * a sibling connection. */

/* Payload with a MATCHING network_id: 005 must be sent. */
TEST(network_id_match_sends_005) {
    char err[128];
    /* Payload includes network_id=7; session has network_id=7 → match → send. */
    const char *json =
        "{\"kind\":\"isupport_changed\",\"network_id\":7,"
        "\"chanmodes_a\":[\"b\"],\"chanmodes_b\":[\"k\"],"
        "\"chanmodes_c\":[\"l\"],\"chanmodes_d\":[\"m\",\"n\"],"
        "\"prefix\":{\"o\":\"@\",\"v\":\"+\"}}";
    json_doc *d = json_parse(json, strlen(json), err, sizeof(err));
    if (!d) { FAIL("json_parse"); return; }

    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.welcome_sent = true;
    sess.network_id   = 7;   /* matches payload */

    char out[1024];
    int tx = open_client();
    if (tx < 0) { json_free(d); return; }

    handle_grappa_isupport_changed_event(tx, "nick", &sess, json_root(d));
    json_free(d);
    size_t len = drain(tx, out, sizeof(out));

    /* Event for OUR network: 005 must be present. */
    CHECK(len > 0);
    CHECK(strstr(out, " 005 ") != NULL);
}

/* Payload with a MISMATCHED network_id: handler must return early, no
 * 005 sent, isupport_005_sent must NOT latch (so the correct event can
 * still send later). */
TEST(network_id_mismatch_drops_event) {
    char err[128];
    /* Payload is for network_id=2; session is for network_id=1 → mismatch. */
    const char *json =
        "{\"kind\":\"isupport_changed\",\"network_id\":2,"
        "\"chanmodes_a\":[\"b\"],\"chanmodes_b\":[\"k\"],"
        "\"chanmodes_c\":[\"l\"],\"chanmodes_d\":[\"m\",\"n\"],"
        "\"prefix\":{\"o\":\"@\",\"h\":\"%\",\"v\":\"+\"}}";
    json_doc *d = json_parse(json, strlen(json), err, sizeof(err));
    if (!d) { FAIL("json_parse"); return; }

    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.welcome_sent = true;
    sess.network_id   = 1;   /* does NOT match payload's network_id=2 */

    char out[1024];
    int tx = open_client();
    if (tx < 0) { json_free(d); return; }

    handle_grappa_isupport_changed_event(tx, "nick", &sess, json_root(d));
    json_free(d);
    size_t len = drain(tx, out, sizeof(out));

    /* Event for a SIBLING network: must be silently dropped. */
    CHECK(len == 0);
    /* The latch must NOT have fired — a subsequent matching event must
     * still be able to send. */
    CHECK(!sess.isupport_005_sent);
}

int main(void) {
    RUN(statusmsg_matches_prefix_sigils_for_three_level_prefix);
    RUN(statusmsg_matches_prefix_sigils_for_two_level_prefix);
    RUN(isupport_005_is_sent_only_once_per_session);
    RUN(network_id_match_sends_005);
    RUN(network_id_mismatch_drops_event);
    return test_report();
}
