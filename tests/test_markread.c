/* test_markread.c — draft/read-marker MARKREAD bridging (#118).
 *
 * Tests two directions of the read-cursor bridge:
 *
 *   (a) IRC client → grappa: `handle_markread` — query form emits
 *       `timestamp=*`, SET form posts to grappa and echoes the timestamp.
 *       HTTP calls to grappa are not exercised here (would need a live
 *       server); the ring-empty path and the no-hc path are verified.
 *
 *   (b) grappa → IRC client: `handle_grappa_read_cursor_set_event` —
 *       with `cap_read_marker=false` the event is silently dropped; with
 *       it true and a seeded chathistory ring the function emits the
 *       correct `MARKREAD #channel timestamp=<ISO8601>` line.
 *
 * Same compile-connection-in pattern as test_sibling_dm.c.
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

static struct grappa_session make_sess(const char *nick, bool cap_rm) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick,  sizeof(sess.network_nick),  "%s", nick);
    snprintf(sess.network_slug,  sizeof(sess.network_slug),  "testnet");
    snprintf(sess.token,         sizeof(sess.token),         "tok");
    sess.cap_read_marker = cap_rm;
    return sess;
}

/* Build a minimal irc_message with up to 2 params. */
static struct irc_message make_msg(const char *cmd, const char *p0, const char *p1) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command, sizeof(msg.command), "%s", cmd);
    if (p0) {
        snprintf(msg.params[0], sizeof(msg.params[0]), "%s", p0);
        msg.param_count = 1;
    }
    if (p0 && p1) {
        snprintf(msg.params[1], sizeof(msg.params[1]), "%s", p1);
        msg.param_count = 2;
    }
    return msg;
}

/* ── (a) IRC → grappa direction ────────────────────────────────────────────── */

/* MARKREAD with no params → FAIL MARKREAD NEED_MORE_PARAMS */
TEST(markread_missing_target_returns_fail) {
    struct grappa_session sess = make_sess("me", true);
    struct irc_message msg = make_msg("MARKREAD", NULL, NULL);

    int tx = open_client();
    if (tx < 0) return;

    handle_markread(tx, NULL, NULL, &sess, &msg);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "FAIL MARKREAD NEED_MORE_PARAMS") != NULL);
}

/* MARKREAD #chan (no timestamp) → query form → timestamp=* */
TEST(markread_query_form_returns_star) {
    struct grappa_session sess = make_sess("me", true);
    struct irc_message msg = make_msg("MARKREAD", "#chan", NULL);

    int tx = open_client();
    if (tx < 0) return;

    handle_markread(tx, NULL, NULL, &sess, &msg);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    /* Must contain "MARKREAD #chan timestamp=*" */
    CHECK(strstr(buf, "MARKREAD #chan timestamp=*") != NULL);
}

/* MARKREAD #chan timestamp=* → explicit star query form → timestamp=* */
TEST(markread_explicit_star_returns_star) {
    struct grappa_session sess = make_sess("me", true);
    struct irc_message msg = make_msg("MARKREAD", "#chan", "timestamp=*");

    int tx = open_client();
    if (tx < 0) return;

    handle_markread(tx, NULL, NULL, &sess, &msg);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "MARKREAD #chan timestamp=*") != NULL);
}

/* MARKREAD #chan timestamp=<ISO> with empty ring → timestamp=* (no ring entry) */
TEST(markread_set_empty_ring_returns_star) {
    struct grappa_session sess = make_sess("me", true);
    /* ring_count == 0 → chathistory_ring_nearest_id returns false */
    struct irc_message msg = make_msg("MARKREAD", "#chan", "timestamp=2026-01-01T00:00:00.000Z");

    int tx = open_client();
    if (tx < 0) return;

    handle_markread(tx, NULL, NULL, &sess, &msg);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "MARKREAD #chan timestamp=*") != NULL);
}

/* MARKREAD #chan with an invalid timestamp → FAIL MARKREAD INVALID_PARAMS */
TEST(markread_invalid_timestamp_returns_fail) {
    struct grappa_session sess = make_sess("me", true);
    struct irc_message msg = make_msg("MARKREAD", "#chan", "timestamp=not-a-date");

    int tx = open_client();
    if (tx < 0) return;

    handle_markread(tx, NULL, NULL, &sess, &msg);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "FAIL MARKREAD INVALID_PARAMS") != NULL);
}

/* ── (b) grappa → IRC direction ────────────────────────────────────────────── */

/* `read_cursor_set` with cap_read_marker=false → no output emitted. */
TEST(read_cursor_set_without_cap_is_silent) {
    struct grappa_session sess = make_sess("me", false);
    /* cap_read_marker is false — event must be silently dropped. */

    int tx = open_client();
    if (tx < 0) return;

    const char *json_str =
        "{\"kind\":\"read_cursor_set\",\"last_read_message_id\":42,\"badge_count\":3}";
    int len = (int)strlen(json_str);
    char err[64];
    json_doc *d = json_parse(json_str, (size_t)len, err, sizeof(err));
    if (!d) { FAIL("parse"); return; }

    const char *topic = "grappa:user:me/network:testnet/channel:#chan";
    handle_grappa_read_cursor_set_event(tx, NULL, NULL, &sess, json_root(d), topic);
    json_free(d);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    /* Nothing must be written — the cap was not negotiated. */
    CHECK(buf[0] == '\0');
}

/* `read_cursor_set` with cap set and a ring entry matching the cursor id →
 * emits `:bicchierino.local MARKREAD #chan timestamp=<ISO8601>`. */
TEST(read_cursor_set_with_cap_and_ring_hit_emits_markread) {
    struct grappa_session sess = make_sess("me", true);
    /* Seed ring with id=42 → server_time_ms = 1735689600000 (2025-01-01T00:00:00Z) */
    remember_chathistory_ring(&sess, 42L, 1735689600000L);

    int tx = open_client();
    if (tx < 0) return;

    const char *json_str =
        "{\"kind\":\"read_cursor_set\",\"last_read_message_id\":42,\"badge_count\":0}";
    int len = (int)strlen(json_str);
    char err[64];
    json_doc *d = json_parse(json_str, (size_t)len, err, sizeof(err));
    if (!d) { FAIL("parse"); return; }

    const char *topic = "grappa:user:me/network:testnet/channel:#chan";
    handle_grappa_read_cursor_set_event(tx, NULL, NULL, &sess, json_root(d), topic);
    json_free(d);

    char buf[512];
    drain(tx, buf, sizeof(buf));
    /* Must contain "MARKREAD #chan timestamp=2025-" (ring entry year). */
    CHECK(strstr(buf, "MARKREAD #chan timestamp=2025-") != NULL);
}

/* `read_cursor_set` with a topic that has no "/channel:" segment → silent. */
TEST(read_cursor_set_bad_topic_is_silent) {
    struct grappa_session sess = make_sess("me", true);
    remember_chathistory_ring(&sess, 42L, 1735689600000L);

    int tx = open_client();
    if (tx < 0) return;

    const char *json_str =
        "{\"kind\":\"read_cursor_set\",\"last_read_message_id\":42,\"badge_count\":0}";
    int len = (int)strlen(json_str);
    char err[64];
    json_doc *d = json_parse(json_str, (size_t)len, err, sizeof(err));
    if (!d) { FAIL("parse"); return; }

    /* Topic with no channel segment — must not emit anything. */
    handle_grappa_read_cursor_set_event(tx, NULL, NULL, &sess, json_root(d),
                                         "grappa:user:me/network:testnet");
    json_free(d);

    char buf[256];
    drain(tx, buf, sizeof(buf));
    CHECK(buf[0] == '\0');
}

/* ── main ───────────────────────────────────────────────────────────────────── */

int main(void) {
    RUN(markread_missing_target_returns_fail);
    RUN(markread_query_form_returns_star);
    RUN(markread_explicit_star_returns_star);
    RUN(markread_set_empty_ring_returns_star);
    RUN(markread_invalid_timestamp_returns_fail);
    RUN(read_cursor_set_without_cap_is_silent);
    RUN(read_cursor_set_with_cap_and_ring_hit_emits_markread);
    RUN(read_cursor_set_bad_topic_is_silent);
    return test_report();
}
