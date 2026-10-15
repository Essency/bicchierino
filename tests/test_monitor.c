/* test_monitor.c — MONITOR / ISON presence bridging (issue #157).
 *
 * Bug: bicchierino had no ISON handler, so ISON went upstream via `"raw"`
 * and the 303 RPL_ISON reply was silently dropped by grappa's EventRouter
 * (it folds 303s into its own sweep and drops 303s with no sweep in flight).
 * grappa's own presence tracking (notify_list / presence_changed /
 * presence_snapshot events) also went unhandled, so online/offline
 * transitions were never relayed to the IRC client as 730/731.
 *
 * Fix: three new event handlers seed the session's presence map, and two
 * new command handlers (ISON, MONITOR) answer from it locally.  MONITOR=64
 * is advertised in 005 so MONITOR-capable clients switch from ISON polling
 * to push presence automatically.
 *
 * Test structure: compile connection.c in directly (same approach as
 * test_isupport, test_sibling_join, test_banlist — all reach static
 * functions that way).  A socketpair captures IRC output; http_stub.c
 * provides a minimal http_client_request stub (used by MONITOR +/-/C REST
 * calls); ws_stub.c replaces ws_client.c at link time (bridge functions
 * used by connection.c, not exercised in these tests but needed for linking).
 */
#include "test.h"
#include "http_stub.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── helpers ────────────────────────────────────────────────────────────── */

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

/* Build an irc_message with up to two params.  irc_message uses fixed char
 * arrays (char command[32], char params[15][512]) — same approach as
 * test_markread.c's make_msg; assignment with '=' is not valid for arrays. */
static struct irc_message make_msg(const char *cmd, const char *p0, const char *p1) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command, sizeof(msg.command), "%s", cmd);
    if (p0) { snprintf(msg.params[0], sizeof(msg.params[0]), "%s", p0); msg.param_count = 1; }
    if (p1) { snprintf(msg.params[1], sizeof(msg.params[1]), "%s", p1); msg.param_count = 2; }
    return msg;
}

/* Minimal session with network_id=1, nick="mynick". */
static struct grappa_session make_sess(void) {
    struct grappa_session s;
    memset(&s, 0, sizeof(s));
    snprintf(s.network_nick,  sizeof(s.network_nick),  "mynick");
    snprintf(s.subject_name,  sizeof(s.subject_name),  "testuser");
    snprintf(s.network_slug,  sizeof(s.network_slug),  "testnet");
    s.network_id    = 1;
    s.user_join_ref = 1;
    return s;
}

/* Wrap a payload in the Phoenix 5-element envelope handle_grappa_event
 * expects: [join_ref, ref, topic, "event", payload]. */
static char *make_grappa_envelope(const char *payload_json) {
    char *buf = malloc(4096);
    if (!buf) abort();
    snprintf(buf, 4096,
             "[\"42\",\"42\",\"grappa:user:testuser\",\"event\",%s]",
             payload_json);
    return buf;
}

/* ── tests ──────────────────────────────────────────────────────────────── */

/* Issue #157 core repro: ISON for a nick that grappa says is online must
 * return a 303 with that nick.  This is the exact scenario from the issue:
 * "a nick that is certainly online gets no reply at all" — the fix makes
 * ISON answer from the presence map instead of going upstream. */
TEST(ison_returns_online_nick) {
    struct grappa_session sess = make_sess();

    /* Seed presence: TrackMe is online. */
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "TrackMe");
    sess.monitor_presence[0] = 'o';
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg = make_msg("ISON", "TrackMe", NULL);
    handle_ison(tx, "mynick", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));

    /* Must reply 303 with TrackMe in the list */
    CHECK(strstr(out, "303") != NULL);
    CHECK(strstr(out, "TrackMe") != NULL);
}

/* ISON for an offline nick returns 303 with empty body (omit offline nicks). */
TEST(ison_omits_offline_nick) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Offline");
    sess.monitor_presence[0] = 'f';
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg = make_msg("ISON", "Offline", NULL);
    handle_ison(tx, "mynick", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 303 must be sent, but the nick must NOT appear */
    CHECK(strstr(out, "303") != NULL);
    CHECK(strstr(out, "Offline") == NULL);
}

/* ISON with multiple space-separated nicks in a trailing param — only online
 * ones appear in 303.  WeeChat uses this form: `ISON :nick1 nick2 nick3`. */
TEST(ison_mixed_online_offline) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Online1");
    sess.monitor_presence[0] = 'o';
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Offline1");
    sess.monitor_presence[1] = 'f';
    snprintf(sess.monitor_nicks[2], sizeof(sess.monitor_nicks[2]), "Online2");
    sess.monitor_presence[2] = 'o';
    sess.monitor_count = 3;

    int tx = open_client();
    if (tx < 0) return;

    /* Trailing-param form (colon stripped by irc_parse_line before we get here,
     * but the space-separated content is still a single param). */
    struct irc_message msg = make_msg("ISON", "Online1 Offline1 Online2", NULL);
    handle_ison(tx, "mynick", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "Online1") != NULL);
    CHECK(strstr(out, "Online2") != NULL);
    CHECK(strstr(out, "Offline1") == NULL);
}

/* ISON is case-insensitive: client sends "trackme", grappa stored "TrackMe". */
TEST(ison_case_insensitive) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "TrackMe");
    sess.monitor_presence[0] = 'o';
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg = make_msg("ISON", "trackme", NULL);
    handle_ison(tx, "mynick", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 303 returned with the DISPLAY form (TrackMe, not the folded form) */
    CHECK(strstr(out, "303") != NULL);
    CHECK(strstr(out, "TrackMe") != NULL);
}

/* presence_changed event (non-initial, online) must push 730 to the client. */
TEST(presence_changed_online_sends_730) {
    struct grappa_session sess = make_sess();

    /* Pre-seed the monitor list — presence_changed only updates an existing
     * entry; an absent entry is silently ignored (same discipline as a real
     * ircd: a presence report for a nick you're not watching is irrelevant). */
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "WatchedNick");
    sess.monitor_presence[0] = 'u'; /* unknown initially */
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    const char *payload_json =
        "{\"kind\":\"presence_changed\","
        "\"network_id\":1,"
        "\"nick\":\"WatchedNick\","
        "\"presence\":\"online\","
        "\"initial\":false,"
        "\"source\":\"watch\","
        "\"ts\":\"2026-10-15T12:00:00Z\"}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 730 RPL_MONONLINE must be sent */
    CHECK(strstr(out, "730") != NULL);
    CHECK(strstr(out, "WatchedNick") != NULL);
    /* Presence must be updated in the session */
    CHECK(sess.monitor_presence[0] == 'o');
}

/* presence_changed event (non-initial, offline) must push 731 to the client. */
TEST(presence_changed_offline_sends_731) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "WatchedNick");
    sess.monitor_presence[0] = 'o'; /* was online */
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    const char *payload_json =
        "{\"kind\":\"presence_changed\","
        "\"network_id\":1,"
        "\"nick\":\"WatchedNick\","
        "\"presence\":\"offline\","
        "\"initial\":false,"
        "\"source\":\"watch\","
        "\"ts\":\"2026-10-15T12:00:00Z\"}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 731 RPL_MONOFFLINE must be sent */
    CHECK(strstr(out, "731") != NULL);
    CHECK(strstr(out, "WatchedNick") != NULL);
    CHECK(sess.monitor_presence[0] == 'f');
}

/* presence_changed with initial=true must NOT push 730/731 (baseline snapshot,
 * not a user-visible transition). */
TEST(presence_changed_initial_is_silent) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "WatchedNick");
    sess.monitor_presence[0] = 'u';
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    const char *payload_json =
        "{\"kind\":\"presence_changed\","
        "\"network_id\":1,"
        "\"nick\":\"WatchedNick\","
        "\"presence\":\"online\","
        "\"initial\":true,"
        "\"source\":\"watch\","
        "\"ts\":\"2026-10-15T12:00:00Z\"}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[512];
    drain(tx, out, sizeof(out));

    /* No 730/731 — initial snapshots are silent */
    CHECK(strstr(out, "730") == NULL);
    CHECK(strstr(out, "731") == NULL);
    /* But presence IS updated */
    CHECK(sess.monitor_presence[0] == 'o');
}

/* presence_changed for a different network_id is ignored. */
TEST(presence_changed_wrong_network_ignored) {
    struct grappa_session sess = make_sess(); /* network_id = 1 */

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "WatchedNick");
    sess.monitor_presence[0] = 'u';
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    const char *payload_json =
        "{\"kind\":\"presence_changed\","
        "\"network_id\":99,"   /* wrong network */
        "\"nick\":\"WatchedNick\","
        "\"presence\":\"online\","
        "\"initial\":false,"
        "\"source\":\"watch\","
        "\"ts\":\"2026-10-15T12:00:00Z\"}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[512];
    drain(tx, out, sizeof(out));

    /* No 730/731 — wrong network */
    CHECK(strstr(out, "730") == NULL);
    CHECK(strstr(out, "731") == NULL);
    /* Presence NOT updated */
    CHECK(sess.monitor_presence[0] == 'u');
}

/* notify_list event seeds monitor_nicks for the session's network. */
TEST(notify_list_seeds_monitor_nicks) {
    struct grappa_session sess = make_sess();

    int tx = open_client();
    if (tx < 0) return;

    /* Wire shape: networks keyed by network_id AS STRING (Elixir integer-keyed
     * map serialises to JSON object with string keys — confirmed in the codebase
     * comment on query_windows_list). */
    const char *payload_json =
        "{\"kind\":\"notify_list\","
        "\"networks\":{"
        "\"1\":["
        "{\"network_id\":1,\"nick\":\"Alice\",\"added_at\":\"2026-01-01T00:00:00Z\"},"
        "{\"network_id\":1,\"nick\":\"Bob\",\"added_at\":\"2026-01-01T00:00:00Z\"}"
        "]}}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    /* Drain (no IRC output expected for notify_list) */
    char out[256];
    drain(tx, out, sizeof(out));
    CHECK(out[0] == '\0');

    /* monitor_nicks must be populated */
    CHECK_LONG((long)sess.monitor_count, 2);
    CHECK(strcmp(sess.monitor_nicks[0], "Alice") == 0);
    CHECK(strcmp(sess.monitor_nicks[1], "Bob") == 0);
    /* Default presence: unknown */
    CHECK(sess.monitor_presence[0] == 'u');
    CHECK(sess.monitor_presence[1] == 'u');
}

/* notify_list preserves presence state for nicks that remain in the list. */
TEST(notify_list_preserves_presence) {
    struct grappa_session sess = make_sess();

    /* Pre-existing entry: Alice is known online. */
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_presence[0] = 'o';
    sess.monitor_count = 1;

    int tx = open_client();
    if (tx < 0) return;

    /* New list: Alice stays + Carol added */
    const char *payload_json =
        "{\"kind\":\"notify_list\","
        "\"networks\":{"
        "\"1\":["
        "{\"network_id\":1,\"nick\":\"Alice\",\"added_at\":\"2026-01-01T00:00:00Z\"},"
        "{\"network_id\":1,\"nick\":\"Carol\",\"added_at\":\"2026-01-01T00:00:01Z\"}"
        "]}}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK_LONG((long)sess.monitor_count, 2);
    /* Alice's presence preserved */
    CHECK(sess.monitor_presence[0] == 'o');
    /* Carol's presence starts as unknown */
    CHECK(sess.monitor_presence[1] == 'u');
}

/* presence_snapshot seeds presence for known monitored nicks. */
TEST(presence_snapshot_seeds_presence) {
    struct grappa_session sess = make_sess();

    /* Pre-populate monitor list */
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_presence[0] = 'u';
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");
    sess.monitor_presence[1] = 'u';
    sess.monitor_count = 2;

    int tx = open_client();
    if (tx < 0) return;

    /* Snapshot keys are ASCII-folded (confirmed from grappa wire.ex type doc) */
    const char *payload_json =
        "{\"kind\":\"presence_snapshot\","
        "\"network_id\":1,"
        "\"nicks\":{"
        "\"alice\":\"online\","
        "\"bob\":\"offline\""
        "}}";

    char *envelope = make_grappa_envelope(payload_json);
    handle_grappa_event(tx, "mynick", NULL, &sess, NULL, NULL,
                        envelope, strlen(envelope));
    free(envelope);

    /* No IRC output expected for presence_snapshot */
    char out[256];
    drain(tx, out, sizeof(out));
    CHECK(out[0] == '\0');

    /* Presence updated */
    CHECK(sess.monitor_presence[0] == 'o'); /* Alice online */
    CHECK(sess.monitor_presence[1] == 'f'); /* Bob offline */
}

/* MONITOR S responds with 730/731 for all monitored nicks. */
TEST(monitor_s_sends_status) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_presence[0] = 'o';
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");
    sess.monitor_presence[1] = 'f';
    sess.monitor_count = 2;

    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    struct http_client hc;
    http_client_init(&hc);

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg = make_msg("MONITOR", "S", NULL);
    handle_monitor(tx, &hc, &cfg, "mynick", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 730 for Alice (online), 731 for Bob (offline) */
    CHECK(strstr(out, "730") != NULL);
    CHECK(strstr(out, "Alice") != NULL);
    CHECK(strstr(out, "731") != NULL);
    CHECK(strstr(out, "Bob") != NULL);
}

/* MONITOR L lists monitored nicks with 732 + 733. */
TEST(monitor_l_sends_list) {
    struct grappa_session sess = make_sess();

    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_presence[0] = 'o';
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");
    sess.monitor_presence[1] = 'f';
    sess.monitor_count = 2;

    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    struct http_client hc;
    http_client_init(&hc);

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg = make_msg("MONITOR", "L", NULL);
    handle_monitor(tx, &hc, &cfg, "mynick", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 732 RPL_MONLIST with both nicks, 733 RPL_ENDOFMONLIST */
    CHECK(strstr(out, "732") != NULL);
    CHECK(strstr(out, "Alice") != NULL);
    CHECK(strstr(out, "Bob") != NULL);
    CHECK(strstr(out, "733") != NULL);
}

/* MONITOR L on empty list sends just 733. */
TEST(monitor_l_empty_sends_only_733) {
    struct grappa_session sess = make_sess();
    /* monitor_count = 0 by memset */

    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    struct http_client hc;
    http_client_init(&hc);

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg = make_msg("MONITOR", "L", NULL);
    handle_monitor(tx, &hc, &cfg, "mynick", &sess, &msg);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK(strstr(out, "733") != NULL);
    CHECK(strstr(out, "732") == NULL);
}

/* MONITOR=64 is advertised in 005 — clients that support MONITOR switch
 * from ISON polling to push presence automatically. */
TEST(monitor_advertised_in_005) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.welcome_sent = true; /* Case B path: send 005 immediately */
    sess.network_id   = 1;   /* must match payload's network_id so the
                               * per-network filter in isupport_changed
                               * does not drop the event */

    /* Fire isupport_changed with a minimal PREFIX payload */
    const char *payload_json =
        "{\"network_id\":1,"
        "\"chanmodes_a\":[\"b\"],"
        "\"chanmodes_b\":[],"
        "\"chanmodes_c\":[\"l\"],"
        "\"chanmodes_d\":[\"i\",\"m\",\"n\",\"p\",\"s\",\"t\"],"
        "\"prefix\":{\"o\":\"@\",\"v\":\"+\"}}";

    char err[128];
    json_doc *doc = json_parse(payload_json, strlen(payload_json), err, sizeof(err));
    if (!doc) { FAIL("json_parse"); return; }

    int tx = open_client();
    if (tx < 0) { json_free(doc); return; }

    handle_grappa_isupport_changed_event(tx, "mynick", &sess, json_root(doc));
    json_free(doc);

    char out[512];
    drain(tx, out, sizeof(out));

    /* 005 must contain MONITOR=64 */
    CHECK(strstr(out, "MONITOR=64") != NULL);
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(void) {
    RUN(ison_returns_online_nick);
    RUN(ison_omits_offline_nick);
    RUN(ison_mixed_online_offline);
    RUN(ison_case_insensitive);
    RUN(presence_changed_online_sends_730);
    RUN(presence_changed_offline_sends_731);
    RUN(presence_changed_initial_is_silent);
    RUN(presence_changed_wrong_network_ignored);
    RUN(notify_list_seeds_monitor_nicks);
    RUN(notify_list_preserves_presence);
    RUN(presence_snapshot_seeds_presence);
    RUN(monitor_s_sends_status);
    RUN(monitor_l_sends_list);
    RUN(monitor_l_empty_sends_only_733);
    RUN(monitor_advertised_in_005);
    return test_report();
}
