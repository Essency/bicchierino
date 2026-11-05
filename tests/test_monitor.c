/* test_monitor.c — MONITOR/ISON presence bridge (issue #157).
 *
 * Bug: bicchierino had no handler for `notify_list`, `presence_snapshot`,
 * and `presence_changed` grappa events (all logged "not yet handled") and
 * forwarded ISON and MONITOR commands via handle_raw, causing grappa's own
 * EventRouter to drop the 303 / 730 / 731 replies.
 *
 * Fix:
 *   - `notify_list`        → rebuilds sess->monitor_nicks[] from grappa's DB list.
 *   - `presence_snapshot`  → seeds sess->monitor_online[] and emits 730/731 per nick.
 *   - `presence_changed`   → updates one nick's state; emits 730/731.
 *   - ISON                 → answered locally from monitor_online[]; 303 reply.
 *   - MONITOR +            → REST POST /networks/:slug/notify; 731 until presence_changed.
 *   - MONITOR -            → REST DELETE; removes from local list.
 *   - MONITOR L            → 732/733 from local list.
 *   - MONITOR C            → REST DELETE (clear all); clears local list.
 *   - MONITOR S            → 730/731 for all current nicks.
 *   - 005 ISUPPORT         → MONITOR=64 token added.
 *
 * Test structure: same pattern as test_chathistory.c / test_sibling_join.c —
 * compile connection.c in directly to reach static handler functions, use a
 * socketpair to capture IRC output, http_stub.c for REST calls (replaces
 * http.c at link time), and ws_stub.c for bridge frames.
 */
#include "test.h"
#include "http_stub.h"
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

/* Build a minimal session with network_id=1 and slug="testnet". */
static struct grappa_session make_sess(const char *own_nick) {
    struct grappa_session s;
    memset(&s, 0, sizeof(s));
    snprintf(s.network_nick,  sizeof(s.network_nick),  "%s", own_nick);
    snprintf(s.subject_name,  sizeof(s.subject_name),  "testuser");
    snprintf(s.network_slug,  sizeof(s.network_slug),  "testnet");
    snprintf(s.token,         sizeof(s.token),         "tok");
    s.network_id    = 1;
    s.user_join_ref = 1;
    return s;
}

/* Build a Phoenix 5-element grappa event envelope, same shape
 * handle_grappa_event expects: [join_ref, ref, topic, event, payload].
 * join_ref/ref 42/42 are non-matching so the frame routes to on_event. */
static char *make_event_envelope(const char *payload_json) {
    char *buf = malloc(4096);
    if (!buf) abort();
    snprintf(buf, 4096,
             "[\"42\",\"42\",\"grappa:user:testuser\",\"event\",%s]",
             payload_json);
    return buf;
}

/* Send one grappa event through handle_grappa_event. */
static void fire_event(int fd, struct grappa_session *sess,
                       struct http_client *hc, struct config *cfg,
                       const char *payload_json) {
    char *env = make_event_envelope(payload_json);
    struct bridge br;
    memset(&br, 0, sizeof(br));
    ws_client_connect("https://grappa.test", "tok", &br.wsc);
    handle_grappa_event(fd, sess->network_nick, &br, sess, hc, cfg,
                        env, strlen(env));
    free(env);
}

/* ── tests ───────────────────────────────────────────────────────────────── */

/* notify_list: rebuilds monitor_nicks[] for the session's network. */
TEST(notify_list_builds_local_state) {
    ws_stub_reset();
    http_stub_reset();
    struct grappa_session sess = make_sess("TestUser");
    int tx = open_client();
    if (tx < 0) return;

    /* network_id=1 → JSON key "1" (Elixir integer keys serialise as strings). */
    fire_event(tx, &sess, NULL, NULL,
               "{\"kind\":\"notify_list\","
               "\"networks\":{\"1\":["
               "{\"network_id\":1,\"nick\":\"Alice\",\"added_at\":\"2026-01-01T00:00:00Z\"},"
               "{\"network_id\":1,\"nick\":\"Bob\",\"added_at\":\"2026-01-01T00:00:01Z\"}"
               "]}}");

    char out[256];
    drain(tx, out, sizeof(out));

    /* notify_list seeds local state only — no IRC lines to the client. */
    CHECK(strstr(out, "730") == NULL);
    CHECK(strstr(out, "731") == NULL);
    CHECK_LONG((long)sess.monitor_count, 2);
    CHECK_STR(sess.monitor_nicks[0], "Alice");
    CHECK_STR(sess.monitor_nicks[1], "Bob");
    /* Presence defaults to offline (no presence_snapshot yet). */
    CHECK(!sess.monitor_online[0]);
    CHECK(!sess.monitor_online[1]);
}

/* notify_list for a different network is silently ignored. */
TEST(notify_list_other_network_ignored) {
    ws_stub_reset();
    http_stub_reset();
    struct grappa_session sess = make_sess("TestUser");
    int tx = open_client();
    if (tx < 0) return;

    /* network_id=99 — not ours (we are on 1). */
    fire_event(tx, &sess, NULL, NULL,
               "{\"kind\":\"notify_list\","
               "\"networks\":{\"99\":["
               "{\"network_id\":99,\"nick\":\"Charlie\",\"added_at\":\"2026-01-01T00:00:00Z\"}"
               "]}}");

    char out[256];
    drain(tx, out, sizeof(out));
    CHECK_LONG((long)sess.monitor_count, 0);
}

/* presence_snapshot seeds monitor_online[] and emits 730 for online,
 * 731 for offline. */
TEST(presence_snapshot_emits_730_and_731) {
    ws_stub_reset();
    http_stub_reset();
    struct grappa_session sess = make_sess("TestUser");
    /* Pre-populate monitor_nicks. */
    sess.monitor_count = 2;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");
    sess.monitor_online[0] = false;
    sess.monitor_online[1] = false;

    int tx = open_client();
    if (tx < 0) return;

    /* Keys in the nicks map are ASCII-folded. */
    fire_event(tx, &sess, NULL, NULL,
               "{\"kind\":\"presence_snapshot\","
               "\"network_id\":1,"
               "\"nicks\":{\"alice\":\"online\",\"bob\":\"offline\"}}");

    char out[1024];
    drain(tx, out, sizeof(out));

    /* 730 for Alice (online). */
    CHECK(strstr(out, "730") != NULL);
    CHECK(strstr(out, "Alice!*@*") != NULL);
    /* 731 for Bob (offline). */
    CHECK(strstr(out, "731") != NULL);
    CHECK(strstr(out, "Bob") != NULL);
    /* Local state updated. */
    CHECK(sess.monitor_online[0]);
    CHECK(!sess.monitor_online[1]);
}

/* presence_snapshot for a different network is silently ignored. */
TEST(presence_snapshot_other_network_ignored) {
    ws_stub_reset();
    http_stub_reset();
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 1;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_online[0] = false;

    int tx = open_client();
    if (tx < 0) return;

    fire_event(tx, &sess, NULL, NULL,
               "{\"kind\":\"presence_snapshot\","
               "\"network_id\":99,"
               "\"nicks\":{\"alice\":\"online\"}}");

    char out[256];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "730") == NULL);
    CHECK(!sess.monitor_online[0]);
}

/* presence_changed: online transition emits 730 and updates local state. */
TEST(presence_changed_online_emits_730) {
    ws_stub_reset();
    http_stub_reset();
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 1;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_online[0] = false;

    int tx = open_client();
    if (tx < 0) return;

    fire_event(tx, &sess, NULL, NULL,
               "{\"kind\":\"presence_changed\","
               "\"network_id\":1,"
               "\"nick\":\"Alice\","
               "\"presence\":\"online\","
               "\"initial\":false,"
               "\"source\":\"watch\","
               "\"ts\":\"2026-01-01T12:00:00Z\"}");

    char out[512];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "730") != NULL);
    CHECK(strstr(out, "Alice!*@*") != NULL);
    CHECK(sess.monitor_online[0]);
}

/* presence_changed: offline transition emits 731 and updates local state. */
TEST(presence_changed_offline_emits_731) {
    ws_stub_reset();
    http_stub_reset();
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 1;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Bob");
    sess.monitor_online[0] = true;

    int tx = open_client();
    if (tx < 0) return;

    fire_event(tx, &sess, NULL, NULL,
               "{\"kind\":\"presence_changed\","
               "\"network_id\":1,"
               "\"nick\":\"Bob\","
               "\"presence\":\"offline\","
               "\"initial\":false,"
               "\"source\":\"watch\","
               "\"ts\":\"2026-01-01T12:01:00Z\"}");

    char out[512];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "731") != NULL);
    CHECK(!sess.monitor_online[0]);
}

/* ISON: online nick appears in 303 reply; offline nick does not. */
TEST(ison_online_nick_in_303_offline_absent) {
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 2;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");
    sess.monitor_online[0] = true;
    sess.monitor_online[1] = false;

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "ISON");
    snprintf(msg.params[0], sizeof(msg.params[0]), "Alice Bob");
    msg.param_count = 1;

    handle_ison(tx, "TestUser", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "303") != NULL);
    CHECK(strstr(out, "Alice") != NULL);
    CHECK(strstr(out, "Bob") == NULL);
}

/* ISON: nick not in monitor list → absent from 303 (unknown → offline). */
TEST(ison_unknown_nick_absent_from_303) {
    struct grappa_session sess = make_sess("TestUser");
    /* Empty monitor list. */

    int tx = open_client();
    if (tx < 0) return;

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "ISON");
    snprintf(msg.params[0], sizeof(msg.params[0]), "Unknown");
    msg.param_count = 1;

    handle_ison(tx, "TestUser", &sess, &msg);

    char out[256];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "303") != NULL);
    /* Reply body after the last ':' should be empty (CRLF follows). */
    const char *colon = strrchr(out, ':');
    CHECK(colon != NULL && (colon[1] == '\r' || colon[1] == '\n'));
}

/* MONITOR L: emits 732 (nick list) + 733 (end); no REST calls. */
TEST(monitor_list_emits_732_733) {
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 2;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");

    int tx = open_client();
    if (tx < 0) return;

    struct http_client hc;
    http_client_init(&hc);
    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");
    http_stub_reset();

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "MONITOR");
    snprintf(msg.params[0], sizeof(msg.params[0]), "L");
    msg.param_count = 1;

    handle_monitor(tx, &hc, &cfg, "TestUser", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "732") != NULL);
    CHECK(strstr(out, "Alice") != NULL);
    CHECK(strstr(out, "Bob") != NULL);
    CHECK(strstr(out, "733") != NULL);
    CHECK_LONG((long)http_stub_request_count(), 0);
}

/* MONITOR +: REST POST to /networks/testnet/notify; 731 emitted immediately;
 * nick added to local list. */
TEST(monitor_plus_calls_rest_and_emits_731) {
    struct grappa_session sess = make_sess("TestUser");

    int tx = open_client();
    if (tx < 0) return;

    struct http_client hc;
    http_client_init(&hc);
    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");
    http_stub_reset();
    http_stub_queue(201,
        "{\"entries\":[{\"nick\":\"Alice\",\"network_id\":1,\"added_at\":\"...\"}]}");

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "MONITOR");
    snprintf(msg.params[0], sizeof(msg.params[0]), "+");
    snprintf(msg.params[1], sizeof(msg.params[1]), "Alice");
    msg.param_count = 2;

    handle_monitor(tx, &hc, &cfg, "TestUser", &sess, &msg);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK_LONG((long)http_stub_request_count(), 1);
    CHECK(strstr(http_stub_request(0), "/networks/testnet/notify") != NULL);
    CHECK_LONG((long)sess.monitor_count, 1);
    CHECK_STR(sess.monitor_nicks[0], "Alice");
    /* 731 (offline) until presence_changed brings the confirmed online state. */
    CHECK(strstr(out, "731") != NULL);
}

/* MONITOR -: REST DELETE to /networks/testnet/notify/Alice; nick removed
 * from local list. */
TEST(monitor_minus_calls_rest_and_removes_nick) {
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 1;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    sess.monitor_online[0] = true;

    int tx = open_client();
    if (tx < 0) return;

    struct http_client hc;
    http_client_init(&hc);
    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");
    http_stub_reset();
    http_stub_queue(200, "{\"ok\":true}");

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "MONITOR");
    snprintf(msg.params[0], sizeof(msg.params[0]), "-");
    snprintf(msg.params[1], sizeof(msg.params[1]), "Alice");
    msg.param_count = 2;

    handle_monitor(tx, &hc, &cfg, "TestUser", &sess, &msg);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK_LONG((long)http_stub_request_count(), 1);
    CHECK(strstr(http_stub_request(0), "/networks/testnet/notify/Alice") != NULL);
    CHECK_LONG((long)sess.monitor_count, 0);
}

/* MONITOR S: emits 730 for online nicks and 731 for offline nicks; no REST. */
TEST(monitor_status_emits_730_and_731) {
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 2;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");
    sess.monitor_online[0] = true;
    sess.monitor_online[1] = false;

    int tx = open_client();
    if (tx < 0) return;

    struct http_client hc;
    http_client_init(&hc);
    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");
    http_stub_reset();

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "MONITOR");
    snprintf(msg.params[0], sizeof(msg.params[0]), "S");
    msg.param_count = 1;

    handle_monitor(tx, &hc, &cfg, "TestUser", &sess, &msg);

    char out[512];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, "730") != NULL);
    CHECK(strstr(out, "731") != NULL);
    CHECK_LONG((long)http_stub_request_count(), 0);
}

/* MONITOR C: REST DELETE to /networks/testnet/notify (no nick); clears
 * local list. */
TEST(monitor_clear_calls_rest_and_clears_list) {
    struct grappa_session sess = make_sess("TestUser");
    sess.monitor_count = 2;
    snprintf(sess.monitor_nicks[0], sizeof(sess.monitor_nicks[0]), "Alice");
    snprintf(sess.monitor_nicks[1], sizeof(sess.monitor_nicks[1]), "Bob");

    int tx = open_client();
    if (tx < 0) return;

    struct http_client hc;
    http_client_init(&hc);
    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");
    http_stub_reset();
    http_stub_queue(200, "{\"ok\":true}");

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    snprintf(msg.command,   sizeof(msg.command),   "MONITOR");
    snprintf(msg.params[0], sizeof(msg.params[0]), "C");
    msg.param_count = 1;

    handle_monitor(tx, &hc, &cfg, "TestUser", &sess, &msg);

    char out[256];
    drain(tx, out, sizeof(out));

    CHECK_LONG((long)http_stub_request_count(), 1);
    /* Clear route has no nick component. */
    CHECK_STR(http_stub_request(0), "/networks/testnet/notify");
    CHECK_LONG((long)sess.monitor_count, 0);
}

/* 005 ISUPPORT from an isupport_changed event must include MONITOR=64. */
TEST(isupport_005_has_monitor_token) {
    char err[128];
    const char *payload_json =
        "{\"kind\":\"isupport_changed\",\"network_id\":1,"
        "\"chanmodes_a\":[\"b\"],\"chanmodes_b\":[\"k\"],"
        "\"chanmodes_c\":[\"l\"],\"chanmodes_d\":[\"m\",\"n\",\"t\"],"
        "\"prefix\":{\"o\":\"@\",\"h\":\"%\",\"v\":\"+\"}}";
    json_doc *d = json_parse(payload_json, strlen(payload_json), err, sizeof(err));
    if (!d) { FAIL("json_parse"); return; }

    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.welcome_sent = true;
    sess.network_id   = 1;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        json_free(d);
        FAIL("socketpair");
        return;
    }
    rx = sv[0];
    int tx = sv[1];

    handle_grappa_isupport_changed_event(tx, "TestUser", &sess, json_root(d));
    json_free(d);

    char out[1024];
    drain(tx, out, sizeof(out));
    CHECK(strstr(out, " 005 ") != NULL);
    CHECK(strstr(out, "MONITOR=64") != NULL);
}

/* ── runner ──────────────────────────────────────────────────────────────── */

int main(void) {
    RUN(notify_list_builds_local_state);
    RUN(notify_list_other_network_ignored);
    RUN(presence_snapshot_emits_730_and_731);
    RUN(presence_snapshot_other_network_ignored);
    RUN(presence_changed_online_emits_730);
    RUN(presence_changed_offline_emits_731);
    RUN(ison_online_nick_in_303_offline_absent);
    RUN(ison_unknown_nick_absent_from_303);
    RUN(monitor_list_emits_732_733);
    RUN(monitor_plus_calls_rest_and_emits_731);
    RUN(monitor_minus_calls_rest_and_removes_nick);
    RUN(monitor_status_emits_730_and_731);
    RUN(monitor_clear_calls_rest_and_clears_list);
    RUN(isupport_005_has_monitor_token);
    return test_report();
}
