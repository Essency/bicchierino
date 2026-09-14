/* test_query_window_cmds.c — QUERYOPEN / QUERYCLOSE client-to-grappa
 * push (#121).
 *
 * IRC provides no native signal for "I opened/closed a DM buffer":
 *   - Buffer open fires no command (first PRIVMSG is the implicit open
 *     already captured by grappa's `maybe_open_query_window`).
 *   - Buffer close fires no command at all (WeeChat's buffer_closing
 *     callback emits PART only for real channels).
 *
 * bicchierino exposes two synthetic commands:
 *   QUERYOPEN  <nick>   ->  push `"open_query_window"` to user topic
 *   QUERYCLOSE <nick>   ->  push `"close_query_window"` to user topic
 *
 * Both are idempotent server-side; clients that never issue them behave
 * exactly as before.
 *
 * Tests exercise handle_irc_line with br_connected=false (flag mutation
 * + no-op WS path) and with a ws_stub bridge (WS push captured) to
 * verify the actual frames sent to grappa.
 *
 * Test structure follows test_grappa_visible.c and test_query_windows.c.
 */
#include "test.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ws_stub.h"

/* ── scaffolding ─────────────────────────────────────────────────────────── */

static int g_rx = -1;

static int open_pair(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair");
        return -1;
    }
    g_rx = sv[0];
    return sv[1];
}

static size_t drain_pair(int tx, char *out, size_t cap) {
    close(tx);
    size_t total = 0;
    ssize_t n;
    while (total + 1 < cap && (n = read(g_rx, out + total, cap - total - 1)) > 0)
        total += (size_t)n;
    out[total] = '\0';
    close(g_rx);
    g_rx = -1;
    return total;
}

/* Minimum scaffolding for handle_irc_line — fully registered session
 * with network resolved so the QUERYOPEN/QUERYCLOSE arms are reachable. */
static void make_scaffolding(struct grappa_session *sess,
                              struct registration *reg,
                              struct config *cfg,
                              struct http_client *hc) {
    memset(sess, 0, sizeof(*sess));
    sess->visible = true;
    sess->network_resolved = true;
    sess->network_id = 1;
    snprintf(sess->network_nick,  sizeof(sess->network_nick),  "testnick");
    snprintf(sess->subject_name,  sizeof(sess->subject_name),  "testuser");
    snprintf(sess->network_slug,  sizeof(sess->network_slug),  "testnet");

    memset(reg, 0, sizeof(*reg));
    snprintf(reg->nick, sizeof(reg->nick), "testnick");
    reg->got_pass = true;
    reg->got_user = true;
    reg->got_nick = true;

    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->grappa_url, sizeof(cfg->grappa_url), "https://grappa.test");

    http_client_init(hc);
}

/* ── QUERYOPEN tests ──────────────────────────────────────────────────────── */

/* QUERYOPEN with br_connected=false must not push anything but also
 * must not crash or write to the client fd. */
TEST(queryopen_no_push_when_bridge_disconnected) {
    ws_stub_reset();
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "QUERYOPEN");
    strcpy(msg.params[0], "alice");
    msg.param_count = 1;

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_pair();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "QUERYOPEN alice", &sess);
    drain_pair(tx, buf, sizeof(buf));

    /* No push, no NOTICE output. */
    CHECK_LONG(ws_stub_sent_count(), 0);
    CHECK(buf[0] == '\0');
}

/* QUERYOPEN with a live ws_stub bridge must push the open_query_window
 * event with the correct network_id and target_nick. */
TEST(queryopen_pushes_open_query_window_to_user_topic) {
    ws_stub_reset();
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "QUERYOPEN");
    strcpy(msg.params[0], "alice");
    msg.param_count = 1;

    struct bridge br = {0};
    ws_client_connect("unused", "unused", &br.wsc);
    bool br_connected = true;
    /* Give user_join_ref a non-zero value so bridge_push has a ref. */
    sess.user_join_ref = 5;

    char buf[512];
    int tx = open_pair();
    if (tx < 0) { bridge_close(&br); return; }

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "QUERYOPEN alice", &sess);
    drain_pair(tx, buf, sizeof(buf));

    /* Exactly one WS frame must have been sent. */
    CHECK_LONG(ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    /* Frame must be addressed to the user topic. */
    CHECK(strstr(frame, "grappa:user:testuser") != NULL);
    /* Event must be open_query_window. */
    CHECK(strstr(frame, "open_query_window") != NULL);
    /* Payload must contain the correct network_id and target_nick. */
    CHECK(strstr(frame, "\"network_id\":1") != NULL);
    CHECK(strstr(frame, "\"target_nick\":\"alice\"") != NULL);

    bridge_close(&br);
}

/* QUERYOPEN with no argument must be silently ignored (no push, no crash). */
TEST(queryopen_no_arg_is_ignored) {
    ws_stub_reset();
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "QUERYOPEN");
    msg.param_count = 0;

    struct bridge br = {0};
    ws_client_connect("unused", "unused", &br.wsc);
    bool br_connected = true;
    sess.user_join_ref = 5;

    char buf[512];
    int tx = open_pair();
    if (tx < 0) { bridge_close(&br); return; }

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "QUERYOPEN", &sess);
    drain_pair(tx, buf, sizeof(buf));

    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

/* ── QUERYCLOSE tests ─────────────────────────────────────────────────────── */

/* QUERYCLOSE with br_connected=false must not push anything. */
TEST(queryclose_no_push_when_bridge_disconnected) {
    ws_stub_reset();
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "QUERYCLOSE");
    strcpy(msg.params[0], "bob");
    msg.param_count = 1;

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_pair();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "QUERYCLOSE bob", &sess);
    drain_pair(tx, buf, sizeof(buf));

    CHECK_LONG(ws_stub_sent_count(), 0);
    CHECK(buf[0] == '\0');
}

/* QUERYCLOSE with a live bridge must push close_query_window with the
 * correct network_id and target_nick. */
TEST(queryclose_pushes_close_query_window_to_user_topic) {
    ws_stub_reset();
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "QUERYCLOSE");
    strcpy(msg.params[0], "bob");
    msg.param_count = 1;

    struct bridge br = {0};
    ws_client_connect("unused", "unused", &br.wsc);
    bool br_connected = true;
    sess.user_join_ref = 9;

    char buf[512];
    int tx = open_pair();
    if (tx < 0) { bridge_close(&br); return; }

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "QUERYCLOSE bob", &sess);
    drain_pair(tx, buf, sizeof(buf));

    CHECK_LONG(ws_stub_sent_count(), 1);
    const char *frame = ws_stub_sent(0);
    CHECK(strstr(frame, "grappa:user:testuser") != NULL);
    CHECK(strstr(frame, "close_query_window") != NULL);
    CHECK(strstr(frame, "\"network_id\":1") != NULL);
    CHECK(strstr(frame, "\"target_nick\":\"bob\"") != NULL);

    bridge_close(&br);
}

/* QUERYCLOSE with no argument must be silently ignored. */
TEST(queryclose_no_arg_is_ignored) {
    ws_stub_reset();
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "QUERYCLOSE");
    msg.param_count = 0;

    struct bridge br = {0};
    ws_client_connect("unused", "unused", &br.wsc);
    bool br_connected = true;
    sess.user_join_ref = 9;

    char buf[512];
    int tx = open_pair();
    if (tx < 0) { bridge_close(&br); return; }

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "QUERYCLOSE", &sess);
    drain_pair(tx, buf, sizeof(buf));

    CHECK_LONG(ws_stub_sent_count(), 0);

    bridge_close(&br);
}

int main(void) {
    RUN(queryopen_no_push_when_bridge_disconnected);
    RUN(queryopen_pushes_open_query_window_to_user_topic);
    RUN(queryopen_no_arg_is_ignored);
    RUN(queryclose_no_push_when_bridge_disconnected);
    RUN(queryclose_pushes_close_query_window_to_user_topic);
    RUN(queryclose_no_arg_is_ignored);
    return test_report();
}
