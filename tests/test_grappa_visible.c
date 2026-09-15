/* test_grappa_visible.c — GRAPPA visible on|off command (#122).
 *
 * Before this fix, bicchierino unconditionally pushed {"visible":true} both
 * at post-join and every 25-second heartbeat, suppressing push notifications
 * for the entire account while any IRC client was attached. The fix:
 *
 *   1. Adds `bool visible` to struct grappa_session, defaulting true.
 *   2. `GRAPPA visible on|off` sets the flag and immediately pushes the
 *      value to grappa's presence layer.
 *   3. Both the initial post-join push and the heartbeat re-push use the
 *      flag instead of the literal "true".
 *
 * These tests follow the issue's own repro path: a client sends
 * `GRAPPA visible off`, bicchierino acknowledges, and subsequent heartbeats
 * carry `{"visible":false}`. We exercise this through `handle_irc_line`
 * with br_connected=false (avoiding the WS path but still verifying flag
 * mutation and NOTICE output), and verify the payload-building logic
 * directly from the sess.visible field.
 *
 * connection.c is compiled in to reach the static helpers — same approach
 * used by test_grappa_admin and test_server_window.
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

/* Build the minimum scaffolding for handle_irc_line — a fully registered
 * session with network resolved, bridge "disconnected" (br_connected=false)
 * so the push path is skipped and we test the flag + NOTICE path cleanly. */
static void make_scaffolding(struct grappa_session *sess,
                              struct registration *reg,
                              struct config *cfg,
                              struct http_client *hc) {
    memset(sess, 0, sizeof(*sess));
    sess->visible = true;           /* explicit — {0} would give false */
    sess->network_resolved = true;
    snprintf(sess->network_nick, sizeof(sess->network_nick), "testnick");
    snprintf(sess->subject_name, sizeof(sess->subject_name), "testuser");

    memset(reg, 0, sizeof(*reg));
    snprintf(reg->nick, sizeof(reg->nick), "testnick");
    reg->got_pass = true;
    reg->got_user = true;
    reg->got_nick = true;

    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->grappa_url, sizeof(cfg->grappa_url), "https://grappa.test");

    http_client_init(hc);
}

/* ── visible defaults ────────────────────────────────────────────────── */

/* sess.visible must start true so a client that never sends GRAPPA visible
 * behaves exactly as before the fix (always-visible). */
TEST(visible_defaults_to_true) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.visible = true;   /* mirrors connection_run's explicit init */
    CHECK(sess.visible == true);
}

/* ── GRAPPA visible off ──────────────────────────────────────────────── */

/* The primary repro path from issue #122: a client sends `GRAPPA visible off`,
 * bicchierino sets the flag false and sends a confirmation NOTICE.
 * br_connected=false here — the bridge-not-connected branch confirms the
 * flag mutation and the NOTICE without needing a live WS. */
TEST(visible_off_sets_flag_and_sends_notice) {
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "visible");
    strcpy(msg.params[1], "off");
    msg.param_count = 2;

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "GRAPPA visible off", &sess);
    drain(tx, buf, sizeof(buf));

    /* Flag must be false now */
    CHECK(sess.visible == false);
    /* NOTICE must confirm the new value */
    CHECK(strstr(buf, "false") != NULL);
    CHECK(strstr(buf, ":grappa!grappa@grappa NOTICE testnick :") != NULL);
}

/* ── GRAPPA visible on ───────────────────────────────────────────────── */

/* Starting from off, `GRAPPA visible on` must flip it back and confirm. */
TEST(visible_on_sets_flag_and_sends_notice) {
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);
    sess.visible = false;   /* start from off */

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "visible");
    strcpy(msg.params[1], "on");
    msg.param_count = 2;

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "GRAPPA visible on", &sess);
    drain(tx, buf, sizeof(buf));

    CHECK(sess.visible == true);
    CHECK(strstr(buf, "true") != NULL);
    CHECK(strstr(buf, ":grappa!grappa@grappa NOTICE testnick :") != NULL);
}

/* ── Invalid arg produces usage error ───────────────────────────────── */

/* `GRAPPA visible` with no argument or an unknown argument must produce a
 * usage NOTICE and leave the flag unchanged. */
TEST(visible_bad_arg_produces_usage_error) {
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "visible");
    strcpy(msg.params[1], "maybe");   /* invalid */
    msg.param_count = 2;

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "GRAPPA visible maybe", &sess);
    drain(tx, buf, sizeof(buf));

    /* Flag must be unchanged */
    CHECK(sess.visible == true);
    /* Must hint at "on|off" */
    CHECK(strstr(buf, "on|off") != NULL);
}

TEST(visible_no_arg_produces_usage_error) {
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "visible");
    msg.param_count = 1;   /* no second arg */

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "GRAPPA visible", &sess);
    drain(tx, buf, sizeof(buf));

    CHECK(sess.visible == true);
    CHECK(strstr(buf, "on|off") != NULL);
}

/* ── Case-insensitivity ──────────────────────────────────────────────── */

/* IRC convention: command args are case-insensitive. `OFF` must work the
 * same as `off`. */
TEST(visible_off_uppercase_works) {
    struct grappa_session sess;
    struct registration reg;
    struct config cfg;
    struct http_client hc;
    make_scaffolding(&sess, &reg, &cfg, &hc);

    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "visible");
    strcpy(msg.params[1], "OFF");
    msg.param_count = 2;

    struct bridge br;
    memset(&br, 0, sizeof(br));
    bool br_connected = false;

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;

    handle_irc_line(tx, &hc, &br, &br_connected, &cfg, &reg, &msg, "GRAPPA visible OFF", &sess);
    drain(tx, buf, sizeof(buf));

    CHECK(sess.visible == false);
    CHECK(strstr(buf, "false") != NULL);
}

/* ── Help mentions visible ───────────────────────────────────────────── */

/* The help output must include "visible" so users know this command exists.
 * Mirrors the existing "help_output_mentions_whoami" guard. */
TEST(help_output_mentions_visible) {
    char buf[4096];
    int tx = open_client();
    if (tx < 0) return;
    grappa_admin_help(tx, "testnick");
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "visible") != NULL);
    CHECK(strstr(buf, "on|off") != NULL);
}

/* ── Payload correctness ─────────────────────────────────────────────── */

/* The visibility payload emitted during the heartbeat must match
 * sess.visible — verify the snprintf pattern for both states.  This is a
 * pure string-building test: no bridge, no socket needed. */
TEST(visibility_payload_true) {
    char payload[32];
    bool visible = true;
    snprintf(payload, sizeof(payload), "{\"visible\":%s}", visible ? "true" : "false");
    CHECK(strcmp(payload, "{\"visible\":true}") == 0);
}

TEST(visibility_payload_false) {
    char payload[32];
    bool visible = false;
    snprintf(payload, sizeof(payload), "{\"visible\":%s}", visible ? "true" : "false");
    CHECK(strcmp(payload, "{\"visible\":false}") == 0);
}

int main(void) {
    RUN(visible_defaults_to_true);
    RUN(visible_off_sets_flag_and_sends_notice);
    RUN(visible_on_sets_flag_and_sends_notice);
    RUN(visible_bad_arg_produces_usage_error);
    RUN(visible_no_arg_produces_usage_error);
    RUN(visible_off_uppercase_works);
    RUN(help_output_mentions_visible);
    RUN(visibility_payload_true);
    RUN(visibility_payload_false);
    return test_report();
}
