/* test_grappa_admin.c — /grappa admin command NOTICE format and input
 * validation. (#56)
 *
 * Every /grappa admin response reaches the client through
 * `grappa_admin_notice`, which calls `send_line` — the same bottleneck
 * every other render arm uses. This suite pins the observable contract:
 *
 *   - The NOTICE prefix is always `grappa!grappa@grappa`, never the
 *     server name or a bare nick, so clients file it under the right
 *     source rather than routing it as a server notice.
 *   - `render_live_list` formats session/visitor rows consistently: [id]
 *     label @netN — channels, mailbox, alive/dead — peer.
 *   - `subject_label: null` renders as "<orphan pid>", not blank.
 *   - `parse_positive_long` rejects non-integers, zero, negative values
 *     and trailing junk without crashing.
 *   - Unknown subcommands produce a "try /quote GRAPPA help" reply, not
 *     silence.
 *   - The help text contains at least one line mentioning "whoami".
 *
 * connection.c is compiled in to reach the static helpers — same
 * approach used by test_render and test_server_window.
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

/* Close the write end, drain everything from the read end into `out`,
 * NUL-terminate. Returns the number of bytes read. */
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

/* ── grappa_admin_notice ─────────────────────────────────────────────── */

/* A NOTICE from grappa!grappa@grappa must start with exactly that prefix
 * so clients know it came from the synthetic admin source, not from the
 * server or a real user. */
TEST(notice_has_correct_prefix) {
    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    grappa_admin_notice(tx, "testuser", "hello");
    drain(tx, buf, sizeof(buf));
    CHECK(strncmp(buf, ":grappa!grappa@grappa NOTICE testuser :hello\r\n",
                  strlen(":grappa!grappa@grappa NOTICE testuser :hello\r\n")) == 0);
}

/* The nick param must be embedded verbatim in the NOTICE target slot. */
TEST(notice_targets_the_correct_nick) {
    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    grappa_admin_notice(tx, "Sonic", "test");
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "NOTICE Sonic :") != NULL);
}

/* Multiple calls produce multiple lines, each CRLF-terminated. */
TEST(notice_multiple_lines) {
    char buf[1024];
    int tx = open_client();
    if (tx < 0) return;
    grappa_admin_notice(tx, "nick", "line1");
    grappa_admin_notice(tx, "nick", "line2");
    drain(tx, buf, sizeof(buf));
    /* Both lines must be present */
    CHECK(strstr(buf, ":line1\r\n") != NULL);
    CHECK(strstr(buf, ":line2\r\n") != NULL);
}

/* ── parse_positive_long ─────────────────────────────────────────────── */

TEST(parse_positive_long_accepts_valid_integer) {
    long v = 0;
    CHECK(parse_positive_long("42", &v));
    CHECK_LONG(v, 42);
}

TEST(parse_positive_long_accepts_one) {
    long v = 0;
    CHECK(parse_positive_long("1", &v));
    CHECK_LONG(v, 1);
}

TEST(parse_positive_long_rejects_zero) {
    long v = 0;
    CHECK(!parse_positive_long("0", &v));
}

TEST(parse_positive_long_rejects_negative) {
    long v = 0;
    CHECK(!parse_positive_long("-5", &v));
}

TEST(parse_positive_long_rejects_empty) {
    long v = 0;
    CHECK(!parse_positive_long("", &v));
}

TEST(parse_positive_long_rejects_null) {
    long v = 0;
    CHECK(!parse_positive_long(NULL, &v));
}

TEST(parse_positive_long_rejects_trailing_junk) {
    long v = 0;
    CHECK(!parse_positive_long("42abc", &v));
}

TEST(parse_positive_long_rejects_non_numeric) {
    long v = 0;
    CHECK(!parse_positive_long("abc", &v));
}

/* ── render_live_list ────────────────────────────────────────────────── */

/* Builds a JSON session array with one alive entry and checks the NOTICE
 * output contains the expected fields: [id], label, @netN, channels,
 * mailbox, alive, peer. */
TEST(render_session_list_full_row) {
    const char *json =
        "{\"sessions\":["
        "{\"id\":1,\"subject_label\":\"Sonic\",\"network_id\":2,"
        "\"live_state\":{\"alive\":true,\"peer_address\":\"203.0.113.4\","
        "\"joined_channels\":[\"#bicc\"],\"mailbox_len\":0}}"
        "]}";
    char err[64];
    json_doc *doc = json_parse(json, strlen(json), err, sizeof(err));
    CHECK(doc != NULL);
    if (!doc) return;

    char buf[1024];
    int tx = open_client();
    if (tx < 0) { json_free(doc); return; }
    render_live_list(tx, "testnick", "sessions", "session", json_root(doc));
    drain(tx, buf, sizeof(buf));
    json_free(doc);

    CHECK(strstr(buf, "[1]") != NULL);
    CHECK(strstr(buf, "Sonic") != NULL);
    CHECK(strstr(buf, "@net2") != NULL);
    CHECK(strstr(buf, "1 channel") != NULL);
    CHECK(strstr(buf, "mailbox=0") != NULL);
    CHECK(strstr(buf, "alive") != NULL);
    CHECK(strstr(buf, "203.0.113.4") != NULL);
}

/* subject_label:null must render as "<orphan pid>", not blank — this is
 * the documented orphan-process signal (BEAM has a pid, DB doesn't). */
TEST(render_session_list_null_label_becomes_orphan_pid) {
    const char *json =
        "{\"sessions\":["
        "{\"id\":7,\"subject_label\":null,\"network_id\":1,"
        "\"live_state\":{\"alive\":false,\"peer_address\":\"198.51.100.1\","
        "\"joined_channels\":[],\"mailbox_len\":3}}"
        "]}";
    char err[64];
    json_doc *doc = json_parse(json, strlen(json), err, sizeof(err));
    CHECK(doc != NULL);
    if (!doc) return;

    char buf[1024];
    int tx = open_client();
    if (tx < 0) { json_free(doc); return; }
    render_live_list(tx, "testnick", "sessions", "session", json_root(doc));
    drain(tx, buf, sizeof(buf));
    json_free(doc);

    CHECK(strstr(buf, "<orphan pid>") != NULL);
    CHECK(strstr(buf, "dead") != NULL);
}

/* An empty session list should produce a "(no sessions)" NOTICE rather
 * than silence — the admin should know the list was fetched and is empty,
 * not wonder if the command failed. */
TEST(render_session_list_empty_produces_notice) {
    const char *json = "{\"sessions\":[]}";
    char err[64];
    json_doc *doc = json_parse(json, strlen(json), err, sizeof(err));
    CHECK(doc != NULL);
    if (!doc) return;

    char buf[512];
    int tx = open_client();
    if (tx < 0) { json_free(doc); return; }
    render_live_list(tx, "testnick", "sessions", "session", json_root(doc));
    drain(tx, buf, sizeof(buf));
    json_free(doc);

    CHECK(strstr(buf, "(no sessions)") != NULL);
}

/* Multiple sessions: each row on its own CRLF-terminated NOTICE. */
TEST(render_session_list_multiple_rows) {
    const char *json =
        "{\"sessions\":["
        "{\"id\":1,\"subject_label\":\"Alice\",\"network_id\":1,"
        "\"live_state\":{\"alive\":true,\"peer_address\":\"10.0.0.1\","
        "\"joined_channels\":[],\"mailbox_len\":0}},"
        "{\"id\":2,\"subject_label\":\"Bob\",\"network_id\":1,"
        "\"live_state\":{\"alive\":true,\"peer_address\":\"10.0.0.2\","
        "\"joined_channels\":[\"#a\",\"#b\"],\"mailbox_len\":5}}"
        "]}";
    char err[64];
    json_doc *doc = json_parse(json, strlen(json), err, sizeof(err));
    CHECK(doc != NULL);
    if (!doc) return;

    char buf[2048];
    int tx = open_client();
    if (tx < 0) { json_free(doc); return; }
    render_live_list(tx, "testnick", "sessions", "session", json_root(doc));
    drain(tx, buf, sizeof(buf));
    json_free(doc);

    CHECK(strstr(buf, "[1]") != NULL);
    CHECK(strstr(buf, "Alice") != NULL);
    CHECK(strstr(buf, "[2]") != NULL);
    CHECK(strstr(buf, "Bob") != NULL);
    CHECK(strstr(buf, "2 channels") != NULL);
    CHECK(strstr(buf, "mailbox=5") != NULL);
}

/* ── vhost grant/revoke input validation (#62) ───────────────────────── */

/* Helper: build a minimal scaffolding for handle_grappa_admin calls that
 * exercise input-validation paths (no HTTP call ever reaches the network). */
static void build_admin_scaffolding(struct http_client *hc, struct config *cfg,
                                     struct grappa_session *sess) {
    http_client_init(hc);
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->grappa_url, sizeof(cfg->grappa_url), "https://grappa.test");
    memset(sess, 0, sizeof(*sess));
    sess->network_resolved = true;
}

/* "vhost grant" with fewer than 4 params must print a usage message rather
 * than silently forwarding to the (now multi-step) HTTP logic. This guards
 * against the dispatcher ever skipping the arity check. */
TEST(vhost_grant_missing_args_shows_usage) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "vhost");
    strcpy(msg.params[1], "grant");
    msg.param_count = 2;  /* address and user are missing */

    struct http_client hc;
    struct config cfg;
    struct grappa_session sess;
    build_admin_scaffolding(&hc, &cfg, &sess);

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    handle_grappa_admin(tx, &hc, &cfg, "testnick", &sess, &msg);
    drain(tx, buf, sizeof(buf));

    CHECK(strstr(buf, "usage") != NULL);
    CHECK(strstr(buf, "grant") != NULL);
}

/* "vhost revoke" with a non-integer id must print a usage message and
 * must NOT reach the HTTP layer. Before #62, this path called the wrong
 * endpoint anyway; now it still must reject garbage ids early. */
TEST(vhost_revoke_invalid_id_shows_usage) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "vhost");
    strcpy(msg.params[1], "revoke");
    strcpy(msg.params[2], "notanumber");
    msg.param_count = 3;

    struct http_client hc;
    struct config cfg;
    struct grappa_session sess;
    build_admin_scaffolding(&hc, &cfg, &sess);

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    handle_grappa_admin(tx, &hc, &cfg, "testnick", &sess, &msg);
    drain(tx, buf, sizeof(buf));

    CHECK(strstr(buf, "usage") != NULL);
    CHECK(strstr(buf, "revoke") != NULL);
}

/* "vhost revoke" with zero id must also be rejected — zero is not a valid
 * grant id and parse_positive_long already rejects it. */
TEST(vhost_revoke_zero_id_shows_usage) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "vhost");
    strcpy(msg.params[1], "revoke");
    strcpy(msg.params[2], "0");
    msg.param_count = 3;

    struct http_client hc;
    struct config cfg;
    struct grappa_session sess;
    build_admin_scaffolding(&hc, &cfg, &sess);

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    handle_grappa_admin(tx, &hc, &cfg, "testnick", &sess, &msg);
    drain(tx, buf, sizeof(buf));

    CHECK(strstr(buf, "usage") != NULL);
}

/* An unknown vhost action must produce an error, not silence. */
TEST(vhost_unknown_action_shows_error) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "vhost");
    strcpy(msg.params[1], "delete");  /* 'delete' is not a valid action */
    msg.param_count = 2;

    struct http_client hc;
    struct config cfg;
    struct grappa_session sess;
    build_admin_scaffolding(&hc, &cfg, &sess);

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    handle_grappa_admin(tx, &hc, &cfg, "testnick", &sess, &msg);
    drain(tx, buf, sizeof(buf));

    /* Must say something — not silence */
    CHECK(strlen(buf) > 0);
    CHECK(strstr(buf, ":grappa!grappa@grappa NOTICE testnick :") != NULL);
}

/* ── grappa_admin_help ───────────────────────────────────────────────── */

/* The help output must mention at least "whoami" (the first listed
 * command) and "help" itself — a static list that forgot to update is
 * caught by anything in it. */
TEST(help_output_mentions_whoami) {
    char buf[4096];
    int tx = open_client();
    if (tx < 0) return;
    grappa_admin_help(tx, "testnick");
    drain(tx, buf, sizeof(buf));
    CHECK(strstr(buf, "whoami") != NULL);
    CHECK(strstr(buf, "help") != NULL);
    /* Must contain at least one CRLF-terminated line with the prefix */
    CHECK(strstr(buf, ":grappa!grappa@grappa NOTICE testnick :") != NULL);
}

/* ── Unknown subcommand ──────────────────────────────────────────────── */

/* An unknown subcommand must not produce silence — it must reply with
 * a NOTICE that mentions "help" so the user knows what to do next. */
TEST(unknown_subcommand_suggests_help) {
    /* Build a minimal irc_message for an unknown subcommand */
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    strcpy(msg.params[0], "unknownverb");
    msg.param_count = 1;

    /* The function under test needs http_client and config. Pass enough
     * scaffolding that it doesn't crash while reaching the unknown-subcommand
     * branch — this path never touches the network (it exits before any
     * HTTP call). */
    struct http_client hc;
    http_client_init(&hc);

    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");

    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.network_resolved = true;

    char buf[512];
    int tx = open_client();
    if (tx < 0) return;
    handle_grappa_admin(tx, &hc, &cfg, "testnick", &sess, &msg);
    drain(tx, buf, sizeof(buf));

    CHECK(strstr(buf, "help") != NULL);
    CHECK(strstr(buf, ":grappa!grappa@grappa NOTICE testnick :") != NULL);
}

/* Empty subcommand (bare /grappa with no args) should also reply with
 * help, not silence. */
TEST(empty_subcommand_shows_help) {
    struct irc_message msg;
    memset(&msg, 0, sizeof(msg));
    strcpy(msg.command, "GRAPPA");
    msg.param_count = 0;

    struct http_client hc;
    http_client_init(&hc);

    struct config cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "https://grappa.test");

    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    sess.network_resolved = true;

    char buf[4096];
    int tx = open_client();
    if (tx < 0) return;
    handle_grappa_admin(tx, &hc, &cfg, "testnick", &sess, &msg);
    drain(tx, buf, sizeof(buf));

    CHECK(strstr(buf, "whoami") != NULL);
}

int main(void) {
    RUN(notice_has_correct_prefix);
    RUN(notice_targets_the_correct_nick);
    RUN(notice_multiple_lines);
    RUN(parse_positive_long_accepts_valid_integer);
    RUN(parse_positive_long_accepts_one);
    RUN(parse_positive_long_rejects_zero);
    RUN(parse_positive_long_rejects_negative);
    RUN(parse_positive_long_rejects_empty);
    RUN(parse_positive_long_rejects_null);
    RUN(parse_positive_long_rejects_trailing_junk);
    RUN(parse_positive_long_rejects_non_numeric);
    RUN(render_session_list_full_row);
    RUN(render_session_list_null_label_becomes_orphan_pid);
    RUN(render_session_list_empty_produces_notice);
    RUN(render_session_list_multiple_rows);
    RUN(vhost_grant_missing_args_shows_usage);
    RUN(vhost_revoke_invalid_id_shows_usage);
    RUN(vhost_revoke_zero_id_shows_usage);
    RUN(vhost_unknown_action_shows_error);
    RUN(help_output_mentions_whoami);
    RUN(unknown_subcommand_suggests_help);
    RUN(empty_subcommand_shows_help);
    return test_report();
}
