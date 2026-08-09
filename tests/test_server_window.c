/* test_server_window.c — what the client sees for a $server-window row.
 *
 * The prefix is the ONLY thing on the wire telling a client whether a
 * NOTICE came from a user or from a server, and clients route the two
 * differently. This corner has been wrong in both directions:
 *
 *   #24 — a bare nick for a user's private notice, so clients filed it as
 *         server chrome and dropped the nick-derived tags with it.
 *   #26 — the fix keyed on `kind == "notice"`, but grappa uses that kind
 *         for server-sourced rows too (persist_server_notice/2 handles the
 *         MOTD and INFO numerics), so every global and MOTD line got a
 *         fabricated user prefix instead (#29).
 *
 * CI stayed green through both, because nothing asserted the shape. This
 * file is that missing assertion.
 *
 * It pins the OBSERVABLE contract — what reaches the client — not the
 * discriminator. Replacing the dot heuristic with a wire-carried sender
 * kind (#29 option 1) leaves every case here passing, which is the point:
 * a test written against the heuristic would pin the heuristic.
 *
 * connection.c is compiled in to reach the handler, which is static —
 * same approach test_http uses for the parsers.
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

/* row_text/1 reads `body` off the message object, so each case needs a
 * parsed one. */
static json_doc *body_doc(const char *text) {
    char json[512];
    char esc[256];
    json_escape_into(text, esc, sizeof(esc));
    int n = snprintf(json, sizeof(json), "{\"body\":\"%s\"}", esc);
    char err[128];
    json_doc *d = json_parse(json, (size_t)n, err, sizeof(err));
    if (!d) FAIL("body_doc: parse failed");
    return d;
}

/* Renders one $server row and hands back the line the client would see. */
static void render_row(const char *kind, const char *sender, const char *text, char *out,
                        size_t out_sz) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", "me");

    int tx = open_client();
    if (tx < 0) {
        out[0] = '\0';
        return;
    }
    json_doc *d = body_doc(text);
    handle_grappa_server_window_row(tx, &sess, kind, sender, json_root(d), NULL, 0);
    json_free(d);
    drain(tx, out, out_sz);
}

/* Same as render_row but passes a meta object carrying sender_kind — simulates
 * grappa >= v0.15.0 which threads this authoritative discriminator through all
 * NOTICE persist paths (vjt/grappa-irc#1070). */
static void render_row_with_sender_kind(const char *kind, const char *sender,
                                        const char *sender_kind_val, const char *text,
                                        char *out, size_t out_sz) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", "me");

    int tx = open_client();
    if (tx < 0) {
        out[0] = '\0';
        return;
    }
    json_doc *body = body_doc(text);

    char meta_json[256];
    int n = snprintf(meta_json, sizeof(meta_json), "{\"sender_kind\":\"%s\"}", sender_kind_val);
    char err[128];
    json_doc *meta_d = json_parse(meta_json, (size_t)n, err, sizeof(err));
    if (!meta_d) FAIL("render_row_with_sender_kind: meta parse failed");

    handle_grappa_server_window_row(tx, &sess, kind, sender, json_root(body),
                                    json_root(meta_d), 0);
    json_free(body);
    json_free(meta_d);
    drain(tx, out, out_sz);
}

/* A user's private notice: the client must see a user prefix, or it files
 * the line as server chrome and drops the nick-derived tags with it. */
TEST(a_user_sender_gets_a_user_prefix) {
    char buf[1024];

    render_row("notice", "alice", "hi there", buf, sizeof(buf));
    CHECK_STR(buf, ":alice!bicchierino@bicchierino NOTICE me :hi there\r\n");

    /* Services pseudo-clients are users on the network, and their names
     * carry no dot, so they land here too — which is correct. */
    render_row("notice", "NickServ", "Password accepted", buf, sizeof(buf));
    CHECK_STR(buf, ":NickServ!bicchierino@bicchierino NOTICE me :Password accepted\r\n");
}

/* A server-sourced line: the prefix must stay bare. This is what #26
 * broke — every global, every MOTD line, arriving as though a user named
 * `leaf4.azzurra.chat` had sent it. */
TEST(a_server_sender_keeps_a_bare_prefix) {
    char buf[1024];

    render_row("notice", "leaf4.azzurra.chat", "*** Global -- from services: x", buf, sizeof(buf));
    CHECK_STR(buf, ":leaf4.azzurra.chat NOTICE me :*** Global -- from services: x\r\n");

    /* MOTD numerics reach this same function, with a server sender and
     * kind "notice" — the case that makes a kind-only test unworkable
     * (grappa's persist_server_notice/2 files them exactly so). */
    render_row("notice", "hub.azzurra.chat", "- message of the day -", buf, sizeof(buf));
    CHECK_STR(buf, ":hub.azzurra.chat NOTICE me :- message of the day -\r\n");
}

/* server_event rows — KILL, WALLOPS, GLOBOPS, ERROR — carry a server
 * sender under a different kind, and must not gain a user prefix either. */
TEST(a_server_event_keeps_a_bare_prefix) {
    char buf[1024];

    render_row("server_event", "leaf4.azzurra.chat", "WALLOPS text", buf, sizeof(buf));
    CHECK_STR(buf, ":leaf4.azzurra.chat NOTICE me :WALLOPS text\r\n");

    /* Even a dot-less sender under this kind stays bare: the kind says
     * server-sourced, and nothing should override that. */
    render_row("server_event", "somehost", "GLOBOPS text", buf, sizeof(buf));
    CHECK_STR(buf, ":somehost NOTICE me :GLOBOPS text\r\n");
}

/* grappa v0.15.0 added meta.sender_kind ("user"/"server") as an authoritative
 * discriminator (vjt/grappa-irc#1070). When present it overrides the dot
 * heuristic — a user nick with a dot, or a server hostname without one (e.g.
 * a single-label IRC test hostname), must still be handled correctly. */
TEST(sender_kind_user_overrides_dot_heuristic) {
    char buf[1024];

    /* A nick containing a dot would fool the dot heuristic into treating it as
     * a server; sender_kind="user" must win and produce a user prefix. */
    render_row_with_sender_kind("notice", "nick.with.dot", "user", "hi", buf, sizeof(buf));
    CHECK_STR(buf, ":nick.with.dot!bicchierino@bicchierino NOTICE me :hi\r\n");
}

TEST(sender_kind_server_overrides_dot_heuristic) {
    char buf[1024];

    /* A single-label hostname (no dot) would fool the dot heuristic into
     * treating it as a user nick; sender_kind="server" must win and keep the
     * prefix bare. */
    render_row_with_sender_kind("notice", "localhost", "server", "MOTD line", buf, sizeof(buf));
    CHECK_STR(buf, ":localhost NOTICE me :MOTD line\r\n");
}

TEST(sender_kind_user_works_for_normal_nick) {
    char buf[1024];

    /* Normal case: sender_kind="user" on an ordinary nick (no dot) must
     * produce the same user prefix as the heuristic path. */
    render_row_with_sender_kind("notice", "alice", "user", "hello", buf, sizeof(buf));
    CHECK_STR(buf, ":alice!bicchierino@bicchierino NOTICE me :hello\r\n");
}

TEST(sender_kind_server_works_for_dotted_hostname) {
    char buf[1024];

    /* Normal case: sender_kind="server" on a dotted hostname must keep the
     * prefix bare, same as the heuristic path. */
    render_row_with_sender_kind("notice", "leaf4.azzurra.chat", "server",
                                "*** Global notice", buf, sizeof(buf));
    CHECK_STR(buf, ":leaf4.azzurra.chat NOTICE me :*** Global notice\r\n");
}

/* The prefix-less sentinel. "*" is not a usable IRC prefix, so the bridge
 * speaks under its own name rather than emitting something a client has
 * to guess at. */
TEST(the_anonymous_sender_becomes_the_bridge_itself) {
    char buf[1024];

    render_row("notice", "*", "something", buf, sizeof(buf));
    CHECK(strncmp(buf, ":" IRCD_SERVER " NOTICE me :", strlen(IRCD_SERVER) + 13) == 0);

    render_row("notice", "", "something", buf, sizeof(buf));
    CHECK(strncmp(buf, ":" IRCD_SERVER " NOTICE me :", strlen(IRCD_SERVER) + 13) == 0);

    render_row(NULL, NULL, "something", buf, sizeof(buf));
    CHECK(strncmp(buf, ":" IRCD_SERVER " NOTICE me :", strlen(IRCD_SERVER) + 13) == 0);
}

int main(void) {
    RUN(a_user_sender_gets_a_user_prefix);
    RUN(a_server_sender_keeps_a_bare_prefix);
    RUN(a_server_event_keeps_a_bare_prefix);
    RUN(the_anonymous_sender_becomes_the_bridge_itself);
    RUN(sender_kind_user_overrides_dot_heuristic);
    RUN(sender_kind_server_overrides_dot_heuristic);
    RUN(sender_kind_user_works_for_normal_nick);
    RUN(sender_kind_server_works_for_dotted_hostname);
    return test_report();
}
