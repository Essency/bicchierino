/* test_channel_prefix.c — what prefix the client sees on channel messages.
 *
 * The root cause of #97: format_prefix() used to emit `nick!bicchierino@bicchierino`
 * whenever grappa's meta did not carry sender_user/sender_host.  Because only
 * join/part/quit metas carry the host pair, every channel PRIVMSG reached the
 * client with the placeholder host.  IRC clients (WeeChat, irssi) treat a
 * PRIVMSG prefix as authoritative and overwrite the host they learned from the
 * JOIN with whatever the PRIVMSG says — so a subsequent /kickban produced
 * `*!*@bicchierino` instead of the real ban mask.
 *
 * The fix: emit a bare nick when no user@host is available.  A bare `:nick`
 * prefix is RFC 1459-valid; clients keep the JOIN-learned host rather than
 * overwriting it with wrong data.
 *
 * connection.c is compiled in to reach handle_grappa_message_event (static) —
 * same pattern as test_server_window.c.
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

/* Build a minimal session with the given own nick. */
static struct grappa_session make_sess(const char *own_nick) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", own_nick);
    return sess;
}

/* Build and parse a JSON message payload for handle_grappa_message_event.
 * Returns a heap-allocated json_doc (caller must json_free). */
static json_doc *make_message(const char *kind, const char *channel,
                               const char *sender, const char *body,
                               const char *sender_user, const char *sender_host) {
    char json[1024];
    char body_esc[256];
    json_escape_into(body, body_esc, sizeof(body_esc));

    int n;
    if (sender_user && sender_host) {
        char user_esc[64], host_esc[64];
        json_escape_into(sender_user, user_esc, sizeof(user_esc));
        json_escape_into(sender_host, host_esc, sizeof(host_esc));
        n = snprintf(json, sizeof(json),
            "{\"kind\":\"%s\",\"channel\":\"%s\",\"sender\":\"%s\","
            "\"body\":\"%s\",\"id\":1,\"server_time\":0,"
            "\"meta\":{\"sender_user\":\"%s\",\"sender_host\":\"%s\"}}",
            kind, channel, sender, body_esc, user_esc, host_esc);
    } else {
        n = snprintf(json, sizeof(json),
            "{\"kind\":\"%s\",\"channel\":\"%s\",\"sender\":\"%s\","
            "\"body\":\"%s\",\"id\":1,\"server_time\":0,\"meta\":{}}",
            kind, channel, sender, body_esc);
    }

    char err[128];
    json_doc *d = json_parse(json, (size_t)n, err, sizeof(err));
    if (!d) FAIL("make_message: parse failed");
    return d;
}

/* Renders a channel message event and returns the line the client would see. */
static void render_channel_msg(const char *kind, const char *channel,
                                const char *sender, const char *own_nick,
                                const char *body,
                                const char *sender_user, const char *sender_host,
                                char *out, size_t out_sz) {
    struct grappa_session sess = make_sess(own_nick);
    int tx = open_client();
    if (tx < 0) { out[0] = '\0'; return; }

    json_doc *d = make_message(kind, channel, sender, body, sender_user, sender_host);
    /* br=NULL is safe: handle_grappa_message_event only uses br in the
     * nick_change branch, not for privmsg/notice/action/join/part/quit. */
    handle_grappa_message_event(tx, NULL, &sess, json_root(d));
    json_free(d);
    drain(tx, out, out_sz);
}

/* ── Core regression for #97 ────────────────────────────────────────────── */

/* A PRIVMSG without sender_user/sender_host in the meta must produce a bare
 * nick prefix, not `nick!bicchierino@bicchierino`.  The bare nick is RFC 1459
 * §2.3-valid; it prevents clients from overwriting the JOIN-learned host with
 * a fake one when building ban masks. */
TEST(privmsg_no_host_uses_bare_nick) {
    char buf[1024];
    render_channel_msg("privmsg", "#chan", "OtherUser", "me",
                       "hello world", NULL, NULL, buf, sizeof(buf));
    CHECK_STR(buf, ":OtherUser PRIVMSG #chan :hello world\r\n");
}

TEST(notice_no_host_uses_bare_nick) {
    char buf[1024];
    render_channel_msg("notice", "#chan", "OtherUser", "me",
                       "a notice", NULL, NULL, buf, sizeof(buf));
    CHECK_STR(buf, ":OtherUser NOTICE #chan :a notice\r\n");
}

/* When the meta DOES carry sender_user/sender_host (join/part/quit metas, and
 * any future kind that starts providing them), the full nick!user@host must be
 * used — the real host should never be discarded in favour of a bare nick. */
TEST(privmsg_with_host_uses_full_prefix) {
    char buf[1024];
    render_channel_msg("privmsg", "#chan", "OtherUser", "me",
                       "hello", "ou", "real.host.example",
                       buf, sizeof(buf));
    CHECK_STR(buf, ":OtherUser!ou@real.host.example PRIVMSG #chan :hello\r\n");
}

/* A JOIN event that carries sender_user/sender_host (the normal case grappa
 * already provides) must still produce the full prefix — regression guard so
 * the format_prefix() change doesn't accidentally drop real hosts on joins. */
TEST(join_with_host_uses_full_prefix) {
    char buf[1024];
    render_channel_msg("join", "#chan", "OtherUser", "me",
                       "", "ou", "real.host.example",
                       buf, sizeof(buf));
    CHECK_STR(buf, ":OtherUser!ou@real.host.example JOIN :#chan\r\n");
}

/* A JOIN that arrives without sender_user/sender_host (rare: old scrollback
 * entries) must also fall back to bare nick rather than a fabricated host. */
TEST(join_no_host_uses_bare_nick) {
    char buf[1024];
    render_channel_msg("join", "#chan", "OtherUser", "me",
                       "", NULL, NULL, buf, sizeof(buf));
    CHECK_STR(buf, ":OtherUser JOIN :#chan\r\n");
}

int main(void) {
    RUN(privmsg_no_host_uses_bare_nick);
    RUN(notice_no_host_uses_bare_nick);
    RUN(privmsg_with_host_uses_full_prefix);
    RUN(join_with_host_uses_full_prefix);
    RUN(join_no_host_uses_bare_nick);
    return test_report();
}
