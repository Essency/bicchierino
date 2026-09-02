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

/* Renders a $server row carrying an IRC numeric.  `params` is the full
 * raw_params list (in wire order: all middle params first, trailing last).
 * `body` is the message's `body` field (may be "" for numerics whose payload
 * is entirely in middle params; NULL is normalised to "" to make the JSON
 * valid — grappa always sets body, though it may be empty).
 *
 * Meta shape matches grappa's own catalogue for `:notice` + `numeric`:
 *   {"numeric": <n>, "raw_params": [<p0>, ..., <pN>]}
 * numeric is a JSON NUMBER (Jason serialises the Elixir integer directly). */
static void render_row_with_numeric(const char *sender, int numeric,
                                    const char **params, int n_params,
                                    const char *body,
                                    char *out, size_t out_sz) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", "me");

    int tx = open_client();
    if (tx < 0) {
        out[0] = '\0';
        return;
    }

    /* Build the message JSON (body may be empty for middle-param-only rows). */
    char msg_json[512];
    {
        char esc[256];
        const char *b = body ? body : "";
        json_escape_into(b, esc, sizeof(esc));
        snprintf(msg_json, sizeof(msg_json), "{\"body\":\"%s\"}", esc);
    }

    /* Build the meta JSON: {"numeric":<n>,"raw_params":["p0",...,"pN"]}. */
    char meta_json[1024];
    {
        int pos = snprintf(meta_json, sizeof(meta_json), "{\"numeric\":%d,\"raw_params\":[", numeric);
        for (int i = 0; i < n_params && pos > 0 && (size_t)pos < sizeof(meta_json) - 4; i++) {
            char esc[256];
            json_escape_into(params[i], esc, sizeof(esc));
            int r = snprintf(meta_json + pos, sizeof(meta_json) - (size_t)pos,
                             "%s\"%s\"", i > 0 ? "," : "", esc);
            if (r > 0) pos += r;
        }
        if (pos > 0 && (size_t)pos < sizeof(meta_json) - 2)
            snprintf(meta_json + pos, sizeof(meta_json) - (size_t)pos, "]}");
    }

    char err[128];
    json_doc *msg  = json_parse(msg_json,  strlen(msg_json),  err, sizeof(err));
    if (!msg)  FAIL("render_row_with_numeric: msg parse failed");
    json_doc *meta = json_parse(meta_json, strlen(meta_json), err, sizeof(err));
    if (!meta) FAIL("render_row_with_numeric: meta parse failed");

    handle_grappa_server_window_row(tx, &sess, "notice", sender,
                                    json_root(msg), json_root(meta), 0);
    json_free(msg);
    json_free(meta);
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

/* ── Numeric rendering (#113) ────────────────────────────────────────────────
 *
 * When meta carries both `numeric` and `raw_params`, the row must be emitted
 * as the real IRC numeric — not a NOTICE — so that middle params reach the
 * client.  The issue's verification matrix:
 *
 *   /stats l → 211 with full link columns (many middle params)
 *   /stats u → 242 with uptime in trailing only (regression guard)
 *   /stats o → 243 with O-line fields in middle params (empty trailing)
 *   end-of-stats → 219 with single trailing (regression guard)
 *
 * The NOTICE path must survive unchanged for bare notices (no numeric) and
 * for old-grappa rows that carry numeric but no raw_params. */

/* RPL_STATSLINKINFO (211): six middle params + trailing.  This is the
 * primary regression — every column was previously dropped, leaving only
 * the last field ("Open_since Idle TS"). */
TEST(numeric_211_emits_full_params) {
    char buf[1024];
    const char *params[] = {
        "leaf4.azzurra.chat", "0", "12345", "67890", "11111", "22222", "Open_since Idle TS"
    };
    render_row_with_numeric("hub.azzurra.chat", 211, params, 7, "Open_since Idle TS",
                            buf, sizeof(buf));
    CHECK_STR(buf, ":hub.azzurra.chat 211 me leaf4.azzurra.chat 0 12345 67890 11111 22222"
                   " :Open_since Idle TS\r\n");
}

/* RPL_STATSUPTIME (242): trailing-only, all payload in body.  The pre-fix
 * NOTICE path forwarded this correctly; the numeric path must preserve it
 * and now also emit the real numeric code instead of NOTICE. */
TEST(numeric_242_trailing_only_regression_guard) {
    char buf[1024];
    const char *params[] = { "Server Up 3 days 12:34:56" };
    render_row_with_numeric("hub.azzurra.chat", 242, params, 1, "Server Up 3 days 12:34:56",
                            buf, sizeof(buf));
    /* Must be a 242, not a NOTICE; body text must be present. */
    CHECK_STR(buf, ":hub.azzurra.chat 242 me :Server Up 3 days 12:34:56\r\n");
}

/* RPL_STATSOLINE (243): payload entirely in middle params, empty trailing.
 * Pre-fix: body="" → NOTICE with empty body → "no line arrives" from the
 * client's perspective (the NOTICE was sent but useless).  Post-fix: real
 * 243 with O-line data. */
TEST(numeric_243_empty_trailing_middle_params_present) {
    char buf[1024];
    const char *params[] = { "O", "*", "192.0.2.1", "testoper", "NetAdmin", "" };
    render_row_with_numeric("hub.azzurra.chat", 243, params, 6, "",
                            buf, sizeof(buf));
    /* All five middle params must be present; trailing is empty but present. */
    CHECK_STR(buf, ":hub.azzurra.chat 243 me O * 192.0.2.1 testoper NetAdmin :\r\n");
}

/* Single-trailing numeric (219 RPL_ENDOFSTATS): regression guard that the
 * simplest case (one element in raw_params = just the trailing) is correct. */
TEST(numeric_219_end_of_stats) {
    char buf[1024];
    const char *params[] = { "End of /STATS report." };
    render_row_with_numeric("hub.azzurra.chat", 219, params, 1, "End of /STATS report.",
                            buf, sizeof(buf));
    CHECK_STR(buf, ":hub.azzurra.chat 219 me :End of /STATS report.\r\n");
}

/* RPL_ISON (303) — empty notify list / nobody in list online.
 *
 * Both bahamut (s_user.c:3435-3438) and solanum (m_ison.c:101) build the
 * 303 line by appending "nick " for every online nick.  When nobody in the
 * ISON query is online — or when bicchierino sends an ISON for a notify list
 * whose entries are all offline — the ircd sends:
 *
 *   :<server> 303 <nick> :
 *
 * grappa persists this as raw_params: [""] — a single-element array whose
 * only element is the empty trailing param.  The pre-fix NOTICE path rendered
 * this as "NOTICE me :" (still wrong: a NOTICE, not a numeric, and body=""
 * means row_text() returns "", which some callers treat as absent).  The
 * numeric path must emit the real 303 with the empty trailing present.
 *
 * This is the complement of the 243 case (empty trailing WITH middle params).
 * Here there are NO middle params at all — n_p = 1, the middle-param loop
 * does not execute, and only the empty trailing is emitted.  Verifying this
 * case catches any future regression where empty-trailing handling is broken
 * specifically for the no-middle-param shape. */
TEST(numeric_303_ison_empty_list) {
    char buf[1024];
    const char *params[] = { "" };
    render_row_with_numeric("hub.azzurra.chat", 303, params, 1, "",
                            buf, sizeof(buf));
    /* Must be a 303, not a NOTICE; trailing must be present (colon only). */
    CHECK_STR(buf, ":hub.azzurra.chat 303 me :\r\n");
}

/* Numeric with no raw_params (old grappa that pre-dates grappa #424):
 * must fall back to the NOTICE path unchanged. */
TEST(numeric_without_raw_params_falls_back_to_notice) {
    char buf[1024];
    /* Build meta with only numeric (no raw_params key). */
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "%s", "me");

    int tx = open_client();
    if (tx < 0) { buf[0] = '\0'; return; }

    json_doc *msg_d = body_doc("some text");
    const char *meta_json = "{\"numeric\":211}";
    char err[64];
    json_doc *meta_d = json_parse(meta_json, strlen(meta_json), err, sizeof(err));
    if (!meta_d) FAIL("numeric_without_raw_params_falls_back_to_notice: meta parse failed");

    handle_grappa_server_window_row(tx, &sess, "notice", "hub.azzurra.chat",
                                    json_root(msg_d), json_root(meta_d), 0);
    json_free(msg_d);
    json_free(meta_d);
    drain(tx, buf, sizeof(buf));
    CHECK_STR(buf, ":hub.azzurra.chat NOTICE me :some text\r\n");
}

/* Bare notice with no numeric key: the NOTICE path must be entirely
 * unaffected by the new numeric check. */
TEST(bare_notice_without_numeric_stays_notice) {
    char buf[1024];
    render_row("notice", "hub.azzurra.chat", "*** Global -- from oper: hello", buf, sizeof(buf));
    CHECK_STR(buf, ":hub.azzurra.chat NOTICE me :*** Global -- from oper: hello\r\n");
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
    /* numeric rendering (#113) */
    RUN(numeric_211_emits_full_params);
    RUN(numeric_242_trailing_only_regression_guard);
    RUN(numeric_243_empty_trailing_middle_params_present);
    RUN(numeric_219_end_of_stats);
    RUN(numeric_303_ison_empty_list);
    RUN(numeric_without_raw_params_falls_back_to_notice);
    RUN(bare_notice_without_numeric_stays_notice);
    return test_report();
}
