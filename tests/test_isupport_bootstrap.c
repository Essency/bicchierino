/* test_isupport_bootstrap.c — PREFIX ordering fix (#82).
 *
 * Bug: handle_grappa_isupport_changed_event always sent a 005 immediately,
 * but in the Case A bootstrap it fires during join_user_topic — before
 * send_welcome — so the corrected PREFIX arrived AFTER the client's JOIN
 * lines. WeeChat builds nicklist groups once, at the first JOIN, against
 * whichever PREFIX the 005 burst gave it. With the old ordering, no PREFIX
 * had been sent yet, so WeeChat used its built-in default ("ov"), missed
 * the "h" group, and halfop nicks rendered at the nicklist bottom forever.
 *
 * Fix: when `welcome_sent` is false, the event handler caches the parsed
 * PREFIX/CHANMODES in the session instead of sending. send_welcome reads
 * the cache and includes the live values in its own 005 line, which reaches
 * the client before any JOIN line for any channel.
 *
 * These tests pin that contract from both directions:
 *   (a) pre-welcome arrival must NOT send anything, only cache
 *   (b) send_welcome with a full cache sends the complete 005 with PREFIX
 *   (c) send_welcome with an empty cache sends the minimal 005 (no PREFIX)
 *   (d) post-welcome arrival (Case B path) sends the 005 immediately,
 *       exactly as before
 *
 * connection.c is compiled in to reach the static functions — same
 * approach as test_render, test_whois, etc.
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

/* A minimal grappa_session with only the fields these tests need.
 * The struct is zero-initialised by default; caller sets what it needs. */
static struct grappa_session make_sess(void) {
    struct grappa_session s = {0};
    snprintf(s.subject_name, sizeof(s.subject_name), "testuser");
    snprintf(s.network_nick, sizeof(s.network_nick), "testuser");
    return s;
}

/* A realistic isupport_changed payload from grappa — azzurra's actual shape. */
static const char ISUPPORT_JSON[] =
    "{\"kind\":\"isupport_changed\",\"network_id\":1,"
    "\"chanmodes_a\":[\"b\",\"z\"],"
    "\"chanmodes_b\":[],"
    "\"chanmodes_c\":[\"l\"],"
    "\"chanmodes_d\":[\"i\",\"m\",\"n\",\"p\",\"s\",\"t\"],"
    "\"prefix\":{\"o\":\"@\",\"h\":\"%\",\"v\":\"+\"}}";

/* Parse the JSON and return the root value; caller owns the doc. */
static json_doc *parse_isupport(void) {
    char err[128];
    json_doc *d = json_parse(ISUPPORT_JSON, sizeof(ISUPPORT_JSON) - 1, err, sizeof(err));
    if (!d) {
        fprintf(stderr, "parse_isupport: %s\n", err);
        return NULL;
    }
    return d;
}

/* ── tests ───────────────────────────────────────────────────────────────── */

/* (a) Pre-welcome: isupport_changed must cache values, send NOTHING. */
TEST(pre_welcome_caches_not_sends) {
    json_doc *d = parse_isupport();
    if (!d) { FAIL("json parse"); return; }

    struct grappa_session sess = make_sess();
    /* welcome_sent starts false (zero-init). */
    CHECK(!sess.welcome_sent);

    char out[4096];
    int tx = open_client();
    if (tx < 0) { json_free(d); return; }

    handle_grappa_isupport_changed_event(tx, "testuser", &sess, json_root(d));
    json_free(d);
    size_t len = drain(tx, out, sizeof(out));

    /* Nothing must have been sent to the client. */
    CHECK(len == 0);

    /* But the values must be cached. */
    CHECK(sess.cached_prefix_letters[0] != '\0');
    CHECK(sess.cached_prefix_sigils[0]  != '\0');
    CHECK(sess.cached_chanmodes[0]       != '\0');

    /* And isupport_005_sent must remain false — send_welcome sets it. */
    CHECK(!sess.isupport_005_sent);
}

/* (a) continued: cached strings must be correct. */
TEST(pre_welcome_cache_content) {
    json_doc *d = parse_isupport();
    if (!d) { FAIL("json parse"); return; }

    struct grappa_session sess = make_sess();
    int tx = open_client();
    if (tx < 0) { json_free(d); return; }

    handle_grappa_isupport_changed_event(tx, "testuser", &sess, json_root(d));
    json_free(d);
    drain(tx, (char[4096]){0}, 4096);

    /* PREFIX=(ohv)@%+ — well-known order: o > h > v. */
    CHECK_STR(sess.cached_prefix_letters, "ohv");
    CHECK_STR(sess.cached_prefix_sigils,  "@%+");

    /* CHANMODES=bz,,l,imnpst — four groups comma-separated. */
    CHECK_STR(sess.cached_chanmodes, "bz,,l,imnpst");
}

/* (b) send_welcome with a cached PREFIX emits the full 005. */
TEST(send_welcome_with_cache_emits_full_005) {
    struct grappa_session sess = make_sess();
    snprintf(sess.cached_prefix_letters, sizeof(sess.cached_prefix_letters), "ohv");
    snprintf(sess.cached_prefix_sigils,  sizeof(sess.cached_prefix_sigils),  "@%%+");
    snprintf(sess.cached_chanmodes,       sizeof(sess.cached_chanmodes),       "bz,,l,imnpst");

    char out[4096];
    int tx = open_client();
    if (tx < 0) return;
    send_welcome(tx, "testuser", &sess);
    drain(tx, out, sizeof(out));

    /* The 005 line must include PREFIX and CHANMODES. */
    CHECK(strstr(out, "PREFIX=(ohv)@%+") != NULL);
    CHECK(strstr(out, "CHANMODES=bz,,l,imnpst") != NULL);
    CHECK(strstr(out, "STATUSMSG=@+") != NULL);

    /* And welcome_sent + isupport_005_sent must now both be true. */
    CHECK(sess.welcome_sent);
    CHECK(sess.isupport_005_sent);
}

/* (c) send_welcome with NO cached PREFIX emits the minimal 005. */
TEST(send_welcome_without_cache_emits_minimal_005) {
    struct grappa_session sess = make_sess();
    /* cached_prefix_letters is empty (zero-init). */
    CHECK(sess.cached_prefix_letters[0] == '\0');

    char out[4096];
    int tx = open_client();
    if (tx < 0) return;
    send_welcome(tx, "testuser", &sess);
    drain(tx, out, sizeof(out));

    /* No PREFIX or CHANMODES in the 005. */
    CHECK(strstr(out, "PREFIX=") == NULL);
    CHECK(strstr(out, "CHANMODES=") == NULL);

    /* But CHANTYPES and CASEMAPPING must be present. */
    CHECK(strstr(out, "CHANTYPES=#") != NULL);
    CHECK(strstr(out, "CASEMAPPING=ascii") != NULL);

    /* welcome_sent true; isupport_005_sent stays false — the follow-up
     * isupport_changed event will send it (Case B path). */
    CHECK(sess.welcome_sent);
    CHECK(!sess.isupport_005_sent);
}

/* (d) Post-welcome (Case B): isupport_changed sends the 005 immediately. */
TEST(post_welcome_sends_005_immediately) {
    json_doc *d = parse_isupport();
    if (!d) { FAIL("json parse"); return; }

    struct grappa_session sess = make_sess();
    sess.welcome_sent = true;  /* send_welcome already fired */

    char out[4096];
    int tx = open_client();
    if (tx < 0) { json_free(d); return; }

    handle_grappa_isupport_changed_event(tx, "testuser", &sess, json_root(d));
    json_free(d);
    drain(tx, out, sizeof(out));

    /* A 005 must have been sent immediately. */
    CHECK(strstr(out, "005") != NULL);
    CHECK(strstr(out, "PREFIX=(ohv)@%+") != NULL);
    CHECK(strstr(out, "CHANMODES=bz,,l,imnpst") != NULL);
    CHECK(sess.isupport_005_sent);
}

/* (d) continued: a second post-welcome arrival is deduplicated. */
TEST(post_welcome_deduplicates_005) {
    json_doc *d = parse_isupport();
    if (!d) { FAIL("json parse"); return; }

    struct grappa_session sess = make_sess();
    sess.welcome_sent      = true;
    sess.isupport_005_sent = true;  /* already sent once */

    char out[4096];
    int tx = open_client();
    if (tx < 0) { json_free(d); return; }

    handle_grappa_isupport_changed_event(tx, "testuser", &sess, json_root(d));
    json_free(d);
    size_t len = drain(tx, out, sizeof(out));

    /* Nothing sent — duplicate suppressed. */
    CHECK(len == 0);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(void) {
    RUN(pre_welcome_caches_not_sends);
    RUN(pre_welcome_cache_content);
    RUN(send_welcome_with_cache_emits_full_005);
    RUN(send_welcome_without_cache_emits_minimal_005);
    RUN(post_welcome_sends_005_immediately);
    RUN(post_welcome_deduplicates_005);
    return test_report();
}
