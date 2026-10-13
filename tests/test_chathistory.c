/* test_chathistory.c — CHATHISTORY replies and the JOIN backlog replay.
 *
 * Pins three behaviours, each measured broken against a live grappa first:
 *
 *   (a) `limit` counts lines SENT. A grappa page carries joins, parts and
 *       quits that are never replayed; they used to eat the client's
 *       budget (`BEFORE msgid=<newest+1> 3` answered 2 lines).
 *   (b) `timestamp=` selectors resolve against grappa, not the
 *       per-connection ring — on a fresh connection the ring was empty and
 *       every timestamp selector answered an empty batch. At grappa
 *       protocol_version >= 40 the rows are asked BY TIME (before_time/
 *       after_time/around_time), which also holds across a backward clock
 *       step; NEVER below 40 (an older grappa ignores the parameter and
 *       answers its newest page), where a backwards walk of the id-cursor
 *       REST places the instant instead.
 *   (c) a client that did not negotiate draft/chathistory gets the newest
 *       JOIN_REPLAY_LINES messages after a JOIN; one that did gets none.
 *
 * Compiles connection.c in, like the other render suites, and links
 * http_stub.c in place of http.c: the stub answers the pages queued here
 * and records the paths asked for, so both what is sent to the client
 * and what is asked of grappa are asserted.
 */
#include "test.h"
#include "http_stub.h"

#include "../src/connection.c"

#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define T_BASE 1760203000000L /* every row's server_time is T_BASE + id*1000 + 381 */

static long row_time(long id) { return T_BASE + id * 1000L + 381L; }

static void iso_ms(long ms, char *out, size_t sz) {
    time_t sec = (time_t)(ms / 1000);
    struct tm tm;
    gmtime_r(&sec, &tm);
    snprintf(out, sz, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ms % 1000);
}

/* ── a page of rows, built the way grappa's Scrollback.Wire shapes them ── */

static char page[64 * 1024];
static size_t page_len;

static void page_begin(void) {
    page_len = (size_t)snprintf(page, sizeof(page), "[");
}

static void page_row(long id, const char *kind) {
    bool message = strcmp(kind, "privmsg") == 0;
    char body[64];
    if (message) snprintf(body, sizeof(body), "\"c-%ld\"", id);
    else snprintf(body, sizeof(body), "null");
    page_len += (size_t)snprintf(page + page_len, sizeof(page) - page_len,
                                 "%s{\"id\":%ld,\"network\":\"testnet\",\"channel\":\"#c\","
                                 "\"server_time\":%ld,\"kind\":\"%s\",\"sender\":\"peer\","
                                 "\"body\":%s,\"meta\":{}}",
                                 page_len > 1 ? "," : "", id, row_time(id), kind, body);
}

static const char *page_end(void) {
    page_len += (size_t)snprintf(page + page_len, sizeof(page) - page_len, "]");
    return page;
}

/* Rows `hi` down to `lo` (DESC, as grappa answers before/latest), all privmsg. */
static const char *page_desc(long hi, long lo) {
    page_begin();
    for (long id = hi; id >= lo; id--) page_row(id, "privmsg");
    return page_end();
}

/* Rows `lo` up to `hi` (ASC, as grappa answers after), all privmsg. */
static const char *page_asc(long lo, long hi) {
    page_begin();
    for (long id = lo; id <= hi; id++) page_row(id, "privmsg");
    return page_end();
}

/* ── driving a request and reading what the client got ───────────────── */

static char out[256 * 1024];
static struct config cfg;
static struct http_client hc;

static struct grappa_session make_sess(bool cap_chathistory) {
    struct grappa_session sess;
    memset(&sess, 0, sizeof(sess));
    snprintf(sess.network_nick, sizeof(sess.network_nick), "me");
    snprintf(sess.network_slug, sizeof(sess.network_slug), "testnet");
    snprintf(sess.token, sizeof(sess.token), "tok");
    sess.cap_batch = cap_chathistory;
    sess.cap_chathistory = cap_chathistory;
    return sess;
}

static void collect(int tx, int rx) {
    close(tx);
    size_t total = 0;
    ssize_t n;
    while (total + 1 < sizeof(out) && (n = read(rx, out + total, sizeof(out) - total - 1)) > 0)
        total += (size_t)n;
    out[total] = '\0';
    close(rx);
}

static bool open_pair(int *tx, int *rx) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        FAIL("socketpair");
        return false;
    }
    *rx = sv[0];
    *tx = sv[1];
    return true;
}

/* `line` is parsed the way handle_irc_line parses it, so params[0] is the
 * subcommand — the shape handle_chathistory is handed. */
static void chathistory(const char *line) {
    struct grappa_session sess = make_sess(true);
    struct irc_message msg;
    CHECK(irc_parse_line(line, &msg));
    int tx, rx;
    if (!open_pair(&tx, &rx)) return;
    handle_chathistory(tx, &hc, &cfg, &sess, &msg);
    collect(tx, rx);
}

static size_t count_lines(const char *needle) {
    size_t n = 0;
    for (const char *p = out; (p = strstr(p, needle)) != NULL; p++) n++;
    return n;
}

static bool sent(long id) {
    char needle[64];
    snprintf(needle, sizeof(needle), "PRIVMSG #c :c-%ld\r\n", id);
    return strstr(out, needle) != NULL;
}

static bool sent_before(long a, long b) {
    char na[64], nb[64];
    snprintf(na, sizeof(na), ":c-%ld\r\n", a);
    snprintf(nb, sizeof(nb), ":c-%ld\r\n", b);
    const char *pa = strstr(out, na), *pb = strstr(out, nb);
    return pa && pb && pa < pb;
}

/* What `GET /api/config` answers — the first request of any timestamp
 * resolution, which picks the walk (< 40) or the time cursor (>= 40). */
static void grappa_at(int protocol_version) {
    char body[128];
    snprintf(body, sizeof(body),
             "{\"version\":\"1.0.0\",\"server\":\"grappa\",\"protocol_version\":%d,"
             "\"min_protocol_version\":1}",
             protocol_version);
    http_stub_queue(200, body);
}

#define CONFIG_PATH "/api/config"
#define MSGS "/networks/testnet/channels/%23c/messages"

static void setup(void) {
    http_stub_reset();
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.grappa_url, sizeof(cfg.grappa_url), "http://127.0.0.1:4000");
    http_client_init(&hc);
    out[0] = '\0';
}

/* ── (a) limit counts lines sent ─────────────────────────────────────── */

TEST(before_limit_skips_presence_rows_and_keeps_newest) {
    setup();
    page_begin();
    page_row(22, "quit");
    page_row(21, "privmsg");
    page_row(20, "privmsg");
    page_row(19, "join");
    page_row(18, "privmsg");
    page_row(17, "privmsg");
    http_stub_queue(200, page_end());
    chathistory("CHATHISTORY BEFORE #c msgid=23 3");
    CHECK(sent(21) && sent(20) && sent(18));
    CHECK(!sent(17));
    CHECK(sent_before(18, 20) && sent_before(20, 21)); /* oldest first */
    CHECK_STR(http_stub_request(0), "/networks/testnet/channels/%23c/messages?before=23&limit=200");
}

TEST(latest_star_counts_only_messages) {
    setup();
    page_begin();
    page_row(25, "part");
    page_row(24, "privmsg");
    page_row(23, "join");
    page_row(22, "privmsg");
    page_row(21, "privmsg");
    http_stub_queue(200, page_end());
    chathistory("CHATHISTORY LATEST #c * 2");
    CHECK(count_lines("PRIVMSG #c") == 2);
    CHECK(sent(22) && sent(24));
    CHECK(count_lines("BATCH +") == 1 && count_lines("BATCH -") == 1);
}

TEST(after_msgid_keeps_oldest_past_anchor) {
    setup();
    http_stub_queue(200, page_asc(6, 20));
    chathistory("CHATHISTORY AFTER #c msgid=5 3");
    CHECK(sent(6) && sent(7) && sent(8) && !sent(9));
    CHECK_STR(http_stub_request(0), "/networks/testnet/channels/%23c/messages?after=5&limit=200");
}

TEST(around_msgid_centres_on_anchor_past_presence) {
    setup();
    page_begin();
    for (long id = 30; id >= 10; id--) page_row(id, id % 2 ? "join" : "privmsg");
    http_stub_queue(200, page_end());
    chathistory("CHATHISTORY AROUND #c msgid=20 4");
    CHECK(count_lines("PRIVMSG #c") == 4);
    CHECK(sent(18) && sent(20) && sent(22) && sent(24));
}

/* ── (b) timestamp selectors walk grappa's REST ──────────────────────── */

TEST(after_timestamp_on_fresh_connection_is_millisecond_exact) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(19), ts, sizeof(ts)); /* the @time= of a line the client holds */
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(21, 17)); /* the walk's first page */
    http_stub_queue(200, page_asc(20, 21));  /* the reply page */
    chathistory(line);
    CHECK(http_stub_request_count() == 3);
    CHECK_STR(http_stub_request(1), "/networks/testnet/channels/%23c/messages?limit=200");
    CHECK_STR(http_stub_request(2), "/networks/testnet/channels/%23c/messages?after=19&limit=200");
    CHECK(sent(20) && sent(21) && !sent(19));
}

TEST(before_timestamp_is_strict) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(20), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY BEFORE #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(21, 17));
    http_stub_queue(200, page_desc(19, 17));
    chathistory(line);
    CHECK_STR(http_stub_request(2), "/networks/testnet/channels/%23c/messages?before=20&limit=200");
    CHECK(sent(19) && sent(17) && !sent(20));
}

TEST(latest_timestamp_answers_newest_past_the_point) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(10), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY LATEST #c timestamp=%s 3", ts);
    http_stub_queue(200, page_desc(30, 1)); /* walk */
    http_stub_queue(200, page_desc(30, 1)); /* reply: the latest page */
    chathistory(line);
    CHECK_STR(http_stub_request(2), "/networks/testnet/channels/%23c/messages?limit=200");
    CHECK(count_lines("PRIVMSG #c") == 3);
    CHECK(sent(28) && sent(29) && sent(30)); /* the NEWEST three, not 11..13 */
}

TEST(walk_pages_back_until_it_passes_the_point) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(700), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 2", ts);
    http_stub_queue(200, page_desc(1000, 801)); /* 200 rows, all newer */
    http_stub_queue(200, page_desc(800, 601));
    http_stub_queue(200, page_asc(701, 702));
    chathistory(line);
    CHECK(http_stub_request_count() == 4);
    CHECK_STR(http_stub_request(2), "/networks/testnet/channels/%23c/messages?before=801&limit=200");
    CHECK_STR(http_stub_request(3), "/networks/testnet/channels/%23c/messages?after=700&limit=200");
    CHECK(sent(701) && sent(702));
}

TEST(walk_reaching_the_start_of_history) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(1), ts, sizeof(ts));
    /* AFTER a point older than everything stored: all of it. */
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(9, 5));
    http_stub_queue(200, page_asc(5, 9));
    chathistory(line);
    CHECK_STR(http_stub_request(2), "/networks/testnet/channels/%23c/messages?after=0&limit=200");
    CHECK(sent(5) && sent(9));

    /* BEFORE that same point: nothing, answered without a second request. */
    setup();
    grappa_at(39);
    snprintf(line, sizeof(line), "CHATHISTORY BEFORE #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(9, 5));
    chathistory(line);
    CHECK(http_stub_request_count() == 2);
    CHECK(count_lines("PRIVMSG") == 0);
    CHECK(count_lines("BATCH +") == 1 && count_lines("BATCH -") == 1);
}

TEST(walk_stops_at_its_declared_ceiling) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(1), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 1", ts);
    long hi = 5000;
    for (int p = 0; p < CHATHISTORY_WALK_MAX_PAGES; p++, hi -= CHATHISTORY_FETCH_LIMIT)
        http_stub_queue(200, page_desc(hi, hi - CHATHISTORY_FETCH_LIMIT + 1));
    long oldest = hi + 1;
    http_stub_queue(200, page_asc(oldest, oldest + 5));
    chathistory(line);
    CHECK(http_stub_request_count() == CHATHISTORY_WALK_MAX_PAGES + 2);
    char want[128];
    snprintf(want, sizeof(want), "/networks/testnet/channels/%%23c/messages?after=%ld&limit=200",
             oldest - 1);
    CHECK_STR(http_stub_request(CHATHISTORY_WALK_MAX_PAGES + 1), want);
}

TEST(grappa_unreachable_during_walk_is_a_fail_not_a_guess) {
    setup();
    char ts[64], line[128];
    iso_ms(row_time(1), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 1", ts);
    chathistory(line); /* nothing queued: every request fails */
    CHECK(strstr(out, "FAIL CHATHISTORY MESSAGE_ERROR AFTER") != NULL);
    CHECK(count_lines("BATCH") == 0);
}

TEST(old_grappa_is_never_sent_a_time_cursor) {
    setup();
    grappa_at(39);
    char ts[64], line[128];
    iso_ms(row_time(19), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY BEFORE #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(21, 17));
    http_stub_queue(200, page_desc(18, 17));
    chathistory(line);
    CHECK_STR(http_stub_request(0), CONFIG_PATH);
    for (size_t i = 0; i < http_stub_request_count(); i++)
        CHECK(strstr(http_stub_request(i), "_time=") == NULL);
}

TEST(unreadable_config_falls_back_to_the_walk) {
    setup();
    http_stub_queue(404, "<html>not here</html>");
    char ts[64], line[128];
    iso_ms(row_time(19), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(21, 17));
    http_stub_queue(200, page_asc(20, 21));
    chathistory(line);
    CHECK_STR(http_stub_request(1), MSGS "?limit=200");
    CHECK_STR(http_stub_request(2), MSGS "?after=19&limit=200");
    CHECK(sent(20) && sent(21));
}

/* A row whose server_time is given, not derived from its id — how a page
 * looks after the server's clock stepped back. */
static void page_row_at(long id, long server_time) {
    page_len += (size_t)snprintf(page + page_len, sizeof(page) - page_len,
                                 "%s{\"id\":%ld,\"network\":\"testnet\",\"channel\":\"#c\","
                                 "\"server_time\":%ld,\"kind\":\"privmsg\",\"sender\":\"peer\","
                                 "\"body\":\"c-%ld\",\"meta\":{}}",
                                 page_len > 1 ? "," : "", id, server_time, id);
}

static void chathistory_on(struct grappa_session *sess, const char *line) {
    struct irc_message msg;
    CHECK(irc_parse_line(line, &msg));
    int tx, rx;
    if (!open_pair(&tx, &rx)) return;
    handle_chathistory(tx, &hc, &cfg, sess, &msg);
    collect(tx, rx);
}

TEST(new_grappa_before_is_asked_by_time) {
    setup();
    grappa_at(40);
    char ts[64], line[128], want[128];
    iso_ms(row_time(20), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY BEFORE #c timestamp=%s 10", ts);
    http_stub_queue(200, page_desc(19, 17));
    chathistory(line);
    CHECK(http_stub_request_count() == 2);
    snprintf(want, sizeof(want), "%s?before_time=%ld&limit=200", MSGS, row_time(20));
    CHECK_STR(http_stub_request(1), want);
    CHECK(sent(19) && sent(17) && sent_before(17, 19));
}

TEST(new_grappa_after_is_asked_by_time) {
    setup();
    grappa_at(40);
    char ts[64], line[128], want[128];
    iso_ms(row_time(19), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY AFTER #c timestamp=%s 10", ts);
    http_stub_queue(200, page_asc(20, 21));
    chathistory(line);
    CHECK(http_stub_request_count() == 2);
    snprintf(want, sizeof(want), "%s?after_time=%ld&limit=200", MSGS, row_time(19));
    CHECK_STR(http_stub_request(1), want);
    CHECK(sent(20) && sent(21));
}

/* The case an id anchor gets wrong: the clock stepped back between rows
 * 11 and 12, so 12 is newer by id and older by time. LATEST past t=100
 * must answer 11 (t=105) and 13 (t=101) — never 12 (t=96). */
TEST(new_grappa_latest_by_time_survives_a_clock_step_back) {
    setup();
    grappa_at(40);
    char ts[64], line[128];
    iso_ms(T_BASE + 100, ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY LATEST #c timestamp=%s 10", ts);
    page_begin();
    page_row_at(13, T_BASE + 101);
    page_row_at(12, T_BASE + 96);
    page_row_at(11, T_BASE + 105);
    page_row_at(10, T_BASE + 100);
    http_stub_queue(200, page_end());
    chathistory(line);
    CHECK_STR(http_stub_request(1), MSGS "?limit=200");
    CHECK(sent(11) && sent(13));
    CHECK(!sent(12) && !sent(10));
}

TEST(new_grappa_around_splits_by_time) {
    setup();
    grappa_at(40);
    char ts[64], line[128], want[128];
    iso_ms(row_time(20), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY AROUND #c timestamp=%s 4", ts);
    http_stub_queue(200, page_desc(30, 10));
    chathistory(line);
    snprintf(want, sizeof(want), "%s?around_time=%ld&limit=200", MSGS, row_time(20));
    CHECK_STR(http_stub_request(1), want);
    CHECK(count_lines("PRIVMSG #c") == 4);
    CHECK(sent(19) && sent(20) && sent(21) && sent(22)); /* T itself on the "before" side */
}

TEST(new_grappa_between_cuts_the_far_end_by_time) {
    setup();
    grappa_at(40);
    char lo[64], hi[64], line[192], want[128];
    iso_ms(row_time(12), lo, sizeof(lo));
    iso_ms(row_time(15), hi, sizeof(hi));
    /* Upper bound first: either order is legal. */
    snprintf(line, sizeof(line), "CHATHISTORY BETWEEN #c timestamp=%s timestamp=%s 10", hi, lo);
    http_stub_queue(200, page_asc(13, 30));
    chathistory(line);
    snprintf(want, sizeof(want), "%s?after_time=%ld&limit=200", MSGS, row_time(12));
    CHECK_STR(http_stub_request(1), want);
    CHECK(sent(13) && sent(14) && !sent(15) && !sent(16));
}

TEST(new_grappa_with_nothing_before_the_instant) {
    setup();
    grappa_at(40);
    char ts[64], line[128];
    iso_ms(row_time(1), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY BEFORE #c timestamp=%s 10", ts);
    http_stub_queue(200, "[]");
    chathistory(line);
    CHECK(http_stub_request_count() == 2);
    CHECK(count_lines("PRIVMSG") == 0);
    CHECK(count_lines("BATCH +") == 1 && count_lines("BATCH -") == 1);
}

TEST(msgid_requests_never_ask_for_the_version) {
    setup();
    http_stub_queue(200, page_desc(22, 17));
    chathistory("CHATHISTORY BEFORE #c msgid=23 3");
    CHECK(http_stub_request_count() == 1);
    CHECK(strstr(http_stub_request(0), "/api/config") == NULL);
}

TEST(protocol_version_is_read_once_per_connection) {
    setup();
    struct grappa_session sess = make_sess(true);
    char ts[64], line[128];
    iso_ms(row_time(20), ts, sizeof(ts));
    snprintf(line, sizeof(line), "CHATHISTORY BEFORE #c timestamp=%s 2", ts);
    grappa_at(40);
    http_stub_queue(200, page_desc(19, 17));
    http_stub_queue(200, page_desc(19, 17));
    chathistory_on(&sess, line);
    chathistory_on(&sess, line);
    CHECK(http_stub_request_count() == 3);
    CHECK_STR(http_stub_request(0), CONFIG_PATH);
    CHECK(strstr(http_stub_request(2), "before_time=") != NULL);
}

/* ── (c) backlog replay after a JOIN ─────────────────────────────────── */

TEST(join_replays_newest_fifty_to_a_client_without_the_cap) {
    setup();
    page_begin();
    for (long id = 120; id >= 1; id--) page_row(id, id % 3 ? "privmsg" : "join");
    http_stub_queue(200, page_end());
    struct grappa_session sess = make_sess(false);
    int tx, rx;
    if (!open_pair(&tx, &rx)) return;
    replay_on_join(tx, &hc, &cfg, &sess, "#c");
    collect(tx, rx);
    CHECK(count_lines("PRIVMSG #c") == JOIN_REPLAY_LINES);
    /* Every third id is a join, so the newest 50 messages are 119..46. */
    CHECK(sent(119) && sent(46) && !sent(44));
    CHECK(sent_before(46, 119));
    CHECK(count_lines("BATCH") == 0);
    CHECK_STR(http_stub_request(0), "/networks/testnet/channels/%23c/messages?limit=200");
}

TEST(join_replays_nothing_to_a_client_with_the_cap) {
    setup();
    http_stub_queue(200, page_desc(10, 1));
    struct grappa_session sess = make_sess(true);
    int tx, rx;
    if (!open_pair(&tx, &rx)) return;
    replay_on_join(tx, &hc, &cfg, &sess, "#c");
    collect(tx, rx);
    CHECK(http_stub_request_count() == 0);
    CHECK(out[0] == '\0');
}

int main(void) {
    RUN(before_limit_skips_presence_rows_and_keeps_newest);
    RUN(latest_star_counts_only_messages);
    RUN(after_msgid_keeps_oldest_past_anchor);
    RUN(around_msgid_centres_on_anchor_past_presence);
    RUN(after_timestamp_on_fresh_connection_is_millisecond_exact);
    RUN(before_timestamp_is_strict);
    RUN(latest_timestamp_answers_newest_past_the_point);
    RUN(walk_pages_back_until_it_passes_the_point);
    RUN(walk_reaching_the_start_of_history);
    RUN(walk_stops_at_its_declared_ceiling);
    RUN(grappa_unreachable_during_walk_is_a_fail_not_a_guess);
    RUN(old_grappa_is_never_sent_a_time_cursor);
    RUN(unreadable_config_falls_back_to_the_walk);
    RUN(new_grappa_before_is_asked_by_time);
    RUN(new_grappa_after_is_asked_by_time);
    RUN(new_grappa_latest_by_time_survives_a_clock_step_back);
    RUN(new_grappa_around_splits_by_time);
    RUN(new_grappa_between_cuts_the_far_end_by_time);
    RUN(new_grappa_with_nothing_before_the_instant);
    RUN(msgid_requests_never_ask_for_the_version);
    RUN(protocol_version_is_read_once_per_connection);
    RUN(join_replays_newest_fifty_to_a_client_without_the_cap);
    RUN(join_replays_nothing_to_a_client_with_the_cap);
    http_stub_reset();
    return test_report();
}
