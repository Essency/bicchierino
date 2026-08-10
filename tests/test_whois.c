/* test_whois.c — handle_grappa_whois_bundle_event: P-0a bahamut fields. (#72)
 *
 * Bug: handle_grappa_whois_bundle_event read the eleven P-0a typed fields
 * grappa's whois_bundle carries (`actually_host`, `actually_ip`, `umodes`,
 * `is_registered`, `using_ssl`, `is_admin`, `is_services_admin`,
 * `is_helper`, `is_chanop`, `is_agent`, `is_java`) but never rendered any
 * of them — they were parsed out of the wire payload and then silently
 * dropped. Five lines were missing from a bahamut /WHOIS seen through
 * bicchierino:
 *
 *   378 — "is connecting from <host> [<ip>]"
 *   379 — "is using modes <modes>"
 *   307 — "has identified for this nick"
 *   671 — "is using a secure connection (SSL)"
 *   320 — "is a Services Agent" (and the other five boolean flags)
 *
 * This suite pins the contract directly against what the client receives.
 *
 * connection.c is compiled in to reach handle_grappa_whois_bundle_event,
 * which is static — the same approach test_render and test_server_window
 * use. A socketpair provides the fd the function writes to.
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

/* ── helpers ─────────────────────────────────────────────────────── */

static void render_whois(const char *payload_json, char *out, size_t out_sz) {
    char err[128];
    json_doc *d = json_parse(payload_json, strlen(payload_json), err, sizeof(err));
    if (!d) {
        FAIL("render_whois: json_parse failed");
        out[0] = '\0';
        return;
    }
    int tx = open_client();
    if (tx < 0) {
        json_free(d);
        out[0] = '\0';
        return;
    }
    handle_grappa_whois_bundle_event(tx, "me", json_root(d));
    json_free(d);
    drain(tx, out, out_sz);
}

/* ── tests ───────────────────────────────────────────────────────── */

/* Baseline: a minimal bundle (user present, no extra fields) must produce
 * 311 + 318 and nothing else. Regression guard: the P-0a block must not
 * emit anything when all fields are absent/false. */
TEST(whois_minimal_bundle_emits_311_and_318) {
    char buf[4096];
    render_whois("{\"target\":\"Target\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"Real Name\"}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 311 ") != NULL);
    CHECK(strstr(buf, " 318 ") != NULL);
    /* No P-0a numerics must appear. */
    CHECK(strstr(buf, " 307 ") == NULL);
    CHECK(strstr(buf, " 378 ") == NULL);
    CHECK(strstr(buf, " 379 ") == NULL);
    CHECK(strstr(buf, " 320 ") == NULL);
    /* 671 for using_ssl must not appear either. */
    CHECK(strstr(buf, "is using a secure connection (SSL)") == NULL);
}

/* 378 RPL_WHOISHOST: both host and ip present. */
TEST(whois_actually_host_and_ip_emits_378) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"actually_host\":\"user.example.net\","
                 "\"actually_ip\":\"1.2.3.4\"}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 378 ") != NULL);
    CHECK(strstr(buf, "is connecting from user.example.net [1.2.3.4]") != NULL);
}

/* 378 RPL_WHOISHOST: only actually_ip set (solanum-style, no hostname). */
TEST(whois_actually_ip_only_emits_378_with_wildcard_host) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"actually_ip\":\"5.6.7.8\"}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 378 ") != NULL);
    CHECK(strstr(buf, "is connecting from * [5.6.7.8]") != NULL);
}

/* 379 RPL_WHOISMODES: umodes string. */
TEST(whois_umodes_emits_379) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"umodes\":\"+ioZ\"}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 379 ") != NULL);
    CHECK(strstr(buf, "is using modes +ioZ") != NULL);
}

/* 307 RPL_WHOISREGNICK: is_registered true. */
TEST(whois_is_registered_emits_307) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_registered\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 307 ") != NULL);
    CHECK(strstr(buf, "has identified for this nick") != NULL);
}

/* 671 from using_ssl (bahamut 275). Distinct from the existing `secure`
 * (solanum 671) path — must fire on using_ssl=true even when secure=false. */
TEST(whois_using_ssl_emits_671_with_ssl_trailer) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"using_ssl\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 671 ") != NULL);
    CHECK(strstr(buf, "is using a secure connection (SSL)") != NULL);
}

/* `secure` (solanum) path still works — must not be broken by the P-0a
 * additions. Emits 671 with no SSL trailer (bare label). */
TEST(whois_secure_flag_still_emits_671) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"secure\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 671 ") != NULL);
    /* The bare label (no [SSL] suffix) from the existing solanum path. */
    CHECK(strstr(buf, "is using a secure connection\r\n") != NULL);
}

/* is_admin → 320 "is an IRC Server Administrator". */
TEST(whois_is_admin_emits_320) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_admin\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 320 ") != NULL);
    CHECK(strstr(buf, "is an IRC Server Administrator") != NULL);
}

/* is_services_admin → 320 "is a Services Administrator". */
TEST(whois_is_services_admin_emits_320) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_services_admin\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 320 ") != NULL);
    CHECK(strstr(buf, "is a Services Administrator") != NULL);
}

/* is_helper → 320 "is a Help Operator". */
TEST(whois_is_helper_emits_320) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_helper\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 320 ") != NULL);
    CHECK(strstr(buf, "is a Help Operator") != NULL);
}

/* is_chanop → 320 "is a channel operator". */
TEST(whois_is_chanop_emits_320) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_chanop\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 320 ") != NULL);
    CHECK(strstr(buf, "is a channel operator") != NULL);
}

/* is_agent → 320 "is a Services Agent". */
TEST(whois_is_agent_emits_320) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_agent\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 320 ") != NULL);
    CHECK(strstr(buf, "is a Services Agent") != NULL);
}

/* is_java → 320 "is a Java User". */
TEST(whois_is_java_emits_320) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_java\":true}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 320 ") != NULL);
    CHECK(strstr(buf, "is a Java User") != NULL);
}

/* Full bahamut-style bundle: all five classes of P-0a fields at once.
 * Matches the "directly against the ircd" shape from issue #72. */
TEST(whois_full_bahamut_bundle_all_p0a_fields) {
    char buf[8192];
    render_whois("{\"target\":\"Target\","
                 "\"user\":\"u\",\"host\":\"h\",\"realname\":\"Real Name\","
                 "\"server\":\"irc.example.net\","
                 "\"server_info\":\"Server description\","
                 "\"is_operator\":true,"
                 "\"oper_text\":\"is an IRC Operator - Server Administrator\","
                 "\"actually_host\":\"host.example.net\","
                 "\"actually_ip\":\"10.0.0.1\","
                 "\"umodes\":\"+oiwsZ\","
                 "\"is_registered\":true,"
                 "\"using_ssl\":true,"
                 "\"is_agent\":true,"
                 "\"is_admin\":true,"
                 "\"idle_seconds\":120,"
                 "\"signon\":1700000000}",
                 buf, sizeof(buf));

    /* Standard numerics. */
    CHECK(strstr(buf, " 311 ") != NULL);
    CHECK(strstr(buf, " 312 ") != NULL);
    CHECK(strstr(buf, " 313 ") != NULL);
    CHECK(strstr(buf, " 317 ") != NULL);
    CHECK(strstr(buf, " 318 ") != NULL);

    /* P-0a numerics. */
    CHECK(strstr(buf, " 378 ") != NULL);
    CHECK(strstr(buf, "is connecting from host.example.net [10.0.0.1]") != NULL);
    CHECK(strstr(buf, " 379 ") != NULL);
    CHECK(strstr(buf, "is using modes +oiwsZ") != NULL);
    CHECK(strstr(buf, " 307 ") != NULL);
    CHECK(strstr(buf, "has identified for this nick") != NULL);
    CHECK(strstr(buf, "is using a secure connection (SSL)") != NULL);
    CHECK(strstr(buf, "is a Services Agent") != NULL);
    CHECK(strstr(buf, "is an IRC Server Administrator") != NULL);
}

/* P-0a fields must appear AFTER 313 and BEFORE 317 (fixed-order
 * post-313 placement per the WIRE.md spec). */
TEST(whois_p0a_fields_ordered_after_313_before_317) {
    char buf[8192];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_operator\":true,"
                 "\"is_registered\":true,"
                 "\"umodes\":\"+i\","
                 "\"idle_seconds\":30,\"signon\":1}",
                 buf, sizeof(buf));

    /* Find positions of the key numerics to assert ordering. */
    const char *p313 = strstr(buf, " 313 ");
    const char *p307 = strstr(buf, " 307 ");
    const char *p379 = strstr(buf, " 379 ");
    const char *p317 = strstr(buf, " 317 ");

    CHECK(p313 != NULL);
    CHECK(p307 != NULL);
    CHECK(p379 != NULL);
    CHECK(p317 != NULL);

    /* 307 and 379 must come after 313 and before 317. */
    CHECK(p313 < p307);
    CHECK(p313 < p379);
    CHECK(p307 < p317);
    CHECK(p379 < p317);
}

/* is_registered == false (default): no 307 must be emitted. */
TEST(whois_is_registered_false_does_not_emit_307) {
    char buf[4096];
    render_whois("{\"target\":\"T\",\"user\":\"u\",\"host\":\"h\","
                 "\"realname\":\"r\","
                 "\"is_registered\":false}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 307 ") == NULL);
}

/* No-such-nick path is unaffected: returns 401 + 318 with no P-0a lines. */
TEST(whois_no_such_nick_still_emits_401_and_318) {
    char buf[4096];
    render_whois("{\"target\":\"Ghost\"}",
                 buf, sizeof(buf));

    CHECK(strstr(buf, " 401 ") != NULL);
    CHECK(strstr(buf, " 318 ") != NULL);
    CHECK(strstr(buf, " 311 ") == NULL);
    CHECK(strstr(buf, " 307 ") == NULL);
    CHECK(strstr(buf, " 378 ") == NULL);
}

int main(void) {
    RUN(whois_minimal_bundle_emits_311_and_318);
    RUN(whois_actually_host_and_ip_emits_378);
    RUN(whois_actually_ip_only_emits_378_with_wildcard_host);
    RUN(whois_umodes_emits_379);
    RUN(whois_is_registered_emits_307);
    RUN(whois_using_ssl_emits_671_with_ssl_trailer);
    RUN(whois_secure_flag_still_emits_671);
    RUN(whois_is_admin_emits_320);
    RUN(whois_is_services_admin_emits_320);
    RUN(whois_is_helper_emits_320);
    RUN(whois_is_chanop_emits_320);
    RUN(whois_is_agent_emits_320);
    RUN(whois_is_java_emits_320);
    RUN(whois_full_bahamut_bundle_all_p0a_fields);
    RUN(whois_p0a_fields_ordered_after_313_before_317);
    RUN(whois_is_registered_false_does_not_emit_307);
    RUN(whois_no_such_nick_still_emits_401_and_318);
    return test_report();
}
