/* test_config.c — the config file and CLI parser.
 *
 * This file decides ONE security-relevant question: whether a plaintext
 * bind on a non-loopback address is allowed to start. Every downstream
 * client's grappa password rides inside PASS, so a false "yes" here puts
 * a real credential on the wire in the clear. That gate, and the parser
 * around it, is what these cases pin down.
 *
 * The rest is ordinary hostile-input work: a config file is a file, and a
 * parser that reads one has to survive whatever is in it.
 */
#include "../src/config.h"

#include "test.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* config_load_from_args takes argv, so each case builds one. The parser
 * only ever reads argv[1..], never argv[0], but a real argv has it. */
static bool load(const char *contents, struct config *cfg, const char *extra_flag,
                 char *stderr_out, size_t stderr_sz) {
    char path[64];
    test_write_temp(path, sizeof(path), contents);

    char *argv[5];
    int argc = 0;
    argv[argc++] = (char *)"bicchierino";
    argv[argc++] = (char *)"--config";
    argv[argc++] = path;
    if (extra_flag) argv[argc++] = (char *)extra_flag;
    argv[argc] = NULL;

    if (stderr_out) test_capture_stderr_start();
    bool ok = config_load_from_args(argc, argv, cfg);
    if (stderr_out) test_capture_stderr_end(stderr_out, stderr_sz);

    unlink(path);
    return ok;
}

TEST(a_minimal_config_loads) {
    struct config cfg;
    CHECK(load("grappa-url https://grappa.example.net\n"
               "bind 127.0.0.1 6667 plain\n",
               &cfg, NULL, NULL, 0));
    CHECK_STR(cfg.grappa_url, "https://grappa.example.net");
    CHECK_LONG(cfg.bind_count, 1);
    CHECK_STR(cfg.binds[0].ip, "127.0.0.1");
    CHECK_LONG(cfg.binds[0].port, 6667);
    CHECK(cfg.binds[0].tls == false);
    CHECK_STR(cfg.log_file, ""); /* absent = stderr only */
}

TEST(comments_and_blank_lines_are_ignored) {
    struct config cfg;
    CHECK(load("# leading comment\n"
               "\n"
               "   \t  \n"
               "grappa-url https://g.example\n"
               "\n"
               "bind 127.0.0.1 6667 plain   # trailing comment\n",
               &cfg, NULL, NULL, 0));
    CHECK_STR(cfg.grappa_url, "https://g.example");
    CHECK_LONG(cfg.bind_count, 1);
    CHECK_LONG(cfg.binds[0].port, 6667);
}

TEST(a_tls_bind_carries_its_paths) {
    struct config cfg;
    CHECK(load("grappa-url https://g.example\n"
               "bind 0.0.0.0 6697 tls /etc/b/cert.pem /etc/b/key.pem\n",
               &cfg, NULL, NULL, 0));
    CHECK_LONG(cfg.bind_count, 1);
    CHECK(cfg.binds[0].tls == true);
    CHECK_STR(cfg.binds[0].cert_path, "/etc/b/cert.pem");
    CHECK_STR(cfg.binds[0].key_path, "/etc/b/key.pem");
}

TEST(binds_are_repeatable_and_keep_their_order) {
    struct config cfg;
    CHECK(load("grappa-url https://g.example\n"
               "bind 127.0.0.1 6667 plain\n"
               "bind 127.0.0.2 6668 plain\n"
               "bind 0.0.0.0 6697 tls /c.pem /k.pem\n",
               &cfg, NULL, NULL, 0));
    CHECK_LONG(cfg.bind_count, 3);
    CHECK_STR(cfg.binds[0].ip, "127.0.0.1");
    CHECK_STR(cfg.binds[1].ip, "127.0.0.2");
    CHECK_LONG(cfg.binds[1].port, 6668);
    CHECK(cfg.binds[2].tls == true);
}

/* THE gate. A plaintext bind off loopback must not start by default. */
TEST(a_plain_bind_off_loopback_is_refused) {
    struct config cfg;
    char err[512];
    CHECK(!load("grappa-url https://g.example\n"
                "bind 0.0.0.0 6667 plain\n",
                &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "refusing to start") != NULL);
    CHECK(strstr(err, "--insecure") != NULL);

    /* Not just 0.0.0.0 — any non-127./::1 address. */
    CHECK(!load("grappa-url https://g.example\n"
                "bind 192.168.1.10 6667 plain\n",
                &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "refusing to start") != NULL);
}

TEST(insecure_opens_the_gate_and_only_that_gate) {
    struct config cfg;
    CHECK(load("grappa-url https://g.example\n"
               "bind 0.0.0.0 6667 plain\n",
               &cfg, "--insecure", NULL, 0));
    CHECK(cfg.insecure == true);
    CHECK_LONG(cfg.bind_count, 1);

    /* A malformed bind is still malformed with --insecure. */
    char err[512];
    CHECK(!load("grappa-url https://g.example\n"
                "bind 0.0.0.0 6667 sideways\n",
                &cfg, "--insecure", err, sizeof(err)));
    CHECK(strstr(err, "plain") != NULL);
}

/* is_loopback() is a deliberate string check, not a prefix parse: the
 * whole 127/8 range counts, and ::1 does. "localhost" deliberately does
 * NOT — it depends on resolver config, which the parser cannot see. */
TEST(loopback_means_127_slash_8_and_colon_colon_1) {
    struct config cfg;
    CHECK(load("grappa-url https://g.example\nbind 127.0.0.1 6667 plain\n", &cfg, NULL, NULL, 0));
    CHECK(load("grappa-url https://g.example\nbind 127.10.20.30 6667 plain\n", &cfg, NULL, NULL, 0));
    CHECK(load("grappa-url https://g.example\nbind ::1 6667 plain\n", &cfg, NULL, NULL, 0));

    char err[512];
    CHECK(!load("grappa-url https://g.example\nbind localhost 6667 plain\n", &cfg, NULL, err,
                sizeof(err)));
    CHECK(strstr(err, "refusing to start") != NULL);
}

TEST(both_required_directives_are_required) {
    struct config cfg;
    char err[512];

    CHECK(!load("bind 127.0.0.1 6667 plain\n", &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "grappa-url is required") != NULL);

    CHECK(!load("grappa-url https://g.example\n", &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "at least one bind") != NULL);

    CHECK(!load("", &cfg, NULL, err, sizeof(err)));
}

TEST(an_unknown_directive_fails_loudly) {
    struct config cfg;
    char err[512];
    CHECK(!load("grappa-url https://g.example\n"
                "bind 127.0.0.1 6667 plain\n"
                "frobnicate yes\n",
                &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "unknown directive") != NULL);
    CHECK(strstr(err, "frobnicate") != NULL);
}

TEST(malformed_binds_are_rejected) {
    struct config cfg;
    char err[512];

    /* Too few fields. */
    CHECK(!load("grappa-url https://g.example\nbind 127.0.0.1\n", &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "bind needs") != NULL);

    CHECK(!load("grappa-url https://g.example\nbind\n", &cfg, NULL, err, sizeof(err)));

    /* tls without its two paths. */
    CHECK(!load("grappa-url https://g.example\nbind 0.0.0.0 6697 tls /only-one.pem\n", &cfg, NULL,
                err, sizeof(err)));
    CHECK(strstr(err, "cert-path") != NULL);
}

TEST(a_directive_with_no_value_is_rejected) {
    struct config cfg;
    char err[512];
    CHECK(!load("grappa-url\nbind 127.0.0.1 6667 plain\n", &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "grappa-url needs a value") != NULL);

    CHECK(!load("grappa-url https://g.example\n"
                "bind 127.0.0.1 6667 plain\n"
                "log-file\n",
                &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "log-file needs a value") != NULL);
}

TEST(more_binds_than_fit_is_refused_not_overflowed) {
    char buf[2048];
    int n = snprintf(buf, sizeof(buf), "grappa-url https://g.example\n");
    for (int i = 0; i < CONFIG_MAX_BINDS + 4; i++) {
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "bind 127.0.0.1 %d plain\n", 7000 + i);
    }
    struct config cfg;
    char err[512];
    CHECK(!load(buf, &cfg, NULL, err, sizeof(err)));
    CHECK(strstr(err, "too many bind") != NULL);
}

/* Oversized tokens must truncate or fail, never scribble past the fixed
 * arrays in struct config. Run this under ASan to mean anything. */
TEST(oversized_values_do_not_overflow) {
    char buf[4096];
    char long_url[1200];
    memset(long_url, 'u', sizeof(long_url) - 1);
    long_url[sizeof(long_url) - 1] = '\0';

    char long_ip[300];
    memset(long_ip, '7', sizeof(long_ip) - 1);
    long_ip[sizeof(long_ip) - 1] = '\0';

    struct config cfg;
    /* These are expected to be rejected, loudly. Capture the complaint so
     * a passing suite stays readable. */
    char noise[1024];

    snprintf(buf, sizeof(buf), "grappa-url https://%s\nbind 127.0.0.1 6667 plain\n", long_url);
    load(buf, &cfg, NULL, noise, sizeof(noise)); /* pass or fail, must not corrupt */
    CHECK(cfg.grappa_url[CONFIG_MAX_URL - 1] == '\0');

    snprintf(buf, sizeof(buf), "grappa-url https://g.example\nbind %s 6667 plain\n", long_ip);
    load(buf, &cfg, NULL, noise, sizeof(noise));

    char long_path[600];
    memset(long_path, 'p', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    snprintf(buf, sizeof(buf), "grappa-url https://g.example\nbind 0.0.0.0 6697 tls /%s /%s\n",
             long_path, long_path);
    load(buf, &cfg, NULL, noise, sizeof(noise));
    CHECK(cfg.binds[0].cert_path[CONFIG_MAX_PATH - 1] == '\0');
}

/* A line longer than CONFIG_MAX_LINE is split by fgets, so its tail is
 * read as a fresh line. That tail must not be mistaken for a directive
 * that silently succeeds — whatever happens, it is not "loaded fine". */
TEST(an_overlong_line_does_not_smuggle_a_directive) {
    char buf[8192];
    char filler[3000];
    memset(filler, 'x', sizeof(filler) - 1);
    filler[sizeof(filler) - 1] = '\0';

    snprintf(buf, sizeof(buf), "grappa-url https://g.example\nbind 127.0.0.1 6667 plain\n# %s\n",
             filler);
    struct config cfg;
    char err[512];
    /* The comment's tail spills into the next fgets chunk as garbage.
     * Fine either way — but if it loads, it must not have invented a
     * second bind out of the filler. */
    if (load(buf, &cfg, NULL, err, sizeof(err))) CHECK_LONG(cfg.bind_count, 1);
}

TEST(missing_config_file_is_reported_not_ignored) {
    struct config cfg;
    char *argv[] = {(char *)"bicchierino", (char *)"--config", (char *)"/nonexistent/nope.config",
                    NULL};
    char err[512];
    test_capture_stderr_start();
    bool ok = config_load_from_args(3, argv, &cfg);
    test_capture_stderr_end(err, sizeof(err));
    CHECK(!ok);
    CHECK(strstr(err, "cannot open config file") != NULL);
}

TEST(cli_arguments_are_validated) {
    struct config cfg;
    char err[512];

    /* --config with nothing after it. */
    char *argv1[] = {(char *)"bicchierino", (char *)"--config", NULL};
    test_capture_stderr_start();
    bool ok = config_load_from_args(2, argv1, &cfg);
    test_capture_stderr_end(err, sizeof(err));
    CHECK(!ok);
    CHECK(strstr(err, "--config needs a path") != NULL);

    /* An argument nobody defined. */
    char *argv2[] = {(char *)"bicchierino", (char *)"--wat", NULL};
    test_capture_stderr_start();
    ok = config_load_from_args(2, argv2, &cfg);
    test_capture_stderr_end(err, sizeof(err));
    CHECK(!ok);
    CHECK(strstr(err, "unknown argument") != NULL);
}

int main(void) {
    RUN(a_minimal_config_loads);
    RUN(comments_and_blank_lines_are_ignored);
    RUN(a_tls_bind_carries_its_paths);
    RUN(binds_are_repeatable_and_keep_their_order);
    RUN(a_plain_bind_off_loopback_is_refused);
    RUN(insecure_opens_the_gate_and_only_that_gate);
    RUN(loopback_means_127_slash_8_and_colon_colon_1);
    RUN(both_required_directives_are_required);
    RUN(an_unknown_directive_fails_loudly);
    RUN(malformed_binds_are_rejected);
    RUN(a_directive_with_no_value_is_rejected);
    RUN(more_binds_than_fit_is_refused_not_overflowed);
    RUN(oversized_values_do_not_overflow);
    RUN(an_overlong_line_does_not_smuggle_a_directive);
    RUN(missing_config_file_is_reported_not_ignored);
    RUN(cli_arguments_are_validated);
    return test_report();
}
