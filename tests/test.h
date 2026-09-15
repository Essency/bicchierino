/* test.h — the smallest thing that can hold bicchierino honest.
 *
 * Ported from shottino's tests/test.h, which is the same set of macros
 * this needs and is already proven across nineteen suites there. The
 * shottino-only parts are deliberately NOT carried over: it grew a
 * temporary-$HOME guard because shottino writes prefs under
 * shottino_state_dir(), and bicchierino never touches $HOME at all (its
 * config path is ./bicchierino.config or whatever --config names). A
 * guard for a thing that cannot happen is noise that later readers have
 * to disprove.
 *
 * No framework dependency: a header of macros, one `main` per suite,
 * non-zero exit on failure.
 *
 * Usage:
 *   TEST(name) { ... CHECK(cond); CHECK_STR(a, b); }
 *   int main(void) { RUN(name); return test_report(); }
 */
#ifndef BICCHIERINO_TEST_H
#define BICCHIERINO_TEST_H

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int test_failures;
static int test_checks;
static const char *test_current;

#define TEST(name) static void test_##name(void)

#define RUN(name)                                                                                  \
    do {                                                                                           \
        test_current = #name;                                                                      \
        test_##name();                                                                             \
    } while (0)

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        test_checks++;                                                                             \
        if (!(cond)) {                                                                             \
            test_failures++;                                                                       \
            fprintf(stderr, "FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, test_current, #cond);      \
        }                                                                                          \
    } while (0)

/* An unconditional failure, for the case a CHECK cannot express: a
 * dependency the test needs is missing, so nothing below it can run. */
#define FAIL(msg)                                                                                  \
    do {                                                                                           \
        test_checks++;                                                                             \
        test_failures++;                                                                           \
        fprintf(stderr, "FAIL %s:%d [%s] %s\n", __FILE__, __LINE__, test_current, msg);            \
    } while (0)

/* String equality with both values printed on failure — a bare CHECK on
 * strcmp tells you it differed but not how, which is the whole question. */
#define CHECK_STR(actual, expect)                                                                  \
    do {                                                                                           \
        test_checks++;                                                                             \
        const char *a_ = (actual);                                                                 \
        const char *e_ = (expect);                                                                 \
        if (!a_ || !e_ || strcmp(a_, e_) != 0) {                                                   \
            test_failures++;                                                                       \
            fprintf(stderr, "FAIL %s:%d [%s] expected \"%s\", got \"%s\"\n", __FILE__, __LINE__,   \
                    test_current, e_ ? e_ : "(null)", a_ ? a_ : "(null)");                         \
        }                                                                                          \
    } while (0)

#define CHECK_LONG(actual, expect)                                                                 \
    do {                                                                                           \
        test_checks++;                                                                             \
        long a_ = (long)(actual);                                                                  \
        long e_ = (long)(expect);                                                                  \
        if (a_ != e_) {                                                                            \
            test_failures++;                                                                       \
            fprintf(stderr, "FAIL %s:%d [%s] expected %ld, got %ld\n", __FILE__, __LINE__,         \
                    test_current, e_, a_);                                                         \
        }                                                                                          \
    } while (0)

/* CAPTURING STDERR. bicchierino's diagnostics contract is that errors
 * ALWAYS reach stderr (example.config says so, and main.c relies on it),
 * so asserting on a rejection means reading what it printed. stderr is
 * also where test.h reports failures, so it is put back BEFORE anything
 * is asserted — a CHECK between start and end writes its own diagnosis
 * into the buffer under test and then loses it. */
static int test_capture_fd = -1;
static char test_capture_path[64];

static inline void test_capture_stderr_start(void) {
    snprintf(test_capture_path, sizeof(test_capture_path), "/tmp/bicchierino-capture-XXXXXX");
    int fd = mkstemp(test_capture_path);
    if (fd < 0) abort();
    fflush(stderr);
    test_capture_fd = dup(STDERR_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
}

static inline void test_capture_stderr_end(char *out, size_t out_sz) {
    fflush(stderr);
    dup2(test_capture_fd, STDERR_FILENO);
    close(test_capture_fd);
    test_capture_fd = -1;
    FILE *f = fopen(test_capture_path, "r");
    size_t n = f ? fread(out, 1, out_sz - 1, f) : 0;
    out[n] = 0;
    if (f) fclose(f);
    unlink(test_capture_path);
}

/* A scratch file, for the suites that must hand a real path to code that
 * opens one (config parsing). Removed by the caller with unlink(). */
static inline void test_write_temp(char *path_out, size_t path_sz, const char *content) {
    snprintf(path_out, path_sz, "/tmp/bicchierino-test-XXXXXX");
    int fd = mkstemp(path_out);
    if (fd < 0) {
        fprintf(stderr, "FATAL %s: mkstemp: %s\n", __FILE__, strerror(errno));
        exit(1);
    }
    size_t len = strlen(content);
    if (len && write(fd, content, len) != (ssize_t)len) {
        fprintf(stderr, "FATAL %s: short write to %s\n", __FILE__, path_out);
        close(fd);
        exit(1);
    }
    close(fd);
}

static int test_report(void) {
    if (test_failures) {
        fprintf(stderr, "\n%d/%d checks FAILED\n", test_failures, test_checks);
        return 1;
    }
    fprintf(stderr, "%d checks passed\n", test_checks);
    return 0;
}

#endif /* BICCHIERINO_TEST_H */
