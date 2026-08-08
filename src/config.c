#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_MAX_LINE 1024
#define DEFAULT_CONFIG_PATH "./bicchierino.config"

/* 127.0.0.0/8 only — a string check, not a real prefix parse.
 * Deliberately narrow: this gates whether a `plain` (non-TLS) bind is
 * allowed to start at all, so a false negative (calling something
 * loopback that isn't) would be the dangerous direction. "localhost" is
 * not accepted here on purpose — it depends on resolver configuration,
 * which is not a fact this function can see.  IPv6 loopback (::1) is not
 * handled here because IPv6 bind addresses are rejected earlier by
 * parse_bind_line, before this function is ever called. */
static bool is_loopback(const char *ip) {
    if (strncmp(ip, "127.", 4) == 0) return true;
    return false;
}

/* Extracts the host of `url`, whose scheme prefix has already been
 * matched and is `prefix_len` bytes long, into `out`.
 *
 * Deliberately a second, minimal parse rather than reusing http.c's
 * parse_grappa_url: config.c is the one translation unit with no OpenSSL
 * dependency — tests/test_config links it on its own, see the Makefile —
 * and this check has to run at startup, before anything opens a socket.
 * The two parsers only need to agree on the shape that matters here: the
 * host ends at the first ':' or '/'. */
static bool url_host(const char *url, size_t prefix_len, char *out, size_t out_sz) {
    const char *rest = url + prefix_len;
    size_t n = strcspn(rest, ":/");
    if (n == 0 || n >= out_sz) return false;
    memcpy(out, rest, n);
    out[n] = '\0';
    return true;
}

/* `https://` always; `http://` only towards a loopback literal, unless
 * --insecure says otherwise.
 *
 * This is the mirror image of parse_bind_line's rule below, and it is
 * the same secret in both directions: there, a plaintext non-loopback
 * bind would put the downstream client's PASS (a real grappa password)
 * on the network; here, a plaintext non-loopback grappa-url would put
 * grappa's own bearer token there. Accepting one and refusing the other
 * would be incoherent.
 *
 * The loopback case is worth supporting because it is the normal
 * self-hosted shape: bicchierino and grappa on the same machine, where
 * demanding TLS means either routing local traffic out through a public
 * name or standing up a certificate for 127.0.0.1 — ceremony that buys
 * nothing a loopback socket does not already give.
 *
 * is_loopback() is reused as-is, which also means "localhost" is refused
 * here: it is a resolver claim, not a fact this function can verify, and
 * this gate decides whether a bearer token may leave the process in the
 * clear. A literal address costs the operator four characters. There is
 * no IPv6 branch either, and not by oversight — http.c's own URL parser
 * splits the host at the first ':', so a literal IPv6 address cannot
 * survive it in any case; recognising ::1 here would only accept a URL
 * that the connect path then fails on. That limit is pre-existing. */
static bool validate_grappa_url(const char *url, struct config *cfg) {
    static const char https_prefix[] = "https://";
    static const char http_prefix[] = "http://";

    if (strncmp(url, https_prefix, sizeof(https_prefix) - 1) == 0) return true;

    if (strncmp(url, http_prefix, sizeof(http_prefix) - 1) != 0) {
        fprintf(stderr, "config: grappa-url %s must start with https:// or http://\n", url);
        return false;
    }

    char host[256];
    if (!url_host(url, sizeof(http_prefix) - 1, host, sizeof(host))) {
        fprintf(stderr, "config: grappa-url %s has no host\n", url);
        return false;
    }
    if (!is_loopback(host) && !cfg->insecure) {
        fprintf(stderr,
                "config: grappa-url %s is plaintext and not loopback — refusing to start "
                "(grappa's bearer token would cross the network in the clear). "
                "Pass --insecure to override.\n",
                url);
        return false;
    }
    return true;
}

static void strip_comment_and_newline(char *line) {
    char *hash = strchr(line, '#');
    if (hash) *hash = '\0';
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r' ||
                        line[len - 1] == ' ' || line[len - 1] == '\t')) {
        line[--len] = '\0';
    }
}

static bool is_blank(const char *line) {
    for (const char *p = line; *p; p++) {
        if (*p != ' ' && *p != '\t') return false;
    }
    return true;
}

static bool parse_bind_line(char *rest, size_t lineno, struct config *cfg) {
    if (cfg->bind_count >= CONFIG_MAX_BINDS) {
        fprintf(stderr, "config line %zu: too many bind directives (max %d)\n", lineno,
                CONFIG_MAX_BINDS);
        return false;
    }
    struct bind_config *b = &cfg->binds[cfg->bind_count];
    memset(b, 0, sizeof(*b));

    char mode[16] = {0};
    int mode_end = 0;
    if (sscanf(rest, "%63s %d %15s%n", b->ip, &b->port, mode, &mode_end) < 3) {
        fprintf(stderr, "config line %zu: bind needs <ip> <port> plain|tls\n", lineno);
        return false;
    }

    /* The listener in main.c is IPv4-only.  Catch IPv6 addresses here, at
     * config-parse time, so the error surfaces before any sockets are
     * touched rather than mid-startup after other listeners may already be
     * open. A colon in the address is a reliable IPv6 marker for any
     * address a user would plausibly write (::1, ::, 2001:db8::1, …). */
    if (strchr(b->ip, ':') != NULL) {
        fprintf(stderr, "config line %zu: bind address '%s': IPv6 not wired up yet\n",
                lineno, b->ip);
        return false;
    }

    if (strcmp(mode, "plain") == 0) {
        b->tls = false;
    } else if (strcmp(mode, "tls") == 0) {
        b->tls = true;
        if (sscanf(rest + mode_end, "%255s %255s", b->cert_path, b->key_path) != 2) {
            fprintf(stderr, "config line %zu: bind ... tls needs <cert-path> <key-path>\n",
                    lineno);
            return false;
        }
    } else {
        fprintf(stderr, "config line %zu: bind mode must be 'plain' or 'tls', got '%s'\n",
                lineno, mode);
        return false;
    }

    if (!b->tls && !is_loopback(b->ip) && !cfg->insecure) {
        fprintf(stderr,
                "config line %zu: bind %s:%d is plaintext and not loopback — refusing to "
                "start (the downstream PASS carries a real grappa password). "
                "Pass --insecure to override.\n",
                lineno, b->ip, b->port);
        return false;
    }

    cfg->bind_count++;
    return true;
}

static bool parse_config_file(const char *path, struct config *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open config file %s: %s\n", path, strerror(errno));
        return false;
    }

    char line[CONFIG_MAX_LINE];
    size_t lineno = 0;
    bool ok = true;

    while (ok && fgets(line, sizeof(line), f)) {
        lineno++;
        strip_comment_and_newline(line);
        if (is_blank(line)) continue;

        char directive[32] = {0};
        int consumed = 0;
        if (sscanf(line, "%31s%n", directive, &consumed) != 1) continue;
        char *rest = line + consumed;
        while (*rest == ' ' || *rest == '\t') rest++;

        if (strcmp(directive, "grappa-url") == 0) {
            if (sscanf(rest, "%511s", cfg->grappa_url) != 1) {
                fprintf(stderr, "config line %zu: grappa-url needs a value\n", lineno);
                ok = false;
            }
        } else if (strcmp(directive, "bind") == 0) {
            ok = parse_bind_line(rest, lineno, cfg);
        } else if (strcmp(directive, "log-file") == 0) {
            if (sscanf(rest, "%255s", cfg->log_file) != 1) {
                fprintf(stderr, "config line %zu: log-file needs a value\n", lineno);
                ok = false;
            }
        } else {
            fprintf(stderr, "config line %zu: unknown directive '%s'\n", lineno, directive);
            ok = false;
        }
    }

    fclose(f);
    return ok;
}

bool config_load_from_args(int argc, char **argv, struct config *out) {
    memset(out, 0, sizeof(*out));
    const char *config_path = DEFAULT_CONFIG_PATH;

    /* First pass: --insecure has to be known before we parse binds, since
     * the bind parser checks it inline. --config just picks the path. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--insecure") == 0) {
            out->insecure = true;
        } else if (strcmp(argv[i], "--config") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "--config needs a path argument\n");
                return false;
            }
            config_path = argv[++i];
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return false;
        }
    }

    if (!parse_config_file(config_path, out)) return false;

    if (out->grappa_url[0] == '\0') {
        fprintf(stderr, "config: grappa-url is required\n");
        return false;
    }
    if (!validate_grappa_url(out->grappa_url, out)) return false;
    if (out->bind_count == 0) {
        fprintf(stderr, "config: at least one bind directive is required\n");
        return false;
    }

    return true;
}
