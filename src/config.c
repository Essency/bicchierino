#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_MAX_LINE 1024
#define DEFAULT_CONFIG_PATH "./bicchierino.config"

/* 127.0.0.0/8 and ::1 only — a string check, not a real prefix parse.
 * Deliberately narrow: this gates whether a `plain` (non-TLS) bind is
 * allowed to start at all, so a false negative (calling something
 * loopback that isn't) would be the dangerous direction. "localhost" is
 * not accepted here on purpose — it depends on resolver configuration,
 * which is not a fact this function can see. */
static bool is_loopback(const char *ip) {
    if (strncmp(ip, "127.", 4) == 0) return true;
    if (strcmp(ip, "::1") == 0) return true;
    return false;
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
    if (out->bind_count == 0) {
        fprintf(stderr, "config: at least one bind directive is required\n");
        return false;
    }

    return true;
}
