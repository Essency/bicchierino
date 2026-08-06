/* config.h — directive-per-line config file + CLI parsing.
 *
 * See example.config in the repo root for the format, and
 * CLAUDE.md §3.1 for why this shape was chosen over JSON/libconfig.
 */
#ifndef BICCHIERINO_CONFIG_H
#define BICCHIERINO_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#define CONFIG_MAX_BINDS 16
#define CONFIG_MAX_PATH 256
#define CONFIG_MAX_URL 512

struct bind_config {
    char ip[64];
    int port;
    bool tls;
    char cert_path[CONFIG_MAX_PATH];
    char key_path[CONFIG_MAX_PATH];
};

struct config {
    char grappa_url[CONFIG_MAX_URL];
    struct bind_config binds[CONFIG_MAX_BINDS];
    size_t bind_count;
    char log_file[CONFIG_MAX_PATH]; /* empty = stderr only */
    bool insecure;                  /* --insecure: allow non-loopback plain binds */
};

/* Parses argv for --config <path> and --insecure, loads the config file
 * (default ./bicchierino.config if --config wasn't given), and validates
 * it (CLAUDE.md §3.1: a non-loopback "plain" bind refuses to start unless
 * --insecure was passed).
 *
 * Returns true and fills *out on success. On failure, prints a message to
 * stderr and returns false — the caller's job is just to exit non-zero. */
bool config_load_from_args(int argc, char **argv, struct config *out);

#endif /* BICCHIERINO_CONFIG_H */
