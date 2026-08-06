#include "connection.h"

#include <ctype.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define IRC_LINE_MAX 512
#define IRC_MAX_PARAMS 15
#define LINEBUF_CAP (IRC_LINE_MAX * 4)

/* ── Line reader ───────────────────────────────────────────────────────
 *
 * A single recv() can hand back a partial line, a whole line, or several
 * — TCP has no message boundaries. This buffers across calls and hands
 * the caller one CRLF- or LF-terminated line at a time, same shape as
 * shottino's ws_reader (buffer, don't assume a read equals a message). */
struct linebuf {
    char data[LINEBUF_CAP];
    size_t len;
};

enum next_line_result { NEXT_LINE_OK = 1, NEXT_LINE_EOF = 0, NEXT_LINE_ERROR = -1 };

static int next_line(int fd, struct linebuf *lb, char *line, size_t line_sz) {
    for (;;) {
        char *nl = memchr(lb->data, '\n', lb->len);
        if (nl) {
            size_t line_len = (size_t)(nl - lb->data);
            if (line_len > 0 && lb->data[line_len - 1] == '\r') line_len--;
            if (line_len >= line_sz) line_len = line_sz - 1;
            memcpy(line, lb->data, line_len);
            line[line_len] = '\0';

            size_t consumed = (size_t)(nl - lb->data) + 1;
            memmove(lb->data, lb->data + consumed, lb->len - consumed);
            lb->len -= consumed;
            return NEXT_LINE_OK;
        }

        if (lb->len >= sizeof(lb->data)) {
            /* A line longer than we're willing to buffer at all — this is
             * not a well-behaved IRC client. Nothing recoverable to do
             * with a line this size; drop the connection. */
            fprintf(stderr, "bicchierino: client sent a line over %zu bytes, closing\n",
                    sizeof(lb->data));
            return NEXT_LINE_ERROR;
        }

        ssize_t n = recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len, 0);
        if (n == 0) return NEXT_LINE_EOF;
        if (n < 0) return NEXT_LINE_ERROR;
        lb->len += (size_t)n;
    }
}

/* ── IRC message parsing ──────────────────────────────────────────────
 *
 * Client-to-server messages carry no prefix (RFC 2812 §2.3 — that's
 * server-to-client only), so this doesn't look for one. Params are
 * space-separated tokens; a token starting with ':' is the trailing
 * param and consumes the rest of the line, spaces included. */
struct irc_message {
    char command[32];
    char params[IRC_MAX_PARAMS][IRC_LINE_MAX];
    int param_count;
};

static bool irc_parse_line(const char *line, struct irc_message *msg) {
    memset(msg, 0, sizeof(*msg));
    const char *p = line;

    while (*p == ' ') p++;
    if (*p == '\0') return false;

    size_t cmd_len = 0;
    while (*p && *p != ' ' && cmd_len < sizeof(msg->command) - 1) msg->command[cmd_len++] = *p++;
    msg->command[cmd_len] = '\0';
    for (size_t i = 0; i < cmd_len; i++) msg->command[i] = (char)toupper((unsigned char)msg->command[i]);

    while (msg->param_count < IRC_MAX_PARAMS) {
        while (*p == ' ') p++;
        if (*p == '\0') break;

        if (*p == ':') {
            p++;
            snprintf(msg->params[msg->param_count], IRC_LINE_MAX, "%s", p);
            msg->param_count++;
            break;
        }

        size_t len = 0;
        char *dst = msg->params[msg->param_count];
        while (*p && *p != ' ' && len < IRC_LINE_MAX - 1) dst[len++] = *p++;
        dst[len] = '\0';
        msg->param_count++;
    }

    return true;
}

static void send_line(int fd, const char *fmt, ...) {
    char buf[IRC_LINE_MAX];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    buf[n++] = '\r';
    buf[n++] = '\n';
    /* Best-effort: if the write fails the connection is already dead and
     * the caller is about to close it anyway. */
    ssize_t unused = write(fd, buf, (size_t)n);
    (void)unused;
}

/* ── Registration state ───────────────────────────────────────────────
 *
 * Buffered until both NICK and USER arrive, same pattern as shottino's
 * ircd_maybe_register — clients send these in either order. CAP is
 * tolerated (parsed, never errors) but not negotiated: bicchierino does
 * not offer any IRCv3 capabilities yet, so there is nothing to LS/REQ.
 *
 * TODO: a client that sends `CAP LS` and waits for a reply before `CAP
 * END` may stall here — we never reply to CAP at all yet. Real clients
 * generally time out and proceed, but this is a known gap, not a design
 * decision (CLAUDE.md §1's IRC-side admin commands note is unrelated;
 * this is plain protocol negotiation, worth fixing before this is used
 * with anything other than a client tested to not require it). */
struct registration {
    char pass_raw[IRC_LINE_MAX]; /* "network:password" or bare "password" */
    char account[IRC_LINE_MAX];  /* USER's first param */
    char nick[IRC_LINE_MAX];
    bool got_pass;
    bool got_user;
    bool got_nick;
};

static void handle_registration_message(const struct irc_message *msg, struct registration *reg) {
    if (strcmp(msg->command, "PASS") == 0) {
        if (msg->param_count >= 1) {
            snprintf(reg->pass_raw, sizeof(reg->pass_raw), "%s", msg->params[0]);
            reg->got_pass = true;
        }
    } else if (strcmp(msg->command, "NICK") == 0) {
        if (msg->param_count >= 1) {
            snprintf(reg->nick, sizeof(reg->nick), "%s", msg->params[0]);
            reg->got_nick = true;
        }
    } else if (strcmp(msg->command, "USER") == 0) {
        if (msg->param_count >= 1) {
            snprintf(reg->account, sizeof(reg->account), "%s", msg->params[0]);
            reg->got_user = true;
        }
    }
    /* CAP, PING, and anything else pre-registration: silently tolerated.
     * A real client sends little else before NICK/USER. */
}

/* Splits "network:password" on the first ':'. No colon → network is
 * empty (resolved against the account's networks once login exists —
 * CLAUDE.md §3, WIRE.md's PASS convention) and the whole string is the
 * password. */
static void split_network_password(const char *raw, char *network, size_t network_sz,
                                    char *password, size_t password_sz) {
    const char *colon = strchr(raw, ':');
    if (!colon) {
        network[0] = '\0';
        snprintf(password, password_sz, "%s", raw);
        return;
    }
    size_t net_len = (size_t)(colon - raw);
    if (net_len >= network_sz) net_len = network_sz - 1;
    memcpy(network, raw, net_len);
    network[net_len] = '\0';
    snprintf(password, password_sz, "%s", colon + 1);
}

/* TODO(next): the real thing — POST /auth/login (WIRE.md §1), then WS
 * connect + topic joins (WIRE.md §3-4). Stubbed so the registration path
 * above is real and testable end to end before the grappa leg exists.
 * CLAUDE.md §3.3's "grappa not reachable" ERROR is for when that call
 * genuinely fails once written — this stub says something different on
 * purpose, so the two are never confused while debugging. */
static void attempt_grappa_login(int fd, const char *account, const char *network,
                                  const char *password, const struct config *cfg) {
    (void)password;
    fprintf(stderr,
            "bicchierino: registration parsed OK (account=%s network=%s grappa_url=%s) — "
            "grappa login not implemented yet\n",
            account, network[0] ? network : "(default)", cfg->grappa_url);
    send_line(fd, "ERROR :bicchierino: grappa login not implemented yet");
}

void *connection_run(void *arg) {
    struct connection_args *args = arg;
    int fd = args->client_fd;
    const struct config *cfg = args->cfg;

    struct linebuf lb = {0};
    struct registration reg = {0};
    char line[IRC_LINE_MAX];

    for (;;) {
        int r = next_line(fd, &lb, line, sizeof(line));
        if (r == NEXT_LINE_EOF) break;
        if (r == NEXT_LINE_ERROR) break;

        struct irc_message msg;
        if (!irc_parse_line(line, &msg)) continue;

        handle_registration_message(&msg, &reg);

        if (reg.got_nick && reg.got_user) {
            char network[IRC_LINE_MAX], password[IRC_LINE_MAX];
            split_network_password(reg.got_pass ? reg.pass_raw : "", network, sizeof(network),
                                    password, sizeof(password));
            attempt_grappa_login(fd, reg.account, network, password, cfg);
            break;
        }
    }

    close(fd);
    free(args);
    return NULL;
}
