#include "connection.h"

#include <ctype.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp — slug matching is case-insensitive */
#include <sys/socket.h>
#include <unistd.h>

#include "http.h"
#include "json.h"
#include "ws_client.h"

#define IRC_LINE_MAX 512
#define MAX_CHANNELS 128 /* a comparable production bouncer's own scale doc uses ~70 channels as
                           * its reference point; this is a hostile-
                           * response backstop, not a real ceiling */
#define MAX_NETWORKS 64  /* generous — real accounts bind a handful */
#define IRCD_SERVER "bicchierino"
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

struct network_entry {
    char slug[64];
    long id;
};

/* Everything learned about this session across login (WIRE.md §1) and
 * the bootstrap discovery calls (WIRE.md §1.5), before the websocket
 * even opens. Lives on connection_run's stack — one per connection
 * thread, never shared (CLAUDE.md §3: zero state shared between
 * connections).
 *
 * `networks[]` is the full list from GET /networks, kept around (not
 * just the one PASS resolved to) so Case B's `GRAPPA NETWORK <slug>`
 * can validate against it later without a second round trip to grappa
 * (CLAUDE.md §3, §1's "IRC-side admin commands" note). */
struct grappa_session {
    char token[512];
    char subject_name[128];
    struct network_entry networks[MAX_NETWORKS];
    size_t network_count;
    char network_slug[64];
    long network_id;
    bool network_resolved;
    char channels[MAX_CHANNELS][128];
    size_t channel_count;
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

/* Minimal JSON string escaper — not a general encoder, just enough for
 * the two string fields the login body ever carries. json.c (vendored)
 * only reads JSON and re-serializes an already-parsed value; it has no
 * builder API for constructing a fresh document from raw C strings, so
 * this is the one place bicchierino writes JSON by hand rather than
 * through the vendored library. */
static void json_escape_into(const char *src, char *dst, size_t dst_sz) {
    size_t di = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && di + 1 < dst_sz; p++) {
        if (*p == '"' || *p == '\\') {
            if (di + 2 >= dst_sz) break;
            dst[di++] = '\\';
            dst[di++] = (char)*p;
        } else if (*p == '\n' || *p == '\r' || *p == '\t') {
            if (di + 2 >= dst_sz) break;
            dst[di++] = '\\';
            dst[di++] = *p == '\n' ? 'n' : (*p == '\r' ? 'r' : 't');
        } else if (*p < 0x20) {
            if (di + 6 >= dst_sz) break;
            di += (size_t)snprintf(dst + di, dst_sz - di, "\\u%04x", *p);
        } else {
            dst[di++] = (char)*p;
        }
    }
    dst[di] = '\0';
}

/* WIRE.md §1: the identifier MUST look like an email or grappa's
 * IdentifierClassifier routes it to nick_login (visitor flow) instead of
 * mode1_login (real account login) — confirmed against auth_controller.ex
 * directly, not guessed. The domain half is never used for anything;
 * "bicchierino.local" just needs to make the string email-shaped. */
#define LOGIN_IDENTIFIER_MAX (IRC_LINE_MAX + 32) /* account + "@bicchierino.local" */
#define LOGIN_BODY_MAX (IRC_LINE_MAX * 2 * 2 + 64) /* both escaped fields + the JSON template */

static void build_login_body(const char *account, const char *password, char *body,
                              size_t body_sz) {
    char identifier[LOGIN_IDENTIFIER_MAX];
    snprintf(identifier, sizeof(identifier), "%s@bicchierino.local", account);

    char esc_identifier[IRC_LINE_MAX * 2];
    char esc_password[IRC_LINE_MAX * 2];
    json_escape_into(identifier, esc_identifier, sizeof(esc_identifier));
    json_escape_into(password, esc_password, sizeof(esc_password));

    snprintf(body, body_sz, "{\"identifier\":\"%s\",\"password\":\"%s\"}", esc_identifier,
             esc_password);
}

/* POST /auth/login (WIRE.md §1) and report what happened on the IRC
 * socket. Returns true only on a genuine 200 with a usable token+subject
 * — false covers everything else (bad credentials, grappa unreachable,
 * a malformed response), and the caller's response is the same either
 * way at this point in the connection (CLAUDE.md §3.3: bare ERROR, no
 * 001 was ever sent, so no numeric). The three failure messages stay
 * textually distinct on purpose — "not reachable" vs "invalid
 * credentials" vs a malformed-response case are different bugs to chase
 * and must not look identical in a log.
 *
 * The token/subject are copied out (not left as pointers into the parsed
 * `json_doc`) because the doc is freed before this returns — a
 * `json_string()` result is only valid as long as its document is. */
static bool attempt_grappa_login(int fd, const char *account, const char *password,
                                  const struct config *cfg, struct grappa_session *sess) {
    char body[LOGIN_BODY_MAX];
    build_login_body(account, password, body, sizeof(body));

    struct http_response resp;
    if (!https_post_login(cfg->grappa_url, body, &resp)) {
        fprintf(stderr, "bicchierino: grappa not reachable at %s\n", cfg->grappa_url);
        send_line(fd, "ERROR :Could not reach the grappa server, please try again");
        return false;
    }

    bool ok = false;
    if (resp.status == 200) {
        char err[128];
        json_doc *doc = json_parse(resp.body, resp.body_len, err, sizeof(err));
        if (!doc) {
            fprintf(stderr, "bicchierino: grappa login: malformed JSON response: %s\n", err);
            send_line(fd, "ERROR :The grappa server sent back something unexpected, "
                          "please contact the admin");
        } else {
            const json_value *root = json_root(doc);
            const char *token = NULL;
            const json_value *subject = json_get(root, "subject");
            const char *subject_name = NULL;
            if (json_str_req(root, "token", &token) && subject &&
                json_str_req(subject, "name", &subject_name)) {
                snprintf(sess->token, sizeof(sess->token), "%s", token);
                snprintf(sess->subject_name, sizeof(sess->subject_name), "%s", subject_name);
                fprintf(stderr, "bicchierino: grappa login OK, subject=%s\n",
                        sess->subject_name);
                ok = true;
            } else {
                fprintf(stderr, "bicchierino: grappa login: 200 response missing "
                                "token/subject.name\n");
                send_line(fd, "ERROR :The grappa server sent back something unexpected, "
                              "please contact the admin");
            }
            json_free(doc);
        }
    } else if (resp.status == 401) {
        fprintf(stderr, "bicchierino: grappa login: invalid credentials for account=%s\n",
                account);
        send_line(fd, "ERROR :Invalid account name or password");
    } else {
        fprintf(stderr, "bicchierino: grappa login: unexpected HTTP status %d\n", resp.status);
        send_line(fd,
                  "ERROR :The grappa server returned an unexpected error (%d), please "
                  "contact the admin",
                  resp.status);
    }

    http_response_free(&resp);
    return ok;
}

/* Percent-encodes everything except RFC 3986 unreserved characters —
 * conservative on purpose (shottino's own url_encode does the same for
 * this exact path), even though a network slug in practice is unlikely
 * to need it. */
static void url_encode(const char *src, char *dst, size_t dst_sz) {
    static const char hex[] = "0123456789ABCDEF";
    size_t di = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p && di + 1 < dst_sz; p++) {
        bool unreserved =
            isalnum(*p) || *p == '-' || *p == '.' || *p == '_' || *p == '~';
        if (unreserved) {
            dst[di++] = (char)*p;
        } else {
            if (di + 3 >= dst_sz) break;
            dst[di++] = '%';
            dst[di++] = hex[*p >> 4];
            dst[di++] = hex[*p & 0xF];
        }
    }
    dst[di] = '\0';
}

/* WIRE.md §1.5: GET /networks. Fills sess->networks[] with everything
 * this account has bound — matching a requested slug against that list
 * is pick_network()'s job, kept separate so Case B's later
 * `GRAPPA NETWORK <slug>` can reuse the same list without a second round
 * trip to grappa.
 *
 * Zero networks is a dead end handled here, not deferred — there is no
 * recovery from it (this account has no credential for any network at
 * all, confirmed against the real TestUser test account), unlike an
 * unmatched-but-nonempty list, which is Case B and stays recoverable. */
static bool fetch_networks(int fd, const struct config *cfg, struct grappa_session *sess) {
    struct http_response resp;
    if (!https_get_bearer(cfg->grappa_url, "/networks", sess->token, &resp)) {
        fprintf(stderr, "bicchierino: grappa not reachable at %s\n", cfg->grappa_url);
        send_line(fd, "ERROR :Could not reach the grappa server, please try again");
        return false;
    }
    if (resp.status != 200) {
        fprintf(stderr, "bicchierino: GET /networks: unexpected HTTP status %d\n", resp.status);
        send_line(fd,
                  "ERROR :Could not retrieve your networks from grappa (%d), please "
                  "contact the admin",
                  resp.status);
        http_response_free(&resp);
        return false;
    }

    char err[128];
    json_doc *doc = json_parse(resp.body, resp.body_len, err, sizeof(err));
    if (!doc) {
        fprintf(stderr, "bicchierino: GET /networks: malformed JSON: %s\n", err);
        send_line(fd, "ERROR :The grappa server sent back something unexpected, please "
                      "contact the admin");
        http_response_free(&resp);
        return false;
    }

    const json_value *root = json_root(doc);
    size_t count = json_len(root);

    if (count == 0) {
        fprintf(stderr, "bicchierino: account has zero networks bound\n");
        send_line(fd, "ERROR :You don't have any network configured, please contact "
                      "the admin");
        json_free(doc);
        http_response_free(&resp);
        return false;
    }

    sess->network_count = 0;
    for (size_t i = 0; i < count && sess->network_count < MAX_NETWORKS; i++) {
        const json_value *entry = json_at(root, i);
        const char *slug = NULL;
        long id = 0;
        if (!json_str_req(entry, "slug", &slug) || !json_long_req(entry, "id", &id)) continue;
        snprintf(sess->networks[sess->network_count].slug, sizeof(sess->networks[0].slug), "%s",
                 slug);
        sess->networks[sess->network_count].id = id;
        sess->network_count++;
    }

    json_free(doc);
    http_response_free(&resp);
    return true;
}

/* Pure matching logic, no I/O — named-and-found, named-and-missing,
 * unnamed-with-exactly-one, unnamed-with-several. Reused by both the
 * initial PASS-driven resolution and Case B's `GRAPPA NETWORK <slug>`
 * (CLAUDE.md §1's "IRC-side admin commands", arriving earlier than
 * planned) against the same already-fetched list. Sets
 * sess->network_slug/id/resolved on success; leaves them untouched
 * (caller must not assume they're cleared) on failure. */
static bool pick_network(struct grappa_session *sess, const char *want_network) {
    for (size_t i = 0; i < sess->network_count; i++) {
        bool matches = want_network[0] ? strcasecmp(sess->networks[i].slug, want_network) == 0
                                        : sess->network_count == 1;
        if (matches) {
            snprintf(sess->network_slug, sizeof(sess->network_slug), "%s",
                     sess->networks[i].slug);
            sess->network_id = sess->networks[i].id;
            sess->network_resolved = true;
            return true;
        }
    }
    return false;
}

static void format_available_networks(const struct grappa_session *sess, char *buf,
                                       size_t buf_sz) {
    size_t len = 0;
    buf[0] = '\0';
    for (size_t i = 0; i < sess->network_count; i++) {
        int written =
            snprintf(buf + len, buf_sz - len, "%s%s", len ? " " : "", sess->networks[i].slug);
        if (written > 0 && (size_t)written < buf_sz - len) len += (size_t)written;
    }
}

/* WIRE.md §1.5: GET /networks/:slug/channels for the ONE network already
 * resolved — bicchierino, unlike shottino, never bridges more than one
 * network per connection, so there is only ever one of these calls per
 * session. Only `joined: true` entries matter here (the channels to
 * present as JOIN lines to the downstream client at registration). */
static bool fetch_joined_channels(int fd, const struct config *cfg, struct grappa_session *sess) {
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char path[256];
    snprintf(path, sizeof(path), "/networks/%s/channels", encoded_slug);

    struct http_response resp;
    if (!https_get_bearer(cfg->grappa_url, path, sess->token, &resp)) {
        fprintf(stderr, "bicchierino: grappa not reachable at %s\n", cfg->grappa_url);
        send_line(fd, "ERROR :Could not reach the grappa server, please try again");
        return false;
    }
    if (resp.status != 200) {
        fprintf(stderr, "bicchierino: GET %s: unexpected HTTP status %d\n", path, resp.status);
        send_line(fd,
                  "ERROR :Could not retrieve channels for that network (%d), please "
                  "contact the admin",
                  resp.status);
        http_response_free(&resp);
        return false;
    }

    char err[128];
    json_doc *doc = json_parse(resp.body, resp.body_len, err, sizeof(err));
    if (!doc) {
        fprintf(stderr, "bicchierino: GET %s: malformed JSON: %s\n", path, err);
        send_line(fd, "ERROR :The grappa server sent back something unexpected, please "
                      "contact the admin");
        http_response_free(&resp);
        return false;
    }

    const json_value *root = json_root(doc);
    size_t count = json_len(root);
    sess->channel_count = 0;

    for (size_t i = 0; i < count && sess->channel_count < MAX_CHANNELS; i++) {
        const json_value *entry = json_at(root, i);
        const char *name = NULL;
        bool joined = false;
        if (!json_str_req(entry, "name", &name)) continue;
        if (!json_bool_req(entry, "joined", &joined)) continue;
        if (!joined) continue;
        snprintf(sess->channels[sess->channel_count], sizeof(sess->channels[0]), "%s", name);
        sess->channel_count++;
    }

    json_free(doc);
    http_response_free(&resp);
    return true;
}

/* Registration numerics — 001-005 + MOTD (375/372/376), same shape as
 * shottino's own ircd_register.
 *
 * The 005 CHANMODES/PREFIX/CASEMAPPING/STATUSMSG values are NOT
 * fabricated: the real, live ISUPPORT table only exists as a websocket
 * push (`isupport_changed`, seeded on channel join —
 * `grappa_channel.ex:1437-1455`, `push_isupport_if_live/3`) — not built
 * yet (WIRE.md §2-5). grappa's own official web client hits the exact
 * same gap and solves it the same way: these are copied verbatim from
 * `Grappa.Session.ISupport.default/0` (`lib/grappa/session/isupport.ex:
 * 117-158`) — the pre-005 bahamut/Azzurra fallback grappa itself uses as
 * `Session.Server`'s initial state, and that cicchetto's own
 * `DEFAULT_ISUPPORT` (`cicchetto/src/lib/isupport.ts:36-44`) is required
 * to stay "in lockstep with" per its own comment. Not a guess, not
 * bicchierino's own default — grappa's, for CHANMODES/PREFIX/CASEMAPPING/
 * STATUSMSG. `CHANTYPES=#` is the one exception: grappa's own ISupport
 * struct doesn't track it at all (checked directly — no `chantypes`
 * field anywhere in `isupport.ex`), so that one token genuinely is
 * bicchierino's own reasonable default, not a sourced one.
 *
 * TODO(next): once the websocket bridge exists, an `isupport_changed`
 * event that disagrees with this should send a corrected 005 — a real
 * IRC server re-advertising ISUPPORT after it changes is normal, and
 * these values are only ever right for a bahamut-shaped network (the
 * common case here, but not a promise for every network an account
 * might have bound). */
static void send_welcome(int fd, const char *nick, const char *subject_name) {
    send_line(fd, ":%s 001 %s :Welcome to grappa via bicchierino, %s", IRCD_SERVER, nick,
              subject_name);
    send_line(fd, ":%s 002 %s :Your host is %s, running bicchierino", IRCD_SERVER, nick,
              IRCD_SERVER);
    send_line(fd, ":%s 003 %s :This server has no particular birthday", IRCD_SERVER, nick);
    send_line(fd, ":%s 004 %s %s bicchierino-0.1 o o", IRCD_SERVER, nick, IRCD_SERVER);
    send_line(fd,
              ":%s 005 %s CHANTYPES=# PREFIX=(ohv)@%%+ CHANMODES=beI,k,l,imnpstrRcCDd "
              "CASEMAPPING=ascii STATUSMSG=@+ :are supported by this server",
              IRCD_SERVER, nick);
    send_line(fd, ":%s 375 %s :- %s message of the day -", IRCD_SERVER, nick, IRCD_SERVER);
    send_line(fd, ":%s 372 %s :- bicchierino is bridging this connection to grappa.", IRCD_SERVER,
              nick);
    send_line(fd, ":%s 376 %s :End of /MOTD command.", IRCD_SERVER, nick);
}

/* Presents channels already known-joined on grappa as JOIN lines, same
 * spirit as shottino's ircd_present_channel: the client sees them
 * without having to ask. No TOPIC/NAMES yet — that only exists once the
 * websocket join snapshot does (WIRE.md §3-4, not built yet); the
 * channel LIST itself is real (GET /networks/:slug/channels, WIRE.md
 * §1.5), so presenting it now is accurate, just incomplete. */
static void present_channels(int fd, const char *nick, const struct grappa_session *sess) {
    for (size_t i = 0; i < sess->channel_count; i++) {
        send_line(fd, ":%s!bicchierino@bicchierino JOIN :%s", nick, sess->channels[i]);
    }
}

/* Case B's in-band selector, `GRAPPA NETWORK <slug>` — CLAUDE.md §1's
 * "IRC-side admin commands" note, arriving earlier than planned because
 * a PASS with no (or an unmatched) network name turned out to have a
 * real, recoverable next step instead of just a dead end. Validates
 * against `sess->networks[]`, already fetched once by fetch_networks()
 * — never a second GET /networks for the same connection. */
static void handle_grappa_network(int fd, const char *nick, const struct config *cfg,
                                   const struct irc_message *msg, struct grappa_session *sess) {
    const char *want = msg->params[1];
    if (!pick_network(sess, want)) {
        char available[512];
        format_available_networks(sess, available, sizeof(available));
        send_line(fd, ":%s NOTICE %s :Unknown network '%s'. Available: %s", IRCD_SERVER, nick,
                  want, available);
        return;
    }

    if (!fetch_joined_channels(fd, cfg, sess)) {
        /* fetch_joined_channels already sent its own ERROR. pick_network
         * set network_resolved=true as a side effect of matching — undo
         * it, so this connection stays in "awaiting selection" rather
         * than silently pretending the selection succeeded. */
        sess->network_resolved = false;
        return;
    }

    present_channels(fd, nick, sess);
    fprintf(stderr,
            "bicchierino: network selected: subject=%s network=%s(%ld) joined_channels=%zu\n",
            sess->subject_name, sess->network_slug, sess->network_id, sess->channel_count);
    send_line(fd,
              ":%s NOTICE %s :Network %s selected, but the websocket bridge isn't "
              "implemented yet — messages will not be delivered",
              IRCD_SERVER, nick, sess->network_slug);
}

static void send_network_reminder(int fd, const char *nick, const struct grappa_session *sess) {
    char available[512];
    format_available_networks(sess, available, sizeof(available));
    send_line(fd,
              ":%s NOTICE %s :You are not connected to any network. Available: %s. Use "
              "/quote GRAPPA NETWORK <name> to select one.",
              IRCD_SERVER, nick, available);
}

/* Best-effort `DELETE /auth/logout`, fire-and-forget — same shape as
 * shottino's own logout_grappa. A no-op if login never succeeded
 * (sess->token empty), otherwise revokes bicchierino's own token.
 *
 * This does NOT disconnect the user from the real IRC network: for a
 * registered-user session (the only kind bicchierino ever creates,
 * WIRE.md §1) logout is a detach, not a teardown —
 * auth_controller.ex's own #126 comment says so explicitly, and
 * https_delete_bearer's doc has the quote. grappa's Session.Server owns
 * the actual upstream connection, keyed by (user, network), independent
 * of any WS client — closing bicchierino's own session here has no more
 * effect on it than closing a cicchetto browser tab would. */
static void logout_grappa(const struct config *cfg, const struct grappa_session *sess) {
    if (sess->token[0] == '\0') return;

    struct http_response resp;
    if (!https_delete_bearer(cfg->grappa_url, "/auth/logout", sess->token, &resp)) {
        fprintf(stderr, "bicchierino: logout: grappa not reachable\n");
        return;
    }
    if (resp.status == 204 || (resp.status >= 200 && resp.status < 300)) {
        fprintf(stderr, "bicchierino: grappa session terminated (subject=%s)\n",
                sess->subject_name);
    } else {
        fprintf(stderr, "bicchierino: logout failed, HTTP %d\n", resp.status);
    }
    http_response_free(&resp);
}

void *connection_run(void *arg) {
    struct connection_args *args = arg;
    int fd = args->client_fd;
    const struct config *cfg = args->cfg;

    struct linebuf lb = {0};
    struct registration reg = {0};
    char line[IRC_LINE_MAX];

    /* Phase 1: IRC registration (PASS/NICK/USER) — unchanged. */
    bool registered = false;
    for (;;) {
        int r = next_line(fd, &lb, line, sizeof(line));
        if (r == NEXT_LINE_EOF || r == NEXT_LINE_ERROR) break;

        struct irc_message msg;
        if (!irc_parse_line(line, &msg)) continue;

        handle_registration_message(&msg, &reg);
        if (reg.got_nick && reg.got_user) {
            registered = true;
            break;
        }
    }

    if (!registered) {
        close(fd);
        free(args);
        return NULL;
    }

    char network[IRC_LINE_MAX], password[IRC_LINE_MAX];
    split_network_password(reg.got_pass ? reg.pass_raw : "", network, sizeof(network), password,
                            sizeof(password));

    /* Everything from here on may obtain a grappa token, so every exit
     * path funnels through `cleanup` — logout_grappa() is a no-op if
     * sess.token was never populated, and a real DELETE /auth/logout
     * otherwise. This is what guarantees a client's QUIT (or any other
     * teardown: EOF, a bootstrap step failing) revokes bicchierino's own
     * token instead of abandoning it — safe for the real IRC connection,
     * see logout_grappa's own doc. */
    struct grappa_session sess = {0};

    /* Two blocking calls, in this one thread, in sequence — the whole
     * reason connections are threads (CLAUDE.md §3): none of this stalls
     * any other connection. Each step's own ERROR is already sent to the
     * client by the function that failed (fetch_networks covers the
     * zero-networks dead end itself — Case A, no recovery). */
    if (!attempt_grappa_login(fd, reg.account, password, cfg, &sess)) goto cleanup;
    if (!fetch_networks(fd, cfg, &sess)) goto cleanup;

    pick_network(&sess, network); /* sets sess.network_resolved on a match */

    if (sess.network_resolved) {
        if (!fetch_joined_channels(fd, cfg, &sess)) goto cleanup;
        send_welcome(fd, reg.nick, sess.subject_name);
        present_channels(fd, reg.nick, &sess);
        fprintf(stderr,
                "bicchierino: bootstrap OK: subject=%s network=%s(%ld) joined_channels=%zu\n",
                sess.subject_name, sess.network_slug, sess.network_id, sess.channel_count);

        /* TODO(next): this only proves the handshake works — it closes
         * the websocket right back up. Topic joins (WIRE.md §3-4) and
         * the poll()-on-two-fds restructure (CLAUDE.md §3) are the next
         * piece; this is deliberately isolated so a handshake bug and a
         * join-sequence bug are never the same failed test. */
        struct ws_client wsc;
        if (ws_client_connect(cfg->grappa_url, sess.token, &wsc)) {
            fprintf(stderr, "bicchierino: websocket handshake OK\n");
            ws_client_close(&wsc);
        } else {
            fprintf(stderr, "bicchierino: websocket handshake FAILED\n");
        }

        send_line(fd,
                  ":%s NOTICE %s :Login successful, but the websocket bridge isn't "
                  "implemented yet — messages will not be delivered",
                  IRCD_SERVER, reg.nick);
    } else {
        /* Case B: registration completes anyway — there IS a real,
         * recoverable next step (`GRAPPA NETWORK <slug>`), unlike the
         * zero-networks dead end fetch_networks() already closed on. */
        send_welcome(fd, reg.nick, sess.subject_name);
        send_network_reminder(fd, reg.nick, &sess);
        char available[512];
        format_available_networks(&sess, available, sizeof(available));
        fprintf(stderr, "bicchierino: subject=%s registered, awaiting network selection: %s\n",
                sess.subject_name, available);
    }

    /* Phase 2: post-registration. PING/PONG always; GRAPPA NETWORK only
     * meaningful before a network is resolved; everything else is a
     * reminder (unresolved — the user needs to know each time) or a
     * silent no-op (resolved — the "not implemented yet" NOTICE above
     * already said so once; repeating it per command would just be
     * noise). */
    for (;;) {
        int r = next_line(fd, &lb, line, sizeof(line));
        if (r == NEXT_LINE_EOF || r == NEXT_LINE_ERROR) break;

        struct irc_message msg;
        if (!irc_parse_line(line, &msg)) continue;

        if (strcmp(msg.command, "PING") == 0) {
            send_line(fd, ":%s PONG %s :%s", IRCD_SERVER, IRCD_SERVER,
                      msg.param_count > 0 ? msg.params[0] : IRCD_SERVER);
            continue;
        }
        if (strcmp(msg.command, "QUIT") == 0) break;

        if (!sess.network_resolved) {
            if (strcmp(msg.command, "GRAPPA") == 0 && msg.param_count >= 2 &&
                strcasecmp(msg.params[0], "NETWORK") == 0) {
                handle_grappa_network(fd, reg.nick, cfg, &msg, &sess);
            } else {
                send_network_reminder(fd, reg.nick, &sess);
            }
        }
        /* network_resolved: everything else is a silent no-op for now —
         * TODO(next): once the websocket bridge exists, this is exactly
         * where real command dispatch (PRIVMSG, JOIN, MODE...) goes. */
    }

cleanup:
    logout_grappa(cfg, &sess);
    close(fd);
    free(args);
    return NULL;
}
