#include "connection.h"

#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp — slug matching is case-insensitive */
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "bridge.h"
#include "http.h"
#include "json.h"
#include "jsonw.h"
#include "version.h"

#define IRC_LINE_MAX 512
#define MAX_CHANNELS 128 /* a comparable production bouncer's own scale doc uses ~70 channels as
                           * its reference point; this is a hostile-
                           * response backstop, not a real ceiling */
#define MAX_NETWORKS 64  /* generous — real accounts bind a handful */
#define MAX_DM_PEERS 64  /* one per person ever DMed on this network — same
                           * "hostile-response backstop, not a real ceiling"
                           * posture as MAX_CHANNELS */
#define IRCD_SERVER "bicchierino"
/* grappa's synthetic per-network window for everything that belongs to no
 * channel and no query: server notices, connect MOTD, unsolicited
 * INFO/VERSION/ADMIN bursts, and the event router's catch-all rows. It is
 * a window KEY, never an IRC target — `GrappaWeb.Validation`'s own
 * `validate_post_target_name("$server")` refuses a write to it. Folds to
 * itself under both sides' ASCII fold (only `A-Z` folds). */
#define GRAPPA_SERVER_WINDOW "$server"
#define IRC_MAX_PARAMS 15
#define LINEBUF_CAP (IRC_LINE_MAX * 4)

/* A real ircd pings an idle client and disconnects it if it never
 * answers — the same "ghost TCP connection" detection every server
 * does, and one bicchierino needs for a different reason than most:
 * without it, a client whose TCP connection died silently (no FIN/RST
 * ever arrives, poll() sees nothing) would leave the WS bridge to
 * grappa held open indefinitely — the periodic heartbeat this file
 * sends keeps THAT alive forever, it does nothing to notice the client
 * itself is gone. Values chosen so a real client (which typically
 * already pings bicchierino on its own every 30-60s, resetting this
 * same timer via "any traffic counts") almost never triggers this path
 * at all — it exists for the client that's actually gone. */
/* How long a client has to complete PASS/NICK/USER (plus CAP END if it
 * opened CAP negotiation) before the connection is closed.  Protects
 * against two distinct resource-exhaustion scenarios:
 *   1. A peer that connects and sends nothing — the recv() in next_line
 *      blocks forever without this timeout (SO_RCVTIMEO on the fd).
 *   2. A peer that is chatty but never finishes (e.g. sends CAP LS and
 *      then goes silent) — the wall-clock deadline check in the Phase 1
 *      loop catches this even if individual recv() calls return quickly.
 * Cleared after registration so Phase 2's poll()-gated recv() calls are
 * unaffected. */
#define REGISTRATION_TIMEOUT 30   /* seconds total for the registration phase */
#define CLIENT_PING_THRESHOLD 180 /* seconds of client silence before WE ping */
#define CLIENT_PING_TIMEOUT 60    /* seconds to wait for a reply before giving up */

/* ── Client transport: plain or TLS, transparent to every caller ────────
 *
 * Exactly two functions ever touch the client socket directly — this
 * one pair, `next_line`'s `recv()` and `send_line`'s `write()` (grepped
 * to confirm: nothing else in this file does). A `bind ... tls` entry
 * means the accepted fd gets wrapped in a real `SSL_accept` handshake
 * before Phase 1 registration even starts (`connection_run`'s own
 * setup, below) — found live as a genuine, pre-existing gap: `main.c`
 * had carried an honest TODO ("TLS listeners accept plaintext for now
 * and never wrap the socket in SSL_accept") that nobody had come back
 * to, and a real `openssl s_client`/Python TLS handshake against a
 * `tls` bind just hung forever — bicchierino was reading raw
 * ClientHello bytes as if they were plain IRC text.
 *
 * Thread-local rather than a new parameter threaded through every
 * function that (transitively) calls `send_line` — which is nearly all
 * of them, dozens of call sites across this file. Sound specifically
 * BECAUSE this codebase's own concurrency model is one thread per
 * connection with zero shared state: thread-local
 * storage naturally scopes to exactly one client's SSL session, same
 * guarantee a `struct` parameter would give, without the mechanical
 * signature-threading cost across a file this size. Set once at the
 * top of `connection_run` (NULL for a plain bind — every plain-bind
 * connection's `next_line`/`send_line` calls behave byte-identically to
 * before this fix), cleared and torn down at every exit path. */
static _Thread_local SSL *g_client_ssl = NULL;

/* SSL_read/SSL_write don't share plain recv/write's simple 0-or-negative
 * error signaling — a negative return can mean "clean shutdown", "the
 * peer reset the connection", or (only relevant for non-blocking
 * sockets, which this codebase never uses for the client fd) "try
 * again". `SSL_get_error` is the only way to tell them apart. Maps onto
 * the same OK/EOF/ERROR trichotomy `next_line`/`send_line` already
 * expect from plain `recv`/`write`, so neither has to branch on
 * TLS-vs-plain beyond calling this. */
static ssize_t client_recv(int fd, void *buf, size_t len) {
    if (!g_client_ssl) return recv(fd, buf, len, 0);
    int n = SSL_read(g_client_ssl, buf, (int)len);
    if (n > 0) return n;
    int err = SSL_get_error(g_client_ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0; /* clean TLS close_notify — EOF */
    return -1;
}

static ssize_t client_write(int fd, const void *buf, size_t len) {
    if (!g_client_ssl) return write(fd, buf, len);
    int n = SSL_write(g_client_ssl, buf, (int)len);
    return n > 0 ? n : -1;
}

/* Loads `bind ... tls <cert> <key>`'s pair fresh per connection (a
 * small, infrequent cost for what is fundamentally a low-connection-
 * count personal bouncer facade — a shared SSL_CTX across every
 * connection to one bind would need its own thread-safety story this
 * isn't worth building yet) and performs the actual `SSL_accept`
 * handshake, setting `g_client_ssl` on success so `next_line`/
 * `send_line` transparently pick it up for the rest of this thread's
 * life. Returns false on ANY failure (cert/key load, or a client that
 * doesn't actually speak TLS at all hitting a `tls` bind) — the caller
 * closes the connection, same as every other unrecoverable pre-
 * registration failure in this file. `*ctx_out` is always set (even on
 * failure, if it got that far) so the caller can free it either way. */
static bool client_tls_accept(int fd, const struct bind_config *listener, SSL_CTX **ctx_out) {
    *ctx_out = NULL;
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "bicchierino: TLS: SSL_CTX_new failed\n");
        return false;
    }
    *ctx_out = ctx;
    if (SSL_CTX_use_certificate_file(ctx, listener->cert_path, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, listener->key_path, SSL_FILETYPE_PEM) != 1) {
        fprintf(stderr, "bicchierino: TLS: failed to load cert/key (%s / %s): %s\n",
                listener->cert_path, listener->key_path,
                ERR_error_string(ERR_get_error(), NULL));
        return false;
    }
    g_client_ssl = SSL_new(ctx);
    if (!g_client_ssl) {
        fprintf(stderr, "bicchierino: TLS: SSL_new failed\n");
        return false;
    }
    SSL_set_fd(g_client_ssl, fd);
    if (SSL_accept(g_client_ssl) != 1) {
        fprintf(stderr, "bicchierino: TLS handshake failed: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        SSL_free(g_client_ssl);
        g_client_ssl = NULL;
        return false;
    }
    fprintf(stderr, "bicchierino: TLS handshake OK (%s, %s)\n", SSL_get_version(g_client_ssl),
            SSL_get_cipher(g_client_ssl));
    return true;
}

/* Mirror of `client_tls_accept` — every exit path from `connection_run`
 * past that point calls this, plain-bind connections included (a no-op
 * for them, `g_client_ssl` was never set). */
static void client_tls_close(SSL_CTX *ctx) {
    if (g_client_ssl) {
        SSL_shutdown(g_client_ssl);
        SSL_free(g_client_ssl);
        g_client_ssl = NULL;
    }
    if (ctx) SSL_CTX_free(ctx);
}

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

        ssize_t n = client_recv(fd, lb->data + lb->len, sizeof(lb->data) - lb->len);
        if (n == 0) return NEXT_LINE_EOF;
        if (n < 0) return NEXT_LINE_ERROR;
        lb->len += (size_t)n;
    }
}

/* True if a complete line is already sitting in the buffer — a pure
 * peek, never touches the socket. Lets the Phase 2 poll() loop drain
 * every line a single recv() happened to pack together (a client
 * pipelining several commands in one write()) without going back to
 * poll() for each one, while never risking a next_line() call that
 * would block on a second recv() the poll() wakeup never promised. */
static bool line_buffered(const struct linebuf *lb) {
    return memchr(lb->data, '\n', lb->len) != NULL;
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
    /* vsnprintf returns what it WOULD have written, not what it did — so
     * on truncation `n` points past the buffer and the CRLF below would
     * land outside it. Clamp to the byte budget the call actually had.
     * A caller with a line worth truncating should have sized it itself
     * (see `send_tagged_line`); this is the backstop that keeps a
     * mis-sized one from being a memory-safety bug. */
    if ((size_t)n > sizeof(buf) - 3) n = (int)sizeof(buf) - 3;
    /* ONE line in, one line out (#9).
     *
     * Every render arm formats grappa-sourced strings through here —
     * body, channel, sender, topic, kick reason. A CR or LF inside one
     * of them ends this line early and starts another, chosen by
     * whoever controls the field, and the client cannot tell it apart
     * from a line the bridge meant to send.
     *
     * grappa refuses those bytes in every public send helper today
     * (`Grappa.IRC.Identifier.safe_line_token?/1`), so nothing should
     * arrive carrying one. That is exactly why this is here: without
     * it the correctness of this side rests on an invariant held by a
     * separate codebase, versioned separately, and a compromised,
     * older or newer grappa turns silently into IRC injection. The
     * Makefile already names frames from grappa as hostile input.
     *
     * At the single choke point rather than per arm: there are dozens
     * of call sites and adding one is routine, so a per-site rule is a
     * rule that will be missed. Replaced with a space rather than
     * removed, so offsets and any length a caller already computed
     * stay valid and the operator still sees the text. After the
     * truncation clamp, so a byte revealed BY truncation cannot slip
     * past it. */
    for (int i = 0; i < n; i++)
        if (buf[i] == '\r' || buf[i] == '\n') buf[i] = ' ';
    buf[n++] = '\r';
    buf[n++] = '\n';
    /* Best-effort: if the write fails the connection is already dead and
     * the caller is about to close it anyway. */
    ssize_t unused = client_write(fd, buf, (size_t)n);
    (void)unused;
}

/* IRC's own whitespace-token convention (mirrors `irc_parse_line`'s own
 * `while (*p == ' ') p++` param-skipping above) — for `CAP REQ`'s
 * space-separated capability list, not comma-separated like a JOIN
 * channel list (`next_csv_token`, defined later where its own callers
 * are). Skips leading spaces so consecutive delimiters don't yield
 * empty tokens. */
static bool next_space_token(const char **cursor, char *out, size_t out_sz) {
    if (!*cursor) return false;
    while (**cursor == ' ') (*cursor)++;
    if (!**cursor) return false;
    const char *space = strchr(*cursor, ' ');
    size_t len = space ? (size_t)(space - *cursor) : strlen(*cursor);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, *cursor, len);
    out[len] = '\0';
    *cursor = space ? space + 1 : *cursor + strlen(*cursor);
    return true;
}

/* ── Registration state ───────────────────────────────────────────────
 *
 * Buffered until both NICK and USER arrive, same pattern as shottino's
 * ircd_maybe_register — clients send these in either order.
 *
 * CAP negotiation (IRCv3 `cap-3.2`) is a real gate on registration, not
 * a side channel: a client that sends `CAP LS` MUST NOT be registered
 * until it sends `CAP END` (or never — a client that hangs here is a
 * client bug, not something bicchierino works around), even once
 * NICK+USER have both arrived. `cap_negotiating` starts false (a
 * pre-IRCv3 client that never sends CAP at all registers exactly as
 * before — this is additive, not a behavior change for existing
 * clients) and flips true on the FIRST `CAP` line of any kind; from
 * then on registration is gated on `cap_done` too. See
 * `handle_cap_command`'s own doc for the supported capability set and
 * REQ/ACK/NAK semantics (bicchierino#2's step 1). */
struct registration {
    char pass_raw[IRC_LINE_MAX]; /* "network:password" or bare "password" */
    char account[IRC_LINE_MAX];  /* USER's first param */
    char nick[IRC_LINE_MAX];
    bool got_pass;
    bool got_user;
    bool got_nick;

    bool cap_negotiating;
    bool cap_done;
    bool cap_server_time;
    bool cap_message_tags;
};

struct network_entry {
    char slug[64];
    long id;
    char nick[64]; /* this account's configured nick on this network —
                     * needed for the DM-listener topic (WIRE.md §3-5),
                     * not a display-only field */
};

/* Everything learned about this session across login (WIRE.md §1) and
 * the bootstrap discovery calls (WIRE.md §1.5), before the websocket
 * even opens. Lives on connection_run's stack — one per connection
 * thread, never shared: this codebase's whole concurrency model relies
 * on zero state being shared between connections.
 *
 * `networks[]` is the full list from GET /networks, kept around (not
 * just the one PASS resolved to) so Case B's `GRAPPA NETWORK <slug>`
 * can validate against it later without a second round trip to grappa
 * — the same list also backs any future IRC-side admin command that
 * needs to enumerate bound networks. */
struct grappa_session {
    char token[512];
    char subject_name[128];
    struct network_entry networks[MAX_NETWORKS];
    size_t network_count;
    char network_slug[64];
    long network_id;
    char network_nick[64]; /* copied from the matched network_entry —
                             * WIRE.md §3-5's own-nick DM listener topic */
    bool network_resolved;
    char channels[MAX_CHANNELS][128];
    size_t channel_count;

    /* Copied from `struct registration`'s own cap_* flags once Phase 1
     * completes — CAP negotiation is a Phase-1-only wire exchange, but
     * what got negotiated needs to outlive it: every later Phase 2 line
     * this connection sends (message-tags/server-time framing) has to
     * know whether the client actually asked for that decoration.
     * `cap_negotiating`/`cap_done` themselves don't need to survive the
     * copy — they're pure Phase-1 gating state, meaningless once
     * registration has already completed. */
    bool cap_server_time;
    bool cap_message_tags;

    /* WS join_refs (WIRE.md §4) — every later push on a topic must carry
     * the join_ref that topic's own phx_join returned, or Phoenix
     * silently drops the frame. Populated by the join sequence, consumed
     * by the poll()-based dispatch in connection_run's Phase 2 loop. */
    unsigned long user_join_ref;
    unsigned long channel_join_refs[MAX_CHANNELS]; /* parallel to channels[] */
    unsigned long dm_join_ref;
    bool dm_joined;

    /* Cached 324 RPL_CHANNELMODEIS state, parallel to `channels[]` —
     * kept in sync every time `channel_modes_changed` arrives (both the
     * after-join snapshot and any live update), so a bare `MODE #chan`
     * query (no modestring — a real, legitimate client pattern for
     * "what are this channel's current modes", NOT the same as the
     * `MODE #chan b` banlist-query form) can be answered INSTANTLY from
     * local state, same as a real ircd server (which also just answers
     * from its own in-memory channel record) — no round-trip to grappa
     * needed at all, since bicchierino already has this exact
     * information cached from the last snapshot/update it rendered.
     * `channel_mode_str[i][0] == '\0'` means "no snapshot cached yet"
     * (the tiny window right after a JOIN's REST 202 but before the
     * WS-driven after-join snapshot has arrived) — a bare query in that
     * window gets no reply at all, never a fabricated one. */
    char channel_mode_str[MAX_CHANNELS][64];
    char channel_mode_params[MAX_CHANNELS][400];

    /* Set by `handle_grappa_message_event` the instant a SELF
     * `nick_change` lands (after already leaving the OLD DM-listener
     * topic — safe, fire-and-forget). Deliberately NOT re-joined right
     * there: that event handler can run NESTED inside a `bridge_join`
     * call's own wait loop (via `bridge_event_dispatch`, e.g. during
     * bootstrap's back-to-back joins) — a nested blocking `bridge_join`
     * from inside another one's wait loop risks stealing the OUTER
     * join's own reply. The Phase 2 main loop (never nested inside a
     * `bridge_join`) polls this flag once per iteration, same pattern
     * as the heartbeat/ping-timeout checks, and does the actual rejoin
     * there instead. */
    bool dm_needs_rejoin;

    /* `isupport_changed` pushes once per channel-shaped topic join
     * (`handle_grappa_isupport_changed_event`'s own doc) — harmless
     * with 1-2 channels, but the DM-peer-topic fix below made a normal
     * session join 5-10+ such topics, so a real session started
     * re-announcing an IDENTICAL 005 that many times in a row (user-
     * spotted live: "can we stop sending 005 for every open window?").
     * The content is always the same within one session (one network,
     * `chanmodes`/`prefix` don't change mid-session in practice), so
     * sending it once and skipping every later push is correct, not
     * just quieter. */
    bool isupport_005_sent;

    /* Real bug found live, testing two simultaneous bicchierino
     * connections for the SAME grappa account: the old is_self check
     * (folded sender == own nick) can't tell "this is MY OWN optimistic
     * echo, already shown locally" from "this is a message a SIBLING
     * connection sharing my identity just sent, which I have NOT seen
     * yet" — both look identical by nick alone, since both connections
     * share the same underlying grappa identity. The old check
     * suppressed BOTH, so a PRIVMSG sent from one connection was
     * invisible on EVERY connection for that account, sender's own
     * included — not just self-echo suppression working as intended,
     * genuine message loss. grappa is already the layer that fans a
     * message out to every attached client (cicchetto, shottino, N
     * bicchierino connections) identically — bicchierino re-multiplexing
     * locally wouldn't remove the need for this correlation, it would
     * just add a second delivery path that ALSO needs it (grappa's own
     * WS broadcast still fires regardless of what bicchierino does
     * locally). Fix: remember the REST-assigned `id` of every message
     * THIS connection just sent (`send_privmsg_rest`'s response body,
     * previously discarded after the status check) in this small ring;
     * a self-labeled live event is suppressed ONLY when its `id` matches
     * something still in here (my own echo, remove it once matched) —
     * anything else self-labeled (a sibling connection's send) renders
     * normally, no different from any other incoming message. Sized
     * generously past normal typing speed — REST send and WS echo
     * round-trip in well under a second on a healthy connection, so 16
     * outstanding sends is not a realistic cap to hit; oldest entries
     * are evicted on overflow rather than growing unbounded (same
     * "best-effort bound, not a hard requirement" posture as every other
     * fixed-size buffer in this file). */
    long pending_self_msg_ids[16];
    size_t pending_self_msg_count;

    /* Real gap found live (testing a DM to a real user with a second
     * client listening, right after the multi-client fixes above):
     * an OUTBOUND DM's message event broadcasts on a topic keyed by the
     * TARGET's folded nick (`channel:<peer>`), not the sender's own nick
     * — confirmed against grappa's own source
     * (`Session.Persistor.persist_and_broadcast/3` derives the topic
     * from `attrs.channel`, and `handle_persisting_send` in
     * `session/server.ex` sets `attrs.channel` to the fold of the DM
     * TARGET for an outbound send). bicchierino used to only join its
     * own-nick DM-listener topic (incoming DMs re-key `channel` to the
     * recipient's own nick, server.ex's own comment on
     * `maybe_open_query_window` confirms this asymmetry) — so no
     * client, not even the sender, ever saw its own outbound DM
     * confirmed. Fix: grappa already pushes `query_windows_list` (the
     * full current DM-window list, one entry per peer ever DMed) on the
     * user topic, both as the after-join snapshot AND live on every
     * new window open (#422) — every bicchierino connection already
     * joins the user topic, so this is free delivery, no extra
     * subscription needed to LEARN about a new peer. `dm_peer_names`
     * are the FOLDED target_nick of every peer topic already joined
     * (parallel `dm_peer_join_refs`); `pending_dm_peer_names` are
     * newly-seen peers waiting for their `bridge_join` — queued here
     * instead of joined immediately for the exact same reason as
     * `dm_needs_rejoin` above: `handle_grappa_query_windows_list_event`
     * can run NESTED inside another `bridge_join`'s own wait loop
     * (confirmed live during bootstrap, same hazard), so the actual
     * join is deferred to the Phase 2 main loop, never nested. */
    char dm_peer_names[MAX_DM_PEERS][64];
    unsigned long dm_peer_join_refs[MAX_DM_PEERS];
    size_t dm_peer_count;
    char pending_dm_peer_names[MAX_DM_PEERS][64];
    size_t pending_dm_peer_count;
};

/* Current wall-clock time as unix milliseconds — the fallback
 * `send_tagged_line` uses when no better (grappa-sourced) timestamp is
 * available for an event. `CLOCK_REALTIME` (not MONOTONIC): the tag is
 * meant to be a real wall-clock instant a client can compare against
 * other timestamps, same reason `server_time` on grappa's own wire is a
 * real epoch value, not a monotonic counter. */
static long now_unix_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Unix ms -> IRCv3 `server-time` tag value (`YYYY-MM-DDTHH:MM:SS.sssZ`,
 * always UTC per the spec). Via `gmtime_r` — POSIX.1-2001, unlike
 * `timegm()` (a glibc/BSD extension `utc_to_unix`'s own doc, further
 * down this file, avoids for the same `_POSIX_C_SOURCE=200809L`
 * reason) — `gmtime_r` has no such issue, it's plain POSIX and does the
 * inverse of what `utc_to_unix` does by hand. */
static void format_server_time_tag(long unix_ms, char *out, size_t out_sz) {
    time_t secs = (time_t)(unix_ms / 1000);
    long msec = unix_ms % 1000;
    if (msec < 0) msec += 1000; /* defensive: unix_ms is never negative in practice */
    struct tm tm_buf;
    gmtime_r(&secs, &tm_buf);
    snprintf(out, out_sz, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm_buf.tm_year + 1900,
             tm_buf.tm_mon + 1, tm_buf.tm_mday, tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, msec);
}

/* IRCv3 `message-tags` + `server-time` — a client that negotiated BOTH
 * (server-time depends on message-tags for its wire syntax, per the
 * server-time spec) gets an `@time=...` tag prepended to every line
 * this is used for; a client that negotiated neither gets the exact
 * same line `send_line` would have sent. `server_time_ms <= 0` means
 * "no authoritative timestamp for this event" (a locally-generated
 * line, not one carrying grappa's own `server_time`) — falls back to
 * `now_unix_ms()`, matching the spec's own guidance ("if no other time
 * is available, the server SHOULD use the current time").
 *
 * Scope: applied to `handle_grappa_message_event`'s whole kind-switch
 * (privmsg/notice/action/join/part/quit/nick_change/mode/kick/topic —
 * every kind sharing grappa's one `Scrollback.Message` wire shape,
 * confirmed against `Grappa.Scrollback.Wire.to_json/1`: `server_time`
 * is a non-optional field on EVERY kind, not just privmsg) and to
 * `handle_grappa_umode_changed_event`'s self-MODE line (a genuine live
 * event with no persisted timestamp, hence the `now` fallback there).
 * Deliberately NOT applied to numeric replies (005/332/353/311/...) —
 * those are direct responses to a client's own command, not
 * asynchronously relayed events, and real ircds don't server-time-tag
 * them either. */
static void send_tagged_line(int fd, const struct grappa_session *sess, long server_time_ms,
                              const char *fmt, ...) {
    /* The tag is built FIRST because it decides how much room is left for
     * the body. Formatting the body to the full line length and prepending
     * the tag afterwards overflows the line budget by exactly the tag's
     * own width, and `send_line` can then only drop the tail it was handed
     * — the caller is the one place that still knows the line is a
     * formatted whole, so the truncation belongs here. */
    char tag[96] = "";
    size_t tag_len = 0;
    if (sess->cap_message_tags && sess->cap_server_time) {
        char ts[64]; /* "YYYY-MM-DDTHH:MM:SS.sssZ" is 24 bytes + NUL;
                      * generous past that so gcc's fortify checker can
                      * prove no truncation even though it can't bound
                      * tm_year's width statically. */
        format_server_time_tag(server_time_ms > 0 ? server_time_ms : now_unix_ms(), ts,
                                sizeof(ts));
        int t = snprintf(tag, sizeof(tag), "@time=%s ", ts);
        if (t > 0 && (size_t)t < sizeof(tag)) tag_len = (size_t)t;
        else tag[0] = '\0'; /* unrepresentable timestamp: send untagged
                              * rather than half a tag */
    }

    /* `send_line`'s own budget is `IRC_LINE_MAX - 3` payload bytes (two
     * reserved for CRLF, one for the NUL), and the tag eats into it. */
    char body[IRC_LINE_MAX];
    size_t body_sz = sizeof(body) - 2 - tag_len;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(body, body_sz, fmt, ap);
    va_end(ap);
    if (n < 0) return;

    send_line(fd, "%s%s", tag, body);
}

/* IRCv3 `cap-3.2` — CAP LS/REQ/END/LIST, the gate registration waits on
 * once a client has shown it's IRCv3-aware at all (`struct
 * registration`'s own doc explains the gating rule).
 *
 * `batch`/`draft/chathistory` were advertised here through bicchierino#2's
 * step 1, in prep for CHATHISTORY — DROPPED (bicchierino#3): grappa's
 * scrollback REST cursor is id-only (`?before=|after=|around=`, always
 * an integer message id, never a timestamp — confirmed against
 * `GrappaWeb.MessagesController`), so a `timestamp=` CHATHISTORY
 * selector (the shape most real clients actually send on reconnect,
 * per the spec) has no direct REST translation. Advertising
 * `draft/chathistory` without being able to honor its most common
 * selector would be the same class of bug as the old guessed-005
 * issue: asserting something not true. `batch` was ONLY ever justified
 * as CHATHISTORY's wire carrier (every `draft/chathistory` reply is
 * batch-wrapped) — with CHATHISTORY gone, batch has no real consumer
 * here either, so it goes too rather than sitting advertised-but-unused.
 * `server-time`/`message-tags` remain: both are actually implemented
 * now (see `send_tagged_line`) — see bicchierino#3 for the CHATHISTORY
 * write-up and what would need to change on grappa's side to unblock it.
 *
 * The advertised set otherwise mirrors shottino's own CAP LS list
 * (`shottino.c:20944-20946`) minus the caps shottino has that
 * bicchierino doesn't implement at all (`multi-prefix`, `echo-message`).
 *
 * `REQ` is atomic per line, matching common ircd practice: if EVERY
 * token in one REQ is a capability bicchierino recognizes, the whole
 * line is ACKed and every flag flips on; if ANY token is unrecognized,
 * the WHOLE line is NAKed and nothing in it takes effect — a client
 * never ends up in an ambiguous "some of what I asked for" state.
 * Capability REMOVAL (`CAP REQ :-server-time`) isn't handled — neither
 * is it in shottino's own reference implementation, and bicchierino has
 * no post-registration re-negotiation use case to justify it yet. */
static void handle_cap_command(int fd, struct registration *reg, const struct irc_message *msg) {
    const char *sub = msg->param_count > 0 ? msg->params[0] : "";
    const char *target = reg->nick[0] ? reg->nick : "*";

    if (strcasecmp(sub, "LS") == 0) {
        reg->cap_negotiating = true;
        send_line(fd, ":%s CAP %s LS :server-time message-tags", IRCD_SERVER, target);
        return;
    }

    if (strcasecmp(sub, "LIST") == 0) {
        reg->cap_negotiating = true;
        char enabled[128] = "";
        size_t len = 0;
        const char *names[] = {"server-time", "message-tags"};
        bool flags[] = {reg->cap_server_time, reg->cap_message_tags};
        for (size_t i = 0; i < 2; i++) {
            if (!flags[i]) continue;
            int written =
                snprintf(enabled + len, sizeof(enabled) - len, "%s%s", len ? " " : "", names[i]);
            if (written > 0 && (size_t)written < sizeof(enabled) - len) len += (size_t)written;
        }
        send_line(fd, ":%s CAP %s LIST :%s", IRCD_SERVER, target, enabled);
        return;
    }

    if (strcasecmp(sub, "REQ") == 0) {
        reg->cap_negotiating = true;
        const char *want = msg->param_count > 1 ? msg->params[1] : "";
        bool all_known = true;
        bool want_server_time = false, want_message_tags = false;
        const char *cursor = want;
        char tok[64];
        while (next_space_token(&cursor, tok, sizeof(tok))) {
            if (strcmp(tok, "server-time") == 0) want_server_time = true;
            else if (strcmp(tok, "message-tags") == 0) want_message_tags = true;
            else all_known = false;
        }
        if (all_known) {
            reg->cap_server_time = reg->cap_server_time || want_server_time;
            reg->cap_message_tags = reg->cap_message_tags || want_message_tags;
            send_line(fd, ":%s CAP %s ACK :%s", IRCD_SERVER, target, want);
        } else {
            send_line(fd, ":%s CAP %s NAK :%s", IRCD_SERVER, target, want);
        }
        return;
    }

    if (strcasecmp(sub, "END") == 0) {
        reg->cap_done = true;
        return;
    }

    /* Unrecognized subcommand: ignored, not errored — the same
     * additive-only posture this codebase already follows for grappa's
     * own wire (WIRE.md) applies to a client's CAP traffic too. */
}

static void handle_registration_message(int fd, const struct irc_message *msg,
                                         struct registration *reg) {
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
    } else if (strcmp(msg->command, "CAP") == 0) {
        handle_cap_command(fd, reg, msg);
    }
    /* PING and anything else pre-registration: silently tolerated. A
     * real client sends little else before NICK/USER. */
}

/* Splits "network:password" on the first ':'. No colon → network is
 * empty (resolved against the account's networks once login exists,
 * per WIRE.md's PASS convention) and the whole string is the
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
 * way at this point in the connection: bare ERROR, no 001 was ever
 * sent, so no numeric. The three failure messages stay
 * textually distinct on purpose — "not reachable" vs "invalid
 * credentials" vs a malformed-response case are different bugs to chase
 * and must not look identical in a log.
 *
 * The token/subject are copied out (not left as pointers into the parsed
 * `json_doc`) because the doc is freed before this returns — a
 * `json_string()` result is only valid as long as its document is. */
static bool attempt_grappa_login(int fd, struct http_client *hc, const char *account,
                                  const char *password, const struct config *cfg,
                                  struct grappa_session *sess) {
    char body[LOGIN_BODY_MAX];
    build_login_body(account, password, body, sizeof(body));

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "POST", "/auth/login", NULL, body, &resp)) {
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

/* Byte-exact mirror of grappa's own `Identifier.fold_ascii_byte/1`
 * (`lib/grappa/irc/identifier.ex:390-393` — A-Z -> a-z, nothing else
 * touched, no locale). Load-bearing, not cosmetic: `Grappa.PubSub.
 * Topic.channel/3` — the function every broadcaster uses to build its
 * topic string — ALWAYS folds the channel/nick segment through this
 * exact rule before broadcasting, unconditionally, regardless of what
 * casemapping a live session has. Phoenix.PubSub topic matching is an
 * exact string compare — a subscription topic built from an unfolded
 * nick (e.g. "TestUser") never matches a broadcast on the folded one
 * ("testuser"), and the mismatch is silent: no error, the frame simply
 * never arrives. Confirmed live: the DM-listener topic (own nick, mixed
 * case from GET /networks) was missing every inbound DM until this fold
 * was added. Every topic this file builds with a channel/nick segment —
 * a real channel name or the DM-listener's own nick — MUST go through
 * this first. `canonicalize_topic` server-side (`grappa_channel.ex`)
 * folds too, but only for ITS OWN snapshot/join-reply lookups; it does
 * NOT retroactively fix the PubSub subscription, which binds to the
 * exact string bicchierino's own phx_join sent. */
static void ascii_fold_lower(const char *src, char *dst, size_t dst_sz) {
    size_t i = 0;
    for (; src[i] && i + 1 < dst_sz; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (char)(c >= 'A' && c <= 'Z' ? c + 32 : c);
    }
    dst[i] = '\0';
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
static bool fetch_networks(int fd, struct http_client *hc, const struct config *cfg,
                            struct grappa_session *sess) {
    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "GET", "/networks", sess->token, NULL, &resp)) {
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
        const char *nick = NULL;
        long id = 0;
        if (!json_str_req(entry, "slug", &slug) || !json_long_req(entry, "id", &id) ||
            !json_str_req(entry, "nick", &nick))
            continue;
        snprintf(sess->networks[sess->network_count].slug, sizeof(sess->networks[0].slug), "%s",
                 slug);
        sess->networks[sess->network_count].id = id;
        snprintf(sess->networks[sess->network_count].nick, sizeof(sess->networks[0].nick), "%s",
                 nick);
        sess->network_count++;
    }

    json_free(doc);
    http_response_free(&resp);
    return true;
}

/* Pure matching logic, no I/O — named-and-found, named-and-missing,
 * unnamed-with-exactly-one, unnamed-with-several. Reused by both the
 * initial PASS-driven resolution and Case B's `GRAPPA NETWORK <slug>`
 * (an IRC-side admin-style command, arriving earlier than planned)
 * against the same already-fetched list. Sets
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
            snprintf(sess->network_nick, sizeof(sess->network_nick), "%s",
                     sess->networks[i].nick);
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
static bool fetch_joined_channels(int fd, struct http_client *hc, const struct config *cfg,
                                   struct grappa_session *sess) {
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char path[256];
    snprintf(path, sizeof(path), "/networks/%s/channels", encoded_slug);

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "GET", path, sess->token, NULL, &resp)) {
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

/* T32 (grappa's own naming) `connection_state` transition — the
 * bicchierino equivalent of cicchetto's "connect" button. Found live
 * chasing a real "stuck" report: a fresh credential (bound via the
 * admin panel, or any account that has simply never gone live before)
 * sits in grappa's DB with `connection_state: "connected"` and ZERO
 * live `Session.Server` — `GET /networks` alone never spawns one
 * (confirmed reading grappa's own `Credentials.bind_credential/3`: a
 * plain `Repo.insert`, no `SpawnOrchestrator` call anywhere on that
 * path). cicchetto has a "connect" button precisely because of this —
 * clicking it fires `PATCH /networks/:network_id
 * {"connection_state":"connected"}` (`NetworksController.update/2`),
 * which delegates to `SpawnOrchestrator.spawn/4` and BLOCKS until the
 * spawn attempt completes (success or failure) before replying —
 * bicchierino had no equivalent action at all, so a client connecting
 * to a never-yet-live account just sat there registered, with an empty
 * channel list, forever. Called UNCONDITIONALLY on every bootstrap, not
 * gated on any "looks already connected" check: grappa's own docs call
 * the already-live case explicitly idempotent
 * (`SpawnOrchestrator.spawn/4` dedupes to `:already_started`,
 * `Networks.connect/1` short-circuits on `:connected` with a no-op DB
 * write) — no bounce, no disruption to an already-working session — so
 * a conditional skip here would just be an unnecessary special case for
 * a cost that's already one cheap REST round-trip per CONNECT, not per
 * message. Failure (capacity/admission rejection, resolve failure, ...)
 * is reported honestly to the client but is NOT fatal to the
 * bicchierino connection — matches the existing "bridge failed to come
 * up" NOTICE precedent (send_welcome's own caller): the rest of
 * bootstrap still proceeds, same as a real bouncer facade would show a
 * "not connected" network rather than refusing the whole session. */
static bool ensure_network_connected(struct http_client *hc, const struct config *cfg,
                                      const struct grappa_session *sess) {
    /* The route param is spelled `:network_id` but `Plugs.ResolveNetwork`
     * actually resolves it via `Networks.get_network_by_slug/1` — it's
     * the SLUG ("azzurra"), not the numeric FK, despite the name. Same
     * gotcha every other REST call in this file already sidesteps by
     * using `network_slug` (`fetch_joined_channels`, `send_join_rest`,
     * `send_part_rest`) — found live here the hard way: `/networks/1`
     * (the numeric id) 404'd, even against `TestUser`'s own
     * already-connected credential, before this was fixed. */
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char path[256];
    snprintf(path, sizeof(path), "/networks/%s", encoded_slug);

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "PATCH", path, sess->token,
                              "{\"connection_state\":\"connected\"}", &resp)) {
        fprintf(stderr, "bicchierino: PATCH %s: grappa not reachable\n", path);
        return false;
    }
    bool ok = resp.status == 200;
    if (!ok)
        fprintf(stderr, "bicchierino: PATCH %s: unexpected HTTP status %d\n", path, resp.status);
    http_response_free(&resp);
    return ok;
}

/* Registration numerics — 001-005 + MOTD (375/372/376), same shape as
 * shottino's own ircd_register.
 *
 * The 005 sent HERE is deliberately minimal, not the bahamut-shaped
 * guess an earlier version of this function sent (`PREFIX=(ohv)@%+
 * CHANMODES=beI,k,l,...`, copied from `ISupport.default/0`). Caught
 * live: that guess was WRONG for the real network (azzurra's actual
 * CHANMODES type-A class is `bz`, not `beI` — confirmed the moment the
 * first real `isupport_changed` arrived) — and CHANMODES/PREFIX are
 * only ever right for a bahamut-shaped network to begin with, not a
 * promise for every network an account might have bound. Asserting a
 * value bicchierino has not actually verified for THIS network is a
 * confidently WRONG numeric — worse than a missing one, since a client
 * will act on it. So: only `CHANTYPES=#` here (bicchierino's own
 * decision, not network-sourced — grappa's ISupport struct doesn't even
 * track it) and `CASEMAPPING=ascii` (grappa's own pre-005
 * `Session.Server` fallback, `ISupport.default/0` — NOT corrected by
 * `isupport_changed` later since that event never carries casemapping
 * at all, confirmed directly against `ISupport.t/0`'s wire projection,
 * so this is the best-available truth for the WHOLE session, not a
 * temporary guess). PREFIX/CHANMODES/STATUSMSG are omitted entirely
 * until `handle_grappa_isupport_changed_event` sends the real,
 * network-confirmed 005 — arriving within moments of the first
 * channel-shaped topic join, WIRE.md §3/§6. */
static void send_welcome(int fd, const char *nick, const char *subject_name) {
    send_line(fd, ":%s 001 %s :Welcome to grappa via bicchierino, %s", IRCD_SERVER, nick,
              subject_name);
    send_line(fd, ":%s 002 %s :Your host is %s, running bicchierino %s", IRCD_SERVER, nick,
              IRCD_SERVER, BICCHIERINO_VERSION);
    send_line(fd, ":%s 003 %s :This server has no particular birthday", IRCD_SERVER, nick);
    send_line(fd, ":%s 004 %s %s bicchierino-%s o o", IRCD_SERVER, nick, IRCD_SERVER,
              BICCHIERINO_VERSION);
    send_line(fd, ":%s 005 %s CHANTYPES=# CASEMAPPING=ascii :are supported by this server",
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

/* Forward declaration: join_grappa_topics is defined later in this file
 * (it needs handle_grappa_event's forward declaration below IT, in turn),
 * but handle_grappa_network — Case B's bridge-bringup path — needs to
 * call it and is defined earlier for readability (right next to
 * present_channels/send_network_reminder, the rest of the Case B flow). */
static void join_grappa_topics(int fd, const char *nick, struct bridge *br,
                                struct grappa_session *sess);

/* Case B's in-band selector, `GRAPPA NETWORK <slug>` — an IRC-side
 * admin-style command, arriving earlier than planned because
 * a PASS with no (or an unmatched) network name turned out to have a
 * real, recoverable next step instead of just a dead end. Validates
 * against `sess->networks[]`, already fetched once by fetch_networks()
 * — never a second GET /networks for the same connection.
 *
 * `br`/`br_connected` are the SAME bridge + liveness flag Phase 2's poll
 * loop reads every iteration (`connection_run` passes `&br_connected`
 * through `handle_irc_line`) — Case A (network resolved straight from
 * `PASS`) brings the bridge up inline in `connection_run` before Phase 2
 * even starts; Case B only learns its network here, mid-Phase-2, so THIS
 * is the only place that can bring it up for that path. Before this,
 * Case B connections got a fully populated channel list at registration
 * but NO live events for the rest of the connection's life — the old
 * "isn't implemented yet" NOTICE below was accurate for this path only,
 * while Case A had long since outgrown it (confirmed live: a raw Case B
 * test connection got 353/366 snapshots fine but never saw a PRIVMSG). */
static void handle_grappa_network(int fd, struct http_client *hc, struct bridge *br,
                                   bool *br_connected, const char *nick, const struct config *cfg,
                                   const struct irc_message *msg, struct grappa_session *sess) {
    const char *want = msg->params[1];
    if (!pick_network(sess, want)) {
        char available[512];
        format_available_networks(sess, available, sizeof(available));
        send_line(fd, ":%s NOTICE %s :Unknown network '%s'. Available: %s", IRCD_SERVER, nick,
                  want, available);
        return;
    }

    if (!ensure_network_connected(hc, cfg, sess))
        send_line(fd,
                  ":%s NOTICE %s :Could not establish the IRC connection for %s (grappa "
                  "rejected the connect request) — you may see an empty channel list until "
                  "this is resolved",
                  IRCD_SERVER, nick, sess->network_slug);

    if (!fetch_joined_channels(fd, hc, cfg, sess)) {
        /* fetch_joined_channels already sent its own ERROR. pick_network
         * set network_resolved=true as a side effect of matching — undo
         * it, so this connection stays in "awaiting selection" rather
         * than silently pretending the selection succeeded. */
        sess->network_resolved = false;
        return;
    }

    /* From here on `sess->network_nick` (just set by `pick_network`
     * above) is the live source, not the `nick` parameter — identical
     * value at this exact instant, but only `sess->network_nick` keeps
     * tracking reality if a nick_change lands later (see
     * `handle_grappa_message_event`'s own doc). */
    present_channels(fd, sess->network_nick, sess);
    fprintf(stderr,
            "bicchierino: network selected: subject=%s network=%s(%ld) joined_channels=%zu\n",
            sess->subject_name, sess->network_slug, sess->network_id, sess->channel_count);

    *br_connected = bridge_connect(cfg->grappa_url, sess->token, sess->subject_name, br);
    if (*br_connected) {
        join_grappa_topics(fd, sess->network_nick, br, sess);
    } else {
        fprintf(stderr, "bicchierino: websocket handshake FAILED (post network-select)\n");
        send_line(fd,
                  ":%s NOTICE %s :Network %s selected, but the live event bridge failed to "
                  "come up — messages and channel activity will not be delivered until you "
                  "reconnect",
                  IRCD_SERVER, sess->network_nick, sess->network_slug);
    }
}

static void send_network_reminder(int fd, const char *nick, const struct grappa_session *sess) {
    char available[512];
    format_available_networks(sess, available, sizeof(available));
    send_line(fd,
              ":%s NOTICE %s :You are not connected to any network. Available: %s. Use "
              "/quote GRAPPA NETWORK <name> to select one.",
              IRCD_SERVER, nick, available);
}

/* WIRE.md §4, exact order from shottino's own `ws_join_topics` /
 * `ws_sync_dm_listeners` / `ws_report_visible`: user topic first (every
 * later user-topic push needs its join_ref) -> one topic per already-
 * known channel -> the per-network DM listener topic (own nick, WIRE.md
 * §5's re-keying gotcha) -> `visibility:true`, sent immediately after so
 * a fresh socket doesn't lose the race with grappa's hidden-socket
 * auto-away debounce (shottino's own comment: the unaway can't fix a
 * debounce that already fired, since it only fires on the
 * hidden->visible TRANSITION, and a client that never reports visible
 * never makes one).
 *
 * Best-effort throughout, matching the existing precedent from the
 * user-topic-only smoke test this replaces: a failure here is logged,
 * never sent to the IRC client as an ERROR — the client already got
 * its one NOTICE saying the bridge isn't live yet. */

/* Forward declaration: handle_grappa_event is defined later in this
 * file (it needs the individual event-kind handlers above it), but
 * bridge_join's on_event callback — needed by every bridge_join call
 * below, including the ones in this bootstrap sequence — must reach it.
 * See bridge_join's own doc: without this, an earlier topic's after-join
 * snapshot arriving while a LATER bridge_join call in this same function
 * is still waiting for its own reply is silently lost — confirmed live,
 * reproducibly, for #testchannel's entire topic/modes/members snapshot
 * during a bootstrap that auto-rejoined an already-joined channel. */
static void handle_grappa_event(int fd, const char *nick, struct bridge *br,
                                 struct grappa_session *sess, const char *payload,
                                 size_t payload_len);

struct bridge_event_ctx {
    int fd;
    const char *nick;
    struct bridge *br;
    struct grappa_session *sess;
};

static void bridge_event_dispatch(void *ctx_raw, const char *payload, size_t payload_len) {
    const struct bridge_event_ctx *ctx = ctx_raw;
    handle_grappa_event(ctx->fd, ctx->nick, ctx->br, ctx->sess, payload, payload_len);
}

static void join_grappa_topics(int fd, const char *nick, struct bridge *br,
                                struct grappa_session *sess) {
    struct bridge_event_ctx ctx = {fd, nick, br, sess};

    char user_topic[160];
    snprintf(user_topic, sizeof(user_topic), "grappa:user:%s", sess->subject_name);
    if (bridge_join(br, user_topic, &sess->user_join_ref, bridge_event_dispatch, &ctx)) {
        fprintf(stderr, "bicchierino: joined %s (join_ref=%lu)\n", user_topic,
                sess->user_join_ref);
    } else {
        fprintf(stderr, "bicchierino: join %s failed\n", user_topic);
    }

    /* The `$server` window is NOT derived from the channel list and never
     * appears in it: `GET /networks/:slug/channels` merges the credential
     * autojoin list with `Session.list_channels/2` (grappa's
     * `channels_controller.ex`), both of which are real channels only.
     * `$server` is synthetic and always exists, so it is joined
     * unconditionally — grappa broadcasts its rows on the per-channel
     * topic like any other window (`Session.Persistor`'s
     * `Topic.channel(subject, slug, attrs.channel)`), which means without
     * this join every server notice, MOTD line and catch-all row is
     * dropped one layer below the renderer. Nothing is ever pushed on this
     * topic, so its join_ref is local — unlike the user topic's, which the
     * heartbeat/visibility pushes need. */
    char server_topic[512];
    snprintf(server_topic, sizeof(server_topic), "grappa:user:%s/network:%s/channel:%s",
             sess->subject_name, sess->network_slug, GRAPPA_SERVER_WINDOW);
    unsigned long server_join_ref = 0;
    if (bridge_join(br, server_topic, &server_join_ref, bridge_event_dispatch, &ctx)) {
        fprintf(stderr, "bicchierino: joined %s (join_ref=%lu)\n", server_topic, server_join_ref);
    } else {
        fprintf(stderr, "bicchierino: join %s failed\n", server_topic);
    }

    for (size_t i = 0; i < sess->channel_count; i++) {
        char folded_channel[128];
        ascii_fold_lower(sess->channels[i], folded_channel, sizeof(folded_channel));
        char topic[512];
        snprintf(topic, sizeof(topic), "grappa:user:%s/network:%s/channel:%s",
                 sess->subject_name, sess->network_slug, folded_channel);
        if (bridge_join(br, topic, &sess->channel_join_refs[i], bridge_event_dispatch, &ctx)) {
            fprintf(stderr, "bicchierino: joined %s (join_ref=%lu)\n", topic,
                    sess->channel_join_refs[i]);
        } else {
            fprintf(stderr, "bicchierino: join %s failed\n", topic);
        }
    }

    if (sess->network_nick[0]) {
        char folded_nick[64];
        ascii_fold_lower(sess->network_nick, folded_nick, sizeof(folded_nick));
        char dm_topic[512];
        snprintf(dm_topic, sizeof(dm_topic), "grappa:user:%s/network:%s/channel:%s",
                 sess->subject_name, sess->network_slug, folded_nick);
        sess->dm_joined =
            bridge_join(br, dm_topic, &sess->dm_join_ref, bridge_event_dispatch, &ctx);
        if (sess->dm_joined) {
            fprintf(stderr, "bicchierino: joined DM listener %s (join_ref=%lu)\n", dm_topic,
                    sess->dm_join_ref);
        } else {
            fprintf(stderr, "bicchierino: join DM listener %s failed\n", dm_topic);
        }
    }

    if (sess->user_join_ref) {
        if (bridge_push(br, user_topic, sess->user_join_ref, "visibility",
                         "{\"visible\":true}")) {
            fprintf(stderr, "bicchierino: visibility:true pushed\n");
        } else {
            fprintf(stderr, "bicchierino: visibility push failed\n");
        }
    }
}

/* WIRE.md §2.5's corrected text: sending a message is REST, not a WS
 * push — `POST /networks/:slug/channels/:target/messages`, body
 * `{"body": "..."}`, confirmed against `messages_controller.ex`
 * directly (`Session.send_privmsg/4`). `target` is percent-encoded the
 * same way fetch_joined_channels() already encodes a channel name in a
 * path segment — a DM target (a bare nick) never needs it, but a
 * channel's `#` always does. No separate NOTICE verb exists on grappa's
 * write surface (only `send_privmsg`/`send_ctcp`), and no CTCP framing
 * translation is needed either — an outbound `/me` already arrives here
 * as literal `\x01ACTION ...\x01` bytes in `body` from the IRC client,
 * and `Session.send_privmsg/4` classifies privmsg-vs-action itself from
 * that same framing, so the raw body is passed through unchanged.
 * Best-effort: a failed send is logged, never torn down as a "lost
 * grappa" case — that treatment is for the CONNECTION being
 * unreachable, not one rejected/failed line (rate-limited, empty
 * body, no session, ...), which a real IRC server also wouldn't drop a
 * whole connection over. */
/* Splits `*cursor` on the next comma, writing the token into `out` and
 * advancing `*cursor` past it — the shared parser for IRC's own
 * comma-separated JOIN/PART channel (and JOIN key) lists (RFC 2812).
 * Returns false once `*cursor` is exhausted; call in a `while` loop. */
static bool next_csv_token(const char **cursor, char *out, size_t out_sz) {
    if (!*cursor || !**cursor) return false;
    const char *comma = strchr(*cursor, ',');
    size_t len = comma ? (size_t)(comma - *cursor) : strlen(*cursor);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, *cursor, len);
    out[len] = '\0';
    *cursor = comma ? comma + 1 : *cursor + strlen(*cursor);
    return true;
}

/* Case-insensitive (IRC identity is never case-sensitive) linear scan —
 * sess->channel_count is small (MAX_CHANNELS=128, real accounts bind a
 * handful), no index needed. Returns sess->channel_count as the
 * not-found sentinel, matching this file's existing style for "no
 * match" (e.g. pick_network's own linear scan). */
static size_t find_channel_index(const struct grappa_session *sess, const char *name) {
    for (size_t i = 0; i < sess->channel_count; i++)
        if (strcasecmp(sess->channels[i], name) == 0) return i;
    return sess->channel_count;
}

/* Removes channels[idx] (and its parallel join_ref), shifting everything
 * after it down by one so both arrays stay dense — required since
 * join_grappa_topics/handle_join/handle_part all iterate channel_count
 * as a contiguous range, never a sparse one. */
static void remove_channel_at(struct grappa_session *sess, size_t idx) {
    for (size_t i = idx; i + 1 < sess->channel_count; i++) {
        snprintf(sess->channels[i], sizeof(sess->channels[0]), "%s", sess->channels[i + 1]);
        sess->channel_join_refs[i] = sess->channel_join_refs[i + 1];
        snprintf(sess->channel_mode_str[i], sizeof(sess->channel_mode_str[0]), "%s",
                 sess->channel_mode_str[i + 1]);
        snprintf(sess->channel_mode_params[i], sizeof(sess->channel_mode_params[0]), "%s",
                 sess->channel_mode_params[i + 1]);
    }
    sess->channel_count--;
}

/* See `pending_self_msg_ids`'s own doc on `struct grappa_session` for
 * why this exists. Insert evicts the OLDEST entry on overflow (a
 * simple shift, not a proper ring cursor — 16 entries is small enough
 * that this is free, and it keeps `consume`'s linear scan simple too;
 * neither is worth a real ring-buffer index for a set this size). */
static void remember_pending_self_id(struct grappa_session *sess, long id) {
    size_t cap = sizeof(sess->pending_self_msg_ids) / sizeof(sess->pending_self_msg_ids[0]);
    if (sess->pending_self_msg_count == cap) {
        memmove(sess->pending_self_msg_ids, sess->pending_self_msg_ids + 1,
                (cap - 1) * sizeof(sess->pending_self_msg_ids[0]));
        sess->pending_self_msg_count--;
    }
    sess->pending_self_msg_ids[sess->pending_self_msg_count++] = id;
}

/* Returns true and removes `id` if found (my own echo, already
 * rendered — suppress this one); false leaves the set untouched (not
 * mine, or already consumed once — render it). */
static bool consume_pending_self_id(struct grappa_session *sess, long id) {
    for (size_t i = 0; i < sess->pending_self_msg_count; i++) {
        if (sess->pending_self_msg_ids[i] != id) continue;
        size_t remaining = sess->pending_self_msg_count - i - 1;
        if (remaining)
            memmove(sess->pending_self_msg_ids + i, sess->pending_self_msg_ids + i + 1,
                    remaining * sizeof(sess->pending_self_msg_ids[0]));
        sess->pending_self_msg_count--;
        return true;
    }
    return false;
}

static void send_privmsg_rest(struct http_client *hc, const struct config *cfg,
                               struct grappa_session *sess, const char *target,
                               const char *body) {
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char encoded_target[300];
    url_encode(target, encoded_target, sizeof(encoded_target));
    char path[1024];
    snprintf(path, sizeof(path), "/networks/%s/channels/%s/messages", encoded_slug,
             encoded_target);

    char esc_body[IRC_LINE_MAX * 2];
    json_escape_into(body, esc_body, sizeof(esc_body));
    char json_body[IRC_LINE_MAX * 2 + 32];
    snprintf(json_body, sizeof(json_body), "{\"body\":\"%s\"}", esc_body);

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "POST", path, sess->token, json_body, &resp)) {
        fprintf(stderr, "bicchierino: PRIVMSG to %s: grappa not reachable\n", target);
        return;
    }
    if (resp.status != 200 && resp.status != 201 && resp.status != 202) {
        fprintf(stderr, "bicchierino: PRIVMSG to %s: unexpected HTTP status %d\n", target,
                resp.status);
    } else if (resp.status == 201) {
        /* 201 = a real, persisted message (the 202 no-persist case —
         * a services-targeted line like a NickServ IDENTIFY — carries
         * no `id` and never comes back as a `message` event at all, so
         * there is nothing to correlate). `Wire.to_json/1` is the SAME
         * shape used everywhere (REST show/index, WS push), so `id` is
         * a plain top-level integer field here too. */
        char err[128];
        json_doc *doc = json_parse(resp.body, resp.body_len, err, sizeof(err));
        if (doc) {
            long id = 0;
            if (json_long_req(json_root(doc), "id", &id)) remember_pending_self_id(sess, id);
            json_free(doc);
        }
    }
    http_response_free(&resp);
}

/* WIRE.md §2.5: JOIN is REST too — `POST /networks/:slug/channels`,
 * body `{"name": "#chan"[, "key": "..."]}` -> `Session.send_join/4`.
 * 202 means "accepted, a :pending window opened" — NOT "joined";
 * success/failure arrives later as a WS event (`joined`/`join_failed`)
 * this codebase doesn't dispatch yet (TODO(next)). The JOIN echo
 * handle_join sends the client is therefore optimistic, same posture
 * grappa's own REST contract already commits cicchetto to (its own
 * doc: "cic's setPending dispatch has fired... by the time this
 * returns 202"). */
static bool send_join_rest(struct http_client *hc, const struct config *cfg,
                            const struct grappa_session *sess, const char *channel,
                            const char *key) {
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char path[512];
    snprintf(path, sizeof(path), "/networks/%s/channels", encoded_slug);

    char esc_channel[300];
    json_escape_into(channel, esc_channel, sizeof(esc_channel));
    char json_body[600];
    if (key && key[0]) {
        char esc_key[192];
        json_escape_into(key, esc_key, sizeof(esc_key));
        snprintf(json_body, sizeof(json_body), "{\"name\":\"%s\",\"key\":\"%s\"}", esc_channel,
                 esc_key);
    } else {
        snprintf(json_body, sizeof(json_body), "{\"name\":\"%s\"}", esc_channel);
    }

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "POST", path, sess->token, json_body, &resp)) {
        fprintf(stderr, "bicchierino: JOIN %s: grappa not reachable\n", channel);
        return false;
    }
    bool ok = resp.status == 200 || resp.status == 201 || resp.status == 202;
    if (!ok)
        fprintf(stderr, "bicchierino: JOIN %s: unexpected HTTP status %d\n", channel, resp.status);
    http_response_free(&resp);
    return ok;
}

/* WIRE.md §2.5: PART is REST too — `DELETE /networks/:slug/channels/:chan`
 * -> `Session.send_part/4`. Takes no reason (the endpoint has no body at
 * all) — a reason the IRC client provides has nowhere to go server-side
 * and is never forwarded upstream; handle_part still echoes it locally
 * (a real ircd would), the gap is grappa's, not bicchierino's to paper
 * over or block on. */
static bool send_part_rest(struct http_client *hc, const struct config *cfg,
                            const struct grappa_session *sess, const char *channel) {
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char encoded_channel[300];
    url_encode(channel, encoded_channel, sizeof(encoded_channel));
    char path[1024];
    snprintf(path, sizeof(path), "/networks/%s/channels/%s", encoded_slug, encoded_channel);

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "DELETE", path, sess->token, NULL, &resp)) {
        fprintf(stderr, "bicchierino: PART %s: grappa not reachable\n", channel);
        return false;
    }
    bool ok = resp.status == 200 || resp.status == 202 || resp.status == 204;
    if (!ok)
        fprintf(stderr, "bicchierino: PART %s: unexpected HTTP status %d\n", channel, resp.status);
    http_response_free(&resp);
    return ok;
}

/* WIRE.md §2.5: TOPIC-set is REST, `POST /networks/:slug/channels/
 * :channel_id/topic` (`{"body": "<new topic>"}`) -> `Session.send_topic/4`
 * — same bucket as JOIN/PART/message-send, no WS twin ever used for this
 * (grappa_channel.ex's `"topic_set"` verb exists too, but bicchierino
 * follows the same REST path already proven for JOIN/PART/PRIVMSG).
 * `channel_id` in the route is, despite the name, the channel NAME
 * (same `:channel_id`-really-means-name pattern `send_part_rest` above
 * already relies on) — never a numeric FK. **Rejects an EMPTY body
 * server-side** (`ChannelsController.topic/2`'s own guard clause,
 * `body != ""`) — a topic CLEAR is a genuinely different verb
 * (`handle_topic_clear`, WS `"topic_clear"`), not this endpoint with an
 * empty string. */
static bool send_topic_rest(struct http_client *hc, const struct config *cfg,
                             const struct grappa_session *sess, const char *channel,
                             const char *text) {
    char encoded_slug[192];
    url_encode(sess->network_slug, encoded_slug, sizeof(encoded_slug));
    char encoded_channel[300];
    url_encode(channel, encoded_channel, sizeof(encoded_channel));
    char path[1024];
    snprintf(path, sizeof(path), "/networks/%s/channels/%s/topic", encoded_slug, encoded_channel);

    char esc_text[600];
    json_escape_into(text, esc_text, sizeof(esc_text));
    char json_body[700];
    snprintf(json_body, sizeof(json_body), "{\"body\":\"%s\"}", esc_text);

    struct http_response resp;
    if (!http_client_request(hc, cfg->grappa_url, "POST", path, sess->token, json_body, &resp)) {
        fprintf(stderr, "bicchierino: TOPIC %s: grappa not reachable\n", channel);
        return false;
    }
    bool ok = resp.status == 200 || resp.status == 201 || resp.status == 202;
    if (!ok)
        fprintf(stderr, "bicchierino: TOPIC %s: unexpected HTTP status %d\n", channel, resp.status);
    http_response_free(&resp);
    return ok;
}

/* IRC `JOIN #a,#b key1,key2` — comma-separated channel list, optional
 * comma-separated key list matched POSITIONALLY (RFC 2812: fewer keys
 * than channels leaves the trailing ones keyless). grappa's own REST
 * batch form only accepts ONE key for a WHOLE multi-join (WIRE.md
 * §2.5), so this issues one REST call per channel instead — strictly
 * more capable (real per-channel keys) AND more forgiving (one bad
 * channel in the list doesn't block the others, unlike grappa's own
 * atomic list-or-nothing REST form).
 *
 * `br`/`br_connected` mirror connection_run's own locals — a newly
 * joined channel gets its own WS topic joined immediately (folded per
 * WIRE.md §5.5) so its events start flowing without waiting for a
 * reconnect; Case B (no bridge yet) or a lost bridge just skips that
 * part, the REST join and IRC echo still happen. */
static void handle_join(int fd, struct http_client *hc, struct bridge *br, bool br_connected,
                         const struct config *cfg, const char *nick, struct grappa_session *sess,
                         const struct irc_message *msg) {
    if (msg->param_count < 1) return;
    const char *channels_cursor = msg->params[0];
    const char *keys_cursor = msg->param_count >= 2 ? msg->params[1] : NULL;

    char channel[128];
    while (next_csv_token(&channels_cursor, channel, sizeof(channel))) {
        char key[128] = {0};
        if (keys_cursor) next_csv_token(&keys_cursor, key, sizeof(key));

        if (!send_join_rest(hc, cfg, sess, channel, key[0] ? key : NULL)) continue;

        if (find_channel_index(sess, channel) == sess->channel_count &&
            sess->channel_count < MAX_CHANNELS) {
            size_t idx = sess->channel_count++;
            snprintf(sess->channels[idx], sizeof(sess->channels[0]), "%s", channel);
            sess->channel_join_refs[idx] = 0;
            /* Clear any stale 324 cache left behind by a PREVIOUS
             * channel that once occupied this array slot (PART can
             * vacate a slot without shifting it — e.g. removing the
             * last entry just decrements channel_count) — otherwise a
             * bare `MODE <this channel>` query, asked before this
             * channel's own fresh `channel_modes_changed` snapshot
             * arrives, would answer with the WRONG channel's modes
             * instead of staying silent. */
            sess->channel_mode_str[idx][0] = '\0';
            sess->channel_mode_params[idx][0] = '\0';

            if (br_connected) {
                char folded_channel[128];
                ascii_fold_lower(channel, folded_channel, sizeof(folded_channel));
                char topic[512];
                snprintf(topic, sizeof(topic), "grappa:user:%s/network:%s/channel:%s",
                         sess->subject_name, sess->network_slug, folded_channel);
                struct bridge_event_ctx ctx = {fd, nick, br, sess};
                if (!bridge_join(br, topic, &sess->channel_join_refs[idx], bridge_event_dispatch,
                                  &ctx))
                    fprintf(stderr, "bicchierino: join %s failed\n", topic);
            }
        }

        send_line(fd, ":%s!bicchierino@bicchierino JOIN :%s", nick, channel);
    }
}

static void handle_part(int fd, struct http_client *hc, struct bridge *br, bool br_connected,
                         const struct config *cfg, const char *nick, struct grappa_session *sess,
                         const struct irc_message *msg) {
    if (msg->param_count < 1) return;
    const char *channels_cursor = msg->params[0];
    const char *reason = msg->param_count >= 2 ? msg->params[1] : NULL;

    char channel[128];
    while (next_csv_token(&channels_cursor, channel, sizeof(channel))) {
        if (!send_part_rest(hc, cfg, sess, channel)) continue;

        size_t idx = find_channel_index(sess, channel);
        if (idx != sess->channel_count) {
            /* `phx_leave` on the channel's own WS topic — closes the
             * previously-documented "innocuous leak" gap: without
             * this, a channel joined then parted then re-joined within
             * the same connection would silently accumulate a second,
             * orphaned subscription to the same topic (Phoenix has no
             * problem with a socket subscribed twice, but there's no
             * reason to leave the old one dangling either). Fire-and-
             * forget, same as `visibility`/`heartbeat` — any reply is
             * just another `phx_reply` frame the existing drain loop
             * already absorbs generically. */
            if (br_connected) {
                char folded_channel[128];
                ascii_fold_lower(channel, folded_channel, sizeof(folded_channel));
                char topic[512];
                snprintf(topic, sizeof(topic), "grappa:user:%s/network:%s/channel:%s",
                         sess->subject_name, sess->network_slug, folded_channel);
                bridge_push(br, topic, sess->channel_join_refs[idx], "phx_leave", "{}");
            }
            remove_channel_at(sess, idx);
        }

        if (reason)
            send_line(fd, ":%s!bicchierino@bicchierino PART %s :%s", nick, channel, reason);
        else
            send_line(fd, ":%s!bicchierino@bicchierino PART %s", nick, channel);
    }
}

/* WIRE.md §2.5: MODE (channel modes) is a genuine WS push verb, unlike
 * PRIVMSG/JOIN/PART/TOPIC-set — `grappa_channel.ex`'s `"mode"` clause,
 * payload `{"network_id": id, "target": chan, "modes": "+o", "params":
 * [...]}` -> `Session.send_mode/5`. Fire-and-forget via `bridge_push`,
 * same posture as the `visibility` push — the reply (if grappa sends
 * one) arrives as a `phx_reply` frame `handle_grappa_event` already
 * no-ops on during Phase 2; the actual confirmation a client sees is
 * the LIVE `mode` `message` kind (already rendered,
 * `handle_grappa_message_event`) once the change lands upstream.
 *
 * Scoped to CHANNEL targets only (`#`-prefixed) for now — a nick target
 * (`MODE mynick +i`, own usermode) is a SEPARATE WS verb ("umode"), not
 * implemented. A bare `MODE #chan` with no modestring is a QUERY, not a
 * set — also not implemented (the client already gets channel modes
 * unsolicited via 324 on join and the live `channel_modes_changed`
 * snapshot, so a query has nothing new to offer yet). Silently
 * no-ops on both: on a channel bicchierino hasn't joined (no
 * `join_ref` to push with — Phoenix has nothing to route the frame
 * to) and when the bridge isn't connected at all. */
static void handle_mode(struct bridge *br, bool br_connected, struct grappa_session *sess,
                         const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 2) return;
    const char *target = msg->params[0];
    if (target[0] != '#') return;

    size_t idx = find_channel_index(sess, target);
    if (idx == sess->channel_count) return;

    const char *modes = msg->params[1];
    char esc_modes[300];
    json_escape_into(modes, esc_modes, sizeof(esc_modes));

    char params_json[600];
    size_t params_len = (size_t)snprintf(params_json, sizeof(params_json), "[");
    for (int i = 2; i < msg->param_count; i++) {
        char esc_param[200];
        json_escape_into(msg->params[i], esc_param, sizeof(esc_param));
        int written = snprintf(params_json + params_len, sizeof(params_json) - params_len,
                                "%s\"%s\"", params_len > 1 ? "," : "", esc_param);
        if (written > 0 && (size_t)written < sizeof(params_json) - params_len)
            params_len += (size_t)written;
    }
    snprintf(params_json + params_len, sizeof(params_json) - params_len, "]");

    char esc_target[300];
    json_escape_into(target, esc_target, sizeof(esc_target));
    char payload[2048];
    snprintf(payload, sizeof(payload),
             "{\"network_id\":%ld,\"target\":\"%s\",\"modes\":\"%s\",\"params\":%s}",
             sess->network_id, esc_target, esc_modes, params_json);

    char folded_channel[128];
    ascii_fold_lower(target, folded_channel, sizeof(folded_channel));
    char topic[512];
    snprintf(topic, sizeof(topic), "grappa:user:%s/network:%s/channel:%s", sess->subject_name,
             sess->network_slug, folded_channel);

    if (!bridge_push(br, topic, sess->channel_join_refs[idx], "mode", payload))
        fprintf(stderr, "bicchierino: MODE %s %s: push failed\n", target, modes);
}

/* Fire-and-forget push on the always-open user topic
 * (`grappa:user:{subject}`) — the natural home for verbs that name
 * their real target via an explicit payload field (channel/nick/...),
 * not via which topic process happens to receive the push. Matches
 * where grappa's own replies for these land too: `whois_bundle`/
 * `banlist_bundle` broadcast on this SAME topic (WIRE.md §6), not a
 * per-channel one. Avoids needing a channel's own join_ref at all,
 * unlike `handle_mode`. */
static bool push_on_user_topic(struct bridge *br, const struct grappa_session *sess,
                                const char *event, const char *json_payload) {
    char user_topic[160];
    snprintf(user_topic, sizeof(user_topic), "grappa:user:%s", sess->subject_name);
    return bridge_push(br, user_topic, sess->user_join_ref, event, json_payload);
}

/* WIRE.md §6: `"topic_clear"` push, payload `{"network_id", "channel"}`
 * -> `Session.send_topic_clear/3` — the irssi `/topic -delete`
 * convention, sends `TOPIC #chan :` (empty trailing) upstream. A
 * SEPARATE verb from TOPIC-set on purpose: the REST topic endpoint
 * explicitly REJECTS an empty body server-side (`ChannelsController.
 * topic/2`'s own guard, `body != ""`) — there is no way to clear via
 * REST at all, confirmed reading the controller directly, not assumed
 * from the empty-body case just silently working. */
static void handle_topic_clear(struct bridge *br, bool br_connected, struct grappa_session *sess,
                                const char *channel) {
    if (!br_connected) return;
    char esc_channel[300];
    json_escape_into(channel, esc_channel, sizeof(esc_channel));
    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"channel\":\"%s\"}", sess->network_id,
             esc_channel);
    if (!push_on_user_topic(br, sess, "topic_clear", payload))
        fprintf(stderr, "bicchierino: TOPIC-clear %s: push failed\n", channel);
}

/* `TOPIC #chan :<text>` (non-empty) -> REST `send_topic_rest`;
 * `TOPIC #chan :` (empty trailing, irssi's `-delete` convention on the
 * wire) -> `handle_topic_clear`'s dedicated WS verb, since REST can't
 * express a clear at all (see that function's own doc). Either path's
 * confirmation arrives the normal way, through the live `message`
 * event with `kind: "topic"` — already rendered unconditionally
 * (self-echo NOT suppressed for topic, same as kick/mode/quit) by
 * `handle_grappa_message_event`, so no separate optimistic echo is
 * needed here — a real ircd's own TOPIC echo does the confirming. Bare
 * `TOPIC #chan` (no second param at all — a QUERY, not a set) is left
 * unhandled: 332/333 at join + the live `topic_changed` event already
 * cover the common case, and extending this to an unjoined channel hits
 * the exact same subscription problem `MODE #chan` does (bicchierino#1,
 * blocked upstream) — not worth solving twice for a rarer command. */
static void handle_topic(struct http_client *hc, struct bridge *br, bool br_connected,
                          const struct config *cfg, struct grappa_session *sess,
                          const struct irc_message *msg) {
    if (msg->param_count < 2) return;
    const char *channel = msg->params[0];
    const char *text = msg->params[1];
    if (text[0] == '\0')
        handle_topic_clear(br, br_connected, sess, channel);
    else
        send_topic_rest(hc, cfg, sess, channel, text);
}

/* WIRE.md §6: `"umode"` push, payload `{"network_id", "modes"}` ->
 * `Session.send_umode/3` (`grappa_channel.ex:953-967`) — own-nick MODE,
 * a SEPARATE WS verb from channel `"mode"` (`handle_mode` above), not
 * the same push with a nick target — grappa itself distinguishes them
 * this way (`/umode +i` doc comment: "MODE own_nick +i", but routed
 * through its own verb, not the generic one). `handle_irc_line`
 * intercepts `MODE <ownnick> <modestring>` (target folds equal to
 * `sess->network_nick`, no `#`) before it ever reaches `handle_mode`,
 * which would otherwise silently no-op on a non-`#` target. */
static void handle_umode(struct bridge *br, bool br_connected, struct grappa_session *sess,
                          const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 2) return;
    const char *modes = msg->params[1];
    char esc_modes[300];
    json_escape_into(modes, esc_modes, sizeof(esc_modes));
    char payload[400];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"modes\":\"%s\"}", sess->network_id,
             esc_modes);
    if (!push_on_user_topic(br, sess, "umode", payload))
        fprintf(stderr, "bicchierino: UMODE %s: push failed\n", modes);
}

/* WIRE.md §6: `"kick"` push, payload `{"network_id", "channel", "nick",
 * "target's the kicked nick", "reason"}` -> `Session.send_kick/5`
 * (`grappa_channel.ex:590-604`). `reason` is a REQUIRED string
 * server-side (`is_binary(reason)`) — RFC 2812's KICK reason is
 * optional, so an absent one falls back to the kicker's own nick,
 * matching common real-ircd behavior for a reasonless kick. Live
 * confirmation is the already-rendered `message` kind `"kick"`
 * (`handle_grappa_message_event`) — UNCONDITIONALLY shown even when we
 * are the kicker (self-echo suppression is scoped away from this kind
 * specifically, see that function's own comment), so a successful kick
 * has real feedback; a rejected one arrives the same way MODE's own
 * live rejection test proved (a NOTICE carrying the real ircd error). */
static void handle_kick(struct bridge *br, bool br_connected, const char *nick,
                         struct grappa_session *sess, const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 2) return;
    const char *channel = msg->params[0];
    const char *target = msg->params[1];
    const char *reason = msg->param_count >= 3 ? msg->params[2] : nick;

    char esc_channel[300], esc_target[300], esc_reason[600];
    json_escape_into(channel, esc_channel, sizeof(esc_channel));
    json_escape_into(target, esc_target, sizeof(esc_target));
    json_escape_into(reason, esc_reason, sizeof(esc_reason));

    char payload[1400];
    snprintf(payload, sizeof(payload),
             "{\"network_id\":%ld,\"channel\":\"%s\",\"nick\":\"%s\",\"reason\":\"%s\"}",
             sess->network_id, esc_channel, esc_target, esc_reason);

    if (!push_on_user_topic(br, sess, "kick", payload))
        fprintf(stderr, "bicchierino: KICK %s %s: push failed\n", channel, target);
}

/* WIRE.md §6: `"invite"` push, payload `{"network_id", "channel",
 * "nick"}` -> `Session.send_invite/4` (`grappa_channel.ex:645-656`).
 * RFC 2812 IRC wire order is `INVITE <nick> <channel>` (nick first);
 * grappa's own payload names them channel-then-nick — just field
 * names, not wire order, no translation needed beyond picking the
 * right param into the right key. No dedicated reply event found in
 * `Session.Wire` for this — the real ircd's own 341 RPL_INVITING (or a
 * rejection numeric) is expected to arrive through the same raw-numeric
 * NOTICE forwarding MODE's rejection test already proved live. */
static void handle_invite(struct bridge *br, bool br_connected, struct grappa_session *sess,
                           const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 2) return;
    const char *target = msg->params[0];
    const char *channel = msg->params[1];

    char esc_target[300], esc_channel[300];
    json_escape_into(target, esc_target, sizeof(esc_target));
    json_escape_into(channel, esc_channel, sizeof(esc_channel));

    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"channel\":\"%s\",\"nick\":\"%s\"}",
             sess->network_id, esc_channel, esc_target);

    if (!push_on_user_topic(br, sess, "invite", payload))
        fprintf(stderr, "bicchierino: INVITE %s %s: push failed\n", target, channel);
}

/* WIRE.md §6: `"away"` push — the ONE verb in this whole catalog keyed
 * by `"network"` (the SLUG, a string) instead of `"network_id"` (the
 * numeric FK every other verb uses) — a real inconsistency in grappa's
 * own wire, confirmed reading `grappa_channel.ex`'s `"away"` clauses
 * directly, not assumed from the naming pattern every other verb
 * follows. Set: `{"action":"set","network":slug,"reason":reason}` ->
 * `Session.set_explicit_away/4`-ish path. Unset: `{"action":"unset",
 * "network":slug}`, no reason field at all. `origin_window` (cicchetto's
 * own reply-routing field) is optional and simply omitted — absent
 * resolves to `{:ok, nil}` server-side (`validate_origin_window/1`),
 * bicchierino has no window concept to route back to anyway. */
static void handle_away(struct bridge *br, bool br_connected, struct grappa_session *sess,
                         const struct irc_message *msg) {
    if (!br_connected) return;
    char esc_slug[128];
    json_escape_into(sess->network_slug, esc_slug, sizeof(esc_slug));
    char payload[900];
    if (msg->param_count >= 1 && msg->params[0][0]) {
        char esc_reason[600];
        json_escape_into(msg->params[0], esc_reason, sizeof(esc_reason));
        snprintf(payload, sizeof(payload), "{\"action\":\"set\",\"network\":\"%s\",\"reason\":\"%s\"}",
                 esc_slug, esc_reason);
    } else {
        snprintf(payload, sizeof(payload), "{\"action\":\"unset\",\"network\":\"%s\"}", esc_slug);
    }
    if (!push_on_user_topic(br, sess, "away", payload))
        fprintf(stderr, "bicchierino: AWAY: push failed\n");
}

/* WIRE.md §6: `"oper"` push, payload `{"network_id", "name",
 * "password"}` -> `Session.send_oper/4` (`grappa_channel.ex:1043-1054`,
 * `validate_args(oper_token: name, oper_token: password)` — stricter
 * per-token validation than RAW's generic CRLF/NUL-only check, why this
 * gets its own handler instead of relying on the RAW fallback below for
 * something this security-sensitive). */
static void handle_oper(struct bridge *br, bool br_connected, struct grappa_session *sess,
                         const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 2) return;
    const char *name = msg->params[0];
    const char *password = msg->params[1];

    char esc_name[300], esc_password[300];
    json_escape_into(name, esc_name, sizeof(esc_name));
    json_escape_into(password, esc_password, sizeof(esc_password));

    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"name\":\"%s\",\"password\":\"%s\"}",
             sess->network_id, esc_name, esc_password);

    if (!push_on_user_topic(br, sess, "oper", payload))
        fprintf(stderr, "bicchierino: OPER %s: push failed\n", name);
}

/* Reconstructs an IRC line from an already-parsed message — NOT
 * byte-identical to what the client originally sent (multiple spaces
 * between params, for instance, don't survive `irc_parse_line`), but
 * semantically equivalent, which is all `handle_raw`'s fallback below
 * needs: it forwards to grappa's own "unrestricted escape hatch"
 * verb, and any real ircd/services command downstream only cares about
 * the tokens, not the original whitespace. Trailing param gets the `:`
 * prefix back only when it contains a space or is otherwise
 * ambiguous — matches how a real client would have sent it, avoiding
 * an unnecessary `:` on every reconstructed one-word trailing param. */
static void reconstruct_irc_line(const struct irc_message *msg, char *out, size_t out_sz) {
    size_t len = (size_t)snprintf(out, out_sz, "%s", msg->command);
    for (int i = 0; i < msg->param_count; i++) {
        const char *p = msg->params[i];
        bool last = i == msg->param_count - 1;
        bool needs_colon = last && (p[0] == '\0' || strchr(p, ' ') || p[0] == ':');
        int written = snprintf(out + len, out_sz - len, " %s%s", needs_colon ? ":" : "", p);
        if (written > 0 && (size_t)written < out_sz - len) len += (size_t)written;
    }
}

/* WIRE.md §6: `"raw"` push, payload `{"network_id", "line"}` ->
 * `Session.send_raw/3` (`grappa_channel.ex:1063-1074`) — grappa's own
 * comment calls this "the unrestricted escape hatch": every upstream/
 * services command bicchierino has no dedicated handler for (STATS,
 * REHASH, ChanServ/NickServ commands typed as raw IRC lines, ...)
 * reaches grappa this way instead of being silently dropped. This is
 * the catch-all `handle_irc_line` falls through to for any command
 * that isn't one of the ones with a dedicated handler above —
 * deliberately, not a placeholder: a real IRC client's `/quote <text>`
 * does not send a distinguishable "RAW" wire command at all, it sends
 * `<text>` verbatim, so THIS is the only place such a line could ever
 * be recognized as one. */
static void handle_raw(struct bridge *br, bool br_connected, struct grappa_session *sess,
                        const struct irc_message *msg) {
    if (!br_connected) return;

    char line[IRC_LINE_MAX];
    reconstruct_irc_line(msg, line, sizeof(line));

    char esc_line[IRC_LINE_MAX * 2];
    json_escape_into(line, esc_line, sizeof(esc_line));

    char payload[IRC_LINE_MAX * 2 + 64];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"line\":\"%s\"}", sess->network_id,
             esc_line);

    if (!push_on_user_topic(br, sess, "raw", payload))
        fprintf(stderr, "bicchierino: RAW %s: push failed\n", line);
}

/* WHOIS/WHO/NAMES/the bare-`b` BANLIST query MUST go out via their OWN
 * dedicated grappa verbs, not `handle_raw`'s `"raw"` escape hatch:
 * `Session.send_whois/5` (and its `who`/`names`/`banlist` siblings)
 * PRIME a per-target accumulator (`state.whois_pending` etc, wire.ex/
 * server.ex, confirmed by reading `grappa_channel.ex`'s own doc for each
 * verb) BEFORE emitting the raw line upstream — EventRouter only folds
 * the reply numerics (311-319 / 352+315 / 353+366 / 367+368) into a
 * typed bundle for a target that's actually pending. A `/quote WHOIS`
 * sent via `"raw"` issues the identical wire line but skips the priming
 * step entirely, so grappa has no bundle to build and the reply is
 * silently lost — confirmed live: a raw-forwarded `WHOIS RealUser` produced
 * no reply of any kind on a real bicchierino connection, while the
 * dedicated verb below round-tripped 311/312/317/319/318 correctly on
 * the same target. */
static void handle_whois(struct bridge *br, bool br_connected, struct grappa_session *sess,
                          const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 1) return;
    const char *server = msg->param_count >= 2 ? msg->params[0] : NULL;
    const char *nick_arg = msg->param_count >= 2 ? msg->params[1] : msg->params[0];

    char esc_nick[300];
    json_escape_into(nick_arg, esc_nick, sizeof(esc_nick));
    char payload[700];
    if (server) {
        char esc_server[300];
        json_escape_into(server, esc_server, sizeof(esc_server));
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"nick\":\"%s\",\"server\":\"%s\"}",
                 sess->network_id, esc_nick, esc_server);
    } else {
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"nick\":\"%s\"}",
                 sess->network_id, esc_nick);
    }
    if (!push_on_user_topic(br, sess, "whois", payload))
        fprintf(stderr, "bicchierino: WHOIS %s: push failed\n", nick_arg);
}

/* `"channel"` is grappa's own wire field name for the WHO target even
 * though it accepts a mask/nick too (`grappa_channel.ex`'s own comment:
 * "the map key stays 'channel' for wire back-compat with cic"). */
static void handle_who(struct bridge *br, bool br_connected, struct grappa_session *sess,
                        const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 1) return;
    const char *target = msg->params[0];
    char esc_target[300];
    json_escape_into(target, esc_target, sizeof(esc_target));
    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"channel\":\"%s\"}", sess->network_id,
             esc_target);
    if (!push_on_user_topic(br, sess, "who", payload))
        fprintf(stderr, "bicchierino: WHO %s: push failed\n", target);
}

static void handle_names(struct bridge *br, bool br_connected, struct grappa_session *sess,
                          const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 1) return;
    const char *cursor = msg->params[0];
    char channel[128];
    while (next_csv_token(&cursor, channel, sizeof(channel))) {
        char esc_channel[300];
        json_escape_into(channel, esc_channel, sizeof(esc_channel));
        char payload[700];
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"channel\":\"%s\"}",
                 sess->network_id, esc_channel);
        if (!push_on_user_topic(br, sess, "names", payload))
            fprintf(stderr, "bicchierino: NAMES %s: push failed\n", channel);
    }
}

/* The `/banlist` twin of the WHOIS gotcha above: grappa's own doc for
 * the `"banlist"` verb is literally "Issues MODE #chan b (no sign)" —
 * the SAME wire line `handle_mode` would send for a bare, sign-less `MODE
 * #chan b`. But `Session.send_banlist/3` primes `state.banlist_pending`
 * first; a `MODE #chan b` sent through the generic `"mode"` verb (this
 * file's own `handle_mode`) does not, so its 367/368 replies fall back to
 * `{:server, nil}` and land as plain scrollback notices instead of a
 * `banlist_bundle`. `handle_irc_line` special-cases this exact shape
 * (2 params, second one bare `"b"`, no +/-) to route here instead of
 * `handle_mode`. */
static void handle_banlist(struct bridge *br, bool br_connected, struct grappa_session *sess,
                            const struct irc_message *msg) {
    if (!br_connected) return;
    const char *channel = msg->params[0];
    char esc_channel[300];
    json_escape_into(channel, esc_channel, sizeof(esc_channel));
    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"channel\":\"%s\"}", sess->network_id,
             esc_channel);
    if (!push_on_user_topic(br, sess, "banlist", payload))
        fprintf(stderr, "bicchierino: BANLIST %s: push failed\n", channel);
}

/* WIRE.md §6: `"links"` push, payload `{"network_id", "mask"?}` ->
 * `Session.send_links/3`, primes `state.links_pending` — same
 * priming-verb class as whois/who/names/banlist (confirmed reading
 * `session.ex`'s own doc for `send_links/3`), so this must be a
 * dedicated verb, not RAW. `mask` omitted entirely for the bare
 * (full-mesh) form — cic sends `null`, but the server clause pattern-
 * matches regardless of whether the key is present at all (mirrors
 * `handle_whois`'s own `server` field omission). */
static void handle_links(struct bridge *br, bool br_connected, struct grappa_session *sess,
                          const struct irc_message *msg) {
    if (!br_connected) return;
    char payload[700];
    if (msg->param_count >= 1 && msg->params[0][0]) {
        char esc_mask[300];
        json_escape_into(msg->params[0], esc_mask, sizeof(esc_mask));
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"mask\":\"%s\"}", sess->network_id,
                 esc_mask);
    } else {
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld}", sess->network_id);
    }
    if (!push_on_user_topic(br, sess, "links", payload))
        fprintf(stderr, "bicchierino: LINKS: push failed\n");
}

/* WIRE.md §6: `"whowas"` push, payload `{"network_id", "nick"}" ->
 * `Session.send_whowas/3`, primes `state.whowas_pending`. */
static void handle_whowas(struct bridge *br, bool br_connected, struct grappa_session *sess,
                           const struct irc_message *msg) {
    if (!br_connected || msg->param_count < 1) return;
    const char *nick_arg = msg->params[0];
    char esc_nick[300];
    json_escape_into(nick_arg, esc_nick, sizeof(esc_nick));
    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"nick\":\"%s\"}", sess->network_id,
             esc_nick);
    if (!push_on_user_topic(br, sess, "whowas", payload))
        fprintf(stderr, "bicchierino: WHOWAS %s: push failed\n", nick_arg);
}

/* WIRE.md §6: `"lusers"` push, payload `{"network_id", "mask"?,
 * "server"?}` -> `Session.send_lusers/4`. Grappa itself rejects a
 * `server` given with no `mask` (positional framing, RFC 2812 §3.4.2)
 * — `handle_lusers` mirrors that same rule client-side so a malformed
 * `LUSERS <server-only>` line fails fast with a clear reason instead of
 * a mysterious server-side 400. No priming found for this one
 * (`lusers_pending` doesn't exist anywhere in grappa's source, unlike
 * every other bundle here) — pushed as a dedicated verb anyway, for
 * consistency and because RAW would produce the byte-identical wire
 * line regardless. */
static void handle_lusers(struct bridge *br, bool br_connected, struct grappa_session *sess,
                           const struct irc_message *msg) {
    if (!br_connected) return;
    if (msg->param_count == 0) {
        char payload[64];
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld}", sess->network_id);
        if (!push_on_user_topic(br, sess, "lusers", payload))
            fprintf(stderr, "bicchierino: LUSERS: push failed\n");
        return;
    }
    char payload[700];
    if (msg->param_count >= 2) {
        char esc_mask[300], esc_server[300];
        json_escape_into(msg->params[0], esc_mask, sizeof(esc_mask));
        json_escape_into(msg->params[1], esc_server, sizeof(esc_server));
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"mask\":\"%s\",\"server\":\"%s\"}",
                 sess->network_id, esc_mask, esc_server);
    } else {
        char esc_mask[300];
        json_escape_into(msg->params[0], esc_mask, sizeof(esc_mask));
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"mask\":\"%s\"}", sess->network_id,
                 esc_mask);
    }
    if (!push_on_user_topic(br, sess, "lusers", payload))
        fprintf(stderr, "bicchierino: LUSERS: push failed\n");
}

/* WIRE.md §6: `"info"`/`"version"` pushes, payload `{"network_id"}` only
 * — bare server queries, `Session.send_info/2` + `Session.send_version/2`. */
static void handle_info_cmd(struct bridge *br, bool br_connected, const struct grappa_session *sess) {
    if (!br_connected) return;
    char payload[64];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld}", sess->network_id);
    if (!push_on_user_topic(br, sess, "info", payload))
        fprintf(stderr, "bicchierino: INFO: push failed\n");
}

static void handle_version_cmd(struct bridge *br, bool br_connected,
                                const struct grappa_session *sess) {
    if (!br_connected) return;
    char payload[64];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld}", sess->network_id);
    if (!push_on_user_topic(br, sess, "version", payload))
        fprintf(stderr, "bicchierino: VERSION: push failed\n");
}

/* WIRE.md §6: `"motd"` push, payload `{"network_id", "target"?}` ->
 * `Session.send_motd/3`. On-demand mid-session MOTD ONLY — bicchierino's
 * own registration-time MOTD (`send_welcome`) is a separate, purely
 * local synthetic burst and is never affected by this (grappa's own
 * doc: "Connect-time MOTD is NOT affected — no pending flag → stays on
 * $server"). */
static void handle_motd_cmd(struct bridge *br, bool br_connected, struct grappa_session *sess,
                             const struct irc_message *msg) {
    if (!br_connected) return;
    char payload[700];
    if (msg->param_count >= 1 && msg->params[0][0]) {
        char esc_target[300];
        json_escape_into(msg->params[0], esc_target, sizeof(esc_target));
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"target\":\"%s\"}",
                 sess->network_id, esc_target);
    } else {
        snprintf(payload, sizeof(payload), "{\"network_id\":%ld}", sess->network_id);
    }
    if (!push_on_user_topic(br, sess, "motd", payload))
        fprintf(stderr, "bicchierino: MOTD: push failed\n");
}

/* `MODE #chan` — bare, no modestring at all — is a real, legitimate
 * query some clients issue for "what are this channel's current
 * modes", distinct from BOTH the banlist-query form (`MODE #chan b`,
 * `handle_banlist`) and a real change (`MODE #chan <modestring>...`,
 * `handle_mode`). A cache hit (the common case: channel already joined
 * via THIS bridge) answers INSTANTLY from `sess->channel_mode_str`/
 * `channel_mode_params` — no round-trip needed, `handle_grappa_
 * channel_modes_changed_event` already keeps it current from every
 * snapshot/update it renders anyway, same as a real ircd server
 * answering from its own in-memory channel record.
 *
 * On a cache MISS — either a channel bicchierino was never asked to
 * join at all, or the brief window between a JOIN's REST 202 and its
 * first WS-driven snapshot — this now pushes a real `"mode"` query
 * upstream instead of staying silent: `Session.send_mode/5` has NO
 * joined-channel requirement (it just forwards `MODE <target> <modes>`
 * raw, exactly like `send_raw`), and `EventRouter`'s 324 handler
 * processes ANY incoming 324 unconditionally — no `state.*_pending`
 * priming gate the way WHOIS/WHO/NAMES/BANLIST need (confirmed reading
 * both directly, not assumed). Found live: a user tried `/mode` on an
 * UNJOINED-via-bicchierino channel through cicchetto and got a real
 * reply — cicchetto has no special "unjoined" case either, it just
 * always asks. Pushed on the USER topic (`sess->user_join_ref`, always
 * joined) rather than a channel topic, since there may be none for this
 * target — every `do_handle_in` clause in `grappa_channel.ex` is
 * reachable from ANY joined `grappa:user:*` topic (`user_socket.ex`'s
 * single wildcard channel route), so this works exactly like
 * `handle_whois`/`handle_kick` already do. The reply (if any) arrives
 * later as an ordinary `channel_modes_changed` event — same handler,
 * same 324 line, this function doesn't wait for it. */
static void handle_channel_modes_query(int fd, struct bridge *br, bool br_connected,
                                        const char *nick, const struct grappa_session *sess,
                                        const struct irc_message *msg) {
    const char *channel = msg->params[0];
    size_t idx = find_channel_index(sess, channel);
    if (idx != sess->channel_count && sess->channel_mode_str[idx][0]) {
        if (sess->channel_mode_params[idx][0])
            send_line(fd, ":%s 324 %s %s %s %s", IRCD_SERVER, nick, channel,
                      sess->channel_mode_str[idx], sess->channel_mode_params[idx]);
        else
            send_line(fd, ":%s 324 %s %s %s", IRCD_SERVER, nick, channel,
                      sess->channel_mode_str[idx]);
        return;
    }

    if (!br_connected) return;
    char esc_channel[300];
    json_escape_into(channel, esc_channel, sizeof(esc_channel));
    char payload[700];
    snprintf(payload, sizeof(payload), "{\"network_id\":%ld,\"target\":\"%s\",\"modes\":\"\",\"params\":[]}",
             sess->network_id, esc_channel);
    if (!push_on_user_topic(br, sess, "mode", payload))
        fprintf(stderr, "bicchierino: MODE %s (query): push failed\n", channel);
}

/* One already-parsed Phase 2 client line. Returns true if the client
 * asked to end the connection (QUIT) — the poll() loop below treats
 * that exactly like EOF/a read error, both fold into the same
 * `cleanup:` path. */
/* `br_connected` is a POINTER here, unlike every handler it calls into
 * (which still take it by value, read-only) — this is the one function
 * on the call path from `connection_run`'s Phase 2 loop down to
 * `handle_grappa_network`, and Case B's `GRAPPA NETWORK <slug>` (handled
 * right here, still mid-registration) is the one place besides
 * `connection_run`'s own bootstrap that can transition the bridge from
 * down to up — the loop's own `br_connected` local must see that
 * transition on the very next iteration, not just within this call. */
static bool handle_irc_line(int fd, struct http_client *hc, struct bridge *br, bool *br_connected,
                             const struct config *cfg, const struct registration *reg,
                             struct irc_message *msg, struct grappa_session *sess) {
    if (strcmp(msg->command, "PING") == 0) {
        send_line(fd, ":%s PONG %s :%s", IRCD_SERVER, IRCD_SERVER,
                  msg->param_count > 0 ? msg->params[0] : IRCD_SERVER);
        return false;
    }
    if (strcmp(msg->command, "QUIT") == 0) return true;

    if (!sess->network_resolved) {
        if (strcmp(msg->command, "GRAPPA") == 0 && msg->param_count >= 2 &&
            strcasecmp(msg->params[0], "NETWORK") == 0) {
            handle_grappa_network(fd, hc, br, br_connected, reg->nick, cfg, msg, sess);
        } else {
            send_network_reminder(fd, reg->nick, sess);
        }
        return false;
    }

    if (strcmp(msg->command, "PRIVMSG") == 0 && msg->param_count >= 2) {
        send_privmsg_rest(hc, cfg, sess, msg->params[0], msg->params[1]);
        return false;
    }
    if (strcmp(msg->command, "JOIN") == 0) {
        handle_join(fd, hc, br, *br_connected, cfg, sess->network_nick, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "PART") == 0) {
        handle_part(fd, hc, br, *br_connected, cfg, sess->network_nick, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "TOPIC") == 0) {
        handle_topic(hc, br, *br_connected, cfg, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "AWAY") == 0) {
        handle_away(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "MODE") == 0) {
        /* `MODE #chan b` (bare, no +/-) is the wire form of a /banlist
         * query — needs the dedicated priming verb, not the generic
         * "mode" push. See handle_banlist's own doc. */
        char folded_target[128], folded_own[64];
        ascii_fold_lower(msg->param_count >= 1 ? msg->params[0] : "", folded_target,
                          sizeof(folded_target));
        ascii_fold_lower(sess->network_nick, folded_own, sizeof(folded_own));
        if (msg->param_count == 1 && msg->params[0][0] == '#')
            handle_channel_modes_query(fd, br, *br_connected, sess->network_nick, sess, msg);
        else if (msg->param_count == 2 && msg->params[0][0] == '#' &&
                 strcmp(msg->params[1], "b") == 0)
            handle_banlist(br, *br_connected, sess, msg);
        else if (msg->param_count >= 2 && msg->params[0][0] != '#' && folded_own[0] &&
                 strcmp(folded_target, folded_own) == 0)
            handle_umode(br, *br_connected, sess, msg);
        else
            handle_mode(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "KICK") == 0) {
        handle_kick(br, *br_connected, sess->network_nick, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "INVITE") == 0) {
        handle_invite(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "OPER") == 0) {
        handle_oper(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "WHOIS") == 0) {
        handle_whois(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "WHO") == 0) {
        handle_who(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "NAMES") == 0) {
        handle_names(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "LINKS") == 0) {
        handle_links(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "WHOWAS") == 0) {
        handle_whowas(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "LUSERS") == 0) {
        handle_lusers(br, *br_connected, sess, msg);
        return false;
    }
    if (strcmp(msg->command, "INFO") == 0) {
        handle_info_cmd(br, *br_connected, sess);
        return false;
    }
    if (strcmp(msg->command, "VERSION") == 0) {
        handle_version_cmd(br, *br_connected, sess);
        return false;
    }
    if (strcmp(msg->command, "MOTD") == 0) {
        handle_motd_cmd(br, *br_connected, sess, msg);
        return false;
    }

    /* Catch-all: anything else — a bare `/quote` line, services
     * commands, ... — goes out via grappa's own RAW escape hatch
     * instead of being silently dropped. See handle_raw's own doc for
     * why this has to be a fallback, not a dedicated handler per
     * command: every verb above whose reply needs a PRIMED accumulator
     * (see handle_whois's doc) is carved out first — RAW alone would
     * get the request upstream but the reply would have nowhere to
     * render. */
    handle_raw(br, *br_connected, sess, msg);
    return false;
}

/* Builds `nick!user@host`, falling back to bicchierino's own placeholder
 * host when the meta doesn't carry a real one (most kinds don't —
 * `Grappa.Scrollback.Meta`'s per-kind table, `meta.ex:68-131`: only
 * `:join`/`:part`/`:quit` ever carry `sender_user`/`sender_host`, and
 * even then only "when present" — both keys or neither, never half). */
static void format_prefix(const json_value *meta, const char *sender, char *out, size_t out_sz) {
    const char *user = meta ? json_string(json_get(meta, "sender_user")) : NULL;
    const char *host = meta ? json_string(json_get(meta, "sender_host")) : NULL;
    if (user && host)
        snprintf(out, out_sz, "%s!%s@%s", sender, user, host);
    else
        snprintf(out, out_sz, "%s!bicchierino@bicchierino", sender);
}

/* The renderable text of a row whose `body` may legitimately be absent.
 * `server_event` is the one kind grappa leaves `body` nullable for
 * (`Scrollback.Message`'s `@body_required_kinds` excludes it, because a
 * catch-all body is a verb-name fallback rather than user-meaningful
 * text), so the catch-all `meta.raw_verb` is the substitute — naming the
 * verb that produced the row beats rendering nothing. */
static const char *row_text(const json_value *message, const json_value *meta) {
    const char *text = NULL;
    if (json_str_req(message, "body", &text)) return text;
    if (meta && json_str_req(meta, "raw_verb", &text)) return text;
    return NULL;
}

/* A row on the synthetic `$server` window, rendered as a NOTICE to our own
 * nick — which is where a real ircd puts these same lines, and the only
 * shape available: `$server` is not a valid IRC target, so no per-kind arm
 * of `handle_grappa_message_event` can render one verbatim.
 *
 * Kind-blind on purpose. Everything grappa files here is a line of server
 * chrome addressed to us — `:notice` rows from `persist_server_notice/2`
 * (connect MOTD, unsolicited INFO/VERSION/ADMIN bursts, 402, and the CP13
 * non-channel NOTICE cluster) and `:server_event` rows from the router
 * fallthrough (KILL, WALLOPS, GLOBOPS, ERROR, CHGHOST, vendor verbs) alike
 * — and a NOTICE is how all of it reaches a client that negotiated no
 * grappa-specific capability. The structured `meta` is deliberately not
 * unpacked: grappa fills `body` with a plain spelling for exactly this
 * reason ("the wire is additive-only — an old client ignores the meta and
 * shows the body").
 *
 * `sender` is `Message.sender_nick/1`: the upstream server's hostname for
 * a server-prefixed line, or the `"*"` sentinel for a prefix-less one.
 * `"*"` is not a usable IRC prefix, and a prefix-less line is one this
 * bridge is speaking on its own behalf anyway, so it becomes IRCD_SERVER. */
static void handle_grappa_server_window_row(int fd, const struct grappa_session *sess,
                                             const char *sender, const json_value *message,
                                             const json_value *meta, long server_time_ms) {
    const char *text = row_text(message, meta);
    if (!text) return;

    const char *prefix = sender && sender[0] && strcmp(sender, "*") != 0 ? sender : IRCD_SERVER;
    const char *target = sess->network_nick[0] ? sess->network_nick : "*";
    send_tagged_line(fd, sess, server_time_ms, ":%s NOTICE %s :%s", prefix, target, text);
}

/* A `"message"` WS event's inner `message` object (WIRE.md §2.5's
 * corrected text — `Scrollback.Wire.message_payload/1`'s wire shape).
 * Per-kind `meta` shapes are `Grappa.Scrollback.Meta`'s own catalogue
 * (`meta.ex:68-131`), read directly rather than guessed. */
static void handle_grappa_message_event(int fd, struct bridge *br, struct grappa_session *sess,
                                         const json_value *message) {
    const char *kind = NULL;
    const char *channel = NULL;
    const char *sender = NULL;
    if (!json_str_req(message, "kind", &kind) || !json_str_req(message, "channel", &channel) ||
        !json_str_req(message, "sender", &sender)) {
        return;
    }
    const json_value *meta = json_get(message, "meta");

    /* `server_time` is a non-optional field on EVERY kind sharing this
     * one wire shape (`Grappa.Scrollback.Wire.to_json/1`, confirmed
     * against the real source, not guessed) — 0 here only means THIS
     * particular payload was malformed/missing it, in which case
     * `send_tagged_line`'s own `now` fallback (its own doc) kicks in
     * rather than tagging with a fabricated zero epoch. Presence isn't
     * otherwise checked (matches this file's own established pattern
     * for a `json_long_opt` caller that only wants the value, e.g.
     * `handle_grappa_links_bundle_event`'s `hopcount`). */
    long server_time_ms = 0;
    json_long_opt(message, "server_time", &server_time_ms, NULL);

    /* Routed by WINDOW before kind: none of the identity/DM/self-echo
     * reasoning below applies to a `$server` row, and its `channel` can
     * never be used as an IRC target. */
    if (strcmp(channel, GRAPPA_SERVER_WINDOW) == 0) {
        handle_grappa_server_window_row(fd, sess, sender, message, meta, server_time_ms);
        return;
    }

    /* Every nick/channel-key identity compare in this codebase mirrors
     * grappa's own rule (its CLAUDE.md: "EVERY server-side nick compare
     * routes through fold... never a bare String.downcase or =="): IRC
     * identity is case-insensitive, and — confirmed live — grappa's own
     * wire is NOT uniformly display-cased either. `sender` is display
     * form (grappa's own docs: nick KEYs fold, "the display stays RAW"),
     * but a DM's `channel` (the own-nick pseudo-channel) IS a channel
     * KEY and grappa folds channel keys AT WRITE TIME ("the folded key
     * IS the display") — so comparing it against `sess->network_nick`
     * unfolded silently never matched. Folding both sides of both
     * compares is the general-case-safe fix, not just a patch for this
     * one observed mismatch. */
    char folded_own_nick[64];
    ascii_fold_lower(sess->network_nick, folded_own_nick, sizeof(folded_own_nick));
    char folded_sender[128];
    ascii_fold_lower(sender, folded_sender, sizeof(folded_sender));
    char folded_channel[512];
    ascii_fold_lower(channel, folded_channel, sizeof(folded_channel));

    /* Our own outbound echo — scoped to specific kinds, NOT applied
     * uniformly (an earlier version of this function did, and that was
     * wrong: a real ircd echoes your OWN mode/kick/topic/nick/quit back
     * to you — that is how a client confirms its own action took
     * effect — the `echo-message` CAP exists ONLY because privmsg/
     * notice/action are the exception, not the rule). So this only
     * fires for:
     *   - privmsg/notice/action: grappa's broadcast has no per-socket
     *     "don't echo to sender" filter, and the IRC client already
     *     knows what it just typed (no `echo-message` CAP negotiated).
     *   - join/part: `handle_join`/`handle_part` already send their own
     *     optimistic echo before this event could ever arrive —
     *     rendering this one too would visibly double the line.
     * kick/mode/topic/quit render UNCONDITIONALLY, sender or not — now
     * that outbound KICK exists (handle_kick), suppressing our own
     * would leave the user with zero confirmation their kick worked,
     * exactly the bug this scoping fixes.
     *
     * `is_self` alone is NOT sufficient for privmsg/notice/action —
     * see the `pending_self_msg_ids` doc on `struct grappa_session`:
     * two simultaneous bicchierino connections sharing one grappa
     * identity both compute `is_self == true` for EITHER connection's
     * own message, which used to mean BOTH suppressed it — real
     * message loss, not just self-echo suppression, found live testing
     * exactly that scenario. The privmsg/notice/action branch below
     * additionally correlates by the message's own `id` before
     * suppressing. */
    bool is_self = folded_own_nick[0] && strcmp(folded_sender, folded_own_nick) == 0;

    char prefix[196];
    format_prefix(meta, sender, prefix, sizeof(prefix));

    if (strcmp(kind, "privmsg") == 0 || strcmp(kind, "notice") == 0 ||
        strcmp(kind, "action") == 0) {
        if (is_self) {
            long id = 0;
            bool has_id = false;
            json_long_opt(message, "id", &id, &has_id);
            /* Correlated by id: this IS my own optimistic echo, from
             * THIS connection — the client already showed it when it
             * was typed, drop the confirmation. NOT correlated: same
             * identity, but a SIBLING connection sent it (see
             * `pending_self_msg_ids`'s own doc on `struct
             * grappa_session`) — genuinely new to THIS connection,
             * must still render, just not necessarily verbatim (see
             * the DM case below). */
            if (has_id && consume_pending_self_id(sess, id)) return;
        }
        const char *body = NULL;
        if (!json_str_req(message, "body", &body)) return;

        /* WIRE.md §5: an incoming DM persists at channel == own nick,
         * with no `dm_with` on the wire at all — `sender` alone names
         * the real peer, so the re-key is exactly this substitution. */
        bool is_incoming_dm = folded_own_nick[0] && strcmp(folded_channel, folded_own_nick) == 0;
        const char *target = is_incoming_dm ? sender : channel;

        /* A SIBLING connection's OUTBOUND DM (is_self, target is a
         * bare peer nick, NOT the incoming-DM re-key case — i.e. we
         * sent this to `channel` from elsewhere) can't be rendered
         * verbatim: a real IRC client routes an incoming PRIVMSG into
         * a query window by its TARGET, not its prefix — a line
         * shaped `:me!... PRIVMSG peer :body` names a target the
         * client never asked about (not its own nick, not a channel
         * it's in), so most clients would just drop it rather than
         * open/update the peer's query window at all. The only way to
         * land it in the RIGHT window on a vanilla IRC client is to
         * fake it as an INCOMING line FROM the peer (so the client
         * opens/updates exactly the query window keyed to that peer,
         * same as a real incoming DM would) and mark the body so a
         * human can tell it was actually SENT by this identity, not
         * received — same convention real multi-client bouncers use
         * for this exact, protocol-level gap (no vanilla IRC wire
         * shape exists for "an outbound message I sent elsewhere").
         * Caught live before ever shipping — a first draft of this fix
         * would have rendered `:me!... PRIVMSG me :body`, which is
         * worse: a real client seeing itself as both prefix AND target
         * would likely open a bogus self-addressed query window. */
        bool is_sibling_dm = is_self && channel[0] != '#' && !is_incoming_dm;
        char sibling_prefix[196];
        const char *effective_prefix = prefix;
        if (is_sibling_dm) {
            snprintf(sibling_prefix, sizeof(sibling_prefix), "%s!bicchierino@bicchierino", channel);
            effective_prefix = sibling_prefix;
            target = sess->network_nick;
        }

        /* `body` for kind=="action" already carries the RAW CTCP
         * `\x01ACTION <text>\x01` frame verbatim — confirmed against
         * grappa's own persist path (`event_router.ex`'s
         * `privmsg_default/3` hands `body` to `build_persist`
         * unmodified regardless of kind; `CTCP.action?/1` classifies
         * without stripping). Re-wrapping it in ANOTHER `\x01ACTION
         * ... \x01` here (the bug this replaces, found live: irssi
         * showed `* OtherUser \x01ACTION accarezza cdc\x01\x01` as
         * literal text — irssi stripped the OUTER frame and displayed
         * the un-stripped INNER one, each `\x01` rendered as a bare
         * `A` via irssi's own control-picture convention) double-frames
         * it. So `action`, like `privmsg`/`notice`, sends `body`
         * verbatim — the framing is already there; CTCP always rides a
         * PRIVMSG (never NOTICE), matching the wire convention. */
        char body_with_marker[900];
        const char *effective_body = body;
        if (is_sibling_dm) {
            if (strcmp(kind, "action") == 0) {
                /* The marker must land INSIDE the CTCP frame, right
                 * after "ACTION ", not in front of the whole string —
                 * `\x01` has to stay the very first byte or the client
                 * won't recognize this as CTCP at all. */
                static const char action_prefix[] = "\x01""ACTION ";
                size_t prefix_len = sizeof(action_prefix) - 1;
                if (strncmp(body, action_prefix, prefix_len) == 0) {
                    snprintf(body_with_marker, sizeof(body_with_marker), "%.*s<%s> %s",
                             (int)prefix_len, body, sess->network_nick, body + prefix_len);
                    effective_body = body_with_marker;
                }
            } else {
                snprintf(body_with_marker, sizeof(body_with_marker), "<%s> %s",
                         sess->network_nick, body);
                effective_body = body_with_marker;
            }
        }

        const char *verb = strcmp(kind, "notice") == 0 ? "NOTICE" : "PRIVMSG";
        send_tagged_line(fd, sess, server_time_ms, ":%s %s %s :%s", effective_prefix, verb, target,
                          effective_body);
        return;
    }

    if (strcmp(kind, "join") == 0) {
        if (is_self) return;
        send_tagged_line(fd, sess, server_time_ms, ":%s JOIN :%s", prefix, channel);
        return;
    }

    if (strcmp(kind, "part") == 0) {
        if (is_self) return;
        const char *reason = NULL;
        json_str_opt(message, "body", &reason);
        if (reason)
            send_tagged_line(fd, sess, server_time_ms, ":%s PART %s :%s", prefix, channel, reason);
        else
            send_tagged_line(fd, sess, server_time_ms, ":%s PART %s", prefix, channel);
        return;
    }

    if (strcmp(kind, "quit") == 0) {
        const char *reason = NULL;
        json_str_opt(message, "body", &reason);
        if (reason)
            send_tagged_line(fd, sess, server_time_ms, ":%s QUIT :%s", prefix, reason);
        else
            send_tagged_line(fd, sess, server_time_ms, ":%s QUIT", prefix);
        return;
    }

    if (strcmp(kind, "nick_change") == 0) {
        const char *new_nick = NULL;
        if (!meta || !json_str_req(meta, "new_nick", &new_nick)) return;
        send_tagged_line(fd, sess, server_time_ms, ":%s NICK :%s", prefix, new_nick);
        /* Our own rename (client-initiated, or from another bouncer
         * front-end sharing this account — cicchetto, shottino). The
         * prefix above correctly names the OLD nick (standard IRC: a
         * NICK line's prefix is always the pre-change identity), but
         * `sess->network_nick` — the one thing this codebase treats as
         * "our current nick" for self-detection AND every client-facing
         * numeric from here on — must move to the new value NOW, or
         * every later numeric keeps addressing a nick this client no
         * longer believes is its own (some clients silently resync
         * their OWN idea of "my nick" from a numeric's target field the
         * moment it stops matching what they last set via NICK/001 —
         * meaning a stale target here doesn't just look wrong, it can
         * make the client and bicchierino disagree about the nick a
         * SECOND time, compounding instead of just being cosmetic), and
         * `is_self` detection on every later event would start
         * comparing against the wrong value, silently un-recognizing
         * our own future echoes.
         *
         * The DM-listener topic is ALSO keyed by our folded nick in its
         * path (`grappa:user:{subject}/network:{net}/channel:{own-nick
         * folded}`, WIRE.md §5) — joined ONCE at bootstrap and never
         * revisited otherwise. Left un-rejoined, incoming DMs would
         * silently stop arriving after a self rename (same ASCII-fold
         * mechanism as §5.5: Phoenix.PubSub does exact string matching,
         * no error, just nothing ever arrives on the stale topic). The
         * LEAVE here is safe to do inline (fire-and-forget push, never
         * blocks) — the matching JOIN under the new folded nick is
         * deliberately NOT done here; see `dm_needs_rejoin`'s own doc
         * on `struct grappa_session` for why a blocking `bridge_join`
         * from inside THIS call chain is unsafe. */
        if (is_self) {
            if (br && sess->dm_joined) {
                char old_dm_topic[512];
                snprintf(old_dm_topic, sizeof(old_dm_topic), "grappa:user:%s/network:%s/channel:%s",
                         sess->subject_name, sess->network_slug, folded_sender);
                bridge_push(br, old_dm_topic, sess->dm_join_ref, "phx_leave", "{}");
                sess->dm_joined = false;
                sess->dm_needs_rejoin = true;
            }
            snprintf(sess->network_nick, sizeof(sess->network_nick), "%s", new_nick);
        }
        return;
    }

    if (strcmp(kind, "mode") == 0) {
        const char *modes = NULL;
        if (!meta || !json_str_req(meta, "modes", &modes)) return;
        const json_value *args = json_get(meta, "args");

        char argline[300] = "";
        size_t argline_len = 0;
        size_t argc = args && json_type_of(args) == JSON_ARRAY ? json_len(args) : 0;
        for (size_t i = 0; i < argc; i++) {
            const char *arg = json_string(json_at(args, i));
            if (!arg) continue;
            int written = snprintf(argline + argline_len, sizeof(argline) - argline_len, " %s",
                                    arg);
            if (written > 0 && (size_t)written < sizeof(argline) - argline_len)
                argline_len += (size_t)written;
        }
        send_tagged_line(fd, sess, server_time_ms, ":%s MODE %s %s%s", prefix, channel, modes,
                          argline);
        return;
    }

    if (strcmp(kind, "kick") == 0) {
        const char *target = NULL;
        if (!meta || !json_str_req(meta, "target", &target)) return;
        const char *reason = NULL;
        json_str_opt(message, "body", &reason);
        if (reason)
            send_tagged_line(fd, sess, server_time_ms, ":%s KICK %s %s :%s", prefix, channel,
                              target, reason);
        else
            send_tagged_line(fd, sess, server_time_ms, ":%s KICK %s %s", prefix, channel, target);
        return;
    }

    if (strcmp(kind, "topic") == 0) {
        const char *text = NULL;
        if (!json_str_req(message, "body", &text)) return;
        send_tagged_line(fd, sess, server_time_ms, ":%s TOPIC %s :%s", prefix, channel, text);
        return;
    }

    if (strcmp(kind, "server_event") == 0) {
        /* The channel-scoped half of the catch-all — the `$server`-scoped
         * half never reaches here, intercepted above. Same reasoning as
         * `handle_grappa_server_window_row`: `body` is a legible line by
         * construction, so a NOTICE on the channel it belongs to beats
         * discarding the row. Not a PRIVMSG: nobody said this. */
        const char *text = row_text(message, meta);
        if (!text) return;
        send_tagged_line(fd, sess, server_time_ms, ":%s NOTICE %s :%s", prefix, channel, text);
        return;
    }

    /* Anything future/unrecognized — no render yet. */
}

/* WIRE.md §3/§6: `topic_changed` payload is `{kind, network, channel,
 * topic: {text, set_by, set_at}}` (`Session.Wire.topic_changed/3`,
 * `lib/grappa/session/wire.ex:905-915`). Only rendered when a topic is
 * actually SET — a real ircd sends nothing (or 331 RPL_NOTOPIC, not
 * implemented) rather than an empty 332. `set_by`/`set_at` would drive
 * 333 RPL_TOPICWHOTIME, skipped for now: `set_at` is an ISO8601 string
 * on the wire and there's no date parser in this codebase to turn it
 * into the unix timestamp 333 wants — TODO(next) if it's worth adding
 * one for a single numeric. */
/* True (Gregorian, proleptic for y<1970) UTC day count since the epoch
 * via a plain year-by-year loop — deliberately not a closed-form
 * leap-day formula (easy to get off-by-one on) and not `timegm()`
 * (a glibc/BSD extension, not exposed under this project's
 * `_POSIX_C_SOURCE=200809L` without pulling in `_DEFAULT_SOURCE` too).
 * grappa timestamps are always recent, so the loop is at most a few
 * dozen iterations — irrelevant cost for an event that fires once per
 * topic change, not a hot path. */
static bool is_leap_year(int year) {
    return (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
}

static time_t utc_to_unix(int year, int mon, int day, int hour, int min, int sec) {
    static const int cumulative_days[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};
    long days = 0;
    if (year >= 1970) {
        for (int y = 1970; y < year; y++) days += is_leap_year(y) ? 366 : 365;
    } else {
        for (int y = year; y < 1970; y++) days -= is_leap_year(y) ? 366 : 365;
    }
    days += cumulative_days[mon - 1];
    if (mon > 2 && is_leap_year(year)) days += 1;
    days += day - 1;
    return (time_t)(((days * 24L + hour) * 60L + min) * 60L + sec);
}

/* grappa's `set_at` is an ISO8601 string, always UTC (`Z` suffix) — the
 * wire projection of an Elixir `DateTime.t()` (`Session.Wire`'s own
 * doc, `wire.ex:212-218`). Fractional seconds and the trailing `Z` are
 * simply left unconsumed by `sscanf`'s format string — 333
 * RPL_TOPICWHOTIME wants whole unix seconds, sub-second precision
 * would be discarded anyway. */
static bool parse_iso8601_utc_epoch(const char *s, long *out) {
    int year, mon, day, hour, min, sec;
    if (sscanf(s, "%d-%d-%dT%d:%d:%d", &year, &mon, &day, &hour, &min, &sec) != 6) return false;
    if (mon < 1 || mon > 12 || day < 1 || day > 31) return false;
    *out = (long)utc_to_unix(year, mon, day, hour, min, sec);
    return true;
}

/* WIRE.md §3/§6: `topic` is `{text, set_by, set_at}` (`topic_entry_wire`,
 * `wire.ex:220-224`) — `set_by`/`set_at` were read only for a nil-check
 * on `text` before; now also feed 333 RPL_TOPICWHOTIME (`<channel>
 * <setter> <unix-epoch>`), sent right after 332 when BOTH are present
 * (an older/incomplete topic row can have `text` but no recorded
 * setter/time — 333 is skipped rather than sent with a fabricated
 * value, same "never send things that are not true" posture as every
 * other numeric in this codebase). This was the one previously-deferred
 * "smaller gap" that needed real work (an ISO8601-to-epoch converter),
 * not just wiring — see `parse_iso8601_utc_epoch`/`utc_to_unix` above. */
static void handle_grappa_topic_changed_event(int fd, const char *nick,
                                               const json_value *payload) {
    const char *channel = NULL;
    if (!json_str_req(payload, "channel", &channel)) return;
    const json_value *topic = json_get(payload, "topic");
    const char *text = topic ? json_string(json_get(topic, "text")) : NULL;
    if (!text) return;
    send_line(fd, ":%s 332 %s %s :%s", IRCD_SERVER, nick, channel, text);

    const char *set_by = topic ? json_string(json_get(topic, "set_by")) : NULL;
    const char *set_at = topic ? json_string(json_get(topic, "set_at")) : NULL;
    long epoch = 0;
    if (set_by && set_at && parse_iso8601_utc_epoch(set_at, &epoch))
        send_line(fd, ":%s 333 %s %s %s %ld", IRCD_SERVER, nick, channel, set_by, epoch);
}

/* WIRE.md §3/§6: `channel_modes_changed` payload is `{kind, network,
 * channel, modes: {modes: [letters...], params: {letter => value|null}}}`
 * (`Session.Wire.channel_modes_changed/3`, `wire.ex:925-935`) — a FULL
 * current-state snapshot, not a delta (no "who changed what" — that's a
 * separate, not-yet-handled `message` kind). Rendered as 324
 * RPL_CHANNELMODEIS (the numeric for "here is the current mode state"),
 * not a live `MODE` line — a `MODE` line implies a just-happened change
 * with an actor, which this payload doesn't carry. Real clients
 * (irssi/weechat) handle repeated 324 pushes fine.
 *
 * Also CACHES `mode_str`/`param_str` into `sess->channel_mode_str`/
 * `channel_mode_params` (parallel to `sess->channels[]`) — this is the
 * ONLY place that snapshot state ever gets refreshed (both the
 * after-join snapshot and every live update flow through here), and a
 * bare `MODE #chan` query answers directly from this cache instead of
 * round-tripping to grappa. */
static void handle_grappa_channel_modes_changed_event(int fd, const char *nick,
                                                        struct grappa_session *sess,
                                                        const json_value *payload) {
    const char *channel = NULL;
    if (!json_str_req(payload, "channel", &channel)) return;
    const json_value *modes_obj = json_get(payload, "modes");
    const json_value *modes_arr = modes_obj ? json_get(modes_obj, "modes") : NULL;
    const json_value *params_obj = modes_obj ? json_get(modes_obj, "params") : NULL;
    if (!modes_arr || json_type_of(modes_arr) != JSON_ARRAY) return;

    char mode_str[64] = "+";
    size_t mode_len = 1;
    char param_str[400] = "";
    size_t param_len = 0;

    size_t count = json_len(modes_arr);
    for (size_t i = 0; i < count; i++) {
        const char *letter = json_string(json_at(modes_arr, i));
        if (!letter || !letter[0] || mode_len + 1 >= sizeof(mode_str)) continue;
        mode_str[mode_len++] = letter[0];
        mode_str[mode_len] = '\0';

        const char *value = params_obj ? json_string(json_get(params_obj, letter)) : NULL;
        if (value) {
            int written = snprintf(param_str + param_len, sizeof(param_str) - param_len,
                                    "%s%s", param_len ? " " : "", value);
            if (written > 0 && (size_t)written < sizeof(param_str) - param_len)
                param_len += (size_t)written;
        }
    }

    if (param_len) {
        send_line(fd, ":%s 324 %s %s %s %s", IRCD_SERVER, nick, channel, mode_str, param_str);
    } else {
        send_line(fd, ":%s 324 %s %s %s", IRCD_SERVER, nick, channel, mode_str);
    }

    size_t idx = find_channel_index(sess, channel);
    if (idx != sess->channel_count) {
        snprintf(sess->channel_mode_str[idx], sizeof(sess->channel_mode_str[0]), "%s", mode_str);
        snprintf(sess->channel_mode_params[idx], sizeof(sess->channel_mode_params[0]), "%s",
                 param_str);
    }
}

/* WIRE.md §3/§6: `members_seeded` payload is `{kind, network, channel,
 * members: [{nick, modes: [letters...]}, ...]}` (already sorted server-
 * side, `Session.Wire.members_seeded/3`, `wire.ex:975-992` — its own doc
 * names 366 RPL_ENDOFNAMES as the intended consumer). Rendered as the
 * classic 353/366 pair. A member's `modes` can carry more than one
 * letter (e.g. op AND voice); IRC's own NAMES convention shows only the
 * SINGLE highest-ranked prefix sigil per nick, so this picks the first
 * match against our own advertised PREFIX order (005: `(ohv)@%+`) —
 * hardcoded to match, not derived from the not-yet-consumed
 * `isupport_changed` event. Chunked at a conservative 20 nicks per 353
 * line — real IRC bounds lines at 512 bytes, not a nick count, but
 * bicchierino doesn't yet track how much of that budget the prefix
 * eats, and 20 nicks is comfortably under it for any realistic nick
 * length. Always announces channel-type `=` (public) — bicchierino
 * doesn't track a channel's secret/private state. */
static void render_names_353_366(int fd, const char *nick, const char *channel,
                                  const json_value *members) {
    size_t count = json_len(members);
    char line[480] = "";
    size_t line_len = 0;
    size_t in_line = 0;

    for (size_t i = 0; i < count; i++) {
        const json_value *m = json_at(members, i);
        const char *mnick = NULL;
        if (!json_str_req(m, "nick", &mnick)) continue;

        /* `modes[0]` is ALREADY the raw prefix SIGIL character (`@`/`%`/
         * `+`), not a mode letter (`o`/`h`/`v`) — confirmed reading
         * grappa's own `split_mode_prefix/1`
         * (`event_router.ex:2908-2912`), which builds this exact array
         * straight from a 353 RPL_NAMREPLY token's leading byte
         * (`<<prefix, rest::binary>> when prefix in [?@, ?%, ?+] ->
         * {rest, [<<prefix>>]}`) — it never translates to a letter at
         * all. An earlier version of this function assumed letters
         * (matching WHO's own `modes` field, which genuinely IS
         * letters — a different event, different shape, same field
         * name) and so never matched anything, silently dropping every
         * sigil — found live: `TestUser`, a confirmed real op in
         * `#testchannel` (per WHOIS's own 319 channel list showing
         * `@#testchannel`), rendered with no `@` in `/names` at all. At
         * most one element (grappa/bahamut send a single leading
         * sigil per NAMES token, never a multi-prefix `@+nick` form —
         * matches this codebase not advertising `multi-prefix`
         * either), so just read it directly; still validated against
         * the known sigil set rather than trusted blindly. */
        char sigil = '\0';
        const json_value *modes = json_get(m, "modes");
        if (modes && json_type_of(modes) == JSON_ARRAY && json_len(modes) > 0) {
            const char *first = json_string(json_at(modes, 0));
            if (first && (first[0] == '@' || first[0] == '%' || first[0] == '+')) sigil = first[0];
        }

        char token[80];
        if (sigil)
            snprintf(token, sizeof(token), "%c%s", sigil, mnick);
        else
            snprintf(token, sizeof(token), "%s", mnick);

        size_t token_len = strlen(token);
        size_t needed = token_len + (in_line ? 1 : 0);
        if (in_line && (in_line >= 20 || line_len + needed >= sizeof(line))) {
            send_line(fd, ":%s 353 %s = %s :%s", IRCD_SERVER, nick, channel, line);
            line[0] = '\0';
            line_len = 0;
            in_line = 0;
        }

        int written = snprintf(line + line_len, sizeof(line) - line_len, "%s%s",
                                in_line ? " " : "", token);
        if (written > 0 && (size_t)written < sizeof(line) - line_len) {
            line_len += (size_t)written;
            in_line++;
        }
    }
    if (line_len) send_line(fd, ":%s 353 %s = %s :%s", IRCD_SERVER, nick, channel, line);

    send_line(fd, ":%s 366 %s %s :End of /NAMES list", IRCD_SERVER, nick, channel);
}

static void handle_grappa_members_seeded_event(int fd, const char *nick,
                                                const json_value *payload) {
    const char *channel = NULL;
    if (!json_str_req(payload, "channel", &channel)) return;
    const json_value *members = json_get(payload, "members");
    if (!members || json_type_of(members) != JSON_ARRAY) return;
    render_names_353_366(fd, nick, channel, members);
}

/* WIRE.md §3/§6: `isupport_changed` payload is `{kind, network_id,
 * chanmodes_a..d: [letters...], prefix: {letter => sigil}}`
 * (`Session.Wire.isupport_changed/2`, `wire.ex:113-131`) — the LIVE
 * values behind the pre-005 fallback `send_welcome` sends at
 * registration (`ISupport.default/0`, only right for a bahamut-shaped
 * network). Re-sends a corrected 005 whenever this arrives — pushed on
 * EVERY channel-shaped topic join (confirmed live: once per channel,
 * again for the DM-listener topic), so a session with several channels
 * re-announces 005 more than once; harmless, real clients (irssi/
 * weechat) handle a repeated 005 fine, and there is no cheap way from
 * this event alone to tell "genuinely changed" from "same value, next
 * topic's snapshot" — CHANTYPES/CASEMAPPING/STATUSMSG stay
 * bicchierino's own fallback values verbatim: confirmed directly
 * against `ISupport.t/0` that only `chanmodes`/`prefix` reach this wire
 * event at all — `casemapping`/`statusmsg` are tracked server-side but
 * never exposed here, so there is nothing live to prefer over the
 * fallback for those three tokens.
 *
 * Sent only ONCE per connection (`sess->isupport_005_sent`) — see its
 * own doc on `struct grappa_session`: with the DM-peer-topic fix a
 * normal session now joins many more channel-shaped topics, each
 * pushing this same event, and re-announcing an identical 005 that
 * many times over is pure noise a real client gains nothing from. */
static void handle_grappa_isupport_changed_event(int fd, const char *nick,
                                                   struct grappa_session *sess,
                                                   const json_value *payload) {
    if (sess->isupport_005_sent) return;

    const json_value *groups[4] = {
        json_get(payload, "chanmodes_a"),
        json_get(payload, "chanmodes_b"),
        json_get(payload, "chanmodes_c"),
        json_get(payload, "chanmodes_d"),
    };
    const json_value *prefix = json_get(payload, "prefix");
    if (!groups[0] || !groups[1] || !groups[2] || !groups[3] || !prefix) return;

    char chanmodes[128];
    size_t cm_len = 0;
    for (int g = 0; g < 4; g++) {
        if (g > 0 && cm_len + 1 < sizeof(chanmodes)) chanmodes[cm_len++] = ',';
        if (json_type_of(groups[g]) != JSON_ARRAY) continue;
        size_t n = json_len(groups[g]);
        for (size_t i = 0; i < n && cm_len + 1 < sizeof(chanmodes); i++) {
            const char *letter = json_string(json_at(groups[g], i));
            if (letter && letter[0]) chanmodes[cm_len++] = letter[0];
        }
    }
    chanmodes[cm_len] = '\0';

    /* PREFIX priority: the well-known letters first, in their canonical
     * rank (o > h > v — the only ranks bahamut/azzurra uses, matching
     * the fallback this corrects). Any OTHER letter the object happens
     * to carry is appended afterward in whatever order the wire gave
     * it — Elixir map iteration order is NOT insertion-order-stable, so
     * there is no reliable rank signal for an unrecognized letter
     * beyond "lower than the known ones". */
    static const char well_known[] = {'o', 'h', 'v'};
    char letters[32];
    char sigils[32];
    size_t ll = 0, sl = 0;
    for (size_t k = 0; k < sizeof(well_known); k++) {
        char key[2] = {well_known[k], '\0'};
        const char *sigil = json_string(json_get(prefix, key));
        if (!sigil || !sigil[0]) continue;
        if (ll + 1 < sizeof(letters)) letters[ll++] = well_known[k];
        if (sl + 1 < sizeof(sigils)) sigils[sl++] = sigil[0];
    }
    size_t pcount = json_len(prefix);
    for (size_t i = 0; i < pcount; i++) {
        const char *letter = json_key_at(prefix, i);
        if (!letter || !letter[0]) continue;
        bool known = false;
        for (size_t k = 0; k < sizeof(well_known); k++)
            if (letter[0] == well_known[k]) known = true;
        if (known) continue;
        const char *sigil = json_string(json_value_at(prefix, i));
        if (!sigil || !sigil[0]) continue;
        if (ll + 1 < sizeof(letters)) letters[ll++] = letter[0];
        if (sl + 1 < sizeof(sigils)) sigils[sl++] = sigil[0];
    }
    letters[ll] = '\0';
    sigils[sl] = '\0';

    send_line(fd,
              ":%s 005 %s CHANTYPES=# PREFIX=(%s)%s CHANMODES=%s CASEMAPPING=ascii "
              "STATUSMSG=@+ :are supported by this server",
              IRCD_SERVER, nick, letters, sigils, chanmodes);
    sess->isupport_005_sent = true;
}

/* WIRE.md §3/§6: `join_failed` payload is `{kind, network, channel,
 * state: :failed, reason: string|nil, numeric: pos_integer|nil}`
 * (`Session.Wire`, `wire.ex:379-386`) — the correction for
 * `handle_join`'s own OPTIMISTIC echo: a REST `202` only means
 * "accepted, :pending window opened" (WIRE.md §2.5), not "succeeded",
 * so the client may already believe it's in a channel it never actually
 * joined (banned, +i, +k mismatch, ...). Real bouncers (irssi-proxy,
 * ZNC) handle exactly this the same way: send the real numeric if one
 * came back, else a NOTICE, THEN a synthetic PART so a well-behaved
 * client corrects its own channel list — and remove the channel from
 * `sess->channels[]` here too, or a retried JOIN after the fix would
 * wrongly believe it's already joined (skipping both the tracking add
 * and the per-channel WS topic join `handle_join` would otherwise do). */
static void handle_grappa_join_failed_event(int fd, const char *nick, struct grappa_session *sess,
                                             const json_value *payload) {
    const char *channel = NULL;
    if (!json_str_req(payload, "channel", &channel)) return;

    const char *reason = NULL;
    json_str_opt(payload, "reason", &reason);
    long numeric = 0;
    bool has_numeric = false;
    json_long_opt(payload, "numeric", &numeric, &has_numeric);

    size_t idx = find_channel_index(sess, channel);
    if (idx != sess->channel_count) remove_channel_at(sess, idx);

    if (has_numeric)
        send_line(fd, ":%s %ld %s %s :%s", IRCD_SERVER, numeric, nick, channel,
                  reason ? reason : "Cannot join channel");
    else
        send_line(fd, ":%s NOTICE %s :Could not join %s%s%s", IRCD_SERVER, nick, channel,
                  reason ? ": " : "", reason ? reason : "");

    send_line(fd, ":%s!bicchierino@bicchierino PART %s :join failed", nick, channel);
}

/* WIRE.md §3/§6: `umode_changed` payload is `{kind, network_id, modes:
 * [letters...]}` (`Session.Wire.umode_changed/2`, `wire.ex:143-152`) —
 * the reply/confirmation counterpart to the `"umode"` push
 * (`handle_umode`). Unlike channel `mode`'s own live-activity event
 * (`kind: "mode"`, carries an explicit +/- delta + actor), THIS is an
 * ABSOLUTE snapshot of the full active set, no actor, no delta — grappa
 * itself doesn't track who triggered a umode change or which letters
 * were added vs removed, only the resulting set. Rendered as the best
 * honest approximation available: a self MODE line adding every letter
 * in the snapshot (`+letters`) — not necessarily byte-accurate if the
 * real change REMOVED a mode (unrepresentable from a snapshot alone),
 * but never asserts a mode that isn't actually active, matching the
 * same "never send things that are not true" posture as the 005 fix. */
static void handle_grappa_umode_changed_event(int fd, const struct grappa_session *sess,
                                               const char *nick, const json_value *payload) {
    const json_value *modes = json_get(payload, "modes");
    if (!modes || json_type_of(modes) != JSON_ARRAY) return;

    char letters[64] = "";
    size_t len = 0;
    size_t count = json_len(modes);
    for (size_t i = 0; i < count; i++) {
        const char *letter = json_string(json_at(modes, i));
        if (!letter || !letter[0]) continue;
        int written = snprintf(letters + len, sizeof(letters) - len, "%s", letter);
        if (written > 0 && (size_t)written < sizeof(letters) - len) len += (size_t)written;
    }
    if (!len) return;

    /* No persisted timestamp for this event (unlike
     * `handle_grappa_message_event`'s kinds) — `send_tagged_line`'s own
     * `now` fallback (`server_time_ms <= 0`) applies. */
    send_tagged_line(fd, sess, 0, ":%s!bicchierino@bicchierino MODE %s :+%s", nick, nick, letters);
}

/* WIRE.md §6: `away_confirmed` payload is `{kind, network, state:
 * "present"|"away"}` (`away_confirmed_payload`, `wire.ex:397-401`) —
 * broadcast on the user topic (`Broadcaster.to_user`), fired for BOTH
 * the explicit `AWAY :<reason>`/`AWAY` verb AND grappa's own
 * hidden-socket auto-away transitions (WSPresence) — a real client
 * seeing an unprompted 305/306 mid-session (no AWAY it sent) is
 * expected, not a bug: it means the LAST cicchetto/bicchierino/shottino
 * socket for this account just went hidden or came back. */
static void handle_grappa_away_confirmed_event(int fd, const char *nick,
                                                const json_value *payload) {
    const char *state = NULL;
    if (!json_str_req(payload, "state", &state)) return;
    if (strcmp(state, "away") == 0)
        send_line(fd, ":%s 306 %s :You have been marked as being away", IRCD_SERVER, nick);
    else if (strcmp(state, "present") == 0)
        send_line(fd, ":%s 305 %s :You are no longer marked as being away", IRCD_SERVER, nick);
}

/* `query_windows_list` payload is `{kind, windows: {network_id =>
 * [{network_id, target_nick, opened_at}, ...]}}` (`QueryWindows.Wire.
 * windows_list_payload/1`) — confirmed against the real wire, not
 * guessed (a raw dump showed `{"windows":{"1":[{"target_nick":"RealUser",
 * ...}, ...]}}`, keyed by network_id AS A STRING since JSON object keys
 * are always strings, even though the Elixir side types it as
 * `integer()`). See `dm_peer_names`'s own doc on `struct grappa_session`
 * for why bicchierino needs this at all — this only QUEUES newly-seen
 * peers into `pending_dm_peer_names`; the actual `bridge_join` happens
 * in the Phase 2 main loop, same deferred pattern as `dm_needs_rejoin`,
 * for the same nested-bridge_join hazard (this can run nested inside
 * another `bridge_join`'s wait loop via `bridge_event_dispatch`, e.g.
 * mid-bootstrap — confirmed live). */
static void handle_grappa_query_windows_list_event(struct grappa_session *sess,
                                                     const json_value *payload) {
    char net_key[32];
    snprintf(net_key, sizeof(net_key), "%ld", sess->network_id);
    const json_value *windows = json_get(payload, "windows");
    const json_value *list = json_get(windows, net_key);
    if (!list || json_type_of(list) != JSON_ARRAY) return;

    for (size_t i = 0; i < json_len(list); i++) {
        const json_value *entry = json_at(list, i);
        const char *target_nick = NULL;
        if (!json_str_req(entry, "target_nick", &target_nick)) continue;

        char folded[64];
        ascii_fold_lower(target_nick, folded, sizeof(folded));

        bool known = false;
        for (size_t j = 0; j < sess->dm_peer_count && !known; j++)
            if (strcmp(sess->dm_peer_names[j], folded) == 0) known = true;
        for (size_t j = 0; j < sess->pending_dm_peer_count && !known; j++)
            if (strcmp(sess->pending_dm_peer_names[j], folded) == 0) known = true;
        if (known) continue;

        if (sess->pending_dm_peer_count >= MAX_DM_PEERS) {
            fprintf(stderr, "bicchierino: pending DM peer topics full, dropping %s\n", folded);
            continue;
        }
        snprintf(sess->pending_dm_peer_names[sess->pending_dm_peer_count++],
                 sizeof(sess->pending_dm_peer_names[0]), "%s", folded);
    }
}

/* WIRE.md §3/§6: `names_reply` payload is `{kind, network, channel,
 * members: [{nick, modes: [letters...]}, ...]}` (`Session.Wire.
 * names_reply_payload/0`, `wire.ex:273-278`) — the EXPLICIT `/names`
 * reply, routed on the user topic (not the channel topic
 * `members_seeded` uses) and not persisted. Same per-member shape, so
 * it renders through the identical 353/366 pair via
 * `render_names_353_366`. */
static void handle_grappa_names_reply_event(int fd, const char *nick,
                                             const json_value *payload) {
    const char *channel = NULL;
    if (!json_str_req(payload, "channel", &channel)) return;
    const json_value *members = json_get(payload, "members");
    if (!members || json_type_of(members) != JSON_ARRAY) return;
    render_names_353_366(fd, nick, channel, members);
}

/* WIRE.md §3/§6: `who_reply` payload is `{kind, network, target, users:
 * [{nick, user, host, server, modes, hops, realname, channel}, ...]}`
 * (`Session.Wire.who_reply_payload/0`, `wire.ex:305-310`) — the reply to
 * an explicit `/who`, routed on the user topic, not persisted. `modes`
 * is the raw upstream WHO-flags string (e.g. "H@") — relayed verbatim,
 * not reinterpreted. `hops`/`realname` are nil for an RFC-violating
 * upstream that omits the trailing field; rendered as `0`/"" so the 352
 * line still has the right field count. */
static void handle_grappa_who_reply_event(int fd, const char *nick,
                                           const json_value *payload) {
    const char *target = NULL;
    if (!json_str_req(payload, "target", &target)) return;
    const json_value *users = json_get(payload, "users");
    if (!users || json_type_of(users) != JSON_ARRAY) return;

    size_t count = json_len(users);
    for (size_t i = 0; i < count; i++) {
        const json_value *u = json_at(users, i);
        const char *unick = NULL, *user = NULL, *host = NULL, *server = NULL, *modes = NULL,
                   *realname = NULL, *channel = NULL;
        if (!json_str_req(u, "nick", &unick) || !json_str_req(u, "user", &user) ||
            !json_str_req(u, "host", &host) || !json_str_req(u, "server", &server) ||
            !json_str_req(u, "modes", &modes) || !json_str_req(u, "channel", &channel))
            continue;
        json_str_opt(u, "realname", &realname);
        long hops = 0;
        bool has_hops = false;
        json_long_opt(u, "hops", &hops, &has_hops);
        send_line(fd, ":%s 352 %s %s %s %s %s %s %s :%ld %s", IRCD_SERVER, nick, channel, user,
                  host, server, unick, modes, hops, realname ? realname : "");
    }
    send_line(fd, ":%s 315 %s %s :End of /WHO list", IRCD_SERVER, nick, target);
}

/* WIRE.md §3/§6: `whois_bundle` payload is the aggregated /whois reply
 * (`Session.Wire.whois_bundle_payload/0`, `wire.ex:444-506`) — every
 * field nullable, populated as 311/312/313/317/319 (plus the solanum-only
 * 330/301/671/276 + free-form `extra_lines`) arrive upstream, broadcast
 * whole on 318. Azzurra (bahamut) never fires the solanum-only fields
 * (`account`, `secure*`, `certfp`) or the P-0a boolean flags
 * (`is_admin`/`is_chanop`/...) — those have no dedicated RFC numeric to
 * round-trip through on their own, so they're read from the bundle but
 * not separately rendered here; `extra_lines` (320 + any unhandled
 * WHOIS-leg numeric) already covers verbatim relay of anything a NEWER
 * network fires that this function doesn't special-case. `user == NULL`
 * with nothing else populated is grappa's own "no such nick" shape
 * (`wire.ex:438-440`) — rendered as 401 before the always-sent 318. */
static void handle_grappa_whois_bundle_event(int fd, const char *nick,
                                              const json_value *payload) {
    const char *target = NULL;
    if (!json_str_req(payload, "target", &target)) return;

    const char *user = NULL, *host = NULL, *realname = NULL;
    json_str_opt(payload, "user", &user);
    json_str_opt(payload, "host", &host);
    json_str_opt(payload, "realname", &realname);

    if (!user) {
        send_line(fd, ":%s 401 %s %s :No such nick/channel", IRCD_SERVER, nick, target);
        send_line(fd, ":%s 318 %s %s :End of /WHOIS list", IRCD_SERVER, nick, target);
        return;
    }
    send_line(fd, ":%s 311 %s %s %s %s * :%s", IRCD_SERVER, nick, target, user, host ? host : "*",
              realname ? realname : "");

    const char *server = NULL, *server_info = NULL;
    json_str_opt(payload, "server", &server);
    json_str_opt(payload, "server_info", &server_info);
    if (server)
        send_line(fd, ":%s 312 %s %s %s :%s", IRCD_SERVER, nick, target, server,
                  server_info ? server_info : "");

    bool is_operator = false;
    json_bool_dflt(payload, "is_operator", false, &is_operator);
    if (is_operator) {
        const char *oper_text = NULL;
        json_str_opt(payload, "oper_text", &oper_text);
        send_line(fd, ":%s 313 %s %s :%s", IRCD_SERVER, nick, target,
                  oper_text ? oper_text : "is an IRC operator");
    }

    long idle_seconds = 0;
    bool has_idle = false;
    json_long_opt(payload, "idle_seconds", &idle_seconds, &has_idle);
    if (has_idle) {
        long signon = 0;
        bool has_signon = false;
        json_long_opt(payload, "signon", &signon, &has_signon);
        if (has_signon)
            send_line(fd, ":%s 317 %s %s %ld %ld :seconds idle, signon time", IRCD_SERVER, nick,
                      target, idle_seconds, signon);
        else
            send_line(fd, ":%s 317 %s %s %ld :seconds idle", IRCD_SERVER, nick, target,
                      idle_seconds);
    }

    const json_value *channels = json_get(payload, "channels");
    if (channels && json_type_of(channels) == JSON_ARRAY && json_len(channels) > 0) {
        char line[480] = "";
        size_t line_len = 0;
        size_t count = json_len(channels);
        for (size_t i = 0; i < count; i++) {
            const char *chan = json_string(json_at(channels, i));
            if (!chan) continue;
            int written = snprintf(line + line_len, sizeof(line) - line_len, "%s%s",
                                    line_len ? " " : "", chan);
            if (written > 0 && (size_t)written < sizeof(line) - line_len) line_len += (size_t)written;
        }
        send_line(fd, ":%s 319 %s %s :%s", IRCD_SERVER, nick, target, line);
    }

    const char *account = NULL;
    json_str_opt(payload, "account", &account);
    if (account) send_line(fd, ":%s 330 %s %s %s :is logged in as", IRCD_SERVER, nick, target, account);

    const char *away_message = NULL;
    json_str_opt(payload, "away_message", &away_message);
    if (away_message) send_line(fd, ":%s 301 %s %s :%s", IRCD_SERVER, nick, target, away_message);

    bool secure = false;
    json_bool_dflt(payload, "secure", false, &secure);
    if (secure) {
        const char *cipher = NULL;
        json_str_opt(payload, "secure_cipher", &cipher);
        if (cipher)
            send_line(fd, ":%s 671 %s %s :is using a secure connection [%s]", IRCD_SERVER, nick,
                      target, cipher);
        else
            send_line(fd, ":%s 671 %s %s :is using a secure connection", IRCD_SERVER, nick, target);
    }

    const char *certfp = NULL;
    json_str_opt(payload, "certfp", &certfp);
    if (certfp)
        send_line(fd, ":%s 276 %s %s :has client certificate fingerprint %s", IRCD_SERVER, nick,
                  target, certfp);

    const json_value *extra_lines = json_get(payload, "extra_lines");
    if (extra_lines && json_type_of(extra_lines) == JSON_ARRAY) {
        size_t count = json_len(extra_lines);
        for (size_t i = 0; i < count; i++) {
            const json_value *entry = json_at(extra_lines, i);
            long enumeric = 0;
            const char *etext = NULL;
            if (!json_long_req(entry, "numeric", &enumeric) || !json_str_req(entry, "text", &etext))
                continue;
            send_line(fd, ":%s %ld %s %s :%s", IRCD_SERVER, enumeric, nick, target, etext);
        }
    }

    send_line(fd, ":%s 318 %s %s :End of /WHOIS list", IRCD_SERVER, nick, target);
}

/* WIRE.md §3/§6: `banlist_bundle` payload is `{kind, network, channel,
 * entries: [{mask, setter, set_ts}, ...]}` (`Session.Wire.
 * banlist_bundle_payload/0`, `wire.ex:620-625`) — reply to an explicit
 * `/banlist` (or a raw `MODE #chan b`), routed on the user topic, not
 * persisted. `set_ts` is the raw upstream unix-epoch STRING, relayed
 * verbatim (no localized formatting, per grappa's own
 * no-localized-strings-server-side rule) — a real client renders it
 * itself. `setter`/`set_ts` are nil for an older ircd that sends a bare
 * mask; the 367 line then drops both trailing fields rather than
 * printing an empty placeholder. */
static void handle_grappa_banlist_bundle_event(int fd, const char *nick,
                                                const json_value *payload) {
    const char *channel = NULL;
    if (!json_str_req(payload, "channel", &channel)) return;
    const json_value *entries = json_get(payload, "entries");
    if (!entries || json_type_of(entries) != JSON_ARRAY) return;

    size_t count = json_len(entries);
    for (size_t i = 0; i < count; i++) {
        const json_value *e = json_at(entries, i);
        const char *mask = NULL;
        if (!json_str_req(e, "mask", &mask)) continue;
        const char *setter = NULL, *set_ts = NULL;
        json_str_opt(e, "setter", &setter);
        json_str_opt(e, "set_ts", &set_ts);
        if (setter && set_ts)
            send_line(fd, ":%s 367 %s %s %s %s %s", IRCD_SERVER, nick, channel, mask, setter,
                      set_ts);
        else
            send_line(fd, ":%s 367 %s %s %s", IRCD_SERVER, nick, channel, mask);
    }
    send_line(fd, ":%s 368 %s %s :End of Channel Ban List", IRCD_SERVER, nick, channel);
}

/* WIRE.md §6: `links_bundle` payload is `{kind, network, mask, entries:
 * [{server, linked_to, hopcount, description}]}` (`links_bundle_payload`,
 * `wire.ex:659-664`). Rendered as the classic 364/365 pair — `<server>
 * <linked_to>` matches the real bahamut wire order (`<server> <uplink>
 * :<hops> <info>`); `linked_to` falls back to the server's own name for
 * a root self-link entry (`server == linked_to`, `hopcount == 0`, per
 * the type's own doc) rather than an empty field. `mask` (nil for the
 * bare full-mesh form) becomes `*` in the 365 trailer, matching the
 * real RFC convention for "no mask was given". */
static void handle_grappa_links_bundle_event(int fd, const char *nick, const json_value *payload) {
    const json_value *entries = json_get(payload, "entries");
    if (!entries || json_type_of(entries) != JSON_ARRAY) return;

    size_t count = json_len(entries);
    for (size_t i = 0; i < count; i++) {
        const json_value *e = json_at(entries, i);
        const char *server = NULL, *linked_to = NULL, *description = NULL;
        if (!json_str_req(e, "server", &server)) continue;
        json_str_opt(e, "linked_to", &linked_to);
        json_str_opt(e, "description", &description);
        long hopcount = 0;
        json_long_opt(e, "hopcount", &hopcount, NULL);
        send_line(fd, ":%s 364 %s %s %s :%ld %s", IRCD_SERVER, nick, server,
                  linked_to ? linked_to : server, hopcount, description ? description : "");
    }

    const char *mask = NULL;
    json_str_opt(payload, "mask", &mask);
    send_line(fd, ":%s 365 %s %s :End of /LINKS list", IRCD_SERVER, nick, mask ? mask : "*");
}

/* WIRE.md §6: `whowas_bundle` payload is `{kind, network, target, user,
 * host, realname, server, logoff_time, not_found}`
 * (`whowas_bundle_payload`, `wire.ex:584-594`) — only the MOST RECENT
 * historical entry (multi-entry history is out of scope server-side
 * too, per the type's own doc). `not_found: true` renders 406
 * ERR_WASNOSUCHNICK; otherwise 314 RPL_WHOWASUSER (same shape as 311)
 * plus an optional 312 carrying `server`/`logoff_time` when BOTH are
 * present (real bahamut ships the disconnect time as 312's free-form
 * trailing text, not a separate numeric — relayed verbatim, no
 * parsing). Always ends with 369 RPL_ENDOFWHOWAS regardless. */
static void handle_grappa_whowas_bundle_event(int fd, const char *nick, const json_value *payload) {
    const char *target = NULL;
    if (!json_str_req(payload, "target", &target)) return;

    bool not_found = false;
    json_bool_dflt(payload, "not_found", false, &not_found);
    if (not_found) {
        send_line(fd, ":%s 406 %s %s :There was no such nickname", IRCD_SERVER, nick, target);
        send_line(fd, ":%s 369 %s %s :End of WHOWAS", IRCD_SERVER, nick, target);
        return;
    }

    const char *user = NULL, *host = NULL, *realname = NULL, *server = NULL, *logoff_time = NULL;
    json_str_opt(payload, "user", &user);
    json_str_opt(payload, "host", &host);
    json_str_opt(payload, "realname", &realname);
    json_str_opt(payload, "server", &server);
    json_str_opt(payload, "logoff_time", &logoff_time);

    if (user)
        send_line(fd, ":%s 314 %s %s %s %s * :%s", IRCD_SERVER, nick, target, user,
                  host ? host : "*", realname ? realname : "");
    if (server && logoff_time)
        send_line(fd, ":%s 312 %s %s %s :%s", IRCD_SERVER, nick, target, server, logoff_time);

    send_line(fd, ":%s 369 %s %s :End of WHOWAS", IRCD_SERVER, nick, target);
}

/* WIRE.md §6: `lusers_bundle` payload (`lusers_bundle_payload`,
 * `wire.ex:553-568`) folds bahamut's 7-numeric sequence (251-255,
 * 265-266). Every field is a nullable integer — only 253
 * RPL_LUSERUNKNOWN is DOCUMENTED as commonly absent, but every numeric
 * here is skipped individually when its required value(s) are missing,
 * never rendered with a fabricated 0 or blank. Trailing text on each
 * matches the conventional bahamut/RFC 2812 §5.1 wording — real clients
 * mostly just display it verbatim rather than parsing it. */
static void handle_grappa_lusers_bundle_event(int fd, const char *nick, const json_value *payload) {
    long total_users = 0, invisible = 0, servers = 0, operators = 0, unknown_connections = 0,
         channels_formed = 0, local_clients = 0, local_servers = 0, current_local = 0,
         max_local = 0, current_global = 0, max_global = 0;
    bool has_total = false, has_invisible = false, has_servers = false, has_operators = false,
         has_unknown = false, has_channels = false, has_local_clients = false,
         has_local_servers = false, has_current_local = false, has_max_local = false,
         has_current_global = false, has_max_global = false;
    json_long_opt(payload, "total_users", &total_users, &has_total);
    json_long_opt(payload, "invisible", &invisible, &has_invisible);
    json_long_opt(payload, "servers", &servers, &has_servers);
    json_long_opt(payload, "operators", &operators, &has_operators);
    json_long_opt(payload, "unknown_connections", &unknown_connections, &has_unknown);
    json_long_opt(payload, "channels_formed", &channels_formed, &has_channels);
    json_long_opt(payload, "local_clients", &local_clients, &has_local_clients);
    json_long_opt(payload, "local_servers", &local_servers, &has_local_servers);
    json_long_opt(payload, "current_local", &current_local, &has_current_local);
    json_long_opt(payload, "max_local", &max_local, &has_max_local);
    json_long_opt(payload, "current_global", &current_global, &has_current_global);
    json_long_opt(payload, "max_global", &max_global, &has_max_global);

    if (has_total && has_invisible && has_servers)
        send_line(fd, ":%s 251 %s :There are %ld users and %ld invisible on %ld servers",
                  IRCD_SERVER, nick, total_users, invisible, servers);
    if (has_operators)
        send_line(fd, ":%s 252 %s %ld :operator(s) online", IRCD_SERVER, nick, operators);
    if (has_unknown)
        send_line(fd, ":%s 253 %s %ld :unknown connection(s)", IRCD_SERVER, nick,
                  unknown_connections);
    if (has_channels)
        send_line(fd, ":%s 254 %s %ld :channels formed", IRCD_SERVER, nick, channels_formed);
    if (has_local_clients && has_local_servers)
        send_line(fd, ":%s 255 %s :I have %ld clients and %ld servers", IRCD_SERVER, nick,
                  local_clients, local_servers);
    if (has_current_local && has_max_local)
        send_line(fd, ":%s 265 %s %ld %ld :Current local users %ld, max %ld", IRCD_SERVER, nick,
                  current_local, max_local, current_local, max_local);
    if (has_current_global && has_max_global)
        send_line(fd, ":%s 266 %s %ld %ld :Current global users %ld, max %ld", IRCD_SERVER, nick,
                  current_global, max_global, current_global, max_global);
}

/* WIRE.md §6: `server_reply` payload is `{kind, network, source: "info"|
 * "version"|"motd", lines: [String.t()]}` (`server_reply_payload`,
 * `wire.ex:330-335`) — the shared reply shape for /INFO, /VERSION, and
 * on-demand /MOTD, discriminated by `source`. `lines` are raw upstream
 * trailing text, relayed verbatim (no parsing) — matches the same
 * no-localized-strings posture as every other bundle here. `:info` ->
 * 371/374, `:version` -> 351 per line (VERSION structurally has
 * separate version/server positional fields on a real 351, but this
 * codebase only receives already-flattened trailing text, so each line
 * rides the trailing slot rather than fabricating positional fields
 * grappa never gave it), `:motd` -> 375/372.../376, or 422 when `lines`
 * is empty (no separate not-found flag for MOTD specifically — an empty
 * burst IS the "no MOTD" signal here, mirrored from ERR_NOMOTD's own
 * meaning). */
static void handle_grappa_server_reply_event(int fd, const char *nick, const json_value *payload) {
    const char *source = NULL;
    if (!json_str_req(payload, "source", &source)) return;
    const json_value *lines = json_get(payload, "lines");
    if (!lines || json_type_of(lines) != JSON_ARRAY) return;
    size_t count = json_len(lines);

    if (strcmp(source, "info") == 0) {
        for (size_t i = 0; i < count; i++) {
            const char *line = json_string(json_at(lines, i));
            if (line) send_line(fd, ":%s 371 %s :%s", IRCD_SERVER, nick, line);
        }
        send_line(fd, ":%s 374 %s :End of /INFO list", IRCD_SERVER, nick);
    } else if (strcmp(source, "version") == 0) {
        for (size_t i = 0; i < count; i++) {
            const char *line = json_string(json_at(lines, i));
            if (line) send_line(fd, ":%s 351 %s :%s", IRCD_SERVER, nick, line);
        }
    } else if (strcmp(source, "motd") == 0) {
        if (count == 0) {
            send_line(fd, ":%s 422 %s :MOTD File is missing", IRCD_SERVER, nick);
            return;
        }
        send_line(fd, ":%s 375 %s :- Message of the day -", IRCD_SERVER, nick);
        for (size_t i = 0; i < count; i++) {
            const char *line = json_string(json_at(lines, i));
            if (line) send_line(fd, ":%s 372 %s :- %s", IRCD_SERVER, nick, line);
        }
        send_line(fd, ":%s 376 %s :End of /MOTD command.", IRCD_SERVER, nick);
    }
}

/* One complete WS text frame from the Phase 2 drain loop. `"message"`,
 * `"topic_changed"`, `"channel_modes_changed"`, `"members_seeded"`,
 * `"isupport_changed"`, `"join_failed"`, `"names_reply"`, `"who_reply"`,
 * `"whois_bundle"`, `"banlist_bundle"`, `"umode_changed"`,
 * `"links_bundle"`, `"whowas_bundle"`, `"lusers_bundle"`, and
 * `"server_reply"` are translated into IRC lines so far — the query
 * bundles (names/who/whois/banlist/links/whowas/lusers/server_reply)
 * are all the receive-side twin of a dedicated send-side push
 * (`handle_whois` etc's own doc explains why RAW alone can't reach
 * these: the reply needs a PRIMED accumulator on grappa's side that
 * only the dedicated verb sets up). `"joined"` is a
 * recognized, deliberate no-op: it's the SUCCESS counterpart to
 * `join_failed` (`Session.Wire`, `wire.ex: 358-363`), and `handle_join`'s
 * own optimistic echo already told the client it joined — nothing left
 * to say. `"channels_changed"` (`wire.ex:105`, carries literally no
 * other field — a bare "go re-fetch GET /channels if you care" signal
 * for a client that polls, which bicchierino doesn't) and
 * `"archive_changed"`/`"window_counts"`/`"query_windows_list"` are all
 * cicchetto-UI concepts (unread badges, DM sidebar tabs) with no
 * IRC-protocol equivalent to render — also deliberate no-ops, not gaps.
 * Everything genuinely unhandled (`bundle_hash`, `server_settings_changed`,
 * `supported_umodes_changed`, `notify_list`, `away_confirmed`, ...) still
 * logs, TODO(next) per WIRE.md §6 — one verb at a time, reading
 * grappa_channel.ex for each, not guessed. */
static void handle_grappa_event(int fd, const char *nick, struct bridge *br,
                                 struct grappa_session *sess, const char *payload,
                                 size_t payload_len) {
    char err[128];
    json_doc *doc = json_parse(payload, payload_len, err, sizeof(err));
    if (!doc) {
        fprintf(stderr, "bicchierino: malformed grappa event JSON: %s\n", err);
        return;
    }

    /* Every WS text frame is the FULL Phoenix envelope, [join_ref, ref,
     * topic, event, payload] (WIRE.md §4/§3 — same shape bridge_join
     * already parses for a phx_reply) — never just the inner event map
     * directly. Two shapes reach here: `event == "phx_reply"` (the
     * asynchronous reply to something WE pushed, e.g. the visibility
     * push — bridge_join already handles its OWN synchronous replies,
     * this is only ones that arrive later/out of order) and `event ==
     * "event"` (an actual grappa-originated push, whose PAYLOAD is the
     * `{"kind": "message"/"topic_changed"/..., ...}` object this
     * function used to — wrongly — treat the whole envelope as). */
    const json_value *root = json_root(doc);
    if (json_type_of(root) != JSON_ARRAY || json_len(root) < 5) {
        fprintf(stderr, "bicchierino: grappa event: not a 5-element envelope\n");
        json_free(doc);
        return;
    }

    const json_value *event = json_at(root, 3);
    const json_value *inner = json_at(root, 4);

    if (json_str_is(event, "phx_reply")) {
        /* Nothing to act on yet — bridge_join already consumed its own
         * synchronous reply; a later one (if any push besides
         * visibility ever expects one) has no handler yet. */
        json_free(doc);
        return;
    }

    const char *kind = NULL;
    if (!json_str_req(inner, "kind", &kind)) {
        json_free(doc);
        return;
    }

    if (strcmp(kind, "message") == 0) {
        const json_value *message = json_get(inner, "message");
        if (message) handle_grappa_message_event(fd, br, sess, message);
    } else if (strcmp(kind, "topic_changed") == 0) {
        handle_grappa_topic_changed_event(fd, nick, inner);
    } else if (strcmp(kind, "channel_modes_changed") == 0) {
        handle_grappa_channel_modes_changed_event(fd, nick, sess, inner);
    } else if (strcmp(kind, "members_seeded") == 0) {
        handle_grappa_members_seeded_event(fd, nick, inner);
    } else if (strcmp(kind, "isupport_changed") == 0) {
        handle_grappa_isupport_changed_event(fd, nick, sess, inner);
    } else if (strcmp(kind, "join_failed") == 0) {
        handle_grappa_join_failed_event(fd, nick, sess, inner);
    } else if (strcmp(kind, "names_reply") == 0) {
        handle_grappa_names_reply_event(fd, nick, inner);
    } else if (strcmp(kind, "who_reply") == 0) {
        handle_grappa_who_reply_event(fd, nick, inner);
    } else if (strcmp(kind, "whois_bundle") == 0) {
        handle_grappa_whois_bundle_event(fd, nick, inner);
    } else if (strcmp(kind, "banlist_bundle") == 0) {
        handle_grappa_banlist_bundle_event(fd, nick, inner);
    } else if (strcmp(kind, "umode_changed") == 0) {
        handle_grappa_umode_changed_event(fd, sess, nick, inner);
    } else if (strcmp(kind, "links_bundle") == 0) {
        handle_grappa_links_bundle_event(fd, nick, inner);
    } else if (strcmp(kind, "whowas_bundle") == 0) {
        handle_grappa_whowas_bundle_event(fd, nick, inner);
    } else if (strcmp(kind, "lusers_bundle") == 0) {
        handle_grappa_lusers_bundle_event(fd, nick, inner);
    } else if (strcmp(kind, "server_reply") == 0) {
        handle_grappa_server_reply_event(fd, nick, inner);
    } else if (strcmp(kind, "away_confirmed") == 0) {
        handle_grappa_away_confirmed_event(fd, nick, inner);
    } else if (strcmp(kind, "query_windows_list") == 0) {
        handle_grappa_query_windows_list_event(sess, inner);
    } else if (strcmp(kind, "joined") == 0 || strcmp(kind, "channels_changed") == 0 ||
               strcmp(kind, "archive_changed") == 0 || strcmp(kind, "window_counts") == 0) {
        /* Recognized, deliberate no-ops — see this function's own doc. */
    } else {
        fprintf(stderr, "bicchierino: grappa event (not yet handled): kind=%s\n", kind);
    }

    json_free(doc);
}

void *connection_run(void *arg) {
    struct connection_args *args = arg;
    int fd = args->client_fd;
    const struct config *cfg = args->cfg;

    /* Registration-phase timeout: a per-recv SO_RCVTIMEO breaks any
     * single blocking recv() that would otherwise wait forever (the
     * completely-idle peer case), and the wall-clock deadline below
     * closes the gap for a peer that sends data slowly but never
     * finishes registration (e.g. sends CAP LS then goes quiet).
     * Cleared after Phase 1 so Phase 2's poll()-gated recv() calls,
     * which should return immediately once poll() fires, are not
     * accidentally timed out. */
    struct timeval reg_tv = {REGISTRATION_TIMEOUT, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &reg_tv, sizeof(reg_tv));
    time_t reg_deadline = time(NULL) + REGISTRATION_TIMEOUT;

    /* `client_ssl_ctx` is scoped to the whole function (not just the
     * setup block) because `client_tls_close` needs it at every exit
     * path from here on, including the ones below Phase 1. NULL for a
     * plain bind — `client_tls_close` is a no-op in that case. */
    SSL_CTX *client_ssl_ctx = NULL;
    if (args->listener->tls && !client_tls_accept(fd, args->listener, &client_ssl_ctx)) {
        client_tls_close(client_ssl_ctx);
        close(fd);
        atomic_fetch_sub(args->live_connections, 1);
        free(args);
        return NULL;
    }

    struct linebuf lb = {0};
    struct registration reg = {0};
    char line[IRC_LINE_MAX];

    /* Phase 1: IRC registration (PASS/NICK/USER), plus CAP negotiation
     * if the client engages in any (`struct registration`'s own doc) —
     * NICK+USER alone are no longer sufficient once a client has shown
     * itself IRCv3-aware; it must also send `CAP END` before
     * registration completes. A pre-IRCv3 client that never sends CAP
     * at all is unaffected — `cap_negotiating` stays false and this
     * degrades to exactly the old condition. */
    bool registered = false;
    for (;;) {
        /* Wall-clock deadline: catches a client that trickles data
         * slowly enough to keep beating the per-recv SO_RCVTIMEO but
         * never actually completes registration. */
        if (time(NULL) >= reg_deadline) break;

        int r = next_line(fd, &lb, line, sizeof(line));
        if (r == NEXT_LINE_EOF || r == NEXT_LINE_ERROR) break;

        struct irc_message msg;
        if (!irc_parse_line(line, &msg)) continue;

        handle_registration_message(fd, &msg, &reg);
        if (reg.got_nick && reg.got_user && (!reg.cap_negotiating || reg.cap_done)) {
            registered = true;
            break;
        }
    }

    /* Clear the registration timeout before Phase 2, which uses its
     * own poll()-based timing and must not be disrupted by a stale
     * SO_RCVTIMEO left over from Phase 1. */
    struct timeval no_tv = {0, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &no_tv, sizeof(no_tv));

    if (!registered) {
        /* Best-effort ERROR — the client may still be connected (just
         * idle or slow), in which case this explains the disconnect. */
        send_line(fd, "ERROR :Registration timeout");
        client_tls_close(client_ssl_ctx);
        close(fd);
        atomic_fetch_sub(args->live_connections, 1);
        free(args);
        return NULL;
    }

    char network[IRC_LINE_MAX], password[IRC_LINE_MAX];
    split_network_password(reg.got_pass ? reg.pass_raw : "", network, sizeof(network), password,
                            sizeof(password));

    /* Everything from here on may obtain a grappa token, so every exit
     * path funnels through `cleanup`. bicchierino deliberately does NOT
     * call DELETE /auth/logout here on ordinary teardown (it used to) —
     * found live via a real 2-client test on one grappa account: the
     * request DOES leave the upstream IRC session alone as intended
     * (auth_controller.ex's own #126 comment confirms Session.Server
     * outlives any one WS client), but it ALSO makes
     * UserSocket.disconnect_subject/1 broadcast a Phoenix "disconnect" to
     * the subject's shared socket_id — force-closing EVERY sibling
     * WebSocket for that account, not just this one. Confirmed with
     * server logs: client B's clean QUIT killed client A's still-active
     * session outright. grappa's own tokens carry a sliding 7-day idle
     * expiry (accounts.ex) — an abandoned, never-revoked token cleans
     * itself up on a bounded timescale, which is a far smaller cost than
     * taking down every sibling connection on every QUIT. */
    struct grappa_session sess = {0};

    /* Carries whatever Phase 1's CAP negotiation actually settled on
     * into Phase 2, where it outlives `reg` (stack-local to this
     * function either way, but conceptually `reg` is Phase-1-only
     * scratch — see `struct registration`'s own doc). `cap_negotiating`/
     * `cap_done` themselves don't need to survive: pure gating state,
     * meaningless once registration has already completed. */
    sess.cap_server_time = reg.cap_server_time;
    sess.cap_message_tags = reg.cap_message_tags;

    /* One persistent HTTP/1.1 connection for every REST call this
     * session makes (login, both bootstrap GETs, every PRIVMSG send,
     * final logout) — http.h's whole reason for existing: a fresh
     * TCP+TLS handshake per outbound chat line was measured as a real,
     * unacceptable cost. Declared here (not inside a narrower scope)
     * because it needs to survive from login all the way to `cleanup:`. */
    struct http_client hc;
    http_client_init(&hc);

    /* Declared here (not inside the branch below) because it needs to
     * survive into Phase 2 and `cleanup:` — the join sequence opens it,
     * and nothing closes it until the connection itself ends. Phase 2's
     * poll() loop below is what actually reads from it. */
    struct bridge br = {0};
    bool br_connected = false;

    /* Two blocking calls, in this one thread, in sequence — the whole
     * reason connections are threads, not one shared event loop: none
     * of this stalls any other connection. Each step's own ERROR is
     * already sent to the client by the function that failed
     * (fetch_networks covers the zero-networks dead end itself — Case
     * A, no recovery). */
    if (!attempt_grappa_login(fd, &hc, reg.account, password, cfg, &sess)) goto cleanup;
    if (!fetch_networks(fd, &hc, cfg, &sess)) goto cleanup;

    pick_network(&sess, network); /* sets sess.network_resolved on a match */

    if (sess.network_resolved) {
        bool network_connected = ensure_network_connected(&hc, cfg, &sess);
        if (!fetch_joined_channels(fd, &hc, cfg, &sess)) goto cleanup;
        /* `sess.network_nick` (set by `pick_network` just above), not
         * `reg.nick`, from here on — the one is live-tracked across a
         * later self nick_change, the other is a one-time registration
         * snapshot. Identical value at this exact point. */
        send_welcome(fd, sess.network_nick, sess.subject_name);
        present_channels(fd, sess.network_nick, &sess);
        if (!network_connected)
            send_line(fd,
                      ":%s NOTICE %s :Could not establish the IRC connection for %s (grappa "
                      "rejected the connect request) — you may see an empty channel list "
                      "until this is resolved",
                      IRCD_SERVER, sess.network_nick, sess.network_slug);
        fprintf(stderr,
                "bicchierino: bootstrap OK: subject=%s network=%s(%ld) joined_channels=%zu\n",
                sess.subject_name, sess.network_slug, sess.network_id, sess.channel_count);

        /* The join sequence below proves every topic's reply is "ok" and
         * pushes visibility, but doesn't itself consume the after-join
         * snapshot pushes (query_windows_list, topic_changed, ...) that
         * arrive as separate frames right after — those stay buffered
         * in the OS socket until Phase 2's poll()-on-two-fds loop reads
         * them. Isolated the same way the handshake was: a join failing
         * here means the join sequence is broken, never the handshake. */
        br_connected = bridge_connect(cfg->grappa_url, sess.token, sess.subject_name, &br);
        if (br_connected) {
            join_grappa_topics(fd, sess.network_nick, &br, &sess);
        } else {
            fprintf(stderr, "bicchierino: websocket handshake FAILED\n");
            send_line(fd,
                      ":%s NOTICE %s :Connected, but the live event bridge failed to come "
                      "up — messages and channel activity will not be delivered until you "
                      "reconnect",
                      IRCD_SERVER, sess.network_nick);
        }
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

    /* Phase 2: poll() on both fds for the rest of the connection's
     * life — the IRC client always, the grappa websocket
     * whenever `br_connected` (Case B, network never resolved, never
     * opens one). `pfds[1].fd` is re-armed to -1 the moment br_connected
     * goes false so poll() simply ignores that slot from then on — no
     * separate nfds bookkeeping needed.
     *
     * Bounded timeout (not the -1/infinite this loop used before): the
     * ONLY way to notice "time to send the Phoenix heartbeat" is to
     * wake up periodically even when neither fd has anything —
     * confirmed live-reasoning necessary, not hypothetical: grappa's
     * `endpoint.ex` sets no `:timeout` override on its `websocket:`
     * transport opts, so Phoenix's own default (60s of receiving
     * NOTHING from the client) applies, and bicchierino previously sent
     * nothing at all once the join sequence finished unless the IRC
     * client itself triggered a command — a genuinely idle IRC client
     * (connected, not typing) would silently lose the grappa bridge
     * after a minute, tripping the same "lost grappa connection"
     * teardown used for a genuine network failure, for no fault of the
     * user's. Matches
     * shottino's own `ws_pump` cadence exactly: a heartbeat every 25s
     * (comfortably inside the 60s window) on topic "phoenix" (never
     * joined — `bridge_push`'s `join_ref == 0` sentinel, WIRE.md/
     * shottino's own convention), bundled with a `visibility` re-push
     * at the same cadence — shottino's own comment explains why: the
     * SAME 60s staleness window also governs presence, so a heartbeat
     * alone keeps the SOCKET alive but not necessarily the "user is
     * here" signal. 5s poll granularity is comfortably fine-grained
     * against a 25s cadence. */
    struct pollfd pfds[2];
    pfds[0].fd = fd;
    pfds[0].events = POLLIN;
    pfds[1].events = POLLIN;
    time_t next_heartbeat = time(NULL) + 25;
    time_t last_client_seen = time(NULL);
    bool client_ping_sent = false;
    time_t client_ping_deadline = 0;

    for (;;) {
        pfds[1].fd = br_connected ? br.wsc.fd : -1;

        int nfds = poll(pfds, 2, 5000);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (br_connected && time(NULL) >= next_heartbeat) {
            if (!bridge_push(&br, "phoenix", 0, "heartbeat", "{}"))
                fprintf(stderr, "bicchierino: heartbeat push failed\n");
            if (sess.user_join_ref) {
                char user_topic[160];
                snprintf(user_topic, sizeof(user_topic), "grappa:user:%s", sess.subject_name);
                bridge_push(&br, user_topic, sess.user_join_ref, "visibility",
                            "{\"visible\":true}");
            }
            next_heartbeat = time(NULL) + 25;
        }

        /* DM-listener rejoin after a self nick_change — deferred here
         * from `handle_grappa_message_event` specifically because THIS
         * point in the loop is never nested inside another
         * `bridge_join`'s own wait loop (unlike where the nick_change
         * event itself was handled, possibly via `bridge_event_dispatch`
         * mid-bootstrap) — see `dm_needs_rejoin`'s doc on
         * `struct grappa_session`. The OLD topic was already left
         * (fire-and-forget) at the point this flag was set; only the
         * new join remains. */
        if (br_connected && sess.dm_needs_rejoin && sess.network_nick[0]) {
            char folded_nick[64];
            ascii_fold_lower(sess.network_nick, folded_nick, sizeof(folded_nick));
            char dm_topic[512];
            snprintf(dm_topic, sizeof(dm_topic), "grappa:user:%s/network:%s/channel:%s",
                     sess.subject_name, sess.network_slug, folded_nick);
            struct bridge_event_ctx ctx = {fd, sess.network_nick, &br, &sess};
            sess.dm_joined =
                bridge_join(&br, dm_topic, &sess.dm_join_ref, bridge_event_dispatch, &ctx);
            if (sess.dm_joined)
                fprintf(stderr, "bicchierino: DM listener rejoined %s (join_ref=%lu)\n", dm_topic,
                        sess.dm_join_ref);
            else
                fprintf(stderr, "bicchierino: DM listener rejoin %s failed\n", dm_topic);
            sess.dm_needs_rejoin = false;
        }

        /* Newly-discovered DM-peer topics, queued by
         * `handle_grappa_query_windows_list_event` — deferred here for
         * the same reason as the DM-listener rejoin right above: this
         * point in the loop is never nested inside another
         * `bridge_join`'s own wait loop. See `dm_peer_names`'s own doc
         * on `struct grappa_session`. */
        if (br_connected && sess.pending_dm_peer_count > 0) {
            for (size_t i = 0; i < sess.pending_dm_peer_count; i++) {
                if (sess.dm_peer_count >= MAX_DM_PEERS) {
                    fprintf(stderr, "bicchierino: DM peer topic slots full, dropping %s\n",
                            sess.pending_dm_peer_names[i]);
                    continue;
                }
                char dm_peer_topic[512];
                snprintf(dm_peer_topic, sizeof(dm_peer_topic),
                         "grappa:user:%s/network:%s/channel:%s", sess.subject_name,
                         sess.network_slug, sess.pending_dm_peer_names[i]);
                struct bridge_event_ctx ctx = {fd, sess.network_nick, &br, &sess};
                unsigned long join_ref = 0;
                if (bridge_join(&br, dm_peer_topic, &join_ref, bridge_event_dispatch, &ctx)) {
                    snprintf(sess.dm_peer_names[sess.dm_peer_count],
                             sizeof(sess.dm_peer_names[0]), "%s", sess.pending_dm_peer_names[i]);
                    sess.dm_peer_join_refs[sess.dm_peer_count] = join_ref;
                    sess.dm_peer_count++;
                    fprintf(stderr, "bicchierino: joined DM peer topic %s (join_ref=%lu)\n",
                            dm_peer_topic, join_ref);
                } else {
                    fprintf(stderr, "bicchierino: join DM peer topic %s failed\n", dm_peer_topic);
                }
            }
            sess.pending_dm_peer_count = 0;
        }

        /* Ghost-client detection — the client-side twin of the
         * heartbeat above. A TCP peer that vanishes without a clean
         * FIN/RST (network drop, laptop sleep, ...) never shows up in
         * poll() at all; without this, the heartbeat would keep the
         * grappa bridge open indefinitely for a client that's actually
         * gone (confirmed necessary: a user asked directly whether this
         * could last 30+ minutes — it genuinely could have, before
         * this). Any client traffic at all resets the timer (below,
         * where POLLIN is handled) — a real client normally pings
         * bicchierino on its own well inside CLIENT_PING_THRESHOLD, so
         * this path is rarely exercised by anything but an actually-gone
         * peer. */
        time_t now = time(NULL);
        if (!client_ping_sent && now - last_client_seen >= CLIENT_PING_THRESHOLD) {
            send_line(fd, "PING :%s", IRCD_SERVER);
            client_ping_sent = true;
            client_ping_deadline = now + CLIENT_PING_TIMEOUT;
        } else if (client_ping_sent && now >= client_ping_deadline) {
            fprintf(stderr, "bicchierino: client ping timeout, closing\n");
            send_line(fd, "ERROR :Ping timeout");
            break;
        }

        if (nfds == 0) continue; /* timeout only — nothing else to service */

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) break;

        if (pfds[0].revents & POLLIN) {
            last_client_seen = time(NULL);
            client_ping_sent = false;

            /* Drain every complete line a single recv() packed together
             * (a client pipelining several commands) before going back
             * to poll() — line_buffered() only peeks, so this never
             * risks a next_line() call blocking on a recv() poll()
             * never promised. */
            bool client_quit = false;
            do {
                int r = next_line(fd, &lb, line, sizeof(line));
                if (r == NEXT_LINE_EOF || r == NEXT_LINE_ERROR) {
                    client_quit = true;
                    break;
                }
                struct irc_message msg;
                if (irc_parse_line(line, &msg) &&
                    handle_irc_line(fd, &hc, &br, &br_connected, cfg, &reg, &msg, &sess)) {
                    client_quit = true;
                    break;
                }
            } while (line_buffered(&lb));
            if (client_quit) break;
        }

        if (!br_connected) continue;

        if (pfds[1].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "bicchierino: grappa websocket closed mid-session\n");
            send_line(fd, "ERROR :lost grappa connection");
            br_connected = false;
            break;
        }

        if (pfds[1].revents & POLLIN) {
            bool ws_lost = false;
            bool first_read = true;
            for (;;) {
                char *payload = NULL;
                size_t payload_len = 0;
                /* Only the FIRST extraction this wakeup is allowed to
                 * touch the network (one blocking SSL_read — safe,
                 * poll() just promised data is coming). Every further
                 * frame this same loop drains comes from a pure buffer
                 * peek instead: a second ws_client_recv call could
                 * trigger a SECOND SSL_read that poll() never promised
                 * would return promptly, and grappa does not always
                 * send its after-join snapshot pushes back-to-back in
                 * one TCP segment — confirmed live, this exact loop
                 * hung the whole connection thread (silently, no other
                 * fd serviced either) before this split existed. */
                ws_result r = first_read ? ws_client_recv(&br.wsc, &payload, &payload_len)
                                          : bridge_recv_buffered(&br, &payload, &payload_len);
                first_read = false;
                if (r == WS_NEED_MORE) break;
                if (r == WS_TEXT) {
                    handle_grappa_event(fd, sess.network_nick, &br, &sess, payload, payload_len);
                    free(payload);
                    continue;
                }
                if (r == WS_PING) {
                    /* RFC 6455 §5.5.2: echo the exact same payload back
                     * as a PONG. grappa's own liveness signal is
                     * Phoenix's app-level heartbeat event, not a raw WS
                     * ping, so this path is unlikely to ever actually
                     * fire against grappa itself — implemented anyway
                     * for RFC compliance with any WS peer that does use
                     * real protocol-level pings (a proxy in front of
                     * grappa, a future grappa version, ...). Failure is
                     * logged, not fatal — matches every other
                     * best-effort push in this loop (heartbeat,
                     * visibility): losing one PONG isn't worth tearing
                     * down the whole bridge over. */
                    if (!ws_client_send_pong(&br.wsc, payload, payload_len))
                        fprintf(stderr, "bicchierino: PONG reply failed\n");
                    free(payload);
                    continue;
                }
                /* WS_CLOSED or WS_ERROR: the bridge is gone mid-session.
                 * Same treatment as any other loss of grappa: ERROR +
                 * close, no retry (the real IRC client reconnects on
                 * its own). */
                fprintf(stderr, "bicchierino: grappa websocket closed mid-session (result=%d)\n",
                        r);
                free(payload);
                ws_lost = true;
                break;
            }
            if (ws_lost) {
                send_line(fd, "ERROR :lost grappa connection");
                br_connected = false;
                break;
            }
        }
    }

cleanup:
    if (br_connected) bridge_close(&br);
    http_client_close(&hc);
    client_tls_close(client_ssl_ctx);
    close(fd);
    atomic_fetch_sub(args->live_connections, 1);
    free(args);
    return NULL;
}
