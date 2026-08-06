/* ws — WebSocket message framing (RFC 6455), receive side.
 *
 * Split out of shottino.c because the old reader could not survive the
 * two things a real socket does: deliver a frame in pieces, and split one
 * MESSAGE across several frames. It read straight from the socket and, if
 * fewer bytes were available than the frame needed, threw away what it had
 * already consumed and reported "no frame yet" — so the remaining bytes of
 * that frame were then read as if they were a new frame header. Small
 * frames (a chat line) arrive in one piece and worked; big ones (a WHOIS
 * bundle, MOTD, LUSERS) do not, and vanished.
 *
 * So the framing is a BUFFER, not a read: bytes go in, whole messages come
 * out, and a partial frame stays in the buffer until the rest of it turns
 * up. That also makes it testable without a socket, which is why it is its
 * own module — same reason json.c and wire.c are.
 *
 * Handles: continuation frames (FIN + opcode 0), control frames
 * interleaved inside a fragmented message (RFC 6455 §5.4), masked frames
 * (a server must not mask, but unmasking costs nothing and a client that
 * refuses is a client that breaks against a proxy), and the 16/64-bit
 * extended lengths.
 */
#ifndef SHOTTINO_WS_H
#define SHOTTINO_WS_H

#include <stdbool.h>
#include <stddef.h>

/* The largest MESSAGE this client will assemble. A frame claiming more
 * than this is a protocol error rather than a very large allocation. */
#define WS_MAX_MESSAGE (4u * 1024u * 1024u)

typedef enum {
    WS_NEED_MORE = 0, /* nothing complete yet — feed more bytes */
    WS_TEXT = 1,      /* a whole text message; caller owns and frees it */
    WS_PING = 2,      /* a ping; caller must answer with its payload */
    WS_CLOSED = -1,   /* peer closed */
    WS_ERROR = -2     /* protocol violation — the connection cannot continue */
} ws_result;

struct ws_reader {
    unsigned char *buf; /* bytes read but not yet consumed */
    size_t len;         /* bytes in buf */
    size_t off;         /* consumed prefix of buf */
    size_t cap;
    unsigned char *msg; /* message being reassembled across fragments */
    size_t msg_len;
    size_t msg_cap;
    bool msg_open;    /* a fragmented message is in progress */
    bool msg_discard; /* ...and it is one we do not want (binary) */
};

void ws_reader_init(struct ws_reader *r);
void ws_reader_free(struct ws_reader *r);

/* Append raw socket bytes. False only on allocation failure. */
bool ws_reader_feed(struct ws_reader *r, const void *bytes, size_t n);

/* Take the next complete message, if the buffered bytes hold one.
 *
 * On WS_TEXT / WS_PING, `*payload` receives a malloc'd NUL-terminated
 * buffer (the caller frees) and `*len` its byte length — NUL-terminated
 * for the JSON parser's convenience, length-carrying because a text
 * message may legitimately contain a NUL. Both may be NULL if the caller
 * does not want them. On every other result they are untouched. */
ws_result ws_reader_take(struct ws_reader *r, char **payload, size_t *len);

#endif /* SHOTTINO_WS_H */
