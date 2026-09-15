/* test_ws — the framing has to survive how a socket actually delivers.
 *
 * The reader this replaces read frames straight off the socket and, when
 * fewer bytes had arrived than the frame declared, threw away what it had
 * already taken and reported "nothing yet". The rest of that frame was
 * then read as if it were a new frame header, and the stream never
 * recovered. A chat line arrives in one piece and hid the bug for
 * months; a WHOIS bundle, a MOTD or a LUSERS reply does not, and those
 * were the replies that never appeared.
 *
 * So the property under test is not "does it parse a frame" — the old one
 * did — but "does it parse a frame delivered ONE BYTE AT A TIME", which
 * is the same question a slow link asks. Every case here is also fed
 * whole, so a parser that only works in the pathological case fails too.
 */
#include "../src/ws.h"

#include "test.h"

#include <stdlib.h>
#include <string.h>

/* Build a server→client frame (unmasked, as a server must send). */
static size_t frame(unsigned char *out, int opcode, bool fin, const char *body, size_t len) {
    size_t n = 0;
    out[n++] = (unsigned char)((fin ? 0x80 : 0x00) | (opcode & 0x0f));
    if (len < 126) {
        out[n++] = (unsigned char)len;
    } else if (len <= 65535) {
        out[n++] = 126;
        out[n++] = (unsigned char)(len >> 8);
        out[n++] = (unsigned char)len;
    } else {
        out[n++] = 127;
        for (int i = 7; i >= 0; i--) out[n++] = (unsigned char)(len >> (i * 8));
    }
    memcpy(out + n, body, len);
    return n + len;
}

/* Feed the whole thing at once and take one message. */
static char *whole(const unsigned char *bytes, size_t n, ws_result *result) {
    struct ws_reader r;
    ws_reader_init(&r);
    CHECK(ws_reader_feed(&r, bytes, n));
    char *msg = NULL;
    *result = ws_reader_take(&r, &msg, NULL);
    ws_reader_free(&r);
    return msg;
}

/* Feed it a byte at a time, which is what the old reader could not do.
 * Every byte but the last must report NEED_MORE — a parser that answers
 * early has consumed something it should not have. */
static char *dribbled(const unsigned char *bytes, size_t n, ws_result *result) {
    struct ws_reader r;
    ws_reader_init(&r);
    char *msg = NULL;
    *result = WS_NEED_MORE;
    for (size_t i = 0; i < n; i++) {
        CHECK(ws_reader_feed(&r, bytes + i, 1));
        *result = ws_reader_take(&r, &msg, NULL);
        if (*result != WS_NEED_MORE) {
            /* Only the final byte may complete it. */
            CHECK(i == n - 1);
            break;
        }
    }
    ws_reader_free(&r);
    return msg;
}

TEST(a_small_frame_arrives_whole_or_in_pieces) {
    unsigned char buf[256];
    size_t n = frame(buf, 0x1, true, "hello", 5);

    ws_result res;
    char *msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_TEXT);
    CHECK_STR(msg, "hello");
    free(msg);

    msg = dribbled(buf, n, &res);
    CHECK_LONG(res, WS_TEXT);
    CHECK_STR(msg, "hello");
    free(msg);
}

TEST(a_big_frame_arrives_in_pieces) {
    /* Past 125 bytes the length moves into its own field, and past 65535
     * into the 64-bit one — the two sizes a reply card actually reaches,
     * and the two the old reader could lose halfway through. */
    static char body[70000];
    static unsigned char buf[70016];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (char)('a' + (i % 26));

    size_t sizes[] = {126, 1000, 65535, 70000};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        size_t len = sizes[s];
        size_t n = frame(buf, 0x1, true, body, len);

        ws_result res;
        char *msg = whole(buf, n, &res);
        CHECK_LONG(res, WS_TEXT);
        CHECK(msg && strlen(msg) == len);
        CHECK(msg && memcmp(msg, body, len) == 0);
        free(msg);

        /* Delivered in chunks that never line up with the frame — the
         * shape of a real read. */
        struct ws_reader r;
        ws_reader_init(&r);
        char *out = NULL;
        ws_result step = WS_NEED_MORE;
        for (size_t off = 0; off < n; off += 1000) {
            size_t chunk = n - off < 1000 ? n - off : 1000;
            CHECK(ws_reader_feed(&r, buf + off, chunk));
            step = ws_reader_take(&r, &out, NULL);
            if (off + chunk < n) CHECK_LONG(step, WS_NEED_MORE);
        }
        CHECK_LONG(step, WS_TEXT);
        CHECK(out && memcmp(out, body, len) == 0);
        free(out);
        ws_reader_free(&r);
    }
}

TEST(one_message_split_across_frames_is_one_message) {
    /* RFC 6455 fragmentation: a server may send a message as
     * text(FIN=0) + continuation(FIN=0) + continuation(FIN=1). The old
     * reader treated the first fragment as the whole message and dropped
     * the rest as an opcode it did not recognise. */
    unsigned char buf[256];
    size_t n = frame(buf, 0x1, false, "one ", 4);
    n += frame(buf + n, 0x0, false, "two ", 4);
    n += frame(buf + n, 0x0, true, "three", 5);

    ws_result res;
    char *msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_TEXT);
    CHECK_STR(msg, "one two three");
    free(msg);

    msg = dribbled(buf, n, &res);
    CHECK_LONG(res, WS_TEXT);
    CHECK_STR(msg, "one two three");
    free(msg);
}

TEST(a_ping_between_fragments_does_not_break_the_message) {
    /* Control frames may be interleaved INSIDE a fragmented message
     * (§5.4). The ping must come back to the caller — it owes a pong —
     * without disturbing the message being assembled. */
    unsigned char buf[256];
    size_t n = frame(buf, 0x1, false, "half ", 5);
    n += frame(buf + n, 0x9, true, "beat", 4);
    n += frame(buf + n, 0x0, true, "half", 4);

    struct ws_reader r;
    ws_reader_init(&r);
    CHECK(ws_reader_feed(&r, buf, n));

    char *ping = NULL;
    size_t ping_len = 0;
    CHECK_LONG(ws_reader_take(&r, &ping, &ping_len), WS_PING);
    CHECK_STR(ping, "beat");
    CHECK_LONG(ping_len, 4);
    free(ping);

    char *msg = NULL;
    CHECK_LONG(ws_reader_take(&r, &msg, NULL), WS_TEXT);
    CHECK_STR(msg, "half half");
    free(msg);
    ws_reader_free(&r);
}

TEST(several_messages_in_one_read_all_come_out) {
    /* A busy socket hands over several frames at once, and the reader
     * must keep yielding without asking for more bytes it will not get. */
    unsigned char buf[256];
    size_t n = frame(buf, 0x1, true, "first", 5);
    n += frame(buf + n, 0x1, true, "second", 6);
    n += frame(buf + n, 0xA, true, "", 0); /* a pong: consumed, not reported */
    n += frame(buf + n, 0x1, true, "third", 5);

    struct ws_reader r;
    ws_reader_init(&r);
    CHECK(ws_reader_feed(&r, buf, n));
    const char *want[] = {"first", "second", "third"};
    for (size_t i = 0; i < 3; i++) {
        char *msg = NULL;
        CHECK_LONG(ws_reader_take(&r, &msg, NULL), WS_TEXT);
        CHECK_STR(msg, want[i]);
        free(msg);
    }
    CHECK_LONG(ws_reader_take(&r, NULL, NULL), WS_NEED_MORE);
    ws_reader_free(&r);
}

TEST(a_masked_frame_is_unmasked) {
    /* A server must not mask, but a proxy in the middle might, and a
     * client that refuses is a client that mysteriously stops working. */
    unsigned char buf[64];
    const unsigned char mask[4] = {0x11, 0x22, 0x33, 0x44};
    const char *body = "masked";
    size_t len = strlen(body);
    size_t n = 0;
    buf[n++] = 0x81;
    buf[n++] = (unsigned char)(0x80 | len);
    memcpy(buf + n, mask, 4);
    n += 4;
    for (size_t i = 0; i < len; i++) buf[n++] = (unsigned char)(body[i] ^ mask[i % 4]);

    ws_result res;
    char *msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_TEXT);
    CHECK_STR(msg, "masked");
    free(msg);
}

TEST(a_close_ends_it_and_a_broken_frame_says_so) {
    unsigned char buf[64];
    ws_result res;

    size_t n = frame(buf, 0x8, true, "", 0);
    char *msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_CLOSED);
    CHECK(msg == NULL);

    /* A continuation with nothing to continue: the stream's shape is
     * lost, and carrying on would mean guessing. */
    n = frame(buf, 0x0, true, "orphan", 6);
    msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_ERROR);

    /* A reserved bit means an extension nobody negotiated. */
    n = frame(buf, 0x1, true, "x", 1);
    buf[0] |= 0x40;
    msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_ERROR);

    /* A control frame is never fragmented and never long. */
    n = frame(buf, 0x9, false, "x", 1);
    msg = whole(buf, n, &res);
    CHECK_LONG(res, WS_ERROR);
}

TEST(a_binary_message_is_skipped_not_mistaken_for_text) {
    /* grappa speaks JSON text. A binary message is not ours to read, and
     * must not be handed up as if it were — nor may it swallow the text
     * message behind it. */
    unsigned char buf[256];
    size_t n = frame(buf, 0x2, false, "\x00\x01\x02", 3);
    n += frame(buf + n, 0x0, true, "\x03", 1);
    n += frame(buf + n, 0x1, true, "after", 5);

    struct ws_reader r;
    ws_reader_init(&r);
    CHECK(ws_reader_feed(&r, buf, n));
    char *msg = NULL;
    CHECK_LONG(ws_reader_take(&r, &msg, NULL), WS_TEXT);
    CHECK_STR(msg, "after");
    free(msg);
    ws_reader_free(&r);
}

TEST(many_frames_keep_buffer_bounded) {
    /* Regression for #106: buf_reserve used to compact only when even the
     * live bytes (len - off) plus extra would not fit in cap, which is
     * exactly the case where compaction is NOT enough and a realloc is
     * coming anyway.  The case compaction actually solves — len + extra >
     * cap while live bytes + extra <= cap — was skipped, so the consumed
     * prefix was never reclaimed.
     *
     * Without the fix, len grows with every feed while off only chases it
     * after each take.  cap therefore doubles every ~cap/framelen frames;
     * with 100-byte frames cap first exceeds WS_MAX_MESSAGE at roughly
     * 4194304 / 102 ≈ 41 000 frames.  100 000 frames puts us well past
     * that and keeps the test under a second.  With the fix, cap never
     * leaves the initial 4 KiB working-set. */
    static char body[100];
    memset(body, 'a', sizeof(body));
    unsigned char frm[112]; /* 2-byte header + 100-byte body */
    size_t flen = frame(frm, 0x1, true, body, sizeof(body));

    struct ws_reader r;
    ws_reader_init(&r);
    for (size_t i = 0; i < 100000; i++) {
        CHECK(ws_reader_feed(&r, frm, flen));
        char *msg = NULL;
        CHECK_LONG(ws_reader_take(&r, &msg, NULL), WS_TEXT);
        free(msg);
        /* cap must stay far below the per-message ceiling — if the
         * consumed prefix is never reclaimed it reaches WS_MAX_MESSAGE
         * after ~41 000 of these frames and the next feed returns false. */
        CHECK(r.cap < WS_MAX_MESSAGE);
    }
    ws_reader_free(&r);
}

TEST(an_empty_message_is_still_a_message) {
    unsigned char buf[16];
    size_t n = frame(buf, 0x1, true, "", 0);
    ws_result res;
    size_t len = 1;
    struct ws_reader r;
    ws_reader_init(&r);
    CHECK(ws_reader_feed(&r, buf, n));
    char *msg = NULL;
    res = ws_reader_take(&r, &msg, &len);
    CHECK_LONG(res, WS_TEXT);
    CHECK_STR(msg, "");
    CHECK_LONG(len, 0);
    free(msg);
    ws_reader_free(&r);
}

int main(void) {
    RUN(a_small_frame_arrives_whole_or_in_pieces);
    RUN(a_big_frame_arrives_in_pieces);
    RUN(one_message_split_across_frames_is_one_message);
    RUN(a_ping_between_fragments_does_not_break_the_message);
    RUN(several_messages_in_one_read_all_come_out);
    RUN(a_masked_frame_is_unmasked);
    RUN(a_close_ends_it_and_a_broken_frame_says_so);
    RUN(a_binary_message_is_skipped_not_mistaken_for_text);
    RUN(many_frames_keep_buffer_bounded);
    RUN(an_empty_message_is_still_a_message);
    return test_report();
}
