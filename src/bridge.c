#include "bridge.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "json.h"
#include "jsonw.h"

bool bridge_connect(const char *grappa_url, const char *bearer_token, const char *subject,
                     struct bridge *br) {
    memset(br, 0, sizeof(*br));
    if (!ws_client_connect(grappa_url, bearer_token, &br->wsc)) return false;
    snprintf(br->subject, sizeof(br->subject), "%s", subject);
    br->next_keepalive = time(NULL) + 25;
    return true;
}

bool bridge_keepalive_tick(struct bridge *br) {
    if (!br->next_keepalive || time(NULL) < br->next_keepalive) return false;
    if (!bridge_push(br, "phoenix", 0, "heartbeat", "{}")) {
        /* Push failed — the bridge is likely dead.  Don't re-arm: the
         * next keepalive_tick call would fail again immediately and the
         * caller will discover the closed bridge through its own read
         * path anyway. */
        fprintf(stderr, "bicchierino: keepalive push failed\n");
        return false;
    }
    br->next_keepalive = time(NULL) + 25;
    return true;
}

bool bridge_join(struct bridge *br, const char *topic, unsigned long *join_ref_out,
                  bridge_event_cb on_event, void *cb_ctx) {
    /* WIRE.md §4: a join and the ref it carries are the same message —
     * both fields of the envelope get this one new ref. */
    unsigned long ref = ++br->ws_ref;

    /* BRIDGE_TOPIC_MAX, not 256. connection.c assembles per-channel topics
     * as `grappa:user:<subject>/network:<slug>/channel:<chan>` out of
     * subject_name[128], network_slug[64] and a folded channel[128], which
     * reaches 347 bytes before escaping — all three sourced from the
     * connecting client (USER, PASS, JOIN). A 256-byte buffer truncated
     * those silently, and grappa imposes no topic length limit of its own
     * (Grappa.PubSub.Topic.parse pattern-matches a prefix and splits the
     * rest), so the bound has to be ours and it has to fit the real
     * worst case. Past it, refuse: a shortened topic is not a degraded
     * message, it is a join on a DIFFERENT channel reported as success. */
    char esc_topic[BRIDGE_TOPIC_MAX];
    if (!json_escape_into(topic, esc_topic, sizeof(esc_topic))) {
        fprintf(stderr, "bicchierino: join refused: topic too long (%zu bytes)\n", strlen(topic));
        return false;
    }

    char frame[BRIDGE_FRAME_MAX];
    int n = snprintf(frame, sizeof(frame), "[\"%lu\",\"%lu\",\"%s\",\"phx_join\",{}]", ref, ref,
                      esc_topic);
    if (n < 0 || (size_t)n >= sizeof(frame)) return false;

    if (!ws_client_send_text(&br->wsc, frame)) return false;

    char expected_ref[32];
    snprintf(expected_ref, sizeof(expected_ref), "%lu", ref);

    /* Not every frame arriving after a phx_join is its reply: grappa
     * pushes several unsolicited "after-join snapshot" events on a topic
     * the instant it's joined (bundle hash, server settings,
     * query_windows_list, ...), and once more than one topic has been
     * joined on the same socket an EARLIER topic's snapshot pushes may
     * still be queued when THIS join's reply comes in — confirmed live:
     * a second bridge_join misread one of the first join's leftover
     * pushes as its own answer before this loop existed. Anything that
     * isn't a phx_reply carrying this join's own ref gets handed to
     * `on_event` (when given) instead of just discarded — confirmed
     * live, the SECOND bug this exact loop shape produced: bootstrap
     * joins 3 topics back-to-back, each via its own bridge_join call,
     * and an EARLIER topic's after-join snapshot arriving while a LATER
     * bridge_join is still in this loop was silently freed here and
     * never seen again — an entire channel's topic/modes/members
     * snapshot vanished, every time, reproducibly. Capped so a truly
     * unresponsive server still fails instead of blocking forever —
     * comfortably above the handful of snapshot pushes a real join
     * produces. */
    /* Wall-clock deadline: a server that sends no frames at all (not even
     * the join reply) must still terminate in bounded time.  Without
     * this, the inner WS_NEED_MORE loop could spin indefinitely on
     * keepalive ticks alone if SO_RCVTIMEO fires but no reply ever
     * arrives.  30 s is generous relative to the frame-cap's own role
     * (stopping a chatty server that never replies); the two caps are
     * complementary, not redundant.  #142. */
    time_t deadline = time(NULL) + 30;

    for (int attempts = 0; attempts < 32; attempts++) {
        /* Loop on WS_NEED_MORE: this call is still purely sequential (no
         * poll() yet), so blocking until a complete frame lands is
         * correct here, unlike the eventual steady-state read loop
         * where WS_NEED_MORE goes back to poll().
         *
         * With SO_RCVTIMEO set to 5 s on the WS fd (ws_client_connect
         * arms it instead of clearing it to zero — #142), each tick of
         * this inner loop takes at most 5 s, allowing bridge_keepalive_tick
         * to fire and keep the Phoenix socket alive even while this join
         * is blocking. */
        char *payload = NULL;
        size_t payload_len = 0;
        ws_result r;
        for (;;) {
            r = ws_client_recv(&br->wsc, &payload, &payload_len);
            if (r != WS_NEED_MORE) break;
            bridge_keepalive_tick(br);
            if (time(NULL) >= deadline) {
                fprintf(stderr,
                        "bicchierino: join %s: timed out after 30 s waiting for reply\n",
                        topic);
                free(payload);
                return false;
            }
        }
        if (r != WS_TEXT) {
            fprintf(stderr, "bicchierino: join %s: websocket closed or errored (result=%d)\n",
                    topic, r);
            free(payload);
            return false;
        }

        char err[128];
        json_doc *doc = json_parse(payload, payload_len, err, sizeof(err));
        if (!doc) {
            fprintf(stderr, "bicchierino: join %s: malformed frame JSON: %s (skipped)\n", topic,
                    err);
            free(payload);
            continue;
        }

        /* [join_ref, ref, topic, event, payload] — WIRE.md §4, confirmed
         * against shottino's own ws_v2_frame, not guessed. A join's
         * reply has event "phx_reply" and payload {"status": "ok"|
         * "error", ...}; anything else on this socket is an unrelated
         * push, not our answer. */
        const json_value *root = json_root(doc);
        bool is_reply = false;
        bool ok = false;
        if (json_type_of(root) == JSON_ARRAY && json_len(root) >= 5) {
            const json_value *reply_ref = json_at(root, 1);
            const json_value *event = json_at(root, 3);
            const json_value *reply_payload = json_at(root, 4);
            const json_value *status = json_get(reply_payload, "status");

            is_reply = json_str_is(reply_ref, expected_ref) && json_str_is(event, "phx_reply");
            ok = is_reply && json_str_is(status, "ok");
        }

        json_free(doc);

        if (!is_reply) {
            if (on_event) on_event(cb_ctx, payload, payload_len);
            free(payload);
            continue;
        }

        free(payload);
        if (!ok) fprintf(stderr, "bicchierino: join %s: reply status was not \"ok\"\n", topic);
        if (ok && join_ref_out) *join_ref_out = ref;
        return ok;
    }

    fprintf(stderr, "bicchierino: join %s: no reply after 32 frames, giving up\n", topic);
    return false;
}

bool bridge_push(struct bridge *br, const char *topic, unsigned long join_ref, const char *event,
                  const char *json_payload) {
    unsigned long ref = ++br->ws_ref;

    /* Same reasoning as bridge_join: a push whose topic was shortened
     * lands on another channel's topic, and one whose event was shortened
     * asks grappa for a different operation. Both refuse. */
    char esc_topic[BRIDGE_TOPIC_MAX];
    if (!json_escape_into(topic, esc_topic, sizeof(esc_topic))) {
        fprintf(stderr, "bicchierino: push refused: topic too long (%zu bytes)\n", strlen(topic));
        return false;
    }
    char esc_event[BRIDGE_EVENT_MAX];
    if (!json_escape_into(event, esc_event, sizeof(esc_event))) {
        fprintf(stderr, "bicchierino: push refused: event too long (%zu bytes)\n", strlen(event));
        return false;
    }

    /* join_ref == 0 is the sentinel for "not tied to any joined
     * topic" — encoded as JSON `null`, not the string "0", matching
     * shottino's own `ws_v2_frame` convention exactly (its heartbeat
     * push on topic "phoenix", never joined, uses this same sentinel).
     * A real join_ref is never 0 (br->ws_ref starts at 0, the first
     * one ever assigned is 1), so the two cases can't collide. */
    char frame[BRIDGE_FRAME_MAX];
    int n;
    if (join_ref) {
        n = snprintf(frame, sizeof(frame), "[\"%lu\",\"%lu\",\"%s\",\"%s\",%s]", join_ref, ref,
                     esc_topic, esc_event, json_payload);
    } else {
        n = snprintf(frame, sizeof(frame), "[null,\"%lu\",\"%s\",\"%s\",%s]", ref, esc_topic,
                     esc_event, json_payload);
    }
    if (n < 0 || (size_t)n >= sizeof(frame)) return false;

    return ws_client_send_text(&br->wsc, frame);
}

ws_result bridge_recv_buffered(struct bridge *br, char **payload, size_t *len) {
    return ws_reader_take(&br->wsc.reader, payload, len);
}

void bridge_close(struct bridge *br) { ws_client_close(&br->wsc); }
