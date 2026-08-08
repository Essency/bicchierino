#include "bridge.h"

#include <stdio.h>
#include <string.h>

#include "json.h"
#include "jsonw.h"

bool bridge_connect(const char *grappa_url, const char *bearer_token, const char *subject,
                     struct bridge *br) {
    memset(br, 0, sizeof(*br));
    if (!ws_client_connect(grappa_url, bearer_token, &br->wsc)) return false;
    snprintf(br->subject, sizeof(br->subject), "%s", subject);
    return true;
}

bool bridge_join(struct bridge *br, const char *topic, unsigned long *join_ref_out,
                  bridge_event_cb on_event, void *cb_ctx) {
    /* WIRE.md §4: a join and the ref it carries are the same message —
     * both fields of the envelope get this one new ref. */
    unsigned long ref = ++br->ws_ref;

    char esc_topic[256];
    json_escape_into(topic, esc_topic, sizeof(esc_topic));

    char frame[512];
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
    for (int attempts = 0; attempts < 32; attempts++) {
        /* Loop on WS_NEED_MORE: this call is still purely sequential (no
         * poll() yet), so blocking until a complete frame lands is
         * correct here, unlike the eventual steady-state read loop
         * where WS_NEED_MORE goes back to poll(). */
        char *payload = NULL;
        size_t payload_len = 0;
        ws_result r;
        for (;;) {
            r = ws_client_recv(&br->wsc, &payload, &payload_len);
            if (r != WS_NEED_MORE) break;
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

    char esc_topic[256];
    json_escape_into(topic, esc_topic, sizeof(esc_topic));
    char esc_event[64];
    json_escape_into(event, esc_event, sizeof(esc_event));

    /* join_ref == 0 is the sentinel for "not tied to any joined
     * topic" — encoded as JSON `null`, not the string "0", matching
     * shottino's own `ws_v2_frame` convention exactly (its heartbeat
     * push on topic "phoenix", never joined, uses this same sentinel).
     * A real join_ref is never 0 (br->ws_ref starts at 0, the first
     * one ever assigned is 1), so the two cases can't collide. */
    char frame[512];
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
