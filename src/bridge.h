/* bridge.h — the Phoenix Channels protocol on top of ws_client's raw
 * frames: phx_join, ref tracking, reply verification. WIRE.md §3-4.
 *
 * Layering, bottom to top: json.c (raw JSON) -> ws.c (raw WS frame
 * parsing) -> ws_client.c (the WS connection's lifecycle) -> this file
 * (what grappa's wire actually says) -> connection.c (what bicchierino
 * does about it).
 */
#ifndef BICCHIERINO_BRIDGE_H
#define BICCHIERINO_BRIDGE_H

#include <stdbool.h>

#include "ws_client.h"

struct bridge {
    struct ws_client wsc;
    unsigned long ws_ref; /* monotonic — every outbound frame gets the next one */
    char subject[128];    /* cached, for building "grappa:user:{subject}/..." topics */
};

/* ws_client_connect + stash `subject` for building topic strings later. */
bool bridge_connect(const char *grappa_url, const char *bearer_token, const char *subject,
                     struct bridge *br);

/* Callback for a frame `bridge_join` reads while waiting for ITS OWN
 * reply that turns out to belong to someone else — an in-flight
 * after-join snapshot push for an earlier topic, most commonly (see
 * `bridge_join`'s own doc). `payload` is the raw, still-enveloped WS
 * text frame (the same shape a Phase-2 drain loop hands to
 * `handle_grappa_event` — NOT pre-unwrapped), valid only for the
 * duration of the call. */
typedef void (*bridge_event_cb)(void *ctx, const char *payload, size_t payload_len);

/* Sends `phx_join` on `topic` and blocks until its own reply arrives
 * (WIRE.md §4: a join and the ref it carries are the same message — the
 * one frame where join_ref and ref are equal). Verifies the reply's ref
 * matches what was sent, the event is `phx_reply`, and
 * `response.status == "ok"`.
 *
 * Any OTHER frame encountered along the way — most commonly an
 * after-join snapshot push (query_windows_list, topic_changed, ...) for
 * a topic joined earlier in the same bootstrap sequence, still in
 * flight when this join's own reply comes in — is handed to `on_event`
 * (if non-NULL; `cb_ctx` is passed through unchanged) instead of being
 * silently discarded. This is not optional when more than one
 * `bridge_join` call happens back-to-back on the same socket: confirmed
 * live, an EARLIER topic's entire snapshot vanishing into a LATER join's
 * wait loop is a real, reproducible bug, not a hypothetical one — see
 * the `.c` file's own comment at the call site this was fixed at.
 *
 * On success, `*join_ref_out` is the ref to use on every future push to
 * this exact topic — Phoenix silently drops a frame whose join_ref
 * doesn't match the topic it names (WIRE.md §4). */
bool bridge_join(struct bridge *br, const char *topic, unsigned long *join_ref_out,
                  bridge_event_cb on_event, void *cb_ctx);

/* Sends an ordinary push (not a join) on an already-joined topic —
 * `event`/`payload` (payload is a raw JSON fragment, caller-built, not
 * escaped by this function). Unlike `bridge_join`, `join_ref` is the
 * fixed ref that topic's join returned, `ref` is a fresh one for this
 * frame — the two differ on every push after the join itself (WIRE.md
 * §4, confirmed against shottino's `ws_push_user`/`ws_v2_frame`).
 * `join_ref == 0` is the sentinel for a push on a topic never joined at
 * all — encoded as JSON `null`, matching shottino's own `ws_v2_frame`
 * (used for the Phoenix `"heartbeat"` push on topic `"phoenix"`, which
 * by definition is never joined).
 *
 * Fire-and-forget, same as shottino's `ws_push_user`: does not wait for
 * or consume a reply. */
bool bridge_push(struct bridge *br, const char *topic, unsigned long join_ref, const char *event,
                  const char *json_payload);

/* Pure buffer peek — never touches the network, unlike ws_client_recv.
 * For a poll()-driven read loop: after the ONE ws_client_recv call a
 * readable-fd wakeup justifies, use this to drain any FURTHER frames
 * that same underlying read already buffered, without risking a second
 * call blocking on a network read poll() never promised would return
 * promptly (ws_client.h's own ws_client_recv doc explains why that
 * distinction matters). */
ws_result bridge_recv_buffered(struct bridge *br, char **payload, size_t *len);

void bridge_close(struct bridge *br);

#endif /* BICCHIERINO_BRIDGE_H */
