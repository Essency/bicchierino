# bicchierino — grappa wire protocol notes

Concrete findings from reading `GrappaWeb.UserSocket`, `GrappaWeb.GrappaChannel` and
`AuthController.login/2` directly in `grappa-irc` (not guessed, not inferred from
shottino's behavior alone — cross-checked against the server source). This is the
"read the code when we get there" step `ARCHITECTURE.md` deferred. Covers the
**join/auth lifecycle only** — not a catalog of every push/event shape, which is
implementation-time work guided by `grappa_channel.ex`'s moduledoc (thorough, read
it directly when wiring a given verb) and cross-referenced against what shottino
already does for the same event.

## 1. REST login — `POST /auth/login`

Body: `{"identifier": "...", "password": "..."}`.

Response: `{"token": "...", "subject": {"kind": "user", "id": "...", "name": "..."}}`.

**The identifier's shape decides the login mode**, and this is the detail that
actually matters for bicchierino: `IdentifierClassifier.classify/1` routes an
email-shaped identifier to `mode1_login` (registered user — what we want) and
anything else to `nick_login` (visitor/nick flow, network param and all — not
what we want). shottino's own `--user` mode hits exactly this: plain `USER` is
sent as `USER@shottino.local` specifically to force the email branch.

**So**: the account name bicchierino gets from `USER`'s first param must be
turned into `<account>@<anything>` before it goes in `identifier`, or login
silently takes the visitor path instead of the registered-user path.

**This isn't just a mode preference — it's what keeps a nonexistent account
from silently becoming a visitor session.** Read `mode1_login`/`account_login`
directly (`auth_controller.ex:365-405`): the email path takes the local part
before `@` as the account name and calls `authenticate_mode1/3` — real
account+password verification, **zero visitor fallback in this path at
all**. A wrong password and a nonexistent account both fail the exact same
way: `{:error, :invalid_credentials}` → HTTP **401**,
`{"error": "invalid_credentials"}` (`fallback_controller.ex:384-388`), no
oracle distinguishing the two (uniform failure, same posture as
`Plugs.Authn`). Map this straight to IRC `464` (`ERR_PASSWDMISMATCH`),
matching shottino's own `ircd_register` for its bad-password case.

The visitor auto-provisioning that exists on grappa lives **only** in the
other branch, `nick_login` (a bare, non-email identifier): if
`Accounts.get_user_by_name/1` finds no such account, it falls through to
`visitor_login` — an anonymous session gets minted with no password check
at all. bicchierino must never take this path; forcing the email shape is
exactly what keeps it out.

**Use `subject.name` from the response as the topic subject**, not the raw
account string bicchierino was given — `Subject.topic_label/1` is the single
source of truth for that value server-side, and assuming it's an unmodified
echo of the input is exactly the kind of guess this doc exists to avoid making.

## 1.5 Network + channel discovery — `GET /networks`, `GET /networks/:slug/channels`

**Correction to an earlier version of this doc's §2.5**: login is not the
only REST call a session makes. shottino's own `seed_state`
(`shottino.c:6275-6316`) calls two more, right after login and before ever
opening the websocket — bicchierino needs the same two, for the same
reason: **there is no other way to learn which networks and channels
exist before joining any topic.** The WS after-join snapshot (§4 below)
tells you about topics/modes for channels you're *already subscribed to*
— it can't tell you which channels to subscribe to in the first place.

- **`GET /networks`** (bearer auth) → JSON array, one entry per network
  bound to this account: `{kind: "user", id, slug, nick, connection_state,
  ...}` (`Grappa.Networks.Wire.network_with_nick_json`,
  `lib/grappa/networks/wire.ex:90-104`). This is where `PASS`'s `network`
  segment gets validated against reality:
  - `PASS network:password` named a network → check it's in this list
    (case-insensitive on `slug`); not found → the same "no such network,
    this account has: ..." shape shottino's own `ircd_register` already
    uses (`ARCHITECTURE.md`'s identity section).
  - `PASS password` named none → exactly one network in the list → use
    it. More than one → same "which network?" listing. **Zero** → dead
    end, see below.
- **`GET /networks/<url-encoded-slug>/channels`** (bearer auth) → JSON
  array for the *one* resolved network: `{name, joined, source}`
  (`channel_json`, `wire.ex:150-164`) — `joined: true` entries are exactly
  the channels bicchierino needs to open a channel-level topic for and
  present as `JOIN` lines to the downstream client at registration,
  mirroring shottino's own `ircd_present_channel` step. Unlike shottino
  (which fetches this for every network it bridges, being single-process
  multi-network), bicchierino only ever needs it for the one network the
  connection resolved to.

**Zero networks bound is a dead end, not an edge case to route around.**
shottino's own bootstrap treats it as fatal (`die("no networks
available")` right after the `GET /networks` call) because there is
nothing left to bridge to — no network-level or channel-level topic can
even be named. bicchierino's equivalent (bare `ERROR`, pre-registration,
no numeric — `001` was never sent, same treatment as every other
"grappa unreachable at connect" case):
`ERROR :bicchierino: no networks bound to this account` and close. This
is a real case, not a hypothetical — confirmed directly against a real
test account (`TestUser`) that has a valid login but zero networks.

## 2. WebSocket connect — `/socket/websocket`

**Auth token rides the `Sec-WebSocket-Protocol` subprotocol header**, not the
URL. Encoded as `base64url.bearer.phx.<token>`. This is deliberate and
enforced server-side (`#95`/`#202` in the moduledoc: a query-string `?token=`
fallback existed once and was removed after telemetry showed zero use — it is
now silently ignored, not merely deprecated).

This is a real implementation cost for the vendored `ws.c`, which only does
frame **framing**, not the HTTP Upgrade handshake itself — the subprotocol
header has to be set on the initial HTTP request bicchierino sends before any
WS frame exists. Direct OpenSSL + raw HTTP Upgrade headers, no shortcut here.

**Optional protocol-version declaration**: `client_proto=<int>` as a **query
param** (not subprotocol — deliberately orthogonal to the secret bearer, see
the moduledoc's DESIGN_NOTES reference). Absent or unparseable is treated as
"current" and negotiates nothing. bicchierino can omit this entirely at
first — shottino and cicchetto both do, and the failure mode for omitting it
is "treated as current," never a rejection.

## 2.5 The actual rule: REST mutates tracked state, WS relays live ops

**Corrected twice now — this is the real dividing line, confirmed against
`messages_controller.ex` AND `channels_controller.ex` directly, not
assumed from shottino's own client behavior.** It is NOT "REST only at
bootstrap, everything else is a WS push." The actual split:

- **Anything that mutates persisted/tracked session state — a chat line,
  joining/leaving a channel, setting a topic — is its own REST call**,
  issued fresh every time the client asks for it, for the life of the
  connection:
  - `POST /networks/:slug/channels/:channel/messages` (`{"body": "..."}`)
    — `Session.send_privmsg/4` (or `Session.send_ctcp/5` with a
    `"ctcp_target"` field in the same body — CTCP QUERY, `/ctcp`/`/ping`,
    not needed for a first PRIVMSG implementation). 201 with the
    persisted message on a normal send, 202 `{"ok": true}` for a
    services-targeted line (NickServ IDENTIFY etc. —
    `Session.send_privmsg/4`'s `:no_persist` case, no scrollback row),
    429 with `Retry-After` if the send-throttle bucket is empty, 400 for
    a malformed/empty body, 404 if the session isn't live.
  - `POST /networks/:slug/channels` (`{"name": "#chan"[, "key": "..."]}`)
    — `ChannelsController.create/2` → `Session.send_join/4`. `name`
    accepts an RFC1459 comma-separated LIST (`"#a,#b,#c"`, same shape a
    raw IRC `JOIN` line's first param already is — no translation
    needed); a single `key` applies to the WHOLE multi-join (grappa does
    not support a per-channel key list here, even though real IRC does).
    202 `{"ok": true}` — this only means the join was ACCEPTED and a
    `:pending` window opened, not that it succeeded; success/failure
    arrives later as a WS event (`joined` — a deliberate no-op, the
    optimistic echo already said it; `join_failed` — real numeric/NOTICE
    + a synthetic PART, `handle_grappa_join_failed_event`, proven live
    against a real `+k` mismatch rejection).
  - `DELETE /networks/:slug/channels/:channel_id` —
    `ChannelsController.delete/2` → `Session.send_part/4`. **Takes no
    reason** — a PART reason a client provides has nowhere to go in this
    endpoint and is never forwarded upstream. Also removes the channel
    from the subject's `autojoin_channels` so the leave sticks across
    reconnects. 202 `{"ok": true}`.
  - `POST /networks/:slug/channels/:channel_id/topic`
    (`{"body": "<new topic>"}`) — `Session.send_topic/4`. 202
    `{"ok": true}`. **REST-vs-WS ambiguity resolved**: `grappa_channel.ex`
    ALSO has a WS `"topic_set"` verb, but bicchierino uses REST here
    (same bucket as JOIN/PART/PRIVMSG). **This endpoint REJECTS an
    empty body** (`ChannelsController.topic/2`'s own guard clause,
    `body != ""` — a non-matching call falls to `{:error, :bad_request}`)
    — there is no way to clear a topic through it at all. A topic CLEAR
    is a genuinely separate verb, the WS `"topic_clear"` (§5.8 below),
    not this endpoint with an empty string.

  - `PATCH /networks/:network_id` (`{"connection_state": "connected"|
    "parked"}`) — `NetworksController.update/2`, T32. **The `:network_id`
    route param is a LIE — it's actually resolved as the SLUG**
    (`Plugs.ResolveNetwork` calls `Networks.get_network_by_slug/1` on
    it, confirmed reading the plug directly, not the moduledoc which is
    what misled a first attempt into 404ing on `sess->network_id`) — use
    `network_slug`, url-encoded, same as every other REST call in this
    codebase. On `:connected`, delegates to `SpawnOrchestrator.spawn/4`
    and blocks until the spawn attempt resolves (success or failure)
    before replying — this is grappa's OWN "connect" action, the one
    cicchetto's connect button fires. **Required, not optional, on every
    bicchierino bootstrap** (`ensure_network_connected` in
    `connection.c`, called unconditionally before `fetch_joined_
    channels`): `GET /networks` alone never spawns a live session for an
    account that has never been live before (confirmed reading
    `Credentials.bind_credential/3` — a bind via the admin panel is a
    bare `Repo.insert`, no spawn call anywhere on that path) — without
    this call, such an account registers fine over IRC, shows an empty
    channel list, and never does anything else, forever, with no error
    anywhere. Calling it on an ALREADY-connected credential is
    explicitly documented as idempotent server-side (`spawn/4` dedupes
    to `:already_started`, `Networks.connect/1` no-ops on an unchanged
    `:connected` state) — confirmed live, no disruption to a working
    `TestUser` session. 200 on success (whether freshly spawned or
    already live); a non-200 (capacity/admission rejection, resolve
    failure, ...) is surfaced to the IRC client as a NOTICE, not treated
    as fatal to the bicchierino connection.

  None of these five have a matching `handle_in` verb doing the same job
  in `grappa_channel.ex` (JOIN/PART/message-send/connection_state
  genuinely don't; topic has both, unresolved above) — REST is not a
  fallback here, for these five it is the ONLY path in.

- **Everything else — the ops/info verbs that don't need a persisted
  row or window-state transition (`kick`, `mode`, `whois`, `who`,
  `names`, `invite`, `ban`, `op`/`deop`/`voice`/`devoice`, `raw`, `oper`,
  `motd`, `version`, `info`, `links`, `lusers`, `banlist`, `umode`,
  `resolve_userhost`, `recover`, `open_query_window`,
  `close_query_window`, `watchlist`, `away`) — genuinely is a `phx_push`
  frame on the already-open channel websocket, exactly one
  `do_handle_in` clause each in `grappa_channel.ex`.

There is no HTTP polling for *receiving*, in either category: an incoming
message (yours or anyone else's, echoed back via the PubSub broadcast
`send_privmsg`/`send_join`/`send_part`/`send_topic` already triggers)
arrives as a WS event on whichever topic is subscribed (§3), never
fetched.

The other HTTP exception, unchanged: optional `CHATHISTORY` backfill
(shottino's `--ircd-archive`) — a REST query issued when a client scrolls
back past what the live session has already seen. Infrequent and
user-triggered, not part of the steady-state message path.

### Message wire shape — `Grappa.Scrollback.Wire`

The `"message"` event pushed on a topic (both the live broadcast AND,
implicitly, what a client would reconstruct from REST history) wraps a
`Scrollback.Message` row:

```json
{"kind": "message", "message": {
  "id": 123, "network": "azzurra", "channel": "#foo", "server_time": 1700000000000,
  "kind": "privmsg", "sender": "someone", "body": "hello", "meta": {}
}}
```

`message.kind` (an `Ecto.Enum`, always one of these — a client that
switches on anything else is guessing): `privmsg`, `notice`, `action`
(CTCP `/me`), `join`, `part`, `quit`, `nick_change`, `mode`, `topic`,
`kick`, `server_event`. Only the first three ever carry a non-null
`body`; the rest are presence/control rows whose detail lives in `meta`
(shape not yet catalogued here — read `Grappa.Scrollback.Meta` when
wiring one of those kinds).

**No `dm_with` field on the wire** — despite the DB schema having one,
`Scrollback.Wire.to_json/1` does not expose it. The DM re-keying gotcha
(§5) is resolved entirely from `channel` + `sender`: for an INCOMING DM,
`channel` equals your own nick (per §5) and `sender` names the actual
other party — that IS the peer identity, nothing else needed. For an
OUTBOUND DM you sent, `channel` is the peer and `sender` is your own
nick. A client's own outbound `privmsg`/`action` will be re-delivered
this same way on any topic it's subscribed to (the broadcast has no
per-socket "don't echo to sender" filter) — a bouncer that already knows
what it just sent needs to filter `sender == own nick` itself, not expect
grappa to skip the echo.

## 2.6 Ops/info verb catalog — kick/invite/oper/raw, and the priming-verb
gotcha for whois/who/names/banlist

**Send side**, all `phx_push` on `grappa:user:{subject}` (fire-and-forget,
no reply consumed — `push_on_user_topic` in `connection.c`):

- `"kick"` — `{"network_id", "channel", "nick", "reason"}` →
  `Session.send_kick/5`.
- `"invite"` — `{"network_id", "channel", "nick"}` → `Session.send_invite/4`.
- `"oper"` — `{"network_id", "name", "password"}` → `Session.send_oper/4`.
- `"whois"` — `{"network_id", "nick"[, "server"]}` → `Session.send_whois/5`.
  `server` only for the two-arg RFC 2812 §3.6.2 form (`WHOIS <server>
  <nick>`); omit the key entirely for the single-arg form, don't send
  `null` — `grappa_channel.ex`'s single-arg clause pattern-matches
  regardless of whether the key is present, cic's own `null` convention
  is just its own habit, not a wire requirement.
- `"who"` — `{"network_id", "channel"}`. The field is named `channel`
  even though the value is really a mask/nick/channel — wire back-compat
  with cic, confirmed in `grappa_channel.ex`'s own comment on this
  clause. Don't rename it to `target` even though `who_reply`'s own
  payload does call it `target`.
- `"names"` — `{"network_id", "channel"}`.
- `"banlist"` — `{"network_id", "channel"}`. **Same wire line as a bare
  `MODE #chan b`** (no `+`/`-`) sent through the generic `"mode"` verb —
  see the gotcha below for why they are NOT interchangeable anyway.
- `"raw"` — `{"network_id", "line"}` → `Session.send_raw/3`. The
  universal fallback (`handle_raw`, `reconstruct_irc_line` rebuilds the
  wire line verbatim from already-parsed `irc_message.params`) for
  anything with no dedicated handler — WHOWAS/LINKS/LUSERS/INFO/VERSION/
  MOTD-on-demand/services commands/a bare `/quote`. A real IRC client's
  `/quote` has no distinguishable "this is raw" wire marker; it sends the
  literal text. **op/deop/voice/devoice/ban/unban need NO handler at
  all**: a real client never sends these as distinct commands, `/op nick`
  always generates a raw `MODE #chan +o nick` line client-side, already
  covered by the existing `"mode"` push (`handle_mode`). The dedicated WS
  verbs of the same names in `grappa_channel.ex` exist purely for
  cicchetto's own UI (bulk-select + ISUPPORT `MODES=` auto-chunking) —
  bicchierino has no equivalent UI need for them.

**The gotcha, found live**: a `WHOIS RealUser` sent via `"raw"` produced NO
reply at all — not a missing-renderer gap (none existed yet either, but
that wasn't the actual cause). `Session.send_whois/5` (and `send_who/3`,
`send_names/3`, `send_banlist/3`) **prime a per-target accumulator**
(`state.whois_pending` / `who_pending` / `names_pending` /
`banlist_pending`, `server.ex`) **before** emitting the raw line
upstream. `EventRouter` only folds the reply numerics (311-319 for
WHOIS, 352+315 for WHO, 353+366 for NAMES, 367+368 for BANLIST) into a
typed bundle for a target that is actually pending — a `/quote WHOIS`
via `"raw"` sends the byte-identical line but skips the priming step, so
the ircd answers same as always but grappa has nothing to fold the
numerics into and the reply is silently lost. **Confirmed**: dedicated
`"whois"` push on the same target round-tripped 311/312/313/319/318
correctly on the very same live connection where `"raw"` got nothing.
This is why `handle_irc_line` carves WHOIS/WHO/NAMES and the
bare-`MODE #chan b` banlist form out of the RAW catch-all instead of
leaving them to it.

**Receive side** — all broadcast on the user topic, `kind` field is the
JSON discriminant (`Session.Wire`, `wire.ex`):

- `"names_reply"` — `{network, channel, members: [{nick, modes:
  [letters...]}]}` — identical per-member shape to `members_seeded`
  (§3 below), rendered through the same 353/366 helper
  (`render_names_353_366`).
- `"who_reply"` — `{network, target, users: [{nick, user, host, server,
  modes, hops, realname, channel}]}` — `modes` is the raw upstream WHO-
  flags string (`"H@"` etc), relayed verbatim into 352, not
  reinterpreted. `hops`/`realname` nil (RFC-violating upstream) render
  as `0`/`""` so the 352 field count stays right. Ends with 315.
- `"whois_bundle"` — every field nullable, populated as 311/312/313/
  317/319 arrive and broadcast whole on 318. `user == nil` (nothing
  else populated either) is grappa's own "no such nick" shape → 401
  before the always-sent 318. bahamut (azzurra) never fires the
  solanum-only fields (`account`/`secure`/`secure_cipher`/`certfp`) or
  the P-0a boolean flags (`is_admin`/`is_chanop`/...) — read but not
  separately rendered, since they carry no dedicated RFC numeric to
  round-trip through on their own; `extra_lines` (`{numeric, text}`
  pairs, 320 + any unhandled WHOIS-leg numeric) already covers verbatim
  relay of whatever a solanum-family network fires that isn't
  special-cased. **Confirmed live against real data**: `WHOIS RealUser` on
  azzurra correctly rendered `RealUser` as a genuine Server Administrator
  (313, real `oper_text`) with a real, sigil-prefixed channel list
  (319).
- `"banlist_bundle"` — `{network, channel, entries: [{mask, setter,
  set_ts}]}`. `set_ts` is the raw upstream unix-epoch STRING (grappa
  never formats it — no-localized-strings-server-side rule) — rendered
  verbatim into 367, dropped entirely (367 shows only the mask) when
  `setter`/`set_ts` are nil (an older ircd that sends a bare mask).
  Ends with 368 regardless of whether any entries existed (a channel
  with no bans still gets a bare 368 — confirmed live on `#testchannel`).

## 3. Channel topics — three shapes, one channel module

All routed through `GrappaWeb.GrappaChannel` via the single subscription
`channel "grappa:user:*", GrappaWeb.GrappaChannel` in `UserSocket`. No other
prefix resolves to anything.

| Shape | What it carries |
|---|---|
| `grappa:user:{subject}` | DM window list, one `topic_changed`/`channel_modes_changed` per cached (network, channel) across **every** network the subject has |
| `grappa:user:{subject}/network:{net}` | connection-state events only, no snapshot |
| `grappa:user:{subject}/network:{net}/channel:{chan}` | `topic_changed`/`channel_modes_changed` for that one channel |

`{subject}` is `subject.name` from the login response (§1). `{net}` is the
network **slug**, matching what bicchierino's own `PASS network:password`
already names — no translation needed there.

**Cross-user authz is enforced server-side** (`socket.assigns.user_name` must
match the topic's embedded subject) — not a bicchierino concern beyond "use
the subject the login response actually gave you."

## 4. The join sequence, exactly as shottino does it (`ws_join_topics`, `shottino.c:6766`)

1. **Join `grappa:user:{subject}` first.** Record the `join_ref` Phoenix
   assigns this join — every later push on this exact topic must carry that
   same `join_ref`, or Phoenix silently discards the frame (`ws_v2_frame`
   docs: "Phoenix discards a frame whose join_ref does not match"). This is
   not a suggestion, it's the framing contract.
2. **Join `grappa:user:{subject}/network:{net}/channel:{chan}`** for every
   channel already known open (from the post-login REST snapshot, per
   `ARCHITECTURE.md`'s statelessness section) — each with its **own**
   `join_ref`, tracked per channel.
3. **Join the DM listener topic per network**:
   `grappa:user:{subject}/network:{net}/channel:{ownNick}` — see the gotcha
   below, this is not optional if inbound DMs need to work at all.
   **`{ownNick}` (and any real channel name in step 2) MUST be ASCII-folded
   (`A-Z` -> `a-z`, byte-for-byte, nothing else touched) before it goes into
   the topic string — see §5.5, this is not optional either.**
4. **Push `visibility` `{"visible": true}` on the user topic**, immediately.
   grappa registers every new socket as hidden and debounces to AWAY after a
   window with nobody visible; a client that never reports visible gets
   auto-away'd and — per shottino's own comment on this — **the unaway can't
   fix it after the fact**, because it fires on the hidden→visible
   *transition* and a client that never reported visible never makes one.
   Send this before anything else can race the debounce.

## 5. The DM re-keying gotcha — read this twice before implementing queries

An inbound DM does **not** persist at `channel = <peer's nick>`. It persists
at `channel = <your own nick>`, with the peer recorded separately as
`dm_with`. Outbound DMs (what you sent) persist the other way — at
`channel = <peer>`.

So subscribing per-window (topic named after who you're talking to) only ever
catches your own outbound echoes. **The only way to receive an incoming DM at
all is the separate own-nick listener topic** from step 3 above — this is
exactly what `ws_sync_dm_listeners` (`shottino.c:6729`) exists for, and its
own comment states plainly that this was a real, shipped bug (query windows
showing only one side of the conversation) before that subscription existed.
Render-side re-keying (mapping `channel == own nick` back to the sender's
window) has to happen on receipt — the wire event names your own nick as the
channel, the UI-facing window is named after the actual other party.

## 5.5 The ASCII-fold gotcha — silent, not an error, found live

**Every channel-shaped topic segment (a real channel name or the DM listener's
`{ownNick}`) MUST be ASCII-folded before it goes into the topic string bicchierino
sends in its own `phx_join`** — `A-Z` -> `a-z`, byte-for-byte, nothing else
touched (`Identifier.fold_ascii_byte/1`, `lib/grappa/irc/identifier.ex:390-393`
— not locale `tolower`, not full casemapping-aware folding, just that one
byte rule). Miss this and the join still succeeds (`status: "ok"`, a real
`join_ref` comes back) — **the failure is entirely silent from there**: no
error, no rejected frame, the topic simply never receives a broadcast, forever.

**Why**: `Grappa.PubSub.Topic.channel/3` — the function every broadcaster in
grappa calls to build ITS topic string — folds the channel segment
unconditionally, always, via `Identifier.canonical_target/1`. But Phoenix's
actual PubSub subscription for a joined channel binds to the EXACT topic
STRING the client's `phx_join` sent, on the raw request — not to whatever
`GrappaChannel.join/3`'s own `canonicalize_topic` computes internally (that
folded value is used only for ITS join-reply/snapshot lookups, never fed back
into the subscription). So an unfolded join topic (`channel:TestUser`) and
the broadcaster's folded one (`channel:testuser`) are two different strings
to Phoenix.PubSub — exact string match, no fuzziness — and the join simply
never sees a matching broadcast. Confirmed live: the DM-listener topic joined
fine, `visibility` pushed fine, and inbound DMs were invisible for an entire
debugging session until this fold was added client-side.

**Also applies past the topic string, to the wire PAYLOAD's `channel` field
itself for a DM row**: grappa's own invariant (its CLAUDE.md: "Channel KEYS...
STORE the folded channel (fold at write)... the folded key IS the display")
means an incoming DM's `message.channel` (WIRE.md §3's wrapped event, the
own-nick pseudo-channel) arrives ALREADY folded (`"testuser"`), while
`message.sender` does NOT (nick KEYs fold, but "the display stays RAW" —
confirmed live: `sender` came back exactly `"RealUser"`, mixed case). The §5
re-keying comparison (`channel == ownNick`) and the self-echo comparison
(`sender == ownNick`) both need `ownNick` (and, for the sender compare, the
wire value too) folded the SAME way before comparing — comparing a raw
`ownNick` against a folded wire `channel` silently never matches either,
same failure shape as the topic-string bug, just one layer further in.

## 5.6 `umode` and 333 RPL_TOPICWHOTIME

- **`"umode"` is its own WS verb, not `"mode"` with a nick target.**
  Payload `{network_id, modes}` (no target field at all — implicitly
  own nick, `Session.send_umode/3`). `handle_irc_line` must intercept
  `MODE <ownnick> <modestring>` (target folds equal to
  `sess->network_nick`) BEFORE it reaches the generic channel-`mode`
  handler, which silently no-ops on any non-`#` target.
- **`umode_changed`'s payload is `{kind, network_id, modes:
  [letters...]}`** — an ABSOLUTE snapshot of the currently-active set,
  no actor, no delta (unlike a channel's live `mode` message-kind,
  which DOES carry a delta + actor). There is no way to tell, from this
  event alone, whether a given render should be "+X" or "-X" for any
  letter not in the new set — bicchierino renders the new set as a
  self `MODE :+<letters>` line, which is honest about what's ACTIVE now
  but can't represent a pure removal precisely (a strict client's own
  local tracking may believe a removed letter is still set until its
  next full resync). Confirmed live: setting an already-active mode
  produces NO event at all (no real change upstream = no event, not a
  bug); unsetting one produces a fresh snapshot with that letter
  genuinely absent.
- **333 RPL_TOPICWHOTIME needs `topic.set_by` + `topic.set_at`**
  (`topic_entry_wire`, §3), both present on the SAME `topic_changed`
  payload that already feeds 332 — no separate event. `set_at` is an
  ISO8601 string (`DateTime.to_iso8601/1`, always UTC/`Z`-suffixed per
  `Session.Wire`'s own doc), and 333 wants a unix epoch — bicchierino
  converts by hand (`parse_iso8601_utc_epoch`/`utc_to_unix` in
  `connection.c`), since `timegm()` isn't exposed under this project's
  `_POSIX_C_SOURCE=200809L` without also pulling in `_DEFAULT_SOURCE`.
  Skip 333 entirely (332 alone still fires) when either field is
  absent — an older/incomplete topic row can have `text` with no
  recorded setter, and a fabricated setter/time would violate the same
  "never send things that are not true" rule the 005 fix established.
- **A bare `MODE #chan` (no modestring at all) is answered LOCALLY,
  never forwarded to grappa.** There is no dedicated "query current
  channel modes" WS verb — grappa doesn't need one, because it already
  broadcasts `channel_modes_changed` (a full snapshot, not a delta)
  both right after every channel-topic join AND on every live change,
  and cicchetto just mirrors that pushed state rather than re-querying
  it (same "cic never originates state" posture grappa's own CLAUDE.md
  documents for window state). bicchierino follows the identical
  pattern: `handle_grappa_channel_modes_changed_event` caches the last
  rendered `mode_str`/`param_str` into `sess->channel_mode_str[]` /
  `channel_mode_params[]` (parallel to `sess->channels[]`), and a bare
  query answers straight from that cache — a real ircd server does the
  same thing from its own in-memory channel record, no round-trip. No
  reply at all (not even an error numeric) when nothing is cached yet.

## 5.7 LINKS/WHOWAS/LUSERS/INFO/VERSION/MOTD-on-demand

Same priming-verb class as §2.6's WHOIS/WHO/NAMES/BANLIST catalog — each
needs its own dedicated push, RAW alone loses the reply. Unlike the
bare-`MODE #chan`-on-an-unjoined-channel case (§ below), **all six of
these broadcast on the user topic** (`grappa:user:{subject}`, always
subscribed) — no per-channel subscription problem at all.

**Send side** (`push_on_user_topic`, all on `grappa:user:{subject}`):

- `"links"` — `{"network_id"[, "mask"]}` → `Session.send_links/3`, primes
  `links_pending`. `mask` omitted entirely for the bare full-mesh form.
- `"whowas"` — `{"network_id", "nick"}` → `Session.send_whowas/3`,
  primes `whowas_pending`.
- `"lusers"` — `{"network_id"[, "mask"[, "server"]]}` →
  `Session.send_lusers/4`. **No priming found anywhere in grappa's
  source for this one** (no `lusers_pending`) — still pushed as a
  dedicated verb for consistency, though RAW would likely work
  identically here. A `server` with no `mask` is rejected client-side
  (positional framing, RFC 2812 §3.4.2) before it ever reaches the wire.
  **Gotcha found live**: the bare `LUSERS` (zero-arg) form MUST still
  carry `{"network_id":...}` — an empty `{}` payload matches NO
  `do_handle_in` clause (`network_id` is required even in the simplest
  form) and silently falls to grappa's unknown-verb catch-all
  (additive-only wire contract, never fatal) — the push itself succeeds
  at the WS layer, so this looks exactly like a network timeout, not a
  malformed payload, until you check grappa's own pattern match.
- `"info"` / `"version"` — bare `{"network_id"}`, no other fields.
  `Session.send_info/2` / `Session.send_version/2`, prime
  `info_pending` / `version_pending`.
- `"motd"` — `{"network_id"[, "target"]}` → `Session.send_motd/3`,
  primes `motd_pending`. On-demand only — bicchierino's own
  registration-time MOTD is a separate local synthetic burst, untouched
  by this (grappa's own doc: "Connect-time MOTD is NOT affected — no
  pending flag → stays on `$server`").

**Receive side**, `kind` on the same user-topic events:

- `"links_bundle"` — `{network, mask, entries: [{server, linked_to,
  hopcount, description}]}` → 364 per entry (`<server> <linked_to>
  :<hopcount> <description>`, matching bahamut's real wire order) + 365
  (`mask` nil → `*` in the trailer).
- `"whowas_bundle"` — `{network, target, user, host, realname, server,
  logoff_time, not_found}` — only the MOST RECENT historical entry
  (multi-entry history is out of scope server-side too). `not_found:
  true` → 406 + 369. Otherwise 314 (same shape as WHOIS's 311) +
  optional 312 (only when BOTH `server` and `logoff_time` are present —
  real bahamut ships the disconnect time as 312's free-form trailing
  text, not a separate structured numeric) + always 369.
- `"lusers_bundle"` — 12 nullable integer fields folding bahamut's
  7-numeric sequence (251-255, 265-266). Each numeric is rendered ONLY
  when every field it needs is present — never a fabricated 0.
- `"server_reply"` — `{network, source: "info"|"version"|"motd", lines:
  [String.t()]}`, the shared shape for all three. `:info` → 371 per
  line + 374. `:version` → 351 per line (a real 351 structurally has
  separate version/server positional fields, but this codebase only
  ever receives already-flattened trailing text from grappa, so each
  line rides 351's trailing slot rather than fabricating positional
  fields grappa never gave it). `:motd` → 375 + 372 per line + 376, or
  422 when `lines` is empty (no separate not-found flag for MOTD
  specifically — an empty burst IS the "no MOTD" signal here).

## 5.8 AWAY and TOPIC-clear

- **`"away"` is the ONE verb keyed by `"network"` (the slug string)
  instead of `"network_id"` (the numeric FK every other verb in this
  catalog uses)** — confirmed reading `grappa_channel.ex`'s `"away"`
  clauses directly, a real inconsistency in grappa's own wire, not a
  typo in this doc. Set: `{"action":"set","network":slug,"reason":
  reason}`. Unset: `{"action":"unset","network":slug}` — no reason
  field at all for unset. Optional `origin_window` (cicchetto's own
  reply-routing field, for correlating 305/306 back to a specific
  window) is safe to omit entirely — absent resolves to `{:ok, nil}`
  server-side, and bicchierino has no window concept to route to
  anyway.
- **`away_confirmed`** — `{kind, network, state: "present"|"away"}`,
  broadcast on the user topic. Fires for BOTH an explicit `AWAY` verb
  AND grappa's own hidden-socket auto-away transitions (`WSPresence`)
  — an unprompted 305/306 with no `AWAY` the client itself sent is
  expected behavior (another socket for the same account going
  hidden/visible), not a bug. `:away` → 306 RPL_NOWAWAY, `:present` →
  305 RPL_UNAWAY.
- **`"topic_clear"`** — `{network_id, channel}` →
  `Session.send_topic_clear/3`, the irssi `/topic -delete` convention
  (`TOPIC #chan :` empty trailing, upstream). See §2.5 above for why
  this can't go through the REST topic endpoint at all.

## 6. What this doc does not cover

The full inbound/outbound event catalog (`op`/`kick`/`mode`/`topic_set`/
`whois`/... — all listed with payload shapes in `grappa_channel.ex`'s own
moduledoc, ~120 lines of it, not worth duplicating here since it's already
written once and would drift). Read that file directly per-verb when wiring
the actual IRC↔JSON translation table — it is the authoritative source, this
document is only the connection lifecycle that has to exist before any of
those verbs can be sent at all.
