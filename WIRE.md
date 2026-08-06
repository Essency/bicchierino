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
even be named. bicchierino's equivalent, consistent with `CLAUDE.md` §3.3
(bare `ERROR`, pre-registration, no numeric — `001` was never sent):
`ERROR :bicchierino: no networks bound to this account` and close. This
is a real case, not a hypothetical — confirmed directly against a real
test account (`SonicTest`) that has a valid login but zero networks.

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

## 2.5 After bootstrap, HTTP is done — everything else is a WS push

**Corrected**: not "after login" as an earlier version of this doc said —
after the **bootstrap REST calls** (§1: login, then §1.5: `GET /networks` +
`GET /networks/:slug/channels`, all blocking, all in the same connection
thread, all before the websocket even opens). Once that's done, every
action — `PRIVMSG`, `JOIN`, `MODE`, `KICK`, whatever — is a `phx_push`
frame on the already-open channel websocket
(`ws_push_user`/`ws_send_frame_locked` in shottino), not a new HTTP
request. There is no per-message HTTP round trip to optimize, batch or
keep-alive for the *steady-state* traffic — the original point of this
section stands, it just started one step too late.

The one exception is optional `CHATHISTORY` backfill (shottino's
`--ircd-archive`) — a REST query issued when a client scrolls back past what
the live session has already seen. Infrequent and user-triggered, not part
of the steady-state message path.

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

## 6. What this doc does not cover

The full inbound/outbound event catalog (`op`/`kick`/`mode`/`topic_set`/
`whois`/... — all listed with payload shapes in `grappa_channel.ex`'s own
moduledoc, ~120 lines of it, not worth duplicating here since it's already
written once and would drift). Read that file directly per-verb when wiring
the actual IRC↔JSON translation table — it is the authoritative source, this
document is only the connection lifecycle that has to exist before any of
those verbs can be sent at all.
