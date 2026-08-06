# bicchierino — reference architecture

A lean IRC-facade bridge to grappa. No GUI, no LLM bot, no media rendering,
no calls — just the wire: a real IRC client connects, `bicchierino` logs
into grappa on its behalf using the credentials *that client sent*, and
bridges the two protocols for as long as the client is attached.

This document is architecture only. No code yet.

## Scope

**In scope:**
- Listen as an IRC server (like shottino's `--ircd`, like scbnc).
- On registration, take the grappa account from `USER`'s first param and
  the password from `PASS`, and log into grappa **with those**, per
  connection — not a single identity fixed at process startup.
- Bridge IRC ⇄ grappa's REST + Phoenix Channels wire for the life of that
  connection.
- Multi-client, multi-account, multi-network, in one process.

**Out of scope (shottino has all of this; we are deliberately not this):**
curses UI, inline media, `/llm`, `/bot`, voice/video messages, calls/WHIP,
alias system, settings panel, `--user`/`--visitor`/`--share` CLI login
modes. bicchierino has exactly one login mode: whatever the connecting
client sends.

## Why not just strip shottino down

Checked directly (`shottino.c`, 22k lines): the ircd-bridge logic
(`ircd_dispatch`/`ircd_register`, ~300 lines) is small and clean, but it's
one file in a monolith where the GUI/media/LLM state is threaded through
the same `struct app`. Carving it out cleanly is more work than writing a
small, purpose-built daemon that reuses the two genuinely reusable,
dependency-free pieces (see Vendoring below) and re-derives the bridge
logic — which we need to change anyway, since the whole point is a
different auth lifecycle (per-connection login vs. per-process login).

## Prior art we're building on

### scbnc (`irc/scbnc`) — pattern reference, no code copied
C bouncer already running in this infra. Relevant
architecture to imitate:
- **libevent** event loop instead of hand-rolled `select`/`poll`.
- Per-user session triggered by the client's own `PASS` at registration —
  the multi-tenant shape we want, just against a real ircd instead of
  grappa.
- SSL/TLS on both the client-facing and server-facing side.

### shottino `--ircd` (`frontends/shottino/shottino.c:20780-21209`) — logic reference
Already solves the "be a believable IRC server" half:
- `ircd_dispatch` — command table: `CAP`, `PASS`, `USER`, `NICK`,
  `PING`/`PONG`, `QUIT` handled at the registration stage; post-registration
  `JOIN`, `PART`, `PRIVMSG`/`NOTICE`, `NAMES`, `WHO`, `WHOIS`, `TOPIC`,
  `CHATHISTORY` answered locally from bridge state; **everything else
  forwarded verbatim** upstream (`MODE`, `INVITE`, `KICK`, `OPER`, `LIST`,
  …) — this is the difference between a bridge and a reimplementation, and
  we keep that principle.
- `ircd_register` — numerics sequence on successful registration (`001`-`005`
  with the real network `PREFIX`, `MOTD`, then present already-open channels
  + replay). We reproduce this sequence; it's what makes a real client
  (irssi/weechat/hexchat) happy.
- `ircd_split_pass` — today splits `PASS` as `network:secret` to pick which
  *grappa network* to bridge, against a single already-authenticated grappa
  session. We keep the `network:` prefix convention but repurpose the
  secret half: it becomes the grappa account password, not a shared bridge
  secret, because there is no pre-existing session to select into.

**What we do NOT reuse from shottino as code**: `USER`'s param is currently
parsed and stored but never used for anything (confirmed — no auth path
reads `c->user`). We give it a job: it's the grappa login identifier.

### grappa's own auth surface (`lib/grappa_web/router.ex`)
- `POST /auth/login` — unauthenticated (`:api` pipeline only), credentials
  in, bearer token out.
- Resource routes gated by `:authn` (bearer token, `GrappaWeb.Plugs.Authn`).
- WebSocket mount: `socket "/socket", GrappaWeb.UserSocket` — channels
  authenticate in `UserSocket.connect/3`. Exact connect-param shape and
  channel topic naming (`user:<id>` per shottino's comments about "the
  USER topic") need to be read out of `GrappaWeb.UserSocket` +
  `GrappaWeb.UserChannel` directly when we get to implementation — not
  guessed.

## Vendoring (MIT, no restriction — confirmed)

`grappa-irc` is MIT, single top-level `LICENSE`, no per-file restriction
headers. Vendoring is clean as long as the notice travels with the code.

- **`ws.c`/`ws.h`** (176+68 lines) — RFC 6455 WebSocket framing, receive
  side. Buffer-based (`ws_reader_feed`/`ws_reader_take`), handles
  fragmented/masked frames, bounded message size (`WS_MAX_MESSAGE`).
  Self-contained, no dependency on shottino's `struct app`.
- **`json.c`/`json.h`** (731+120 lines) — arena-allocated recursive-descent
  JSON reader **and** writer (`json_write`). Depth-bounded
  (`JSON_MAX_DEPTH`) against hostile frames. Also self-contained.

Both are unit-tested upstream (shottino's `make check`, 14 suites,
ASan/UBSan) — vendor as-is, don't rewrite.

**Attribution**: a `THIRD_PARTY_LICENSES` (or `NOTICE`) file crediting
Marcello Barnaba / `vjt/grappa-irc`, MIT, alongside the vendored files.
Worth a heads-up to vjt when this starts for real, even though the license
doesn't require it.

## Connection lifecycle (draft)

```
downstream IRC client                bicchierino                    grappa
        |                                |                             |
        |--- CAP LS / PASS network:pw / NICK / USER ->                 |
        |                                | (buffered until NICK+USER)  |
        |                                |--- POST /auth/login ------->|
        |                                |    {account, password}      |
        |                                |<-- 200 {token} -------------|
        |                                |   (or 401 -> IRC 464, close)|
        |                                |--- WS connect /socket ----->|
        |                                |    ?token=...                |
        |                                |<-- phx_reply ok -------------|
        |                                |--- phx_join <network> ------>|
        |                                |<-- channels/state ------------|
        |<-- 001..005, MOTD, JOINs, replay -|                             |
        |                                |                             |
        |--- PRIVMSG #chan :hi --------->|--- push message ----------->|
        |                                |<-- event (echo/others) ------|
        |<-- :nick PRIVMSG #chan :hi ----|                             |
        |                                |                             |
        |--- QUIT / disconnect --------->|--- (see open question: -----|
        |                                |     teardown or detach?)    |
```

## Decided

### Identity has three fronts, not two: user, password, network

grappa is multi-user **and** multi-network — an account can have several
networks bound, same as shottino's own `--ircd` had to handle. So
authentication needs three pieces of information, not two, and IRC's
registration handshake only gives us two fields to carry them in:

- `USER`'s first param → grappa **account** (already decided).
- `PASS` → **`network:password`** (shottino's own convention, kept
  as-is — no reason to invent a new separator when one already exists and
  every existing shottino user already knows it).

So `PASS azzurra:hunter2` means: log into grappa as the account from
`USER`, with password `hunter2`, and bridge the `azzurra` network bound to
that account. A `PASS` with no colon is tried as a bare password against
the account's only network first (single-network accounts don't need to
name one — same fallback shottino already has in `ircd_register`), and
answered with the network list if that account has more than one and none
was named.

This resolves former open question 3 outright — no longer a fork, it's
the design.

## Open questions — decide before writing code

1. **Session persistence on disconnect.** Does the grappa session die with
   the IRC socket (simplest, but loses "offline while client is away"
   bouncer behavior — the whole point of a bouncer), or does it persist
   detached and reattach on the next connection with matching
   account+network+password (real bouncer behavior, needs a session cache
   keyed by (account, network), closer to what scbnc already does for real
   IRC servers)? This is the single biggest architectural fork — decides
   whether bicchierino needs any persistent state at all.
2. **grappa base URL**: one bicchierino process → one grappa deployment,
   configured at daemon startup (matches how you'd actually run it against
   e.g. your own grappa instance), or does it need to be per-connection
   too? Leaning toward daemon-level config — the account/password varying
   per-connection is the actual ask, the target deployment isn't.
3. **TLS**: both legs need it eventually (downstream for real clients off
   loopback, upstream because grappa is presumably HTTPS/WSS). libevent's
   `bufferevent_openssl` on both sides, matching scbnc's existing approach
   — no new decision needed here, just confirming before implementation.
4. **Reattach identity**: if (1) picks persistence, how is "same session"
   decided — (account, network) alone, or password re-checked each time?
   Re-checking is safer (a revoked/changed password should kick a stale
   session) but means every reconnect is a fresh `/auth/login` call even
   for a session that never actually died.

## Next step

Once (1)-(2) above are answered, the actual work is: read
`GrappaWeb.UserSocket`/`UserChannel` to pin the exact connect-param and
channel-topic shape, then write the skeleton (libevent listener +
vendored `ws.c`/`json.c` + the registration/login/bridge state machine
sketched above).
