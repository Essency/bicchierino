# bicchierino — reference architecture

A lean IRC-facade bridge to grappa. No GUI, no LLM bot, no media rendering,
no calls — just the wire: a real IRC client connects, `bicchierino` logs
into grappa on its behalf using the credentials *that client sent*, and
bridges the two protocols for as long as the client is attached.

This document is architecture only. No code yet.

## Guiding principle: as dumb as possible

bicchierino is a **stateless JSON⇄IRC translator**, nothing more. It holds
no state that outlives a connection, and it originates no domain logic of
its own — grappa already decides what happened, bicchierino only decides
how to say it in IRC.

This is possible, not just a nice slogan, because grappa's own persistence
turns out to be complete enough to make it true (checked directly, see
`lib/grappa/scrollback/message.ex` + `event_router.ex`):
`Grappa.Scrollback.Message` covers `:privmsg`, `:notice`, `:action`,
`:join`, `:part`, `:quit`, `:nick_change`, `:mode`, `:topic`, `:kick`, plus
a `:server_event` catch-all that keeps `raw_verb`/`raw_sender`/`raw_params`
for anything else (`KILL`, `WALLOPS`, vendor verbs, …) — nothing falls
through uncaptured. So a fresh login + a REST replay reconstructs a session
that is content-equivalent to one that stayed connected the whole time.
grappa's own wire is JSON, not IRC bytes (`Scrollback.Wire` says the IRC
serializer is still an unbuilt "Phase 6" on grappa's side) — the JSON→IRC
translation is exactly bicchierino's one job, same as it's already
shottino's one job on the client side today.

**What "no state" actually means, precisely:**
- **Nothing persists across a disconnect.** No session cache, no reattach,
  no on-disk anything. Every new connection is a fresh `/auth/login` +
  fresh WS join + fresh channel-snapshot fetch + fresh `CHATHISTORY` replay
  for backfill. This resolves former open questions 1 and 4 outright —
  4 doesn't just get answered, it stops applying: there is no reattach
  path to decide an identity rule for.
- **Something small DOES live in memory for the duration of one live
  connection**, and this is not a contradiction: to answer `WHOIS`/`NAMES`/
  `WHO` without a REST round-trip per query, bicchierino keeps the same
  kind of per-channel member/topic/mode mirror shottino keeps
  (`ircd_cmd_whois` answers from `app->windows[i].members`, never forwards
  upstream). This isn't extra state to design or maintain — it falls out
  for free from relaying `JOIN`/`PART`/`QUIT`/`NICK`/`MODE`/`KICK` events to
  the client, which bicchierino has to parse and translate anyway. Discarded
  the instant the socket closes; never written anywhere; never consulted by
  a different connection.

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
- Per-user session triggered by the client's own `PASS` at registration —
  the multi-tenant shape we want, just against a real ircd instead of
  grappa. (scbnc itself uses libevent for its reactor — see "Event loop"
  below for why we don't follow it there.)
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

## Event loop: `poll()`, no library

Checked directly: shottino itself does **not** use libevent, or any event
library — plain `poll()` (`shottino.c:21462-21493`), direct OpenSSL for
TLS. Final runtime deps are just `libssl, libcrypto, libm, libc, libz,
libzstd`. Considered and rejected in favor of this:

- **libevent** (what scbnc uses) — the one thing it buys over raw `poll()`
  is `bufferevent_openssl` (TLS wired into the reactor). Against that:
  some discomfort with the library itself (not universal, but real), and
  every event library still leaves you writing the OpenSSL BIO plumbing
  by hand for anything beyond the simple client-role case anyway.
- **epoll directly** — considered and dropped. `epoll` is **Linux-only**;
  vjt develops on BSD, which is presumably exactly why shottino uses
  `poll()` and not `epoll` — `poll()` is POSIX (POSIX.1-2001), identical
  behavior on Linux, FreeBSD, OpenBSD, NetBSD, macOS. `epoll`'s O(1) vs.
  `poll()`'s O(n) fd-scan is not a real difference at bicchierino's scale
  (tens of connections, not tens of thousands) — so there is no upside to
  the Linux lock-in and a real downside (can't build/run alongside vjt's
  own toolchain).
- **libuv** — modern, actively maintained, MIT, nicer API than libevent.
  Still doesn't include TLS (same OpenSSL wiring either way), so the
  actual win over raw `poll()` is thinner than it looks — and it's still a
  dependency to justify.

**Decided: `poll()` + direct OpenSSL, matching shottino exactly.** One
fewer dependency, portable to whatever vjt's own machine is, and proven at
this exact scale by the very codebase we're vendoring pieces of.

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

## Connection lifecycle

Superseded by `WIRE.md` for the exact request/response shapes — this is
just the sequencing, kept here because it's the shape the code follows,
not the wire detail. `WIRE.md` §1-4 is authoritative; this diagram was
wrong on two points in an earlier draft (bearer via query string, a
single generic network join, no bootstrap REST calls) and has been
corrected against it, not the other way around.

```
downstream IRC client                bicchierino                    grappa
        |                                |                             |
        |--- CAP LS / PASS net:pw / NICK / USER ->                     |
        |                                | (buffered until NICK+USER)  |
        |                                |--- POST /auth/login ------->|
        |                                |    {identifier, password}   |
        |                                |<-- 200 {token, subject} ----|
        |                                |   (401 / unreachable: bare  |
        |                                |    ERROR, close — §3.3)     |
        |                                |--- GET /networks ----------->|
        |                                |<-- [{slug, id, ...}] --------|
        |                                | (resolve PASS's network      |
        |                                |  against this list; zero     |
        |                                |  or unmatched: ERROR, close) |
        |                                |--- GET /networks/:slug/     ->|
        |                                |    channels                  |
        |                                |<-- [{name, joined, ...}] ----|
        |                                |--- WS connect /socket ------>|
        |                                |    (bearer via              |
        |                                |    Sec-WebSocket-Protocol,   |
        |                                |    not query string)         |
        |                                |--- phx_join                 ->|
        |                                |    grappa:user:{subject}     |
        |                                |<-- snapshot (DM windows,     |
        |                                |    topic/modes) -------------|
        |                                |--- phx_join per joined       ->|
        |                                |    channel + own-nick DM     |
        |                                |    listener (WIRE.md §4-5)   |
        |                                |--- push visibility:true     ->|
        |<-- 001..005, MOTD, JOINs -------|                             |
        |                                |                             |
        |--- PRIVMSG #chan :hi --------->|--- push message ----------->|
        |                                |<-- event (echo/others) ------|
        |<-- :nick PRIVMSG #chan :hi ----|                             |
        |                                |                             |
        |--- QUIT / disconnect --------->|--- WS leave + close -------->|
        |                                | (in-memory mirror dropped;   |
        |                                |  nothing persisted)          |
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

### OpenSSL, in two distinct roles — don't conflate them

TLS is needed on **both legs**, but they are not the same job and the code
must not pretend they are:

- **Client role** (bicchierino → grappa): `SSL_connect`, verifying
  *grappa's* server certificate (chain of trust, hostname check) for the
  REST login (`https://`) and the Phoenix Channels socket (`wss://`). No
  local certificate needed on our side for this leg.
- **Server role** (downstream IRC client → bicchierino): `SSL_accept`,
  presenting **bicchierino's own** certificate + private key to whatever
  connects to the `ircs://` listener. This is the leg that needs a cert to
  provision/renew (self-signed or real, per how it's deployed — same
  the same kind of question a TLS-terminating reverse-proxy front answers once, not a new problem to solve from scratch).

Same library (direct OpenSSL, no bufferevent — see "Event loop" above),
two different `SSL_CTX` setups, two different handshake directions. Both
sides matter independently: loopback-only downstream deployments can skip
the server-role cert (plaintext on `127.0.0.1`, same reasoning shottino's
`--ircd` already uses for `SHOTTINO_IRCD_PASS`), but the client role
towards grappa is not optional — grappa is presumably always behind TLS.

### Horizontal scaling is free, because there's no state to coordinate

Direct consequence of "Guiding principle" above: since no state survives a
disconnect and the only per-connection state (the WHOIS/NAMES mirror) is
private to that one connection, **nothing needs to be shared between
bicchierino processes**. N instances behind a plain TCP load balancer (or
even bare DNS round-robin — an IRC client reconnecting to a different IP
is normal) need zero coordination: no sticky sessions, no shared cache, no
cluster protocol. Relevant if this ever fronts more than a personal/small-
group deployment (a small IRC network's worth of users) — `poll()`'s O(n)
cost per process stays irrelevant by keeping each instance's connection
count low, rather than by switching to `epoll`/`kqueue`.

### grappa base URL is daemon-level config, not per-connection

One bicchierino process → one grappa deployment, given at daemon startup
(CLI arg, matching shottino's own positional
`https://grappa.example.net`). The thing that varies per-connection is
*who's* logging in (account/password/network, from `USER`/`PASS`) — the
deployment it's logging into is an infrastructure choice, fixed for the
life of the process, not something a random downstream IRC client should
be able to redirect. It also composes cleanly with horizontal scaling
(above): every instance behind the load balancer points at the same
`--grappa-url`, no per-connection routing logic needed anywhere.

## Open questions — decide before writing code

None left. All four are resolved above:
~~1. Session persistence~~, ~~2. Reattach identity~~, ~~3. TLS~~,
~~4. grappa base URL~~.

## Next step

Nothing left to decide at the architecture level — implementation can
start. First real step: read `GrappaWeb.UserSocket`/`UserChannel` to pin
the exact connect-param and channel-topic shape (the one piece of the
design that was deliberately left "read the code when we get there"
rather than guessed), then write the skeleton (`poll()`-based listener +
direct OpenSSL + vendored `ws.c`/`json.c` + the registration/login/bridge
state machine sketched above).
