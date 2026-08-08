# bicchierino

A stateless IRC-facade bridge to [grappa](https://github.com/vjt/grappa-irc).

Any real IRC client (irssi, WeeChat, HexChat, ...) can connect to
bicchierino and talk to a grappa-backed account exactly as if grappa spoke
IRC natively — even though grappa's actual client-facing wire protocol is
REST + Phoenix Channels (WebSocket), not IRC bytes at all.

## What grappa is, and why bicchierino exists

[grappa](https://github.com/vjt/grappa-irc) is an always-on IRC bouncer:
one supervised process per `(user, network)`, persistent scrollback, a
REST API for actions (login, join, send a message, ...), and a Phoenix
Channels (WebSocket) push feed for everything that happens live. Its own
first-class client is a browser PWA (`cicchetto`) that looks like irssi
in a tab.

grappa's wire protocol is JSON, not IRC — by design, its own client-facing
IRC listener is still an unbuilt future phase. bicchierino is the missing
piece for anyone who wants to point a *real* IRC client at a grappa
account today: it logs into grappa via REST using exactly the credentials
the connecting IRC client sent (`USER <account>`, `PASS
<network>:<password>`), opens the WebSocket bridge on that account's
behalf, and translates every event in both directions — grappa's JSON
events become IRC lines, and IRC commands become grappa REST calls or
WebSocket pushes.

## Design

- **Stateless per connection.** No state survives a disconnect. Every
  reconnect is a fresh REST login, a fresh set of channel joins, and (once
  supported) a fresh history replay — never a resumed session.
- **One thread per connection, zero shared state.** No locks needed
  anywhere except around the optional log file. The blocking REST login
  only stalls the thread handling that one connection; every other client
  is unaffected.
- **TLS on both legs.** As a client, verifying grappa's own certificate
  against the system trust store; as a server, presenting bicchierino's
  own certificate to downstream IRC clients — two distinct roles, two
  distinct `SSL_CTX` setups.
- **IRCv3-aware.** Full `CAP` negotiation (`cap-3.2`); `server-time` and
  `message-tags` are fully implemented — every relayed event carries a
  real `@time=` tag once a client negotiates both. `draft/chathistory`
  is deliberately not advertised yet: grappa's scrollback REST cursor is
  always an integer message id, never a timestamp, which blocks the
  timestamp-based selectors a real client is likely to send on
  reconnect. See this repo's issue tracker for the exact blocker and the
  options considered to unblock it.

Full design rationale lives in [`ARCHITECTURE.md`](ARCHITECTURE.md). The
grappa wire-protocol contract this bridge relies on — read from grappa's
own source, not guessed — is documented in [`WIRE.md`](WIRE.md).

## Building

Requires a C11 compiler, OpenSSL, and pthreads — nothing else.
`src/ws.c`/`ws.h` and `src/json.c`/`json.h` are vendored verbatim from
grappa-irc's own `shottino` frontend (MIT-licensed; see
[`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES)) rather than reimplemented.

```sh
make
```

## Configuring

See [`example.config`](example.config) for the full directive format. A
minimal config:

```
grappa-url https://your-grappa-instance.example
bind 127.0.0.1 6667 plain
```

A `bind` on a non-loopback address with `plain` is refused at startup
unless `--insecure` is passed on the command line: every client's grappa
password travels inside IRC's `PASS`, and that is a real secret exposed
on the network if sent in the clear off loopback.

## Running

```sh
./bicchierino --config bicchierino.config
```

`./bicchierino --version` prints the running build's version
(`vX.Y.Z+shorthash`, derived from the nearest git tag at build time —
see the Makefile), which also shows up in a connected client's `002`
and `004` lines.

Then configure any IRC client to connect to it — nobody types `USER`,
`NICK`, or `PASS` by hand, the client sends those automatically from its
own connection settings at connect time:

- **Server / host**: the bicchierino host and port.
- **Password** (sometimes labeled "server password" — not SASL): grappa's
  `<network>:<password>`, exactly as you'd give the grappa network you're
  binding to.
- **Nick**: anything — it's not used for identity, only for how the
  bridge addresses you until grappa's own nick is known.
- **Username / ident** (some clients call this "user" or derive it from
  the account/login field): your grappa account name.

bicchierino logs into grappa with exactly those credentials, for that
connection only — there is no fixed identity baked into the running
process the way a single-account bouncer front-end would have one.

## License

MIT — see [`LICENSE`](LICENSE). The vendored WebSocket/JSON code carries
its own MIT license from its original author; see
[`THIRD_PARTY_LICENSES`](THIRD_PARTY_LICENSES).
