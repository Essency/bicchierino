# test/ — a sealed azzurra, for exercising bicchierino end to end

An IRC network, services, a grappa bouncer, TLS, bicchierino and a real
weechat, wired together and cut off from the internet.

The point is to run the actual binary against the actual protocol: a real
bahamut network with real azzurra services, a real grappa in front of it,
and a real IRC client at the other end. Unit tests cover the parsers; this
covers the parts only a live peer can show.

```
weechat ──plain 6667──▶ bicchierino
                             │
                      https (TLS, verified)
                             ▼
                       nginx ──▶ grappa :4000
                                     │
                               IRC upstream
                                     ▼
                    leaf4.azzurra.chat ──▶ hub ──▶ services
```

## Why it cannot reach the real network

`azzurra.chat` is a live network, and its names are compiled into the
bahamut and services binaries this stack runs — `config.h`'s `STATS_NAME`,
`STAFF_ADDRESS`, `HELPER_ADDRESS`, services' return address. The testnet
reproduces those names deliberately: that fidelity is what makes it a
useful target, and it is also what makes accidental egress dangerous.

So the containment is structural rather than configured. Every docker
network here is `internal: true` — docker gives such a network no gateway
at all, so nothing in the stack can send a packet off the host, to azzurra
or anywhere else.

`isolation.sh` asserts that rather than trusting it, and it verifies its own
detector first: if the probe cannot reach the internet on a normal bridge,
the script stops and says it cannot prove anything, instead of reporting a
sealed stack.

## Running it

```sh
git submodule update --init --recursive   # azzurra-testnet + grappa
export CONTAINER_UID=$(id -u) CONTAINER_GID=$(id -g)

cd test
./prepare.sh                              # once; needs the network
docker compose up -d --wait
./isolation.sh                            # proves the seal
```

`prepare.sh` is separate on purpose. grappa runs from source in dev mode and
wants Hex, rebar and its dependencies from the internet on first boot — which
this stack, by design, cannot provide. Rather than open a gateway "just for
setup" and leave the ircds one config mistake from production, everything
needing the network happens there, once, unsealed and explicit. The same
reasoning put openssl into `Dockerfile.certinit` at build time instead of
`apk add` at runtime.

Expect the first `prepare.sh` to take a few minutes: it is a cold Elixir
compile.

## What is in it

| | |
|---|---|
| `azzurra-testnet/` | submodule — hub, leaf-v4, leaf-v6, services, bahamut from source |
| `grappa/` | submodule — the bouncer |
| `compose.yaml` | the stack, and every override with the reason for it |
| `Dockerfile.certinit` | alpine + openssl, so cert generation needs no runtime network |
| `Dockerfile.bicchierino` | builds this repo, and installs the throwaway CA |
| `Dockerfile.weechat` | weechat 4.10.0 |
| `nginx.conf` | TLS termination in front of grappa, websocket included |
| `certs/gen-tls.sh` | mints the CA and the server cert |
| `prepare.sh` | the network-needing steps, once |
| `isolation.sh` | proves the stack is sealed, and that the proof works |

## The TLS leg

bicchierino speaks HTTPS to grappa and nothing else — `GRAPPA_URL_PREFIX`
is `https://`, `parse_grappa_url` refuses every other scheme, and the
connection verifies the chain and the hostname with no way to disable
either. That is correct for a binary whose clients hand it real passwords
inside `PASS`.

So the stack brings TLS to it instead of asking it to accept less: a
throwaway CA signs a cert for `grappa-tls`, nginx terminates, and the
bicchierino image installs that CA into its system trust store — the same
store `SSL_CTX_set_default_verify_paths` already reads. No client-side
configuration, and no patched binary: what runs here is what ships.

The cert carries a `subjectAltName`, not just a CN. OpenSSL's
`X509_check_host` ignores the CN when a SAN is present, so a CN-only cert
fails verification for a reason that takes a while to find.

## The weechat leg

`test/weechat/` is one server pointing at the bicchierino in this compose,
and nothing else. Its `logger.conf` writes one file per buffer
(`$plugin.$name.weechatlog`), which makes "where did this message land?"
answerable from the filesystem rather than by scraping a TUI.

To validate a real setup, mount it over `/home/user/.config/weechat`. Be
deliberate about that: a personal `irc.conf` carries live servers with
autoconnect, and while `internal: true` means it cannot reach them, a
config that merely looks like it might dial production is worth stripping
first.

## Two upstream quirks it works around

**`SVC_AKILL_CLONES` must be 0**, and not for the reason the testnet's
template gives. In `azzurra/services`' `conf.c`, `CLONES` is a boolean
(`CONF_SET_CLONE`); the numeric clone-autokill threshold is a separate
`CLONEKILL` directive. The template writes the threshold into `CLONES` and
defaults it to 5, so services fatals at startup with
`Value 5 for CLONES is not valid` and the testnet cannot come up on its own
defaults. Reported as vjt/grappa-irc#1066.

**`SERVICES_MASTER` must be the bridged session's nick.** Services
identifies its root by nick, and the testnet points it at `testoper`, a nick
nothing in this stack holds — so every RootServ and OperServ command answers
`Access denied` no matter what the O:line grants, which reads like a relay
failure and is not one. Related: `/OPER` drops the services identification,
so re-identify after opering.
