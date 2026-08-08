#!/bin/sh
# prepare.sh — the steps that need the network, done once, before the
# sealed stack is brought up.
#
# WHY THIS FILE EXISTS. grappa runs here in dev mode against a
# bind-mounted source tree (the image is toolchain-only, same shape as
# grappa's own e2e), so its first boot wants to fetch Hex, rebar and every
# dependency from the internet. The test stack has no internet — every
# network in compose.yaml is `internal: true`, deliberately, because the
# ircds it runs have azzurra.chat compiled into them and must never reach
# the real network.
#
# Those two facts cannot both hold inside one `docker compose up`. The
# resolution is to split provisioning from running, exactly as the
# cert-init image does with its openssl dependency: everything that needs
# to reach a mirror happens HERE, unsealed and explicit, writing into the
# bind-mounted tree; everything the sealed stack does afterwards is
# offline work against what this left behind.
#
# The alternative — giving the stack a gateway "just for setup" — would
# put the ircds one config mistake away from production, which is the one
# outcome this whole directory exists to prevent.
#
# Safe to re-run: every step is idempotent, and the expensive one (the
# cold Elixir compile) is skipped once _build/ is populated.
set -eu
cd "$(dirname "$0")"

GRAPPA_SRC=./grappa
IMAGE=grappa:bicchierino-test
UID_GID="$(id -u):$(id -g)"

if [ ! -f "$GRAPPA_SRC/mix.exs" ]; then
    echo "prepare: $GRAPPA_SRC is empty — run: git submodule update --init --recursive" >&2
    exit 1
fi

mkdir -p runtime/grappa

# Certificates FIRST, because Dockerfile.bicchierino copies test/certs/ca.pem
# into the image's trust store — so `docker compose build` fails outright if
# the CA does not exist yet. tls-init in the compose mints them too and is
# idempotent, but that runs at `up`, which is after the build that needs
# them. Doing it here is what makes a clean clone work in the documented
# order instead of on the second attempt.
echo "prepare: minting the throwaway CA and server cert"
docker build -q -t bicchierino-test-certinit -f Dockerfile.certinit . >/dev/null
docker run --rm \
    --user "$UID_GID" \
    -v "$(pwd)/certs":/certs \
    --entrypoint /bin/sh \
    bicchierino-test-certinit /certs/gen-tls.sh

echo "prepare: fetching Hex, rebar and deps (needs network, runs unsealed)"
# --network bridge, NOT one of the stack's networks: this container is
# doing the fetching precisely because the stack's own networks cannot.
docker run --rm \
    --network bridge \
    --user "$UID_GID" \
    -v "$(cd "$GRAPPA_SRC" && pwd)":/app \
    -v "$(pwd)/runtime/grappa":/app/runtime \
    -w /app \
    -e MIX_ENV=dev \
    -e ELIXIR_ERL_OPTIONS=+fnu \
    "$IMAGE" \
    sh -euc '
        mix local.hex --force
        mix local.rebar --force
        mix deps.get
        mix compile
    '

echo "prepare: done — the sealed stack can now boot offline"
echo "         next: docker compose up -d --wait"
