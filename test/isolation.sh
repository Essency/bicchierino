#!/bin/sh
# isolation.sh — prove the test stack cannot reach azzurra prod, or anything
# else off this host.
#
# This exists because containment is the ONE property that must not regress
# quietly. azzurra.chat is a live network whose names are compiled into the
# bahamut and services binaries this stack runs, so a stack that leaks does
# not fail visibly — it talks to production and looks fine.
#
# WHY IT IS WRITTEN THIS WAY. The first version of this script ran its
# checks INSIDE the stack's own containers:
#
#     docker compose exec hub sh -c 'command -v ping && ping -c1 1.1.1.1'
#
# and reported everything sealed. It was proving nothing: the bahamut and
# services images ship neither `ping` nor `ip`, so `command -v` was false,
# so the whole test was false, so it read as "cannot reach". Every check
# passed for the one reason that makes a check worthless. A missing tool
# has to be a FAILURE, never a pass — and better still, the checks should
# not depend on what the images happen to contain.
#
# So the evidence here comes from two places that cannot go vacuous:
#   - `docker inspect`, which is authoritative about whether a network has
#     a gateway and which networks a container is on;
#   - a probe container this script chooses (alpine, tools guaranteed),
#     attached to the stack's own networks.
#
# Egress is probed with a TCP connect rather than ICMP. Not cosmetic:
# outbound ICMP is commonly blocked on cloud-hosted CI runners, and there
# the control below would fail and abort the whole script — reporting that
# it cannot prove anything, which is true but reads like a broken stack.
# A TCP connect answers the same question and survives that network.
#
# And the probe itself is verified against a normal bridge first: if it
# cannot detect egress where egress definitely exists, its silence on the
# sealed networks means nothing either.
set -eu

COMPOSE="${COMPOSE:-docker compose}"
PROBE="${PROBE:-alpine:3.20}"
FAIL=0

ok()  { printf '  ok: %s\n' "$1"; }
bad() { printf '  LEAK: %s\n' "$1"; FAIL=1; }

project=$($COMPOSE ps --format '{{.Project}}' 2>/dev/null | head -1)
if [ -z "$project" ]; then
    echo "isolation: no running stack — bring it up first" >&2
    exit 1
fi

# ── 0. The detector works ────────────────────────────────────────────────
# A probe that cannot see a leak on an OPEN network would report every
# sealed one as fine. Establish it can before trusting anything below.
echo "control (must succeed, or every result below is meaningless):"
if docker run --rm "$PROBE" sh -c 'nc -z -w3 1.1.1.1 443 >/dev/null 2>&1'; then
    ok "the probe reaches 1.1.1.1:443 on a normal bridge"
else
    echo "  BROKEN: the probe cannot reach 1.1.1.1:443 even unsealed." >&2
    echo "  Either this host has no egress or $PROBE lacks nc; either way" >&2
    echo "  this script cannot prove anything. Fix that before trusting it." >&2
    exit 1
fi

# ── 1. Every network in the project has no gateway ───────────────────────
echo "networks:"
nets=$(docker network ls --filter "label=com.docker.compose.project=$project" \
       --format '{{.Name}}' 2>/dev/null)
[ -n "$nets" ] || { echo "  no project networks found" >&2; exit 1; }

for n in $nets; do
    if [ "$(docker network inspect "$n" --format '{{.Internal}}')" = "true" ]; then
        ok "$n is internal (no gateway)"
    else
        bad "$n is NOT internal — everything on it can leave the host"
    fi
done

# ── 2. Every container sits only on those networks ───────────────────────
# Catches the service added later that quietly joins a bridge with a route.
echo "containers:"
for c in $($COMPOSE ps -a --format '{{.Name}}' 2>/dev/null); do
    for n in $(docker inspect "$c" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}'); do
        if [ "$(docker network inspect "$n" --format '{{.Internal}}' 2>/dev/null)" = "true" ]; then
            ok "$c on $n (sealed)"
        else
            bad "$c is on $n, which has a gateway"
        fi
    done
done

# ── 3. Egress really is impossible, measured from those networks ─────────
# docker inspect says there is no gateway; this says no packet gets out.
echo "egress, probed from inside each network:"
for n in $nets; do
    if docker run --rm --network "$n" "$PROBE" \
        sh -c 'nc -z -w3 1.1.1.1 443 >/dev/null 2>&1'; then
        bad "reached 1.1.1.1:443 from $n"
    else
        ok "no route to 1.1.1.1:443 from $n"
    fi

    # 443 and 6667: the two an escaped container would plausibly want, and
    # a sealed network refuses both before DNS even matters. A failure here
    # does not distinguish "did not resolve" from "resolved but
    # unreachable" — for proving no egress that is the same answer, and the
    # alias check below is what covers resolution.
    for host in azzurra.chat www.azzurra.chat staff.azzurra.chat helper.azzurra.chat; do
        for port in 443 6667; do
            if docker run --rm --network "$n" "$PROBE" \
                sh -c "nc -z -w3 $host $port >/dev/null 2>&1"; then
                bad "reached $host:$port from $n"
            fi
        done
    done
    ok "no route to any real azzurra.chat host from $n"
done

# ── 4. The stack still works ─────────────────────────────────────────────
# An isolation check that passes because the network is broken is not
# evidence. The leaf is what every client in this stack talks to.
echo "still functional:"
leafnet=$(echo "$nets" | grep 'bicc-net' | head -1)
if [ -n "$leafnet" ] && docker run --rm --network "$leafnet" "$PROBE" \
    sh -c 'getent hosts bahamut-test >/dev/null 2>&1'; then
    ok "bahamut-test resolves inside the stack (sealed, not broken)"
else
    bad "bahamut-test does not resolve — the stack is broken, so the above proves little"
fi

# ── 5. Nothing reachable from the host either ────────────────────────────
if $COMPOSE ps --format '{{.Ports}}' 2>/dev/null | grep -q '\->'; then
    bad "a service publishes a host port"
else
    ok "no host ports published"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "isolation: FAILED — this stack can reach the outside world" >&2
    exit 1
fi
echo "isolation: sealed"
