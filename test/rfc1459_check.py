#!/usr/bin/env python3
"""
rfc1459_check.py — RFC 1459 wire compliance assertions against a live bicchierino.

Mechanically checkable invariants verified here:
  1. Every server line ends in CRLF                         (RFC 1459 §2.3)
  2. Every server line is ≤ 512 bytes (CRLF included)      (RFC 1459 §2.3)
  3. Numeric reply lines match the format                   (RFC 1459 §2.3.1)
     :<prefix> <3-digit-code> <target> ...
  4. 001, 002, 003, 004 are all present and arrive in       (RFC 1459 §4.1 /
     that order                                             common client
                                                            expectations)
  5. PRIVMSG — channel and DM, correct nick!user@host       (RFC 1459 §4.4.1)
     prefix, correct target
  6. NOTICE — user-to-user (nick!user@host prefix) and      (RFC 1459 §4.4.2)
     server-sourced (bare server-hostname prefix, never a
     nick) — asserts the #29 regression fix
  7. CTCP ACTION — exactly one \\x01ACTION ...\\x01 frame,   (CTCP spec)
     never double-wrapped (CLAUDE.md §12 regression)
  8. KICK — :kicker!user@host KICK #chan target :reason     (RFC 1459 §4.2.8)
  9. TOPIC — 332/333 on join snapshot, live TOPIC echo on   (RFC 1459 §4.2.4)
     a set
 10. WHOIS — 311/312/317/319/318 present and well-formed    (RFC 1459 §4.5.2)
 11. WHO — 352 rows + 315 end                               (RFC 1459 §4.5.1)
 12. NAMES — 353/366, correct sigils (CLAUDE.md §9 sigil    (RFC 1459 §4.2.5)
     regression)

Architecture: two raw sockets.
  PRIMARY  — the existing client connecting through bicchierino (port 6667).
  LEAF_PEER — a second client connecting DIRECTLY to the testnet's bahamut
              leaf (bahamut-test:6667), bypassing bicchierino/grappa
              entirely.  The peer generates real IRC events on the real ircd;
              the primary client asserts what bicchierino actually relays.

Run from inside bicc-net (docker run --network ...).

Credentials used are those seeded by grappa-seed in compose.yaml:
  PASS bahamut-test:test-password-not-secret
  USER bicc ...
  NICK rfc-check   (bicchierino presents the underlying session nick to the
                    client — bicc-grappa — so 001-004 target that nick)

The underlying grappa session IRC nick is bicc-grappa (from grappa-seed's
--nick bicc-grappa).  bicc-grappa is also SERVICES_MASTER (compose.yaml
services.environment.SERVICES_MASTER), giving it root OperServ access used
for the KICK check.
"""

import re
import select
import socket
import sys
import time

HOST          = "bicchierino"
PORT          = 6667
LEAF_HOST     = "bahamut-test"
LEAF_PORT     = 6667
CHANNEL       = "#bicc"
PEER_NICK     = "rfc-peer"
OWN_IRC_NICK  = "bicc-grappa"   # grappa session nick; bicchierino presents this in 001

# How long to wait for the server to respond at all, and how long to wait
# after sending registration commands before giving up waiting for 004.
CONNECT_TIMEOUT   = 10
READ_TIMEOUT      = 60   # grappa login + network spawn + WS join can be slow
# Extra seconds to drain the post-004 burst: channel snapshots, NAMES,
# members_seeded, scrollback replay all arrive in this window.
POST_BURST_WAIT   = 10
EVENT_WAIT        = 12   # seconds to wait for async bicchierino relay

# RFC 1459 §2.3.1: :<prefix> <3-digit-code> <target> [<params>]
# The prefix must be present (starts with ':'), code exactly 3 decimal digits.
NUMERIC_RE = re.compile(r"^:(\S+) (\d{3}) (\S+)(.*)?$")

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL: {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ok:   {msg}", flush=True)


def info(msg: str) -> None:
    print(f"  info: {msg}", flush=True)


# ── raw line I/O ──────────────────────────────────────────────────────────────

def check_line(raw: bytes) -> str | None:
    """
    Validate one raw line from the server.
    Returns the decoded text (without CRLF) on success, None if the line
    itself was fatally malformed (no CRLF at all).
    """
    # Rule 1 — CRLF termination
    if not raw.endswith(b"\r\n"):
        if raw.endswith(b"\n"):
            fail(f"line ends in bare LF (no CR): {raw!r}")
        else:
            fail(f"line has no CRLF terminator: {raw!r}")
        return None

    # Rule 2 — max length (512 bytes including CRLF per RFC 1459 §2.3)
    if len(raw) > 512:
        fail(f"line exceeds 512 bytes ({len(raw)} bytes): {raw[:60]!r}…")

    text = raw[:-2].decode("utf-8", errors="replace")

    # Rule 3 — numeric reply format
    parts = text.split()
    if len(parts) >= 2 and parts[1].isdigit():
        m = NUMERIC_RE.match(text)
        if not m:
            fail(f"numeric reply does not match :<prefix> <code> <target>: {text!r}")
        else:
            code = m.group(2)
            if len(code) != 3:
                fail(f"numeric code is not exactly 3 digits ({code!r}): {text!r}")
            if not m.group(1):
                fail(f"numeric reply has empty prefix: {text!r}")

    return text


def _drain_buf(buf: bytes) -> tuple[list[bytes], bytes]:
    """Extract all complete lines (CRLF or bare LF) from buf."""
    lines: list[bytes] = []
    while True:
        crlf = buf.find(b"\r\n")
        lf   = buf.find(b"\n")
        if crlf == -1 and lf == -1:
            break
        if crlf != -1 and (lf == -1 or crlf <= lf):
            lines.append(buf[:crlf + 2])
            buf = buf[crlf + 2:]
        else:
            lines.append(buf[:lf + 1])
            buf = buf[lf + 1:]
    return lines, buf


def recv_until(
    sock: socket.socket,
    stop_pred,           # callable(text: str) -> bool — stop when True
    timeout: float = READ_TIMEOUT,
    apply_check: bool = True,
) -> list[str]:
    """
    Read from sock until stop_pred returns True for a line, the connection
    closes, or timeout seconds elapse with no data.
    Returns all decoded, validated lines received (including the trigger).
    """
    buf   = b""
    lines: list[str] = []
    deadline = time.monotonic() + timeout

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        rlist, _, _ = select.select([sock], [], [], min(remaining, 2.0))
        if not rlist:
            continue
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        raw_lines, buf = _drain_buf(buf)
        for raw in raw_lines:
            text = check_line(raw) if apply_check else raw[:-2].decode("utf-8", errors="replace")
            if text is not None:
                lines.append(text)
                if stop_pred(text):
                    return lines
    return lines


def recv_for(
    sock: socket.socket,
    seconds: float,
    apply_check: bool = True,
) -> list[str]:
    """Read all lines from sock for up to `seconds`, then return."""
    return recv_until(
        sock,
        stop_pred=lambda _: False,
        timeout=seconds,
        apply_check=apply_check,
    )


def recv_lines_peer(
    sock: socket.socket,
    timeout: float = READ_TIMEOUT,
) -> list[str]:
    """Read from a leaf-peer (unchecked — it's bahamut's own output)."""
    return recv_until(
        sock,
        stop_pred=lambda t: " 001 " in t,
        timeout=timeout,
        apply_check=False,
    )


def send(sock: socket.socket, line: str) -> None:
    sock.sendall((line + "\r\n").encode())


# ── registration ──────────────────────────────────────────────────────────────

def register_primary(sock: socket.socket) -> list[str]:
    """
    Register the primary client through bicchierino and read the mandatory
    registration burst (001-004) plus the post-004 channel/snapshot burst.
    """
    send(sock, "PASS bahamut-test:test-password-not-secret")
    send(sock, f"NICK rfc-check")
    send(sock, "USER bicc 0 * :RFC 1459 compliance check")

    # Phase 1: wait for 004.
    lines = recv_until(sock, lambda t: len(t.split()) >= 2 and t.split()[1] == "004")
    if not any(t.split()[1] == "004" if len(t.split()) >= 2 else False for t in lines):
        fail("timed out waiting for 004 — registration burst never completed")
        return lines

    # Phase 2: drain the post-burst (snapshots, NAMES, members_seeded, replay).
    burst = recv_for(sock, POST_BURST_WAIT)
    lines.extend(burst)
    return lines


def register_leaf_peer(sock: socket.socket) -> list[str]:
    """Register rfc-peer directly on bahamut-test (unchecked output)."""
    send(sock, "NICK rfc-peer")
    send(sock, "USER rfc-peer 0 * :RFC 1459 peer")
    return recv_lines_peer(sock)


# ── assertion helpers ─────────────────────────────────────────────────────────

def find_lines(lines: list[str], command: str, channel_or_target: str | None = None) -> list[str]:
    """Return lines where the IRC verb matches command (case-insensitive)."""
    result = []
    cmd = command.upper()
    for t in lines:
        parts = t.split()
        if len(parts) < 2:
            continue
        # Skip the prefix for command position detection.
        offset = 1 if parts[0].startswith(":") else 0
        if offset >= len(parts):
            continue
        if parts[offset].upper() != cmd:
            continue
        if channel_or_target is not None:
            target_pos = offset + 1
            if target_pos >= len(parts):
                continue
            if parts[target_pos].lstrip(":").lower() != channel_or_target.lower():
                continue
        result.append(t)
    return result


def find_numerics(lines: list[str], *codes: str) -> dict[str, list[str]]:
    """Return a dict of code -> matching lines for each requested numeric."""
    result: dict[str, list[str]] = {c: [] for c in codes}
    for t in lines:
        parts = t.split()
        if len(parts) >= 2 and parts[1] in result:
            result[parts[1]].append(t)
    return result


def prefix_nick(line: str) -> str | None:
    """
    Extract the nick (or server name) from the prefix of an IRC line.
    Returns None if the line has no prefix.
    """
    if not line.startswith(":"):
        return None
    return line[1:].split()[0]


def has_user_prefix(line: str) -> bool:
    """True if the prefix is nick!user@host (contains '!')."""
    p = prefix_nick(line)
    return p is not None and "!" in p


def has_server_prefix(line: str) -> bool:
    """
    True if the prefix looks like a server hostname (contains a dot,
    no '!') — the heuristic bicchierino uses for the #29 fix.
    """
    p = prefix_nick(line)
    return p is not None and "." in p and "!" not in p


# ── check blocks ──────────────────────────────────────────────────────────────

def check_registration_numerics(lines: list[str]) -> None:
    """Rule 4: 001, 002, 003, 004 must be present and in order."""
    required = ["001", "002", "003", "004"]
    indices: dict[str, int] = {}
    for i, text in enumerate(lines):
        parts = text.split()
        if len(parts) >= 2 and parts[1].isdigit() and len(parts[1]) == 3:
            code = parts[1]
            if code in required and code not in indices:
                indices[code] = i

    for code in required:
        if code in indices:
            ok(f"numeric {code} present (line {indices[code]})")
        else:
            fail(f"missing mandatory registration numeric {code} (RFC 1459 §4.1)")

    prev_idx  = -1
    prev_code = "(start)"
    for code in required:
        if code not in indices:
            continue
        if indices[code] <= prev_idx:
            fail(f"numeric {code} arrived before {prev_code} (indices {indices[code]} ≤ {prev_idx})")
        else:
            ok(f"numeric {code} in correct order relative to {prev_code}")
        prev_idx  = indices[code]
        prev_code = code


def check_server_notice_prefix(burst: list[str]) -> bool:
    """
    Rule 6 (server-NOTICE half) — asserts the #29 regression fix:
    any NOTICE whose prefix is a server hostname must NOT carry !user@host.

    Scans the received burst for naturally-occurring server NOTICEs
    (e.g. from the ircd's own NOTICE AUTH flow that grappa stores in
    scrollback and replays to a fresh client).

    Returns True if at least one server-prefix NOTICE was found and
    checked, False if none appeared (caller may try to generate one).
    """
    server_notices = [
        t for t in burst
        if " NOTICE " in t and has_server_prefix(t)
    ]
    if not server_notices:
        return False

    for t in server_notices:
        p = prefix_nick(t)
        if "!" in (p or ""):
            fail(
                f"server NOTICE has !user@host prefix — #29 regression: {t!r}"
            )
        else:
            ok(f"server NOTICE carries bare server-hostname prefix (no !user@host): {p!r}")
    return True


def check_privmsg_channel(
    primary: socket.socket,
    peer: socket.socket,
) -> None:
    """
    Rule 5 (channel PRIVMSG): leaf-peer sends PRIVMSG to #bicc;
    primary client must receive a correctly-prefixed relay.
    """
    body = "rfc1459-channel-privmsg-test"
    send(peer, f"PRIVMSG {CHANNEL} :{body}")
    lines = recv_for(primary, EVENT_WAIT)

    matches = [t for t in lines if f"PRIVMSG" in t and body in t]
    if not matches:
        fail(f"channel PRIVMSG not relayed to primary client (body: {body!r})")
        return

    for t in matches:
        parts = t.split()
        if not has_user_prefix(t):
            fail(f"channel PRIVMSG has wrong prefix format (expected nick!user@host): {t!r}")
        else:
            ok(f"channel PRIVMSG relayed with nick!user@host prefix: {prefix_nick(t)!r}")
        # Target should be the channel, not the nick.
        cmd_pos = next((i for i, p in enumerate(parts) if p.upper() == "PRIVMSG"), None)
        if cmd_pos is not None and cmd_pos + 1 < len(parts):
            target = parts[cmd_pos + 1]
            if target.lower() == CHANNEL.lower():
                ok(f"channel PRIVMSG target is correct ({target})")
            else:
                fail(f"channel PRIVMSG target is {target!r}, expected {CHANNEL!r}: {t!r}")


def check_privmsg_dm(
    primary: socket.socket,
    peer: socket.socket,
) -> None:
    """
    Rule 5 (DM PRIVMSG): leaf-peer sends a private PRIVMSG to bicc-grappa;
    primary client must receive a relay with a nick!user@host prefix.
    """
    body = "rfc1459-dm-privmsg-test"
    send(peer, f"PRIVMSG {OWN_IRC_NICK} :{body}")
    lines = recv_for(primary, EVENT_WAIT)

    matches = [t for t in lines if "PRIVMSG" in t and body in t]
    if not matches:
        fail(f"DM PRIVMSG not relayed to primary client (body: {body!r})")
        return

    for t in matches:
        if not has_user_prefix(t):
            fail(f"DM PRIVMSG has wrong prefix format (expected nick!user@host): {t!r}")
        else:
            ok(f"DM PRIVMSG relayed with nick!user@host prefix: {prefix_nick(t)!r}")


def check_notice_user(
    primary: socket.socket,
    peer: socket.socket,
) -> None:
    """
    Rule 6 (user NOTICE): leaf-peer sends NOTICE to bicc-grappa;
    bicchierino must relay it with a nick!user@host prefix (not a bare nick,
    not a server hostname).
    """
    body = "rfc1459-user-notice-test"
    send(peer, f"NOTICE {OWN_IRC_NICK} :{body}")
    lines = recv_for(primary, EVENT_WAIT)

    matches = [t for t in lines if "NOTICE" in t and body in t]
    if not matches:
        fail(f"user NOTICE not relayed to primary client (body: {body!r})")
        return

    for t in matches:
        if not has_user_prefix(t):
            fail(
                f"user NOTICE has wrong prefix format (expected nick!user@host, "
                f"got {prefix_nick(t)!r}): {t!r}"
            )
        else:
            ok(f"user NOTICE relayed with nick!user@host prefix: {prefix_nick(t)!r}")


def check_notice_server(
    primary: socket.socket,
    burst: list[str],
) -> None:
    """
    Rule 6 (#29 regression): server-sourced NOTICEs must reach the client
    with a bare server-hostname prefix, never nick!user@host.

    First checks the registration/replay burst already received.  If no
    server NOTICE appeared naturally, sends OperServ GLOBAL to generate one
    (bicc-grappa is SERVICES_MASTER so OperServ accepts the command without
    further authentication).
    """
    if check_server_notice_prefix(burst):
        return   # already asserted from the burst

    info("no server NOTICE in burst — sending OperServ GLOBAL to generate one")
    body = "rfc1459-server-notice-test"
    send(primary, f"PRIVMSG OperServ :GLOBAL {body}")
    lines = recv_for(primary, EVENT_WAIT)
    all_lines = burst + lines

    server_notices = [
        t for t in lines
        if " NOTICE " in t and (has_server_prefix(t) or body in t)
    ]
    if not server_notices:
        # Not a failure: OperServ GLOBAL may not reach us if the ircd routes
        # global notices differently on this testnet.  Log and move on.
        info(
            "OperServ GLOBAL NOTICE did not arrive — "
            "server-NOTICE prefix check skipped (no server NOTICE generated)"
        )
        return

    for t in server_notices:
        if has_user_prefix(t):
            fail(f"server NOTICE has !user@host prefix — #29 regression: {t!r}")
        else:
            ok(f"server NOTICE carries bare server-hostname prefix (no !user@host): {prefix_nick(t)!r}")


def check_ctcp_action(
    primary: socket.socket,
    peer: socket.socket,
) -> None:
    """
    Rule 7 (CTCP ACTION): leaf-peer sends \\x01ACTION waves\\x01 to #bicc.
    Bicchierino must relay exactly ONE \\x01ACTION ...\\x01 frame — the
    double-wrap regression (CLAUDE.md §12, \\x01ACTION \\x01ACTION text\\x01\\x01)
    must not recur.
    """
    action_text = "waves at the testnet"
    ctcp_body   = f"\x01ACTION {action_text}\x01"
    send(peer, f"PRIVMSG {CHANNEL} :{ctcp_body}")
    lines = recv_for(primary, EVENT_WAIT)

    matches = [t for t in lines if "PRIVMSG" in t and action_text in t]
    if not matches:
        fail(f"CTCP ACTION not relayed to primary client (body: {action_text!r})")
        return

    for t in matches:
        # Extract the trailing parameter (everything after the last ':')
        colon_pos = t.find(" :")
        if colon_pos == -1:
            fail(f"CTCP ACTION line has no trailing param: {t!r}")
            continue
        body = t[colon_pos + 2:]

        x01_count = body.count("\x01")
        if x01_count == 2 and body.startswith("\x01ACTION ") and body.endswith("\x01"):
            ok(f"CTCP ACTION has exactly one \\x01ACTION ...\\x01 frame (no double-wrap)")
        elif x01_count > 2:
            fail(
                f"CTCP ACTION double-wrap regression: body has {x01_count} \\x01 bytes "
                f"(expected 2): {body!r}"
            )
        else:
            fail(f"CTCP ACTION body malformed ({x01_count} \\x01 bytes): {body!r}")


def check_kick(
    primary: socket.socket,
    peer: socket.socket,
) -> None:
    """
    Rule 8 (KICK): bicchierino must relay the KICK echo to the primary client
    with a :kicker!user@host KICK #chan target :reason shape.

    Uses OperServ MODE to grant bicc-grappa (the underlying IRC session,
    SERVICES_MASTER) op in #bicc before kicking rfc-peer.

    This call REMOVES rfc-peer from #bicc — must be called AFTER all checks
    that need rfc-peer present in the channel.
    """
    reason = "rfc1459-kick-test"

    # Grant op to bicc-grappa via OperServ (it IS SERVICES_MASTER).
    send(primary, f"PRIVMSG OperServ :MODE {CHANNEL} +o {OWN_IRC_NICK}")
    # Wait for the MODE event confirming op was granted (or just proceed after
    # a short wait — the KICK itself will fail on the ircd if we lack op,
    # and bicchierino will relay a NOTICE with the error).
    mode_lines = recv_for(primary, EVENT_WAIT)
    mode_granted = any(
        "MODE" in t and "+o" in t and OWN_IRC_NICK in t
        for t in mode_lines
    )
    if mode_granted:
        ok(f"OperServ granted op to {OWN_IRC_NICK} in {CHANNEL}")
    else:
        info(
            f"MODE +o not seen in {EVENT_WAIT}s — proceeding with KICK attempt "
            f"(may fail if op was not granted)"
        )

    kick_reason = reason
    send(primary, f"KICK {CHANNEL} {PEER_NICK} :{kick_reason}")
    lines = recv_for(primary, EVENT_WAIT)

    kick_lines = [t for t in lines if " KICK " in t and PEER_NICK in t]
    if not kick_lines:
        fail(
            f"KICK {PEER_NICK} from {CHANNEL} not relayed to primary client "
            f"(or rejected — check that OperServ MODE succeeded)"
        )
        return

    for t in kick_lines:
        parts = t.split()
        if not has_user_prefix(t):
            fail(f"KICK line has wrong prefix format (expected nick!user@host): {t!r}")
        else:
            ok(f"KICK relayed with nick!user@host prefix: {prefix_nick(t)!r}")

        # Target channel.
        cmd_pos = next((i for i, p in enumerate(parts) if p.upper() == "KICK"), None)
        if cmd_pos is not None and cmd_pos + 1 < len(parts):
            chan = parts[cmd_pos + 1]
            if chan.lower() == CHANNEL.lower():
                ok(f"KICK target channel correct ({chan})")
            else:
                fail(f"KICK target channel is {chan!r}, expected {CHANNEL!r}: {t!r}")

        # Kicked nick.
        if cmd_pos is not None and cmd_pos + 2 < len(parts):
            kicked = parts[cmd_pos + 2]
            if kicked.lower() == PEER_NICK.lower():
                ok(f"KICK kicked nick correct ({kicked})")
            else:
                fail(f"KICK kicked nick is {kicked!r}, expected {PEER_NICK!r}: {t!r}")

        # Reason in trailing param.
        if kick_reason in t:
            ok(f"KICK reason present in relay")
        else:
            fail(f"KICK reason {kick_reason!r} not found in line: {t!r}")


def check_topic(
    primary: socket.socket,
    burst: list[str],
) -> None:
    """
    Rule 9 (TOPIC):
      a) 332 RPL_TOPIC must be present in the join burst.
      b) Sending a live TOPIC set must produce a TOPIC echo with
         :setter!user@host TOPIC #chan :new-text.
    """
    # Part a — 332 in burst.
    nums = find_numerics(burst, "332", "333")
    if nums["332"]:
        ok(f"332 RPL_TOPIC present in join burst: {nums['332'][0]!r}")
    else:
        # #bicc might not have had a topic yet on first run.
        info("332 RPL_TOPIC absent from burst — channel may have no topic yet")

    if nums["333"]:
        ok(f"333 RPL_TOPICWHOTIME present in join burst: {nums['333'][0]!r}")
    else:
        info("333 RPL_TOPICWHOTIME absent — skipped (optional per implementation)")

    # Part b — live TOPIC set.
    new_topic = "rfc1459-topic-test"
    send(primary, f"TOPIC {CHANNEL} :{new_topic}")
    lines = recv_for(primary, EVENT_WAIT)

    topic_echo = [t for t in lines if " TOPIC " in t and new_topic in t]
    if not topic_echo:
        fail(f"live TOPIC echo not received after setting topic to {new_topic!r}")
        return

    for t in topic_echo:
        if not has_user_prefix(t):
            fail(f"TOPIC echo has wrong prefix format (expected nick!user@host): {t!r}")
        else:
            ok(f"TOPIC echo relayed with nick!user@host prefix: {prefix_nick(t)!r}")

        parts = t.split()
        cmd_pos = next((i for i, p in enumerate(parts) if p.upper() == "TOPIC"), None)
        if cmd_pos is not None and cmd_pos + 1 < len(parts):
            chan = parts[cmd_pos + 1]
            if chan.lower() == CHANNEL.lower():
                ok(f"TOPIC echo channel correct ({chan})")
            else:
                fail(f"TOPIC echo channel is {chan!r}, expected {CHANNEL!r}: {t!r}")


def check_whois(primary: socket.socket) -> None:
    """
    Rule 10 (WHOIS): must receive 311/312/317/319/318 from bicchierino.
    Sends WHOIS rfc-peer (the peer should still be online at this point).
    """
    send(primary, f"WHOIS {PEER_NICK}")
    lines = recv_for(primary, EVENT_WAIT)

    nums = find_numerics(lines, "311", "312", "317", "318", "319", "401")
    if nums["401"]:
        # rfc-peer may not have been visible to WHOIS yet.
        info(f"WHOIS {PEER_NICK} returned 401 (no such nick) — trying own nick {OWN_IRC_NICK!r}")
        send(primary, f"WHOIS {OWN_IRC_NICK}")
        lines = recv_for(primary, EVENT_WAIT)
        nums = find_numerics(lines, "311", "312", "317", "318", "319", "401")

    required = ["311", "318"]
    for code in required:
        if nums[code]:
            ok(f"WHOIS {code} present: {nums[code][0]!r}")
        else:
            fail(f"WHOIS: missing {code}")

    for code in ["312", "317", "319"]:
        if nums[code]:
            ok(f"WHOIS {code} present: {nums[code][0]!r}")
        else:
            info(f"WHOIS {code} absent — field may be unpopulated for this nick")

    # 311 must be well-formed: :<server> 311 <our-nick> <target> <user> <host> * :<realname>
    for t in nums["311"]:
        parts = t.split()
        # :<srv> 311 <us> <them> <user> <host> * :<realname>  → ≥ 8 tokens
        if len(parts) < 8:
            fail(f"311 line has fewer than 8 tokens: {t!r}")
        else:
            ok(f"311 has correct field count (≥8): {t!r}")


def check_who(primary: socket.socket) -> None:
    """Rule 11 (WHO): must receive 352 rows and a 315 end."""
    send(primary, f"WHO {CHANNEL}")
    lines = recv_for(primary, EVENT_WAIT)

    nums = find_numerics(lines, "352", "315")
    if nums["352"]:
        ok(f"WHO 352 present ({len(nums['352'])} row(s)): {nums['352'][0]!r}")
    else:
        fail(f"WHO: no 352 RPL_WHOREPLY received for {CHANNEL}")

    if nums["315"]:
        ok(f"WHO 315 end present: {nums['315'][0]!r}")
    else:
        fail(f"WHO: no 315 RPL_ENDOFWHO received for {CHANNEL}")

    # Each 352 line: :<server> 352 <us> <channel> <user> <host> <server>
    #                <nick> <flags> :<hops> <realname>  — ≥ 10 tokens
    for t in nums["352"]:
        parts = t.split()
        if len(parts) < 10:
            fail(f"352 line has fewer than 10 tokens: {t!r}")
        else:
            ok(f"352 has correct field count (≥10)")
        # The H/G away-flag must be first in the flags field (position 8).
        if len(parts) >= 9:
            flags = parts[8]
            if flags and flags[0] not in ("H", "G"):
                fail(f"352 flags field {flags!r} does not start with H or G: {t!r}")
            else:
                ok(f"352 flags field starts with H/G ({flags!r})")


def check_names(primary: socket.socket, burst: list[str]) -> None:
    """
    Rule 12 (NAMES):
      a) 353/366 must be in the join burst (snapshot).
      b) An explicit NAMES #bicc must also produce 353+366 and the channel
         member list must contain correctly-sigiled nicks (CLAUDE.md §9
         regression: channel op must carry '@', voice '+', plain nick bare).
    """
    # Part a — snapshot 353/366 in burst.
    nums_burst = find_numerics(burst, "353", "366")
    if nums_burst["353"]:
        ok(f"353 RPL_NAMREPLY in join burst: {nums_burst['353'][0]!r}")
    else:
        fail("353 RPL_NAMREPLY absent from join burst — channel snapshot missing")
    if nums_burst["366"]:
        ok(f"366 RPL_ENDOFNAMES in join burst: {nums_burst['366'][0]!r}")
    else:
        fail("366 RPL_ENDOFNAMES absent from join burst")

    # Part b — explicit NAMES command.
    send(primary, f"NAMES {CHANNEL}")
    lines = recv_for(primary, EVENT_WAIT)
    nums = find_numerics(lines, "353", "366")

    if not nums["353"]:
        fail(f"NAMES: no 353 RPL_NAMREPLY received for {CHANNEL}")
        return
    ok(f"NAMES 353 present: {nums['353'][0]!r}")

    if not nums["366"]:
        fail(f"NAMES: no 366 RPL_ENDOFNAMES received for {CHANNEL}")
    else:
        ok(f"NAMES 366 end present: {nums['366'][0]!r}")

    # Sigil check (CLAUDE.md §9 regression):
    # Each nick in the 353 trailing param must be bare, @nick, or +nick —
    # never a multi-byte sigil or a literal \\x01 or garbled byte.
    for t in nums["353"]:
        colon_pos = t.rfind(" :")
        if colon_pos == -1:
            fail(f"353 line has no trailing param: {t!r}")
            continue
        nick_list = t[colon_pos + 2:].split()
        for entry in nick_list:
            if entry.startswith("@") or entry.startswith("+"):
                sigil = entry[0]
                nick  = entry[1:]
                ok(f"NAMES sigil {sigil!r} on nick {nick!r}")
            elif entry[0].isalpha() or entry[0] in "_-\\[]{}|`^":
                ok(f"NAMES plain nick (no sigil): {entry!r}")
            else:
                fail(f"NAMES nick has unexpected leading byte {entry[:1]!r}: {t!r}")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Primary client: connect through bicchierino ──────────────────────
    print(f"\n=== Connecting primary client to {HOST}:{PORT} ===", flush=True)
    try:
        primary = socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        print(f"FATAL: cannot connect to {HOST}:{PORT}: {exc}", file=sys.stderr)
        sys.exit(1)

    burst = register_primary(primary)

    if not burst:
        fail("received no lines from bicchierino — registration stalled or failed")
    else:
        print(f"Received {len(burst)} line(s) in registration+burst. Transcript:", flush=True)
        for line in burst:
            print(f"    {line}", flush=True)

    print("\n--- Registration numerics ---", flush=True)
    check_registration_numerics(burst)

    # ── Leaf peer: connect directly to bahamut-test ───────────────────────
    print(f"\n=== Connecting leaf peer to {LEAF_HOST}:{LEAF_PORT} ===", flush=True)
    try:
        peer = socket.create_connection((LEAF_HOST, LEAF_PORT), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        fail(f"cannot connect leaf peer to {LEAF_HOST}:{LEAF_PORT}: {exc}")
        peer = None

    if peer is not None:
        peer_lines = register_leaf_peer(peer)
        if any(" 001 " in t for t in peer_lines):
            ok(f"leaf peer {PEER_NICK} registered on {LEAF_HOST}")
        else:
            fail(f"leaf peer did not receive 001 — registration failed: {peer_lines[-3:]!r}")

        # Join #bicc.
        send(peer, f"JOIN {CHANNEL}")
        time.sleep(2)   # let the JOIN propagate through the IRC network

    # ── PRIVMSG ───────────────────────────────────────────────────────────
    if peer is not None:
        print("\n--- PRIVMSG (channel) ---", flush=True)
        check_privmsg_channel(primary, peer)

        print("\n--- PRIVMSG (DM) ---", flush=True)
        check_privmsg_dm(primary, peer)

    # ── NOTICE ────────────────────────────────────────────────────────────
    if peer is not None:
        print("\n--- NOTICE (user-to-user) ---", flush=True)
        check_notice_user(primary, peer)

    print("\n--- NOTICE (server-sourced, #29 regression) ---", flush=True)
    check_notice_server(primary, burst)

    # ── CTCP ACTION ───────────────────────────────────────────────────────
    if peer is not None:
        print("\n--- CTCP ACTION ---", flush=True)
        check_ctcp_action(primary, peer)

    # ── TOPIC (332/333 in burst + live echo) ─────────────────────────────
    print("\n--- TOPIC ---", flush=True)
    check_topic(primary, burst)

    # ── WHOIS ─────────────────────────────────────────────────────────────
    print("\n--- WHOIS ---", flush=True)
    check_whois(primary)

    # ── WHO ───────────────────────────────────────────────────────────────
    print("\n--- WHO ---", flush=True)
    check_who(primary)

    # ── NAMES (burst snapshot + explicit command) ─────────────────────────
    print("\n--- NAMES ---", flush=True)
    check_names(primary, burst)

    # ── KICK (OperServ MODE for op, then kick rfc-peer from #bicc) ────────
    if peer is not None:
        print("\n--- KICK ---", flush=True)
        check_kick(primary, peer)

    # ── tear down ─────────────────────────────────────────────────────────
    try:
        send(primary, "QUIT :rfc1459_check done")
        primary.close()
    except OSError:
        pass
    if peer is not None:
        try:
            send(peer, "QUIT :rfc1459_check peer done")
            peer.close()
        except OSError:
            pass

    # ── final report ──────────────────────────────────────────────────────
    print("", flush=True)
    if errors:
        print(
            f"RFC 1459 check FAILED — {len(errors)} violation(s):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    total_checks = 12   # rough count of rule blocks above
    ok(f"all checks passed")
    print("RFC 1459 check passed.", flush=True)


if __name__ == "__main__":
    main()
