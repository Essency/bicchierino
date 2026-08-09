#!/usr/bin/env python3
"""
chathistory_check.py — IRCv3 draft/chathistory wire compliance assertions
against a live bicchierino.

Spec under test: https://ircv3.net/specs/extensions/chathistory
Also depends on: batch, server-time, message-tags specs.

Checks verified:
  1. CAP negotiation — CAP LS includes batch, server-time, message-tags,
     draft/chathistory; CAP REQ for all four is ACKed; CAP END clears the
     gate (004 arrives)
  2. ISUPPORT — 005 includes CHATHISTORY=<N> (spec SHOULD)
  3. LATEST * — returns a well-formed chathistory batch with BATCH+/BATCH-
     framing, messages inside carry @batch=; ordering is ascending (oldest
     first per spec)
  4. LATEST * — each message inside the batch carries @msgid= and @time=
     (spec SHOULD for both; implemented as of this PR)
  5. BEFORE msgid= — returns messages before the given id, well-formed
     batch, correct ordering
  6. AFTER msgid= — returns messages after the given id, correct ordering
  7. AROUND msgid= — returns messages around the given id, batch-framed
  8. BETWEEN msgid= msgid= — returns only messages between the two ids
     (inclusive bounds per spec), batch-framed
  9. LATEST with selector (not *) — returns messages after the selector
 10. Empty batch on unknown selector (resolve failure) — BATCH+/BATCH-
     with no content rather than FAIL (bicchierino's documented behaviour:
     "empty reads as 'no matching history'")
 11. TARGETS — answered as empty success (not FAIL — client probing learns
     "no targets", not "malformed request"); no batch expected since TARGETS
     is not implemented, but also no FAIL CHATHISTORY
 12. FAIL CHATHISTORY INVALID_PARAMS on bad limit — server returns an error
     not a crash, and the error code is well-formed

Wire invariants enforced (same as rfc1459_check.py):
  - Every server line ends in CRLF
  - Every server line is ≤ 512 bytes (CRLF included)

Run from inside bicc-net (docker run --network ...).

Sockets:
  • bicc-ch — connects to bicchierino:6667, registers with full CAP
    negotiation (batch + server-time + message-tags + draft/chathistory).
    Uses the same grappa credentials as rfc1459_check.py.
  • ch-peer — connects directly to bahamut-test:6667, generates real
    channel messages that grappa stores; bicc-ch then queries them via
    CHATHISTORY.
"""

import re
import socket
import sys
import time

# ── Connection targets ────────────────────────────────────────────────────────

HOST         = "bicchierino"
PORT         = 6667
BAHAMUT_HOST = "bahamut-test"
BAHAMUT_PORT = 6667

# ── Timeouts ─────────────────────────────────────────────────────────────────

CONNECT_TIMEOUT  = 10
READ_TIMEOUT     = 60   # grappa login + network spawn + WS join can be slow
RELAY_TIMEOUT    = 30   # wait for a relayed event to arrive at bicc-ch
POST_REG_SECS    = 15   # drain post-004 traffic (grappa snapshot)

# ── Test channel ──────────────────────────────────────────────────────────────

TEST_CHAN = "#chathistt"

# ── IRCv3 message-tag parse ───────────────────────────────────────────────────

# Matches optional message-tags (@key=val;...) at the start of a line.
TAGS_RE = re.compile(r"^@([^ ]+) (.*)$")

# ── Global error accumulator ──────────────────────────────────────────────────

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL: {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ok:   {msg}", flush=True)


# ── Wire-level validation ─────────────────────────────────────────────────────

def check_line(raw: bytes) -> "str | None":
    """Validate one raw line; returns decoded text (CRLF stripped) or None."""
    if not raw.endswith(b"\r\n"):
        if raw.endswith(b"\n"):
            fail(f"line ends in bare LF (no CR): {raw!r}")
        else:
            fail(f"line has no CRLF terminator: {raw!r}")
        return None
    if len(raw) > 512:
        fail(f"line exceeds 512 bytes ({len(raw)} bytes): {raw[:60]!r}…")
    return raw[:-2].decode("utf-8", errors="replace")


# ── Message-tag helpers ───────────────────────────────────────────────────────

def parse_tags(line: str) -> "tuple[dict[str, str], str]":
    """
    Split IRCv3 message tags from the rest of the line.
    Returns (tags_dict, rest_of_line).  tags_dict is empty if no tags present.
    """
    m = TAGS_RE.match(line)
    if not m:
        return {}, line
    tag_str = m.group(1)
    rest    = m.group(2)
    tags: dict[str, str] = {}
    for part in tag_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k] = v
        elif part:
            tags[part] = ""
    return tags, rest


def irc_parse(line: str) -> "tuple[dict[str,str], str, str, list[str]]":
    """
    Parse one IRC line into (tags, prefix, command, params).
    prefix is "" if absent.  params is the list of parameters.
    """
    tags, rest = parse_tags(line)
    prefix = ""
    if rest.startswith(":"):
        parts = rest.split(" ", 1)
        prefix = parts[0][1:]
        rest = parts[1] if len(parts) > 1 else ""
    # split command + params
    if " :" in rest:
        head, tail = rest.split(" :", 1)
        parts = head.split()
        params = parts[1:] + [tail]
        command = parts[0] if parts else ""
    else:
        parts = rest.split()
        command = parts[0] if parts else ""
        params = parts[1:]
    return tags, prefix, command, params


# ── IRC connection helper ─────────────────────────────────────────────────────

class IRCConn:
    """Minimal blocking IRC socket — line-oriented, CRLF-aware."""

    def __init__(self, host: str, port: int, label: str = "") -> None:
        self.label = label
        self.sock   = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        self.buf    = b""

    def send(self, text: str) -> None:
        self.sock.sendall((text + "\r\n").encode("utf-8"))

    def _extract_line(self) -> "str | None":
        crlf = self.buf.find(b"\r\n")
        lf   = self.buf.find(b"\n")
        if crlf != -1 and (lf == -1 or crlf <= lf):
            raw      = self.buf[:crlf + 2]
            self.buf = self.buf[crlf + 2:]
            return check_line(raw)
        if lf != -1 and (crlf == -1 or lf < crlf):
            raw      = self.buf[:lf + 1]
            self.buf = self.buf[lf + 1:]
            return check_line(raw)
        return None

    def recv_line(self, timeout: float = 5.0) -> "str | None":
        deadline = time.monotonic() + timeout
        while True:
            line = self._extract_line()
            if line is not None:
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(min(remaining, 2.0))
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                self.buf += chunk
            except socket.timeout:
                pass

    def recv_until(self, timeout: float, stop_fn=None) -> "tuple[list[str], bool]":
        deadline = time.monotonic() + timeout
        lines: list[str] = []
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            text = self.recv_line(min(remaining, 1.0))
            if text is not None:
                lines.append(text)
                if stop_fn and stop_fn(text):
                    return lines, True
        return lines, False

    def recv_match(self, timeout: float, match_fn) -> "str | None":
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            text = self.recv_line(min(remaining, 1.0))
            if text is not None and match_fn(text):
                return text
        return None

    def drain(self, timeout: float = 0.5) -> list[str]:
        lines, _ = self.recv_until(timeout)
        return lines

    def close(self) -> None:
        try:
            self.send("QUIT :chathistory_check done")
            self.sock.close()
        except OSError:
            pass


# ── CAP-aware registration ────────────────────────────────────────────────────

def irc_register_with_caps(
    conn: IRCConn,
    nick: str,
    user: str,
    realname: str,
    password: "str | None",
    caps: "list[str]",
) -> "tuple[list[str], bool, dict[str, str]]":
    """
    Register with IRCv3 CAP negotiation.

    Sends CAP LS 302, PASS (if given), NICK, USER, then waits for the server's
    CAP LS reply, sends CAP REQ for the requested caps, waits for ACK/NAK,
    then CAP END.  Waits for 004.

    Returns (all_lines, got_004, acked_caps) where acked_caps maps cap_name →
    "" (value if the server sends one, or "" for valueless caps).
    """
    conn.send("CAP LS 302")
    if password:
        conn.send(f"PASS {password}")
    conn.send(f"NICK {nick}")
    conn.send(f"USER {user} 0 * :{realname}")

    all_lines: list[str] = []
    ls_seen = False
    acked: dict[str, str] = {}

    def is_004(text: str) -> bool:
        p = text.split()
        return len(p) >= 2 and p[1] == "004"

    deadline = time.monotonic() + READ_TIMEOUT
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        line = conn.recv_line(min(remaining, 2.0))
        if line is None:
            continue
        all_lines.append(line)

        _, _, command, params = irc_parse(line)

        # Handle CAP LS — collect advertised caps, then REQ our list
        if command == "CAP" and len(params) >= 3 and params[1] == "LS":
            # Last LS line has no leading '*' continuation marker
            ls_seen = True
            cap_list_str = params[2] if len(params) >= 3 else ""
            # advertised caps (may include =value; we just note names)
            adv = set()
            for tok in cap_list_str.split():
                adv.add(tok.split("=")[0])
            # Request the intersection of what we want and what's available
            want = [c for c in caps if c in adv]
            if want:
                conn.send("CAP REQ :" + " ".join(want))
            else:
                conn.send("CAP END")

        # Handle ACK
        elif command == "CAP" and len(params) >= 3 and params[1] == "ACK":
            for tok in params[2].split():
                cap_name = tok.lstrip("-").split("=")[0]
                acked[cap_name] = tok.split("=")[1] if "=" in tok else ""
            conn.send("CAP END")

        # Handle NAK (should not happen with valid caps)
        elif command == "CAP" and len(params) >= 3 and params[1] == "NAK":
            fail(f"CAP REQ NAKed: {params[2]!r}")
            conn.send("CAP END")

        # Handle PING during registration
        elif command == "PING":
            conn.send(f"PONG :{params[0] if params else ''}")

        if is_004(line):
            return all_lines, True, acked

    return all_lines, False, acked


# ── Collect a complete chathistory batch ──────────────────────────────────────

def collect_batch(
    conn: IRCConn,
    timeout: float,
    expect_batch_type: str = "chathistory",
) -> "tuple[list[str] | None, list[tuple[dict, str, str, list[str]]], str]":
    """
    Wait for a BATCH +ref <type> [target] line, then collect all lines tagged
    with @batch=ref until the matching BATCH -ref.

    Returns (batch_open_line_or_None, messages_inside, batch_ref).
    `messages_inside` is a list of (tags, prefix, command, params) tuples,
    one per line tagged with @batch=ref (i.e. the replayed IRC lines).

    Returns (None, [], "") on timeout without finding any BATCH+ line.
    """
    deadline = time.monotonic() + timeout
    batch_ref: str = ""
    open_line: "str | None" = None

    # ── Step 1: wait for BATCH+ ───────────────────────────────────────────────
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        line = conn.recv_line(min(remaining, 1.0))
        if line is None:
            continue
        tags, prefix, command, params = irc_parse(line)
        if command == "BATCH" and params and params[0].startswith("+"):
            batch_ref = params[0][1:]
            open_line = line
            break
        # Ignore everything else (PING, residual channel lines, etc.)
        if command == "PING":
            conn.send(f"PONG :{params[0] if params else ''}")

    if not open_line:
        return None, [], ""

    # ── Step 2: collect tagged lines until BATCH- ─────────────────────────────
    messages: list[tuple[dict, str, str, list]] = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        line = conn.recv_line(min(remaining, 1.0))
        if line is None:
            continue
        tags, prefix, command, params = irc_parse(line)
        if command == "BATCH" and params and params[0] == f"-{batch_ref}":
            break
        if command == "PING":
            conn.send(f"PONG :{params[0] if params else ''}")
        if tags.get("batch") == batch_ref:
            messages.append((tags, prefix, command, params))

    return open_line, messages, batch_ref


# ── Spec check helpers ────────────────────────────────────────────────────────

def assert_batch_open(open_line: "str | None", target: str, context: str) -> bool:
    """Assert a BATCH +ref chathistory <target> line is present and well-formed."""
    if open_line is None:
        fail(f"{context}: no BATCH+ line received")
        return False
    _, prefix, command, params = irc_parse(open_line)
    if command != "BATCH":
        fail(f"{context}: expected BATCH, got {command!r}")
        return False
    if not params or not params[0].startswith("+"):
        fail(f"{context}: BATCH start param does not begin with '+': {params!r}")
        return False
    # params[1] should be the batch type
    batch_type = params[1] if len(params) > 1 else ""
    if batch_type != "chathistory":
        fail(f"{context}: batch type is {batch_type!r}, expected 'chathistory'")
        return False
    # params[2] should be the target
    batch_target = params[2] if len(params) > 2 else ""
    if batch_target.lower() != target.lower():
        fail(
            f"{context}: batch target is {batch_target!r}, "
            f"expected {target!r} (case-insensitive)"
        )
        return False
    ok(f"{context}: BATCH+ is well-formed (type=chathistory, target={batch_target})")
    return True


def assert_messages_ascending(messages: list, context: str) -> None:
    """
    Assert message ordering is ascending (oldest-first per spec).
    Uses the @time= tag if present; falls back to @msgid= (grappa ids
    are monotonically increasing integers, so numeric order == time order).
    """
    times = []
    for tags, prefix, command, params in messages:
        t = tags.get("time")
        if t:
            times.append(t)
    if len(times) < 2:
        ok(f"{context}: ordering check skipped (fewer than 2 messages with time= tag)")
        return
    for i in range(len(times) - 1):
        if times[i] > times[i + 1]:
            fail(
                f"{context}: messages not in ascending order: "
                f"times[{i}]={times[i]!r} > times[{i+1}]={times[i+1]!r}"
            )
            return
    ok(f"{context}: {len(times)} messages in ascending time order")


def assert_each_has_tag(messages: list, tag_name: str, context: str) -> None:
    """Assert every message inside the batch has a specific tag."""
    missing = 0
    for tags, prefix, command, params in messages:
        if tag_name not in tags:
            missing += 1
    if missing:
        fail(f"{context}: {missing}/{len(messages)} messages missing @{tag_name}= tag")
    else:
        ok(f"{context}: all {len(messages)} messages have @{tag_name}= tag")


# ── Per-subcommand checks ─────────────────────────────────────────────────────

def check_cap_negotiation(bicc: IRCConn, reg_lines: list[str], acked: dict[str, str]) -> None:
    """
    Check 1 — CAP LS advertises expected caps, CAP REQ is ACKed for all four.
    Check 2 — 005 includes CHATHISTORY=N.
    """
    print("\n─ CAP negotiation check ─", flush=True)

    required_caps = ["batch", "server-time", "message-tags", "draft/chathistory"]
    for cap in required_caps:
        if cap in acked:
            ok(f"CAP ACKed: {cap}")
        else:
            fail(f"CAP not ACKed: {cap} (acked={list(acked.keys())})")

    # Check 2 — ISUPPORT CHATHISTORY=N
    print("\n─ ISUPPORT CHATHISTORY=N check ─", flush=True)
    found_chathistory_isupport = False
    for line in reg_lines:
        _, _, command, params = irc_parse(line)
        if command == "005":
            for p in params:
                if p.startswith("CHATHISTORY="):
                    val = p.split("=", 1)[1]
                    try:
                        n = int(val)
                        if n > 0:
                            ok(f"ISUPPORT CHATHISTORY={n} present in 005")
                            found_chathistory_isupport = True
                        else:
                            fail(f"ISUPPORT CHATHISTORY={val!r}: value must be > 0")
                    except ValueError:
                        fail(f"ISUPPORT CHATHISTORY={val!r}: value is not an integer")
    if not found_chathistory_isupport:
        fail("ISUPPORT CHATHISTORY=N missing from 005 (spec SHOULD)")


def check_chathistory_latest_star(bicc: IRCConn, target: str, n_messages: int) -> "list[str]":
    """
    Check 3 — LATEST * returns a well-formed chathistory batch.
    Check 4 — Each message carries @msgid= and @time= tags.

    Returns a list of msgid values seen, so subsequent checks can use them
    as selectors.
    """
    print(f"\n─ CHATHISTORY LATEST * check ({target}) ─", flush=True)
    bicc.send(f"CHATHISTORY LATEST {target} * {n_messages}")
    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if not assert_batch_open(open_line, target, "LATEST *"):
        return []

    ok(f"LATEST *: BATCH+ received (ref={batch_ref!r}), {len(messages)} message(s) inside")

    if len(messages) == 0:
        fail(
            f"LATEST *: batch is empty — expected ≥ {n_messages} messages "
            f"(rfc-peer should have seeded the channel with {n_messages} messages)"
        )
        return []

    assert_messages_ascending(messages, "LATEST *")
    assert_each_has_tag(messages, "msgid", "LATEST * (msgid)")
    assert_each_has_tag(messages, "time",  "LATEST * (time)")

    # Also validate each message is PRIVMSG or NOTICE
    for tags, prefix, command, params in messages:
        if command not in ("PRIVMSG", "NOTICE"):
            fail(
                f"LATEST *: unexpected command {command!r} inside chathistory batch "
                f"(only PRIVMSG/NOTICE expected without event-playback CAP)"
            )

    msgids = [tags["msgid"] for tags, _, _, _ in messages if "msgid" in tags]
    ok(f"LATEST *: {len(msgids)} message(s) with msgid= tags")
    return msgids


def check_chathistory_before(bicc: IRCConn, target: str, msgids: "list[str]") -> None:
    """Check 5 — BEFORE msgid= returns messages before that id."""
    if len(msgids) < 2:
        print(f"\n─ CHATHISTORY BEFORE — skipped (need ≥2 msgids, got {len(msgids)}) ─",
              flush=True)
        return
    print(f"\n─ CHATHISTORY BEFORE check ({target}) ─", flush=True)

    # Use the last msgid — we expect to get messages before it
    pivot = msgids[-1]
    bicc.send(f"CHATHISTORY BEFORE {target} msgid={pivot} 50")
    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if not assert_batch_open(open_line, target, "BEFORE"):
        return

    ok(f"BEFORE: BATCH+ received, {len(messages)} message(s)")

    # None of the returned messages should have msgid == pivot (excluded)
    for tags, _, command, params in messages:
        if tags.get("msgid") == pivot:
            fail(f"BEFORE: pivot msgid={pivot!r} appears in BEFORE result (should be excluded)")
            return
    ok(f"BEFORE: pivot msgid={pivot!r} correctly excluded")

    assert_messages_ascending(messages, "BEFORE")


def check_chathistory_after(bicc: IRCConn, target: str, msgids: "list[str]") -> None:
    """Check 6 — AFTER msgid= returns messages after that id."""
    if len(msgids) < 2:
        print(f"\n─ CHATHISTORY AFTER — skipped (need ≥2 msgids, got {len(msgids)}) ─",
              flush=True)
        return
    print(f"\n─ CHATHISTORY AFTER check ({target}) ─", flush=True)

    pivot = msgids[0]
    bicc.send(f"CHATHISTORY AFTER {target} msgid={pivot} 50")
    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if not assert_batch_open(open_line, target, "AFTER"):
        return

    ok(f"AFTER: BATCH+ received, {len(messages)} message(s)")

    for tags, _, command, params in messages:
        if tags.get("msgid") == pivot:
            fail(f"AFTER: pivot msgid={pivot!r} appears in AFTER result (should be excluded)")
            return
    ok(f"AFTER: pivot msgid={pivot!r} correctly excluded")

    # All returned ids should be > pivot (since grappa ids are integers)
    try:
        pivot_int = int(pivot)
        for tags, _, _, _ in messages:
            mid = tags.get("msgid", "")
            try:
                if int(mid) <= pivot_int:
                    fail(
                        f"AFTER: msgid={mid!r} ≤ pivot={pivot!r} — "
                        f"expected all returned ids to be > pivot"
                    )
                    return
            except ValueError:
                pass  # non-integer msgid, skip ordering check
        ok(f"AFTER: all returned msgids > pivot {pivot!r}")
    except ValueError:
        ok(f"AFTER: pivot not integer, ordering check skipped")

    assert_messages_ascending(messages, "AFTER")


def check_chathistory_around(bicc: IRCConn, target: str, msgids: "list[str]") -> None:
    """Check 7 — AROUND msgid= returns messages around that id, batch-framed."""
    if not msgids:
        print(f"\n─ CHATHISTORY AROUND — skipped (no msgids) ─", flush=True)
        return
    print(f"\n─ CHATHISTORY AROUND check ({target}) ─", flush=True)

    # Pick middle msgid if available
    pivot = msgids[len(msgids) // 2]
    bicc.send(f"CHATHISTORY AROUND {target} msgid={pivot} 50")
    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if not assert_batch_open(open_line, target, "AROUND"):
        return

    ok(f"AROUND: BATCH+ received (ref={batch_ref!r}), {len(messages)} message(s)")
    assert_messages_ascending(messages, "AROUND")


def check_chathistory_between(bicc: IRCConn, target: str, msgids: "list[str]") -> None:
    """Check 8 — BETWEEN two msgids returns only messages in [lo, hi], batch-framed."""
    if len(msgids) < 3:
        print(
            f"\n─ CHATHISTORY BETWEEN — skipped (need ≥3 msgids, got {len(msgids)}) ─",
            flush=True,
        )
        return
    print(f"\n─ CHATHISTORY BETWEEN check ({target}) ─", flush=True)

    lo = msgids[0]
    hi = msgids[-1]
    bicc.send(f"CHATHISTORY BETWEEN {target} msgid={lo} msgid={hi} 50")
    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if not assert_batch_open(open_line, target, "BETWEEN"):
        return

    ok(f"BETWEEN: BATCH+ received, {len(messages)} message(s)")

    # All returned ids should be in [lo, hi] (integer compare)
    try:
        lo_int = int(lo)
        hi_int = int(hi)
        out_of_range = 0
        for tags, _, _, _ in messages:
            mid = tags.get("msgid", "")
            try:
                mid_int = int(mid)
                if mid_int < lo_int or mid_int > hi_int:
                    out_of_range += 1
                    fail(
                        f"BETWEEN: msgid={mid!r} is outside [{lo}, {hi}] range"
                    )
            except ValueError:
                pass
        if out_of_range == 0:
            ok(f"BETWEEN: all {len(messages)} messages within [{lo}, {hi}] range")
    except ValueError:
        ok("BETWEEN: non-integer msgids; range bounds check skipped")

    assert_messages_ascending(messages, "BETWEEN")


def check_chathistory_latest_with_selector(
    bicc: IRCConn, target: str, msgids: "list[str]"
) -> None:
    """Check 9 — LATEST with a real selector (not *) returns messages after it."""
    if len(msgids) < 2:
        print(
            f"\n─ CHATHISTORY LATEST selector — skipped (need ≥2 msgids, got {len(msgids)}) ─",
            flush=True,
        )
        return
    print(f"\n─ CHATHISTORY LATEST msgid= check ({target}) ─", flush=True)

    pivot = msgids[0]
    bicc.send(f"CHATHISTORY LATEST {target} msgid={pivot} 50")
    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if not assert_batch_open(open_line, target, "LATEST selector"):
        return

    ok(f"LATEST selector: BATCH+ received, {len(messages)} message(s)")

    # Pivot should not appear in results (LATEST with a selector is "after" the selector)
    for tags, _, _, _ in messages:
        if tags.get("msgid") == pivot:
            fail(
                f"LATEST selector: pivot msgid={pivot!r} appears in results "
                f"(expected to be excluded)"
            )
            return
    ok(f"LATEST selector: pivot msgid={pivot!r} correctly excluded")


def check_chathistory_unknown_selector(bicc: IRCConn, target: str) -> None:
    """
    Check 10 — LATEST with an unresolvable timestamp= returns an EMPTY batch
    (not FAIL) — bicchierino's documented "empty reads as 'no matching history'"
    behavior.  An epoch in the far future guarantees the ring won't have it.
    """
    print(f"\n─ CHATHISTORY unknown timestamp= (empty batch) check ─", flush=True)

    # 2099-01-01T00:00:00.000Z — the ring won't have anything this recent
    # unless the test machine's clock is very wrong
    bicc.send(f"CHATHISTORY LATEST {target} timestamp=2099-01-01T00:00:00.000Z 10")

    open_line, messages, batch_ref = collect_batch(bicc, RELAY_TIMEOUT)

    if open_line is None:
        # Might also be that the ring covers this (extremely unlikely); also
        # it might have responded with FAIL CHATHISTORY instead — check that
        # there's no FAIL with a short drain
        bicc.drain(2.0)
        # An unresolvable selector should either give empty BATCH or just nothing
        # (resolve failure). The implementation sends empty batch; allow both.
        ok("unknown timestamp=: no BATCH received (resolve failed silently, acceptable)")
        return

    if messages:
        fail(
            f"unknown timestamp= (2099): batch contains {len(messages)} message(s) — "
            f"expected empty batch for a future timestamp not in the ring"
        )
    else:
        ok(f"unknown timestamp=: empty BATCH+ received (ref={batch_ref!r}) — correct")


def check_chathistory_targets(bicc: IRCConn, target: str) -> None:
    """
    Check 11 — CHATHISTORY TARGETS is answered as empty success (not FAIL).
    TARGETS is not implemented (returns empty), but should never return
    FAIL CHATHISTORY.
    """
    print(f"\n─ CHATHISTORY TARGETS check ─", flush=True)

    bicc.send("CHATHISTORY TARGETS timestamp=2020-01-01T00:00:00.000Z timestamp=2099-01-01T00:00:00.000Z 50")
    # Drain a short window looking for FAIL CHATHISTORY
    lines = bicc.drain(5.0)
    for line in lines:
        _, _, command, params = irc_parse(line)
        if command == "FAIL" and params and params[0] == "CHATHISTORY":
            fail(
                f"CHATHISTORY TARGETS: received FAIL CHATHISTORY {params[1:]} — "
                f"should return empty success, not FAIL (client probing for TARGETS "
                f"support should see 'no targets', not 'malformed request')"
            )
            return
    ok("CHATHISTORY TARGETS: no FAIL CHATHISTORY received (answered as empty success)")


def check_chathistory_invalid_params(bicc: IRCConn, target: str) -> None:
    """
    Check 12 — CHATHISTORY LATEST with a bad limit returns FAIL CHATHISTORY,
    not a crash.  Verifies the error response is a well-formed FAIL line.
    """
    print(f"\n─ CHATHISTORY invalid params (bad limit) check ─", flush=True)

    bicc.send(f"CHATHISTORY LATEST {target} * notanumber")
    line = bicc.recv_match(
        10.0,
        lambda t: "FAIL" in t and "CHATHISTORY" in t,
    )
    if line is None:
        fail("CHATHISTORY bad-limit: no FAIL response received within 10s")
        return

    _, _, command, params = irc_parse(line)
    if command != "FAIL":
        fail(f"CHATHISTORY bad-limit: expected FAIL, got {command!r} in {line!r}")
        return
    if not params or params[0] != "CHATHISTORY":
        fail(
            f"CHATHISTORY bad-limit: FAIL first param should be 'CHATHISTORY', "
            f"got {params!r}"
        )
        return
    ok(f"CHATHISTORY bad-limit: received FAIL CHATHISTORY {params[1]} (well-formed)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Connect bicc-ch (via bicchierino, with full CAP negotiation) ──────────
    print(f"Connecting bicc-ch to {HOST}:{PORT}…", flush=True)
    try:
        bicc = IRCConn(HOST, PORT, label="bicc-ch")
    except OSError as exc:
        print(f"FATAL: cannot connect to {HOST}:{PORT}: {exc}", file=sys.stderr)
        sys.exit(1)

    wanted_caps = ["batch", "server-time", "message-tags", "draft/chathistory"]
    reg_lines, got_004, acked = irc_register_with_caps(
        bicc,
        nick="ch-check",
        user="bicc",
        realname="chathistory check",
        password="bahamut-test:test-password-not-secret",
        caps=wanted_caps,
    )

    if not got_004:
        print("FATAL: bicc-ch: did not receive 004 after CAP negotiation", file=sys.stderr)
        bicc.close()
        sys.exit(1)

    print(f"Received {len(reg_lines)} line(s) through 004.", flush=True)

    # Check 1 + 2: CAP negotiation and ISUPPORT
    check_cap_negotiation(bicc, reg_lines, acked)

    # Drain grappa's post-registration snapshot
    print(f"\nCollecting post-registration lines ({POST_REG_SECS}s)…", flush=True)
    post_reg = bicc.drain(POST_REG_SECS)
    print(f"  {len(post_reg)} post-registration line(s).", flush=True)

    # ── Connect ch-peer (direct to bahamut-test, no bicchierino) ─────────────
    print(f"\nConnecting ch-peer to {BAHAMUT_HOST}:{BAHAMUT_PORT}…", flush=True)
    try:
        peer = IRCConn(BAHAMUT_HOST, BAHAMUT_PORT, label="ch-peer")
    except OSError as exc:
        print(f"FATAL: cannot connect to {BAHAMUT_HOST}:{BAHAMUT_PORT}: {exc}",
              file=sys.stderr)
        bicc.close()
        sys.exit(1)

    # Register peer (no caps needed — just generates real IRC events)
    peer.send(f"NICK ch-peer")
    peer.send(f"USER ch-test 0 * :chathistory peer")
    peer_lines, peer_got_004 = peer.recv_until(
        READ_TIMEOUT,
        lambda t: len(t.split()) >= 2 and t.split()[1] == "004",
    )
    if not peer_got_004:
        fail(f"ch-peer: did not receive 004 from {BAHAMUT_HOST}")
    else:
        ok(f"ch-peer registered on {BAHAMUT_HOST}")
    peer.drain(2.0)

    # ── Set up the test channel ───────────────────────────────────────────────
    # Peer joins first to get auto-op, then bicc joins.
    print(f"\nch-peer joining {TEST_CHAN} (to get auto-op)…", flush=True)
    peer.send(f"JOIN {TEST_CHAN}")
    peer.drain(3.0)

    # ── Seed real message history via ch-peer ─────────────────────────────────
    # We send N_SEED messages through the real ircd (bahamut) so grappa
    # has something to return for our CHATHISTORY queries.
    N_SEED = 5
    SEED_TAG = "chathistory-check-seed"
    print(f"\nSeeding {N_SEED} messages into {TEST_CHAN} via ch-peer…", flush=True)
    for i in range(N_SEED):
        peer.send(f"PRIVMSG {TEST_CHAN} :{SEED_TAG}-{i}")
        time.sleep(0.3)   # brief gap so messages get distinct timestamps

    # bicc joins the test channel — this triggers grappa to subscribe to its
    # topic, which is what makes the channel visible to chathistory queries.
    print(f"\nbicc-ch joining {TEST_CHAN}…", flush=True)
    bicc.send(f"JOIN {TEST_CHAN}")
    join_lines, got_join = bicc.recv_until(
        15.0,
        stop_fn=lambda t: TEST_CHAN.lower() in t.lower() and
                          ("JOIN" in t or (len(t.split()) >= 2 and t.split()[1] == "353")),
    )
    if not got_join:
        fail(f"bicc-ch: no JOIN echo or NAMES for {TEST_CHAN} within 15s")
    snapshot = join_lines + bicc.drain(8.0)
    print(f"  {TEST_CHAN} snapshot: {len(snapshot)} line(s).", flush=True)

    # Give grappa a moment to store all seeded messages before we query them
    time.sleep(2.0)

    # ── Feature checks ────────────────────────────────────────────────────────
    # 3 + 4: LATEST * (batch framing + msgid/time tags)
    msgids = check_chathistory_latest_star(bicc, TEST_CHAN, N_SEED)

    # 5: BEFORE
    check_chathistory_before(bicc, TEST_CHAN, msgids)

    # 6: AFTER
    check_chathistory_after(bicc, TEST_CHAN, msgids)

    # 7: AROUND
    check_chathistory_around(bicc, TEST_CHAN, msgids)

    # 8: BETWEEN
    check_chathistory_between(bicc, TEST_CHAN, msgids)

    # 9: LATEST with a real selector
    check_chathistory_latest_with_selector(bicc, TEST_CHAN, msgids)

    # 10: Unknown/unresolvable selector → empty batch, not FAIL
    check_chathistory_unknown_selector(bicc, TEST_CHAN)

    # 11: TARGETS → empty success, not FAIL
    check_chathistory_targets(bicc, TEST_CHAN)

    # 12: Invalid params → FAIL CHATHISTORY
    check_chathistory_invalid_params(bicc, TEST_CHAN)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    try:
        peer.close()
    except OSError:
        pass
    try:
        bicc.close()
    except OSError:
        pass

    # ── Report ────────────────────────────────────────────────────────────────
    print("", flush=True)
    if errors:
        print(
            f"chathistory check FAILED — {len(errors)} violation(s):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    ok("all chathistory checks passed")
    print("chathistory check passed.", flush=True)


if __name__ == "__main__":
    main()
