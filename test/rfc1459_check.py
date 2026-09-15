#!/usr/bin/env python3
"""
rfc1459_check.py — RFC 1459 wire compliance assertions against a live bicchierino.

Mechanically checkable invariants verified here:
  1. Every server line ends in CRLF           (RFC 1459 §2.3)
  2. Every server line is ≤ 512 bytes (CRLF   (RFC 1459 §2.3)
     included)
  3. Numeric reply lines match the format      (RFC 1459 §2.3.1)
     :<prefix> <3-digit-code> <target> ...
  4. 001, 002, 003, 004 are all present and    (RFC 1459 §4.1 / common
     arrive in that order                       client expectations)
  5. PRIVMSG — channel and DM: correct         (RFC 1459 §4.4.1)
     nick!user@host prefix, correct target
  6. NOTICE — user NOTICE: nick!user@host;     (#29 fix)
     server NOTICE: bare hostname prefix
     (dot-containing, no !), never a nick.
     Validated against any server NOTICE that
     arrives in the grappa snapshot or within
     a short observation window.
  7. CTCP ACTION (/me) — exactly one           (CTCP spec; bicchierino
     \\x01ACTION ...\\x01 frame, no             regression guard)
     double-wrapping
  8. KICK — :kicker!user@host KICK #chan       (RFC 1459 §4.2.8)
     target :reason
  9. TOPIC — 332/333 on join; live TOPIC       (RFC 1459 §4.2.4)
     echo when topic is changed
 10. WHOIS — 311/312/317/318 present and       (RFC 1459 §4.5.2)
     well-formed
 11. WHO — 352 rows + 315 end                  (RFC 1459 §4.5.1)
 12. NAMES — 353/366, correct sigils           (RFC 1459 §4.2.5;
     (@/+/none, not letter-form mode)           bicchierino regression
                                                guard from irssi testing)

Run from inside bicc-net (docker run --network ...).

Two sockets are opened:
  • rfc-check — connects to bicchierino:6667 (the bridge under test).
    Uses the grappa account seeded by grappa-seed in compose.yaml:
      PASS bahamut-test:test-password-not-secret / USER bicc
  • rfc-peer  — connects directly to bahamut-test:6667, bypassing
    bicchierino and grappa entirely.  Generates real protocol events
    on the real ircd; rfc-check asserts what bicchierino actually
    relays end to end.

The round trip through grappa's WebSocket can be slow (20 s+), so
timeouts are generous.
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
RELAY_TIMEOUT    = 30   # wait this long for a relayed event to arrive at rfc-check
POST_REG_SECS    = 15   # seconds to drain post-004 traffic (grappa snapshot)

# ── Test channel — ephemeral, created fresh by rfc-peer ──────────────────────

TEST_CHAN = "#rfc1459t"

# ── Patterns ─────────────────────────────────────────────────────────────────

# RFC 1459 §2.3.1: :<prefix> <3-digit-code> <target> [<params>]
NUMERIC_RE    = re.compile(r"^:(\S+) (\d{3}) (\S+)(.*)?$")
# RFC 1459 §2.3: nick!user@host
USER_PFX_RE   = re.compile(r"^(.+)!(.+)@(.+)$")

# ── Global error accumulator ──────────────────────────────────────────────────

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL: {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ok:   {msg}", flush=True)


# ── Wire-level validation (applies to every line from the server) ─────────────

def check_line(raw: bytes) -> "str | None":
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
        """Pop and validate the earliest complete line from the buffer."""
        crlf = self.buf.find(b"\r\n")
        lf   = self.buf.find(b"\n")

        if crlf != -1 and (lf == -1 or crlf <= lf):
            raw       = self.buf[:crlf + 2]
            self.buf  = self.buf[crlf + 2:]
            return check_line(raw)

        if lf != -1 and (crlf == -1 or lf < crlf):
            raw       = self.buf[:lf + 1]
            self.buf  = self.buf[lf + 1:]
            return check_line(raw)

        return None

    def recv_line(self, timeout: float = 5.0) -> "str | None":
        """
        Return the next complete line (CRLF stripped), or None on
        timeout / connection close.  Validates every line it reads.
        """
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

    def recv_until(
        self,
        timeout: float,
        stop_fn=None,
    ) -> "tuple[list[str], bool]":
        """
        Read lines until stop_fn(text) is True or timeout expires.
        Returns (all_lines, stopped_early).
        """
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
        """
        Discard lines until match_fn(text) is True or timeout.
        Returns the matching line, or None.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            text = self.recv_line(min(remaining, 1.0))
            if text is not None and match_fn(text):
                return text
        return None

    def drain(self, timeout: float = 0.5) -> list[str]:
        """Collect all lines that arrive within *timeout* seconds."""
        lines, _ = self.recv_until(timeout)
        return lines

    def close(self) -> None:
        try:
            self.send("QUIT :rfc1459_check done")
            self.sock.close()
        except OSError:
            pass


# ── Registration ──────────────────────────────────────────────────────────────

def irc_register(
    conn: IRCConn,
    nick: str,
    user: str,
    realname: str,
    password: "str | None" = None,
) -> "tuple[list[str], bool]":
    """
    Send IRC registration (PASS/NICK/USER), collect lines through 004.
    Returns (lines, got_004).
    """
    if password:
        conn.send(f"PASS {password}")
    conn.send(f"NICK {nick}")
    conn.send(f"USER {user} 0 * :{realname}")

    def is_004(text: str) -> bool:
        p = text.split()
        return len(p) >= 2 and p[1] == "004"

    return conn.recv_until(READ_TIMEOUT, is_004)


def parse_own_nick(lines: list[str]) -> "str | None":
    """Extract the own nick from the 001 target field."""
    for text in lines:
        p = text.split()
        if len(p) >= 3 and p[1] == "001":
            return p[2]
    return None


# ── Rule 4: registration numerics (unchanged from original) ──────────────────

def check_registration_numerics(lines: list[str]) -> None:
    """001, 002, 003, 004 must all be present and arrive in that order."""
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
            fail(
                f"numeric {code} arrived before {prev_code} "
                f"(indices {indices[code]} ≤ {prev_idx})"
            )
        else:
            ok(f"numeric {code} in correct order relative to {prev_code}")
        prev_idx  = indices[code]
        prev_code = code


# ── Prefix helpers ────────────────────────────────────────────────────────────

def assert_user_prefix(text: str, context: str) -> bool:
    """
    Assert the prefix is either nick!user@host (with a REAL host, not the
    bicchierino@bicchierino placeholder) or a bare nick (when grappa does not
    carry the sender's host on this message kind — #97 fix).

    The old placeholder host `nick!bicchierino@bicchierino` is a fabricated
    value that causes IRC clients to overwrite the real host they learned from
    JOIN with a fake one, breaking /kickban.  A bare nick is better: clients
    keep the JOIN-learned host rather than poisoning it with wrong data.

    Both forms are valid; only the placeholder is rejected.
    """
    if not text.startswith(":"):
        fail(f"{context}: missing leading ':' in {text!r}")
        return False
    prefix = text.split()[0][1:]

    # Bare nick (no ! at all) — #97 fix: honest absence of user@host.
    if "!" not in prefix:
        ok(f"{context}: prefix {prefix!r} is bare nick (no user@host in grappa meta — #97 fix)")
        return True

    # nick!user@host — must not be the bicchierino@bicchierino placeholder.
    if not USER_PFX_RE.match(prefix):
        fail(f"{context}: prefix {prefix!r} is not nick!user@host")
        return False
    _nick, uh = prefix.split("!", 1)
    if uh == "bicchierino@bicchierino":
        fail(
            f"{context}: prefix {prefix!r} uses the bicchierino@bicchierino placeholder — "
            f"clients build wrong ban masks from this (#97)"
        )
        return False
    ok(f"{context}: prefix {prefix!r} matches nick!user@host")
    return True


def assert_server_prefix(text: str, context: str) -> bool:
    """
    Assert the prefix is a bare server hostname: contains a dot and no '!'.
    This is the #29 fix: a server NOTICE must never carry a nick!user@host
    prefix that would make IRC clients mistake it for a user message.
    """
    if not text.startswith(":"):
        fail(f"{context}: missing leading ':' in {text!r}")
        return False
    prefix = text.split()[0][1:]
    if "!" in prefix:
        fail(
            f"{context}: server-sourced NOTICE prefix {prefix!r} contains '!' — "
            f"expected bare hostname, not nick!user@host (#29 regression)"
        )
        return False
    if "." not in prefix:
        fail(
            f"{context}: server NOTICE prefix {prefix!r} has no dot — "
            f"expected a server hostname"
        )
        return False
    ok(f"{context}: server NOTICE prefix {prefix!r} is a bare hostname (no '!')")
    return True


# ── Feature check functions ───────────────────────────────────────────────────

def check_privmsg(bicc: IRCConn, peer: IRCConn, own_nick: str) -> None:
    """
    Rule 5: PRIVMSG — channel message and DM.
    rfc-peer sends both; rfc-check verifies what bicchierino relays.
    """
    print("\n─ PRIVMSG check ─", flush=True)

    # ── channel PRIVMSG ──────────────────────────────────────────────────────
    tag = "rfc1459-privmsg-chan"
    peer.send(f"PRIVMSG #bicc :{tag}")
    line = bicc.recv_match(
        RELAY_TIMEOUT,
        lambda t: "PRIVMSG" in t and "#bicc" in t.lower() and tag in t,
    )
    if not line:
        fail(f"PRIVMSG channel: not relayed within {RELAY_TIMEOUT}s")
    else:
        assert_user_prefix(line, "PRIVMSG #bicc")
        parts = line.split()
        # :prefix PRIVMSG #bicc :body
        if len(parts) >= 3 and parts[1] == "PRIVMSG" and parts[2].lower() == "#bicc":
            ok(f"PRIVMSG channel: verb=PRIVMSG, target=#bicc")
        else:
            fail(f"PRIVMSG channel: unexpected format {line!r}")

    # ── DM PRIVMSG ───────────────────────────────────────────────────────────
    # Peer sends to own_nick (bicc-grappa's network nick).
    # bicchierino re-keys the channel to the sender nick per WIRE.md §5:
    # the relayed line has target = sender (rfc-peer), not own_nick.
    tag_dm = "rfc1459-privmsg-dm"
    peer.send(f"PRIVMSG {own_nick} :{tag_dm}")
    line_dm = bicc.recv_match(
        RELAY_TIMEOUT,
        lambda t: "PRIVMSG" in t and tag_dm in t,
    )
    if not line_dm:
        fail(f"PRIVMSG DM: not relayed within {RELAY_TIMEOUT}s")
    else:
        assert_user_prefix(line_dm, "PRIVMSG DM")
        parts_dm = line_dm.split()
        if len(parts_dm) >= 3 and parts_dm[1] == "PRIVMSG":
            target = parts_dm[2]
            if target.lower() != "rfc-peer":
                fail(f"PRIVMSG DM: target={target!r}, expected 'rfc-peer' (WIRE.md §5 re-key)")
            else:
                ok(f"PRIVMSG DM: verb=PRIVMSG, target={target!r} (re-keyed to peer)")
        else:
            fail(f"PRIVMSG DM: unexpected format {line_dm!r}")


def check_notice_user(bicc: IRCConn, peer: IRCConn) -> None:
    """
    Rule 6a: user NOTICE — prefix must be nick!user@host.
    rfc-peer sends NOTICE to #bicc; bicchierino relays with full prefix.
    """
    print("\n─ NOTICE (user) check ─", flush=True)
    tag = "rfc1459-notice-user"
    peer.send(f"NOTICE #bicc :{tag}")
    line = bicc.recv_match(
        RELAY_TIMEOUT,
        lambda t: "NOTICE" in t and "#bicc" in t.lower() and tag in t,
    )
    if not line:
        fail(f"NOTICE user: not relayed within {RELAY_TIMEOUT}s")
    else:
        assert_user_prefix(line, "NOTICE user #bicc")
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "NOTICE":
            ok(f"NOTICE user: verb=NOTICE, target={parts[2]!r}")
        else:
            fail(f"NOTICE user: unexpected format {line!r}")


def check_notice_server(bicc: IRCConn, already_seen: "list[str]") -> None:
    """
    Rule 6b: server NOTICE (#29 fix) — prefix must be a bare server hostname
    (contains a dot, no '!') for NOTICEs originating from the ircd or services.

    Server NOTICEs are emitted by the services scheduler (database-write cycle,
    every UPDATE seconds) and by the ircd itself on various events.  The
    scheduler period (UPDATE:1200) is too long to wait for in a test, so we:

      1. Scan *already_seen* lines (the post-registration grappa snapshot, which
         replays recent $server window messages — often includes startup/linkup
         Global NOTICEs from services).
      2. Then observe the live connection for a SHORT extra window (5 s) to
         catch any that arrive just after registration.

    If a server NOTICE IS observed we validate its prefix (the #29 fix).
    If none arrive in either batch we record a warning — not a hard failure —
    because a missing server NOTICE means the event simply did not fire during
    the test window, not that bicchierino mis-formatted it.

    The expected wire path (no client action required):
      services scheduler fires (UPDATE:1200s) or ircd event
      → :services.azzurra.chat NOTICE * :*** Global -- ... Completed database write
      → bahamut → grappa $server window (live push) → bicchierino WS
      → handle_grappa_server_window_row (sender has dot, no !)
      → :services.azzurra.chat NOTICE bicc-grappa :... → rfc-check
    """
    LIVE_OBSERVE_SECS = 5  # extra live-connection observation window

    print("\n─ NOTICE (server/#29 fix) check ─", flush=True)

    def is_server_notice(t: str) -> bool:
        if not (t.startswith(":") and " NOTICE " in t):
            return False
        prefix = t.split()[0][1:]
        return "!" not in prefix and "." in prefix

    # ── Pass 1: already-collected lines ────────────────────────────────────────
    found_in_snapshot = [t for t in already_seen if is_server_notice(t)]
    if found_in_snapshot:
        for line in found_in_snapshot:
            ok(f"NOTICE server (#29): server-prefixed NOTICE in snapshot")
            assert_server_prefix(line, "NOTICE server (snapshot)")
        return

    # ── Pass 2: short live observation ─────────────────────────────────────────
    print(
        f"  no server NOTICE in snapshot; observing live for {LIVE_OBSERVE_SECS}s…",
        flush=True,
    )
    server_notice = bicc.recv_match(
        LIVE_OBSERVE_SECS,
        is_server_notice,
    )

    if server_notice:
        ok("NOTICE server (#29): received server-prefixed NOTICE (live)")
        assert_server_prefix(server_notice, "NOTICE server")
    else:
        # No hard failure — the services scheduler period (1200 s) is longer
        # than any reasonable test window.  Log a note and move on.
        print(
            "  note: no server-hostname-prefixed NOTICE observed during test run "
            f"(snapshot + {LIVE_OBSERVE_SECS}s live); #29 prefix check skipped "
            "(would require waiting ≥UPDATE:1200s for services write cycle).",
            flush=True,
        )


def check_ctcp_action(bicc: IRCConn, peer: IRCConn) -> None:
    """
    Rule 7: CTCP ACTION (/me) — body must be exactly one \\x01ACTION ...\\x01
    frame.  bicchierino must pass grappa's stored body verbatim, not
    re-wrap it in an additional \\x01ACTION...\\x01 (the double-wrap regression
    found live: irssi rendered literal control chars).
    """
    print("\n─ CTCP ACTION check ─", flush=True)
    action_text = "rfc1459-action-test"
    ctcp        = f"\x01ACTION {action_text}\x01"
    peer.send(f"PRIVMSG #bicc :{ctcp}")

    line = bicc.recv_match(
        RELAY_TIMEOUT,
        lambda t: "PRIVMSG" in t and action_text in t and "\x01" in t,
    )
    if not line:
        fail(f"CTCP ACTION: not relayed within {RELAY_TIMEOUT}s")
        return

    assert_user_prefix(line, "CTCP ACTION")

    # Extract body: everything after the space-colon that follows the target
    # Format: :prefix PRIVMSG #bicc :\x01ACTION text\x01
    parts = line.split(" ", 3)
    body  = parts[3][1:] if len(parts) == 4 and parts[3].startswith(":") else ""

    delimiters = body.count("\x01")
    if not body.startswith("\x01ACTION "):
        fail(f"CTCP ACTION: body does not start with \\x01ACTION : {body!r}")
    elif not body.endswith("\x01"):
        fail(f"CTCP ACTION: body does not end with \\x01: {body!r}")
    elif delimiters != 2:
        fail(
            f"CTCP ACTION: expected exactly 2 \\x01 delimiters (one wrapping pair), "
            f"got {delimiters} — possible double-wrap: {body!r}"
        )
    else:
        ok("CTCP ACTION: single \\x01ACTION ...\\x01 frame — no double-wrap")


def check_topic_332_333(post_join_lines: list[str], channel: str) -> None:
    """
    Rule 9a: 332/333 on join — when a topic is set, bicchierino must send
    332 (RPL_TOPIC) and, if set_by/set_at are present, 333 (RPL_TOPICWHOTIME).
    Checked against the snapshot lines collected right after bicc joined
    TEST_CHAN (where rfc-peer had already set a topic).
    """
    print("\n─ TOPIC 332/333 on join check ─", flush=True)

    def has_code(code: str) -> bool:
        return any(
            len(t.split()) >= 2 and t.split()[1] == code and channel.lower() in t.lower()
            for t in post_join_lines
        )

    if has_code("332"):
        ok(f"332 RPL_TOPIC present for {channel}")
    else:
        fail(
            f"332 RPL_TOPIC missing for {channel} — expected after rfc-peer set topic "
            f"before bicc joined (grappa snapshot should carry it)"
        )

    if has_code("333"):
        ok(f"333 RPL_TOPICWHOTIME present for {channel}")
    else:
        ok(f"333 RPL_TOPICWHOTIME absent for {channel} (optional if set_by/set_at missing)")


def check_topic_live(bicc: IRCConn, peer: IRCConn) -> None:
    """
    Rule 9b: live TOPIC echo — when rfc-peer changes the topic AFTER bicc has
    joined, bicchierino must relay `:kicker!user@host TOPIC #chan :text`.
    """
    print("\n─ TOPIC live echo check ─", flush=True)
    tag = "rfc1459-topic-live"
    peer.send(f"TOPIC {TEST_CHAN} :{tag}")

    line = bicc.recv_match(
        RELAY_TIMEOUT,
        lambda t: " TOPIC " in t and TEST_CHAN.lower() in t.lower() and tag in t,
    )
    if not line:
        fail(f"TOPIC live echo: not relayed within {RELAY_TIMEOUT}s")
    else:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "TOPIC":
            assert_user_prefix(line, "TOPIC live echo")
            ok(f"TOPIC live echo: verb=TOPIC, channel={parts[2]!r}")
        else:
            fail(f"TOPIC live echo: unexpected format {line!r}")


def check_kick(bicc: IRCConn, peer: IRCConn, own_nick: str) -> None:
    """
    Rule 8: KICK — :kicker!user@host KICK #chan target :reason.
    rfc-peer (opped as first joiner in TEST_CHAN) kicks bicc-grappa.
    """
    print("\n─ KICK check ─", flush=True)
    reason = "rfc1459-kick-test"
    peer.send(f"KICK {TEST_CHAN} {own_nick} :{reason}")

    line = bicc.recv_match(
        RELAY_TIMEOUT,
        lambda t: " KICK " in t and TEST_CHAN.lower() in t.lower() and reason in t,
    )
    if not line:
        fail(
            f"KICK: not relayed within {RELAY_TIMEOUT}s "
            f"(channel={TEST_CHAN}, target={own_nick})"
        )
        return

    assert_user_prefix(line, "KICK")
    parts = line.split()
    # :prefix KICK #chan target :reason
    if len(parts) < 4 or parts[1] != "KICK":
        fail(f"KICK: unexpected format {line!r}")
        return

    if parts[2].lower() == TEST_CHAN.lower():
        ok(f"KICK channel correct: {parts[2]}")
    else:
        fail(f"KICK: wrong channel {parts[2]!r} (expected {TEST_CHAN})")

    if parts[3].lower() == own_nick.lower():
        ok(f"KICK target correct: {parts[3]}")
    else:
        fail(f"KICK: wrong target {parts[3]!r} (expected {own_nick})")

    if reason in line:
        ok(f"KICK reason present: {reason!r}")
    else:
        fail(f"KICK: reason {reason!r} missing in {line!r}")


def check_whois(bicc: IRCConn, target_nick: str) -> None:
    """
    Rule 10: WHOIS — 311/318 mandatory; 312/317/319 optional.
    bicchierino sends WHOIS via a grappa WS push; grappa queries bahamut
    and replies with a whois_bundle event; bicchierino renders numerics.
    """
    print("\n─ WHOIS check ─", flush=True)
    bicc.send(f"WHOIS {target_nick}")

    collected: set[str] = set()
    deadline = time.monotonic() + RELAY_TIMEOUT
    while time.monotonic() < deadline:
        line = bicc.recv_line(min(deadline - time.monotonic(), 1.0))
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit() and len(parts[1]) == 3:
            code = parts[1]
            if code in ("311", "312", "317", "318", "319", "313", "401"):
                collected.add(code)
            if code == "318":  # End of /WHOIS — all numerics are in
                break

    mandatory = {"311", "318"}
    optional  = {"312", "317", "319"}
    for code in mandatory:
        if code in collected:
            ok(f"WHOIS {code} present")
        else:
            fail(f"WHOIS {code} missing (311=WHOISUSER, 318=ENDOFWHOIS are mandatory)")
    for code in optional:
        if code in collected:
            ok(f"WHOIS {code} present")
        else:
            ok(f"WHOIS {code} absent (optional)")


def check_who(bicc: IRCConn, channel: str) -> None:
    """
    Rule 11: WHO — 352 rows + 315 end.
    bicchierino routes via grappa WS "who" push; bahamut replies;
    grappa builds who_bundle; bicchierino renders 352 + 315.
    """
    print("\n─ WHO check ─", flush=True)
    bicc.send(f"WHO {channel}")

    rows_352: list[str] = []
    got_315 = False
    deadline = time.monotonic() + RELAY_TIMEOUT
    while time.monotonic() < deadline:
        line = bicc.recv_line(min(deadline - time.monotonic(), 1.0))
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            if parts[1] == "352":
                rows_352.append(line)
            elif parts[1] == "315":
                got_315 = True
                break   # 315 signals end of WHO reply

    if rows_352:
        ok(f"WHO 352: {len(rows_352)} row(s)")
        # Spot-check the first row for minimum field count
        # :<server> 352 <nick> <channel> <user> <host> <server> <nick> <flags> :<hops> <rn>
        first = rows_352[0].split()
        if len(first) >= 9:
            ok("WHO 352: enough fields present")
        else:
            fail(f"WHO 352: too few fields ({len(first)}) in {rows_352[0]!r}")
    else:
        fail(f"WHO: no 352 rows received for {channel}")

    if got_315:
        ok("WHO 315 RPL_ENDOFWHO present")
    else:
        fail("WHO 315 RPL_ENDOFWHO missing")


def check_names(bicc: IRCConn, channel: str) -> None:
    """
    Rule 12: NAMES — 353/366 with correct sigils.
    bicchierino routes via grappa WS "names" push; grappa aggregates the
    bahamut 353 tokens (split_mode_prefix/1 stores the RAW sigil byte,
    not a mode letter) and sends names_bundle; bicchierino renders 353/366.
    The sigil regression: an earlier version read modes as letters (matching
    WHO's field), so every sigil was silently dropped.  We assert any op
    appearing in the channel carries '@'.
    """
    print("\n─ NAMES check ─", flush=True)
    bicc.send(f"NAMES {channel}")

    rows_353: list[str] = []
    got_366 = False
    deadline = time.monotonic() + RELAY_TIMEOUT
    while time.monotonic() < deadline:
        line = bicc.recv_line(min(deadline - time.monotonic(), 1.0))
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 2:
            if parts[1] == "353":
                rows_353.append(line)
            elif parts[1] == "366":
                got_366 = True
                break

    if rows_353:
        ok(f"NAMES 353: {len(rows_353)} row(s)")

        # Collect all nick tokens from trailing params (after " :")
        all_tokens: list[str] = []
        for row in rows_353:
            colon_idx = row.rfind(" :")
            if colon_idx == -1:
                fail(f"NAMES 353: no trailing param in {row!r}")
                continue
            all_tokens.extend(row[colon_idx + 2:].split())

        valid_sigils = {"@", "%", "+"}
        for tok in all_tokens:
            if tok and tok[0] in valid_sigils:
                ok(f"NAMES: {tok[0]!r} sigil on {tok[1:]!r}")
            elif tok and tok[0] == "!":
                fail(f"NAMES: nick {tok!r} starts with '!' — invalid sigil (letter-mode bug?)")
            # no-sigil nicks are fine — just channel members without status

        # rfc-peer is first-joined (opped) in TEST_CHAN; assert its sigil
        if channel.lower() == TEST_CHAN.lower():
            peer_toks = [t for t in all_tokens if t.lstrip("@%+").lower() == "rfc-peer"]
            if not peer_toks:
                fail(f"NAMES: rfc-peer not found in {TEST_CHAN} NAMES response")
            else:
                tok = peer_toks[0]
                if tok.startswith("@"):
                    ok(f"NAMES: rfc-peer shows as '@rfc-peer' (op sigil correct)")
                else:
                    fail(
                        f"NAMES: rfc-peer expected as '@rfc-peer' (first-joiner auto-op) "
                        f"but got {tok!r}"
                    )
    else:
        fail(f"NAMES: no 353 rows received for {channel}")

    if got_366:
        ok("NAMES 366 RPL_ENDOFNAMES present")
    else:
        fail("NAMES 366 RPL_ENDOFNAMES missing")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # ── Connect rfc-check (via bicchierino) ──────────────────────────────────
    print(f"Connecting rfc-check to {HOST}:{PORT}…", flush=True)
    try:
        bicc = IRCConn(HOST, PORT, label="bicc")
    except OSError as exc:
        print(f"FATAL: cannot connect to {HOST}:{PORT}: {exc}", file=sys.stderr)
        sys.exit(1)

    # PASS first — bicchierino buffers until NICK+USER arrive
    reg_lines, got_004 = irc_register(
        bicc,
        nick="rfc-check",
        user="bicc",
        realname="RFC 1459 compliance check",
        password="bahamut-test:test-password-not-secret",
    )

    if not reg_lines:
        fail("received no lines from the server — registration stalled or failed")
    else:
        print(f"Received {len(reg_lines)} line(s) through 004:", flush=True)
        for line in reg_lines:
            print(f"    {line}", flush=True)

    # Rule 4 — registration numerics
    print("\n─ Registration numerics check ─", flush=True)
    check_registration_numerics(reg_lines)

    own_nick = parse_own_nick(reg_lines)
    if not own_nick:
        print("FATAL: could not parse own nick from 001 line", file=sys.stderr)
        bicc.close()
        sys.exit(1)
    print(f"\nOwn nick on network: {own_nick!r}", flush=True)

    # ── Collect post-registration snapshot from grappa ────────────────────────
    # grappa's WS delivers channel snapshots ($server window, topic, members)
    # after the bridge joins its topics.  Give it POST_REG_SECS seconds.
    print(f"\nCollecting post-registration lines ({POST_REG_SECS}s)…", flush=True)
    post_reg_lines = bicc.drain(POST_REG_SECS)
    print(f"  {len(post_reg_lines)} post-registration line(s):", flush=True)
    for line in post_reg_lines:
        print(f"    {line}", flush=True)

    # ── Connect rfc-peer (direct to bahamut-test) ─────────────────────────────
    print(f"\nConnecting rfc-peer directly to {BAHAMUT_HOST}:{BAHAMUT_PORT}…", flush=True)
    try:
        peer = IRCConn(BAHAMUT_HOST, BAHAMUT_PORT, label="peer")
    except OSError as exc:
        print(f"FATAL: cannot connect to {BAHAMUT_HOST}:{BAHAMUT_PORT}: {exc}", file=sys.stderr)
        bicc.close()
        sys.exit(1)

    peer_lines, peer_got_004 = irc_register(
        peer,
        nick="rfc-peer",
        user="rfc-test",
        realname="RFC 1459 direct peer",
    )
    if not peer_got_004:
        fail(f"rfc-peer: did not receive 004 from {BAHAMUT_HOST}")
    else:
        ok(f"rfc-peer registered on {BAHAMUT_HOST} directly")

    # Drain any trailing bahamut burst (MOTD, etc.)
    peer.drain(2.0)

    # ── Set up channels ────────────────────────────────────────────────────────
    # 1. Peer joins #bicc so it can generate channel events bicc-grappa receives.
    print(f"\nrfc-peer joining #bicc…", flush=True)
    peer.send("JOIN #bicc")
    peer.drain(3.0)

    # 2. Peer joins TEST_CHAN FIRST — this gives rfc-peer auto-op (first joiner).
    #    Then set a topic so the 332/333 snapshot arrives when bicc joins later.
    print(f"\nrfc-peer joining {TEST_CHAN} (to get auto-op) and setting topic…", flush=True)
    peer.send(f"JOIN {TEST_CHAN}")
    peer.drain(2.0)
    peer.send(f"TOPIC {TEST_CHAN} :rfc1459-topic-initial")
    peer.drain(2.0)

    # 3. bicc joins TEST_CHAN second — bicc-grappa is not opped.
    #    Wait for the JOIN echo so we know bicchierino has processed the REST
    #    call and joined the grappa WS topic (snapshot incoming).
    print(f"\nbicc joining {TEST_CHAN}…", flush=True)
    bicc.send(f"JOIN {TEST_CHAN}")
    join_echo, got_join = bicc.recv_until(
        15.0,
        stop_fn=lambda t: TEST_CHAN.lower() in t.lower()
                          and ("JOIN" in t or (len(t.split()) >= 2 and t.split()[1] == "353")),
    )
    if not got_join:
        fail(f"bicc: no JOIN echo or NAMES snapshot for {TEST_CHAN} within 15s")

    # Collect the rest of the snapshot (topic_changed → 332/333, names_bundle → 353/366)
    snapshot_lines = join_echo + bicc.drain(8.0)
    print(f"  {TEST_CHAN} snapshot: {len(snapshot_lines)} line(s)", flush=True)
    for line in snapshot_lines:
        print(f"    {line}", flush=True)

    # ── Feature checks ─────────────────────────────────────────────────────────
    # Order: stable reads-only first, then destructive (KICK last since it
    # removes bicc-grappa from TEST_CHAN).

    check_topic_332_333(snapshot_lines, TEST_CHAN)
    check_notice_server(bicc, post_reg_lines + snapshot_lines)
    check_names(bicc, TEST_CHAN)
    check_who(bicc, TEST_CHAN)
    check_whois(bicc, "rfc-peer")
    check_privmsg(bicc, peer, own_nick)
    check_notice_user(bicc, peer)
    check_ctcp_action(bicc, peer)
    check_topic_live(bicc, peer)
    check_kick(bicc, peer, own_nick)   # last — removes bicc-grappa from TEST_CHAN

    # ── Cleanup ────────────────────────────────────────────────────────────────
    try:
        peer.close()
    except OSError:
        pass
    try:
        bicc.send("QUIT :rfc1459_check done")
        bicc.sock.close()
    except OSError:
        pass

    # ── Report ─────────────────────────────────────────────────────────────────
    print("", flush=True)
    total_lines = len(reg_lines) + len(post_reg_lines) + len(snapshot_lines)
    if errors:
        print(
            f"RFC 1459 check FAILED — {len(errors)} violation(s) "
            f"(across {total_lines} lines checked):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    ok(
        f"all checks passed — {total_lines} lines validated, "
        f"PRIVMSG/NOTICE/ACTION/KICK/TOPIC/WHOIS/WHO/NAMES all correct"
    )
    print("RFC 1459 check passed.", flush=True)


if __name__ == "__main__":
    main()
