#!/usr/bin/env python3
"""
raw_passthrough_check.py — Regression for bicchierino issue #101.

handle_raw MUST forward the client's original IRC line verbatim to the
upstream ircd.  Under the pre-fix code, bicchierino would parse the line
into at most IRC_MAX_PARAMS (15) tokens and reconstruct a shorter line,
silently discarding any tokens beyond the 15th.

Anatomy of the test line (why bahamut + services cooperate end-to-end):

  OS TAGLINE ADD a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19

  Command:  OS
  bicchierino-side token count after command: 22 (TAGLINE + ADD + a0..a19)
  IRC_MAX_PARAMS = 15 → old code stopped here, losing a13..a19.

  bahamut's m_os has parameters=1 in its message table.  When parse()
  hits that limit, it breaks out of the param-collection loop WITHOUT
  advancing past the current token — so parv[1] ends up pointing to the
  entire unsplit remainder "TAGLINE ADD a0 a1 ... a19", not just the
  first word "TAGLINE".  m_os then sends:

    :<nick> PRIVMSG OperServ@services.azzurra.chat :TAGLINE ADD a0 ... a19

  services' m_privmsg → operserv() → handle_tagline parses that text
  with strtok(NULL, "") (capturing everything after ADD) and emits:

    GLOBOPS :**bicc-grappa** added the following tagline: a0 a1 ... a19

  bahamut receives the GLOBOPS and relays it to all local IRC opers as:

    :<server> NOTICE <nick> :*** Global -- from services.azzurra.chat: …

  The bicc-raw socket (= the bicc-grappa network identity) is an oper
  (after /OPER) and therefore receives this NOTICE.

  Under the pre-fix code the tagline text would end at a12 (params[14]
  in bicchierino's 0-indexed array, the 15th slot); with the fix, all 20
  words arrive and "a19" is present.

Auth setup:
  bicc-raw connects to bicchierino as the grappa account (PASS
  bahamut-test:test-password-not-secret), becoming bicc-grappa on the
  network.  bicc-grappa is SERVICES_MASTER (compose.yaml overrides the
  testnet default), so services gives it ULEVEL_MASTER — above the
  ULEVEL_SOP required by OS TAGLINE.  But m_privmsg in services also
  requires the IRC-oper umode (+o) before calling operserv(), so the
  test OPERs first.

  The sealed testnet always has an O:line for the oper name "testoper"
  with password "testoperpass" (OPER_NICK/OPER_PASS testnet defaults,
  not overridden by the bicchierino compose.yaml).

  raw-peer connects directly to bahamut-test:6667, OPERs as "testoper"
  as well, and serves as a second independent observation point for the
  GLOBOPS — it arrives at both sockets.

Run from inside bicc-net (docker run --network ...).
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
RELAY_TIMEOUT    = 30   # grappa round-trip can be slow (WS + Phoenix Channels)
POST_REG_SECS    = 8    # seconds to drain post-004 burst before OPER
POST_OPER_WAIT   = 3.0  # seconds to wait for UMODE +o to propagate to services
GLOBOPS_TIMEOUT  = 20.0 # wait this long for the GLOBOPS NOTICE

# ── The raw line under test ───────────────────────────────────────────────────
# 20 words after the verb (a0..a19) = 22 tokens total after "OS"
# (TAGLINE + ADD + 20 words), well past IRC_MAX_PARAMS=15.
TOKENS       = [f"a{i}" for i in range(20)]
TAGLINE_TEXT = " ".join(TOKENS)          # "a0 a1 a2 … a19"
RAW_LINE     = f"OS TAGLINE ADD {TAGLINE_TEXT}"

# ── Wire-level patterns ───────────────────────────────────────────────────────

NUMERIC_RE = re.compile(r"^:(\S+) (\d{3}) (\S+)(.*)?$")

# ── Global error accumulator ──────────────────────────────────────────────────

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL: {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ok:   {msg}", flush=True)


# ── Wire-level line validation ────────────────────────────────────────────────

def check_line(raw: bytes) -> "str | None":
    """Validate one raw line; return decoded text (no CRLF) or None."""
    if not raw.endswith(b"\r\n"):
        if raw.endswith(b"\n"):
            fail(f"line ends in bare LF (no CR): {raw!r}")
        else:
            fail(f"line has no CRLF terminator: {raw!r}")
        return None

    if len(raw) > 512:
        fail(f"line exceeds 512 bytes ({len(raw)} bytes): {raw[:60]!r}…")

    text = raw[:-2].decode("utf-8", errors="replace")

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


# ── IRCConn — same pattern as rfc1459_check.py ───────────────────────────────

class IRCConn:
    """Minimal blocking IRC socket — line-oriented, CRLF-aware."""

    def __init__(self, host: str, port: int, label: str = "") -> None:
        self.label = label
        self.sock  = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        self.buf   = b""

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

    def recv_until(
        self,
        timeout: float,
        stop_fn=None,
    ) -> "tuple[list[str], bool]":
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
            self.sock.close()
        except Exception:
            pass


# ── IRC helpers ───────────────────────────────────────────────────────────────

def irc_register(
    conn: IRCConn,
    nick: str,
    user: str,
    realname: str,
    password: str = "",
) -> "tuple[list[str], bool]":
    """Send PASS/NICK/USER; collect lines through 004.  Return (lines, got_004)."""
    if password:
        conn.send(f"PASS {password}")
    conn.send(f"NICK {nick}")
    conn.send(f"USER {user} 0 * :{realname}")

    lines: list[str] = []
    got_004 = False
    while True:
        text = conn.recv_line(timeout=60.0)
        if text is None:
            break
        # respond to PING during registration
        parts = text.split()
        if parts and parts[0] == "PING":
            conn.send(f"PONG :{parts[1] if len(parts) > 1 else 'x'}")
            continue
        lines.append(text)
        if len(parts) >= 2 and parts[1] == "004":
            got_004 = True
            break

    return lines, got_004


def strip_irc_formatting(text: str) -> str:
    """Remove IRC colour/bold/underline control codes."""
    return re.sub(r"[\x02\x03\x0f\x16\x1d\x1f](?:\d{1,2}(?:,\d{1,2})?)?", "", text)


# ── Test checks ───────────────────────────────────────────────────────────────

def check_globops(globops_line: str) -> None:
    """
    Assert that the GLOBOPS NOTICE contains the complete tagline text
    (all 20 tokens, a0..a19), proving the raw line was forwarded verbatim
    and not truncated at IRC_MAX_PARAMS=15.
    """
    clean = strip_irc_formatting(globops_line)

    # The 20th token (a19, index 19) is the one that would be absent under
    # the old bicchierino bug — assert it first for a sharp diagnostic.
    if "a19" in clean:
        ok("GLOBOPS contains 'a19' — token at position 19, beyond IRC_MAX_PARAMS=15 boundary")
    else:
        fail(
            "GLOBOPS missing 'a19' (the 20th token) — "
            "bicchierino may have truncated the raw line at 15 params\n"
            f"  raw:   {globops_line!r}\n"
            f"  clean: {clean!r}"
        )

    # Assert the full contiguous tagline text is present in the right order.
    if TAGLINE_TEXT in clean:
        ok(f"GLOBOPS contains full tagline text '{TAGLINE_TEXT}' — all tokens a0..a19 present and in order")
    else:
        missing = [t for t in TOKENS if t not in clean.split()]
        if missing:
            fail(
                f"GLOBOPS missing tokens: {missing!r}\n"
                f"  expected substring: {TAGLINE_TEXT!r}\n"
                f"  clean: {clean!r}"
            )
        else:
            # All tokens individually present but not contiguous — unexpected ordering.
            fail(
                f"GLOBOPS has all tokens individually but not as contiguous substring "
                f"{TAGLINE_TEXT!r}\n"
                f"  clean: {clean!r}"
            )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:

    # ── Connect bicc-raw (via bicchierino) ───────────────────────────────────
    print(f"\nConnecting bicc-raw to {HOST}:{PORT}…", flush=True)
    try:
        bicc = IRCConn(HOST, PORT, label="bicc")
    except OSError as exc:
        print(f"FATAL: cannot connect to {HOST}:{PORT}: {exc}", file=sys.stderr)
        sys.exit(1)

    reg_lines, got_004 = irc_register(
        bicc,
        nick="raw-check",
        user="bicc",
        realname="handle_raw passthrough regression (#101)",
        password="bahamut-test:test-password-not-secret",
    )

    if not got_004:
        print("FATAL: did not receive 004 from bicchierino", file=sys.stderr)
        bicc.close()
        sys.exit(1)

    ok(f"bicc-raw registered ({len(reg_lines)} line(s) through 004)")

    # Drain the post-registration burst (grappa snapshot, joins, etc.)
    print(f"\nDraining post-registration traffic ({POST_REG_SECS}s)…", flush=True)
    post_reg = bicc.drain(POST_REG_SECS)
    print(f"  {len(post_reg)} post-registration line(s)", flush=True)

    # ── Connect raw-peer (direct to bahamut-test) ────────────────────────────
    print(f"\nConnecting raw-peer directly to {BAHAMUT_HOST}:{BAHAMUT_PORT}…", flush=True)
    try:
        peer = IRCConn(BAHAMUT_HOST, BAHAMUT_PORT, label="peer")
    except OSError as exc:
        print(f"FATAL: cannot connect to {BAHAMUT_HOST}:{BAHAMUT_PORT}: {exc}", file=sys.stderr)
        bicc.close()
        sys.exit(1)

    peer_lines, peer_got_004 = irc_register(
        peer,
        nick="raw-peer",
        user="rawtest",
        realname="handle_raw peer observer",
    )
    if peer_got_004:
        ok(f"raw-peer registered directly on {BAHAMUT_HOST}")
    else:
        fail(f"raw-peer: did not receive 004 from {BAHAMUT_HOST}")

    peer.drain(2.0)

    # ── OPER ─────────────────────────────────────────────────────────────────
    #
    # bicc-grappa (the network identity shared by this bicchierino session)
    # must have IRC oper status (UMODE_o) for two reasons:
    #  1. services' m_privmsg requires isOper before dispatching to operserv().
    #  2. bahamut's send_globops only sends to opers — we need to receive it.
    #
    # raw-peer also OPERs to serve as an independent GLOBOPS observer.
    #
    # O:line: "testoper" / "testoperpass" — always present in the testnet,
    # set by OPER_NICK/OPER_PASS defaults (not overridden by bicchierino's
    # compose.yaml).  "azzurra" / "azzt3st" is an alternative fixed O:line.
    #
    # bicchierino routes OPER via grappa's Session.send_oper/4 (WIRE.md §2.6
    # "oper" push), so bahamut is the one that verifies credentials and
    # emits 381 RPL_YOUREOPER.
    print("\n─ OPER (bicc-raw) ─", flush=True)
    bicc.send("OPER testoper testoperpass")

    # 381 RPL_YOUREOPER confirms oper succeeded.  Not all ircd numerics are
    # guaranteed to flow back through grappa → bicchierino → client, so
    # treat 381 as optional confirmation rather than a hard requirement.
    got_381 = bicc.recv_match(
        timeout=8.0,
        match_fn=lambda t: len(t.split()) >= 2 and t.split()[1] == "381",
    )
    if got_381:
        ok("bicc-raw OPER: 381 RPL_YOUREOPER received")
    else:
        print("  (381 RPL_YOUREOPER not observed via bicchierino — continuing)", flush=True)

    bicc.drain(1.0)

    print("\n─ OPER (raw-peer) ─", flush=True)
    peer.send("OPER testoper testoperpass")
    got_381_peer = peer.recv_match(
        timeout=8.0,
        match_fn=lambda t: len(t.split()) >= 2 and t.split()[1] == "381",
    )
    if got_381_peer:
        ok("raw-peer OPER: 381 RPL_YOUREOPER received")
    else:
        fail("raw-peer OPER: no 381 received — GLOBOPS observation on peer may not work")

    peer.drain(1.0)

    # Wait for UMODE +o to propagate to services before sending OS.
    print(f"\nWaiting {POST_OPER_WAIT}s for oper status to propagate to services…", flush=True)
    time.sleep(POST_OPER_WAIT)

    # ── Send the raw line through bicchierino ────────────────────────────────
    #
    # This is the handle_raw path: "OS" has no dedicated handler in
    # bicchierino, so handle_irc_line falls through to handle_raw, which
    # (after the fix) forwards the original line bytes verbatim.
    print(f"\n─ Sending raw line ({len(RAW_LINE.split())} tokens) ─", flush=True)
    print(f"  {RAW_LINE!r}", flush=True)
    bicc.send(RAW_LINE)

    # ── Wait for the GLOBOPS NOTICE ──────────────────────────────────────────
    #
    # services emits GLOBOPS, bahamut routes it as:
    #   :<server> NOTICE <oper-nick> :*** Global -- from services.azzurra.chat: …
    #
    # bicc-raw receives this because bicc-grappa is an oper on bahamut-test.
    # raw-peer receives it because it is also an oper on the same server.
    #
    # The GLOBOPS body is:
    #   **bicc-grappa** added the following tagline: a0 a1 … a19
    # (where ** = IRC bold 0x02).  After stripping formatting codes,
    # "a0 a1 … a19" must appear as an uninterrupted substring.
    print(f"\n─ Waiting for GLOBOPS on bicc-raw (timeout={GLOBOPS_TIMEOUT}s) ─", flush=True)

    def is_tagline_notice(text: str) -> bool:
        return "NOTICE" in text and "tagline" in text.lower()

    globops_bicc = bicc.recv_match(GLOBOPS_TIMEOUT, is_tagline_notice)

    if globops_bicc is None:
        fail(
            f"No tagline GLOBOPS NOTICE received on bicc-raw within {GLOBOPS_TIMEOUT}s\n"
            "  Possible causes: OPER failed, services not responding, "
            "handle_raw not forwarding, or GLOBOPS not relayed by grappa."
        )
    else:
        print(f"  bicc-raw GLOBOPS: {globops_bicc!r}", flush=True)
        print("\n─ Asserting GLOBOPS content ─", flush=True)
        check_globops(globops_bicc)

    # ── Also check on raw-peer (direct bahamut observation) ──────────────────
    print(f"\n─ Waiting for GLOBOPS on raw-peer (timeout=5s) ─", flush=True)
    globops_peer = peer.recv_match(5.0, is_tagline_notice)
    if globops_peer is not None:
        ok(f"raw-peer also received GLOBOPS: {globops_peer!r}")
    else:
        # Not a hard failure — peer GLOBOPS reception depends on oper timing.
        print("  (GLOBOPS not observed on raw-peer within 5s — not fatal)", flush=True)

    bicc.close()
    peer.close()

    # ── Final report ─────────────────────────────────────────────────────────
    print(f"\n{'─' * 60}", flush=True)
    if errors:
        print(f"FAILED — {len(errors)} error(s):", flush=True)
        for e in errors:
            print(f"  • {e}", flush=True)
        sys.exit(1)
    else:
        print("All checks passed.", flush=True)
        sys.exit(0)


if __name__ == "__main__":
    main()
