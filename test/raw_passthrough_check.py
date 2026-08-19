#!/usr/bin/env python3
"""
raw_passthrough_check.py — Regression for bicchierino issue #101.

handle_raw MUST forward the client's original IRC line verbatim to the
upstream ircd.  Under the pre-fix code, bicchierino would parse the line
into at most IRC_MAX_PARAMS (15) tokens and reconstruct a shorter line,
silently discarding any tokens beyond the 15th.

Anatomy of the test line (why bahamut + services cooperate end-to-end):

  OS AKILL PERM *@192.0.2.1 a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 a10 a11 a12 a13 a14 a15 a16 a17 a18 a19

  Command:  OS
  Token count after "OS": 22 (AKILL + PERM + *@192.0.2.1 + a0..a19)
  IRC_MAX_PARAMS = 15 → old code stopped at params[14] = "a11",
  losing a12..a19 when reconstructing the line from parsed tokens.

  bahamut's m_os has parameters=1 in its message table.  When parse()
  hits that limit, it breaks WITHOUT advancing past the current token —
  so parv[1] points to the entire unsplit remainder
  "AKILL PERM *@192.0.2.1 a0 a1 … a19", not just "AKILL".  m_os sends:

    :<nick> PRIVMSG OperServ@services.azzurra.chat :AKILL PERM *@192.0.2.1 a0 … a19

  services' m_privmsg → operserv() → handle_akill parses:
    subcommand = "PERM"  (→ expireTime=0, permanent)
    username   = "*"
    host       = "192.0.2.1"
    reason     = strtok(NULL, "") = "a0 a1 … a19" (all remaining text)

  handle_akill emits (via send_globops with s_Snooper = s_OperServ):

    GLOBOPS :**bicc-grappa** added a permanent AKILL for ***@192.0.2.1** [Reason: a0 a1 … a19]

  bahamut receives the GLOBOPS and relays it to all local IRC opers as:

    :<server> NOTICE <nick> :*** Global -- from services.azzurra.chat: …

  The bicc-raw socket (= the bicc-grappa network identity) is an oper
  (after /OPER) and therefore receives this NOTICE.

  Under the old code the reason would end at "a11" (params[14], the last
  slot in the 15-element array); with the fix, all 20 tokens arrive and
  "[Reason: a0 a1 … a19]" is present in the GLOBOPS, including "a19".

Auth setup:
  bicc-raw connects to bicchierino as the grappa account (PASS
  bahamut-test:test-password-not-secret), becoming bicc-grappa on the
  network.  bicc-grappa needs IRC-oper status (UMODE_o) because:
    1. services' m_privmsg requires isOper before calling operserv().
    2. bahamut's send_globops delivers only to IsAnOper() local users.

  The sealed testnet always has an O:line for "testoper"/"testoperpass"
  (OPER_NICK/OPER_PASS defaults, not overridden by bicchierino compose).

  AKILL PERM access level — why NickServ identification is required:

  services' oper_invoke_agent_command() uses the AKILL command table
  entry { "AKILL", ULEVEL_OPER, ... } for the top-level dispatch.
  That check passes for a bare IRC oper (ULEVEL_OPER = 0x03).

  BUT handle_akill (akill.c line 726) has a second, stricter check
  for the PERM / ADD / TIME subcommands:

    else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
        send_notice_lang_to_user(..., OPER_ERROR_ACCESS_DENIED);

  CMDLEVEL_SOP = 0x20.  ULEVEL_OPER = 0x03.  0x03 & 0x20 = 0 → the
  check fails and services sends "Access denied." — the raw line
  arrived correctly, but the command is rejected before the GLOBOPS.

  services keeps a per-nick oper DB entry.  The M:bicc-grappa conf line
  (services.conf.tmpl, rendered from compose.yaml SERVICES_MASTER) tells
  oper_db_load to create a ULEVEL_MASTER (0x3FF) entry for bicc-grappa.
  0x3FF has CMDLEVEL_SOP set, so bicc-grappa can do AKILL PERM — IF the
  entry is loaded into user->oper.

  check_oper() is what loads user->oper.  It is called from
  users.c:1908 only when the user receives UMODE_r (identified to
  NickServ).  servers_oper_add() — called when UMODE_o is set — only
  updates statistics, it does NOT call check_oper.

  Solution: register bicc-grappa's nick with NickServ in the test.
  With SVC_EMAIL=0 and SVC_FORCE_AUTH=0 (testnet defaults), services
  registers the nick and identifies the user immediately, setting +r.
  That triggers check_oper, which finds the MASTER oper DB entry and
  sets user->oper = MASTER → ULEVEL_MASTER for all subsequent OperServ
  commands, including AKILL PERM.

  Each CI run starts with an empty services DB so NS REGISTER always
  succeeds.  A re-run against a persistent services DB gets "already
  registered"; the test falls through to NS IDENTIFY in that case.

  raw-peer connects directly to bahamut-test:6667 and OPERs as a second
  independent GLOBOPS observer.

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
POST_REG_SECS    = 8    # seconds to drain post-004 burst before OPER
POST_OPER_WAIT   = 3.0  # seconds to wait for UMODE +o to propagate to services
POST_NS_WAIT     = 2.0  # seconds for NickServ +r to propagate → check_oper
GLOBOPS_TIMEOUT  = 20.0 # wait this long for the GLOBOPS NOTICE

# ── The raw line under test ───────────────────────────────────────────────────
# 20 reason tokens (a0..a19) = 22 tokens total after "OS"
# (AKILL + PERM + *@192.0.2.1 + 20 tokens), well past IRC_MAX_PARAMS=15.
#
# Substitution: OS AKILL PERM instead of OS TAGLINE ADD (see module docstring).
TOKENS      = [f"a{i}" for i in range(20)]
REASON_TEXT = " ".join(TOKENS)           # "a0 a1 a2 … a19"
AKILL_MASK  = "*@192.0.2.1"             # RFC 5737 TEST-NET-1 — safe, never real
RAW_LINE    = f"OS AKILL PERM {AKILL_MASK} {REASON_TEXT}"

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

def check_akill_globops(globops_line: str) -> None:
    """
    Assert that the GLOBOPS NOTICE from AKILL PERM contains the full reason
    text (all 20 tokens, a0..a19), proving the raw line was forwarded verbatim
    and not truncated at IRC_MAX_PARAMS=15.

    The GLOBOPS from services looks like (after stripping bold codes):
      :leaf4.azzurra.chat NOTICE bicc-grappa :*** Global -- from
      services.azzurra.chat: bicc-grappa added a permanent AKILL for
      *@192.0.2.1 [Reason: a0 a1 … a19]
    """
    clean = strip_irc_formatting(globops_line)

    # "a19" is the first token that the old bicchierino would have dropped
    # (it falls beyond params[14] in the 15-element array).
    if "a19" in clean:
        ok("AKILL GLOBOPS contains 'a19' — token beyond IRC_MAX_PARAMS=15, verbatim passthrough confirmed")
    else:
        fail(
            "AKILL GLOBOPS missing 'a19' (token beyond IRC_MAX_PARAMS=15) — "
            "bicchierino may have truncated the raw line at 15 params\n"
            f"  raw:   {globops_line!r}\n"
            f"  clean: {clean!r}"
        )

    # Also assert the full contiguous reason text is present in order.
    if REASON_TEXT in clean:
        ok(f"AKILL GLOBOPS contains full reason '{REASON_TEXT}' — all tokens a0..a19 present and in order")
    else:
        missing = [t for t in TOKENS if t not in clean.split()]
        if missing:
            fail(
                f"AKILL GLOBOPS missing tokens: {missing!r}\n"
                f"  expected substring: {REASON_TEXT!r}\n"
                f"  clean: {clean!r}"
            )
        else:
            fail(
                f"AKILL GLOBOPS has all tokens individually but not as contiguous substring "
                f"{REASON_TEXT!r}\n"
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
    # bicc-grappa (the network identity of this bicchierino session) needs
    # IRC oper status (UMODE_o) for two reasons:
    #  1. services' m_privmsg requires isOper before calling operserv().
    #  2. bahamut's send_globops only delivers to IsAnOper() local clients.
    #
    # raw-peer also OPERs to serve as an independent GLOBOPS observer.
    #
    # O:line: "testoper" / "testoperpass" — sealed testnet default, never
    # overridden by the bicchierino compose.yaml.
    print("\n─ OPER (bicc-raw) ─", flush=True)
    bicc.send("OPER testoper testoperpass")

    # 381 RPL_YOUREOPER confirms the OPER succeeded.  Grappa may not relay
    # this numeric back to the bicchierino client, so treat it as optional.
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

    # ── NickServ registration → services ULEVEL_MASTER for AKILL PERM ────────
    #
    # AKILL PERM requires CMDLEVEL_SOP (0x20) inside handle_akill, not just the
    # ULEVEL_OPER (0x03) that a bare IRC oper has.  services loads the
    # ULEVEL_MASTER oper DB entry (created by M:bicc-grappa conf line) into
    # user->oper only when check_oper() fires — and that happens only on
    # UMODE_r, i.e., NickServ identification.  (See module docstring for the
    # full services access level analysis.)
    #
    # With SVC_EMAIL=0 (testnet default), registration is immediate: services
    # sets +r right away, no email step.  On a fresh CI run REGISTER always
    # succeeds; on a persistent-DB re-run we fall through to IDENTIFY.
    print("\n─ NickServ identify (bicc-grappa needs ULEVEL_MASTER for AKILL PERM) ─", flush=True)
    bicc.send("PRIVMSG NickServ :REGISTER testpassword test@example.com")

    ns_register_resp = bicc.recv_match(
        timeout=5.0,
        match_fn=lambda t: "NOTICE" in t and "NickServ" in t,
    )
    if ns_register_resp is not None:
        clean_ns = strip_irc_formatting(ns_register_resp)
        print(f"  NS REGISTER: {clean_ns!r}", flush=True)
        if "already" in ns_register_resp.lower():
            # Persistent DB: nick registered from a prior run — identify
            bicc.send("PRIVMSG NickServ :IDENTIFY testpassword")
            ns_id_resp = bicc.recv_match(
                timeout=5.0,
                match_fn=lambda t: "NOTICE" in t and "NickServ" in t,
            )
            if ns_id_resp is not None:
                print(f"  NS IDENTIFY: {strip_irc_formatting(ns_id_resp)!r}", flush=True)
    else:
        print("  (no NickServ REGISTER response within 5s — services may not be ready)", flush=True)

    # Wait for services to process +r and run check_oper for bicc-grappa.
    print(f"\nWaiting {POST_NS_WAIT}s for NickServ +r to propagate (check_oper → ULEVEL_MASTER)…", flush=True)
    time.sleep(POST_NS_WAIT)

    # ── Send the raw line through bicchierino ────────────────────────────────
    #
    # "OS" has no dedicated handler in bicchierino, so handle_irc_line
    # falls through to handle_raw.  After the PR #104 fix, handle_raw
    # forwards the original raw bytes verbatim rather than reconstructing
    # the line from the parsed (and truncated) params array.
    print(f"\n─ Sending raw line ({len(RAW_LINE.split())} tokens) ─", flush=True)
    print(f"  {RAW_LINE!r}", flush=True)
    bicc.send(RAW_LINE)

    # ── Wait for the GLOBOPS NOTICE on bicc-raw ──────────────────────────────
    #
    # handle_akill in services (on AKILL PERM success) calls:
    #   send_globops(s_Snooper, "… added a permanent AKILL for … [Reason: %s]", reason)
    # where s_Snooper = s_OperServ (conf.h) and reason = "a0 a1 … a19".
    #
    # bahamut receives the GLOBOPS from services and delivers it to all
    # local IRC opers as:
    #   :<server> NOTICE <nick> :*** Global -- from services.azzurra.chat: …
    #
    # bicc-raw receives this because bicc-grappa has UMODE_o on bahamut-test.
    # "[Reason:" is a unique marker present only in AKILL GLOBOPS messages.
    print(f"\n─ Waiting for AKILL GLOBOPS on bicc-raw (timeout={GLOBOPS_TIMEOUT}s) ─", flush=True)

    def is_akill_globops(text: str) -> bool:
        return "NOTICE" in text and "[Reason:" in text

    globops_bicc = bicc.recv_match(GLOBOPS_TIMEOUT, is_akill_globops)

    if globops_bicc is None:
        fail(
            f"No AKILL GLOBOPS NOTICE received on bicc-raw within {GLOBOPS_TIMEOUT}s\n"
            "  Possible causes:\n"
            "  • OPER failed — bicc-grappa lacks UMODE_o (services requires isOper)\n"
            "  • NickServ registration failed — bicc-grappa lacks ULEVEL_MASTER\n"
            "    (AKILL PERM requires CMDLEVEL_SOP; bare IRC opers only have ULEVEL_OPER)\n"
            "  • AKILL mask rejected by services validate_host\n"
            "  • handle_raw not forwarding verbatim (pre-PR#104 truncation)\n"
            "  • GLOBOPS NOTICE not relayed by grappa to the bicchierino client"
        )
    else:
        print(f"  bicc-raw GLOBOPS: {globops_bicc!r}", flush=True)
        print("\n─ Asserting GLOBOPS content ─", flush=True)
        check_akill_globops(globops_bicc)

    # ── Also check on raw-peer (direct bahamut observation, optional) ─────────
    print(f"\n─ Waiting for AKILL GLOBOPS on raw-peer (timeout=5s) ─", flush=True)
    globops_peer = peer.recv_match(5.0, is_akill_globops)
    if globops_peer is not None:
        ok(f"raw-peer also received AKILL GLOBOPS: {globops_peer!r}")
    else:
        # Not a hard failure — peer reception depends on OPER timing.
        print("  (AKILL GLOBOPS not observed on raw-peer within 5s — not fatal)", flush=True)

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
