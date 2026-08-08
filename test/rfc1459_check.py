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

Run from inside bicc-net (docker run --network ...).

Credentials used are those seeded by grappa-seed in compose.yaml:
  PASS bahamut-test:test-password-not-secret
  USER bicc ...
  NICK rfc-check

bicchierino relays to grappa which then spawns the IRC connection; the
full round trip can take 20+ seconds, so the socket timeout is generous.
"""

import re
import socket
import sys

HOST = "bicchierino"
PORT = 6667

# How long to wait for the server to respond at all, and how long to wait
# after sending registration commands before giving up waiting for 004.
CONNECT_TIMEOUT = 10
READ_TIMEOUT    = 60   # grappa login + network spawn + WS join can be slow

# RFC 1459 §2.3.1: :<prefix> <3-digit-code> <target> [<params>]
# The prefix must be present (starts with ':'), code exactly 3 decimal digits.
NUMERIC_RE = re.compile(r"^:(\S+) (\d{3}) (\S+)(.*)?$")

errors: list[str] = []


def fail(msg: str) -> None:
    errors.append(msg)
    print(f"  FAIL: {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ok:   {msg}", flush=True)


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


def recv_registration(sock: socket.socket) -> list[str]:
    """
    Read server lines until 004 arrives (end of the mandatory registration
    burst) or until READ_TIMEOUT seconds pass without data.
    Returns all decoded lines received.
    """
    buf = b""
    lines: list[str] = []
    sock.settimeout(READ_TIMEOUT)

    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk

            # Extract complete lines.  RFC 1459 §2.3 guarantees \r\n, but we
            # handle a bare \n as an error so we don't hang on malformed data.
            while True:
                crlf = buf.find(b"\r\n")
                lf   = buf.find(b"\n")

                if crlf == -1 and lf == -1:
                    break  # no complete line yet

                if crlf != -1 and (lf == -1 or crlf <= lf):
                    raw  = buf[:crlf + 2]
                    buf  = buf[crlf + 2:]
                else:
                    # bare LF before any CRLF — extract and flag
                    raw  = buf[:lf + 1]
                    buf  = buf[lf + 1:]

                text = check_line(raw)
                if text is not None:
                    lines.append(text)

                    # Stop once we have seen 004 — that ends the mandatory
                    # registration burst (001-004).  Additional lines (MOTD,
                    # JOINs) may follow but are not required here.
                    parts = text.split()
                    if len(parts) >= 2 and parts[1] == "004":
                        return lines

    except socket.timeout:
        pass  # fall through — we'll report missing numerics below

    return lines


def check_registration_numerics(lines: list[str]) -> None:
    """
    Rule 4: 001, 002, 003, 004 must all be present and arrive in that order.
    """
    required = ["001", "002", "003", "004"]

    # Collect the indices (position in the line list) of each required numeric.
    indices: dict[str, int] = {}
    for i, text in enumerate(lines):
        parts = text.split()
        if len(parts) >= 2 and parts[1].isdigit() and len(parts[1]) == 3:
            code = parts[1]
            if code in required and code not in indices:
                indices[code] = i

    # Presence check
    for code in required:
        if code in indices:
            ok(f"numeric {code} present (line {indices[code]})")
        else:
            fail(f"missing mandatory registration numeric {code} (RFC 1459 §4.1)")

    # Order check: each numeric's index must be strictly greater than the
    # previous one's.
    prev_idx = -1
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


def main() -> None:
    print(f"Connecting to {HOST}:{PORT}…", flush=True)
    try:
        sock = socket.create_connection((HOST, PORT), timeout=CONNECT_TIMEOUT)
    except OSError as exc:
        print(f"FATAL: cannot connect to {HOST}:{PORT}: {exc}", file=sys.stderr)
        sys.exit(1)

    # IRC registration — PASS first (bicchierino buffers until NICK+USER).
    # Credentials are those seeded by grappa-seed.
    sock.sendall(b"PASS bahamut-test:test-password-not-secret\r\n")
    sock.sendall(b"NICK rfc-check\r\n")
    sock.sendall(b"USER bicc 0 * :RFC 1459 compliance check\r\n")

    lines = recv_registration(sock)

    try:
        sock.sendall(b"QUIT :rfc1459_check done\r\n")
        sock.close()
    except OSError:
        pass

    if not lines:
        fail("received no lines from the server — registration stalled or failed")
        # Fall through to report + exit below.
    else:
        print(f"Received {len(lines)} line(s). Transcript:", flush=True)
        for line in lines:
            print(f"    {line}", flush=True)

    # Rule 4 — registration numerics
    check_registration_numerics(lines)

    print("", flush=True)
    if errors:
        print(
            f"RFC 1459 check FAILED — {len(errors)} violation(s):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    ok(f"all {len(lines)} lines compliant, 001–004 present and in order")
    print("RFC 1459 check passed.", flush=True)


if __name__ == "__main__":
    main()
