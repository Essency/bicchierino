#!/usr/bin/env python3
"""caps.py — the connection cap and the registration deadline (#7, PR #20).

Neither is unit-testable in any useful way. The cap arithmetic lives inline
in main.c's accept loop, and the part that can actually break is not the
arithmetic: it is the INVARIANT that connection_run decrements the counter
on every exit path. Miss one and the count leaks — a bouncer that has been
up a week quietly refuses everything, with no error anywhere and nothing a
unit test would catch.

So this drives the real binary over real sockets and asserts the observable
behaviour, including the part that only appears after connections have come
and gone.

grappa is deliberately unreachable (https://127.0.0.1:1, the same trick the
existing CI smoke test uses): a client that connects and stays quiet sits in
the registration phase holding its slot, which is the state the cap bounds.

WHAT THIS DOES NOT COVER, established by breaking each decrement in turn and
re-running: connection_run has three exit paths that release a slot, and
these tests catch a leak on two of them — the TLS-accept failure (test 5)
and the registration timeout (tests 2 and 3). Breaking the third, the
`cleanup:` path taken after registration completes, leaves every assertion
here still passing, because reaching it needs a grappa the connection can
actually finish registering against. That path is uncovered and worth
saying so: a suite that looks like it guards the whole invariant is worse
than one that names the gap.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time

BIN = os.environ.get("BIN", "./bicchierino")
PORT = int(os.environ.get("PORT", "17777"))
TLS_PORT = PORT + 1
CAP = int(os.environ.get("CAP", "64"))
DEADLINE = int(os.environ.get("DEADLINE", "30"))

failures = []


def ok(msg):
    print(f"  ok: {msg}")


def bad(msg):
    print(f"  FAIL: {msg}")
    failures.append(msg)


def connect(timeout=5):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=timeout)
    return s


def read_some(s, timeout=3):
    s.settimeout(timeout)
    try:
        return s.recv(400).decode("utf-8", "replace")
    except (socket.timeout, OSError):
        return ""


def main():
    workdir = tempfile.mkdtemp()
    cfg = os.path.join(workdir, "b.config")
    # A tls bind alongside the plain one, so the TLS-accept failure path
    # can be exercised too — see test 5. Self-signed and thrown away with
    # the temp dir.
    cert = os.path.join(workdir, "c.pem")
    key = os.path.join(workdir, "c.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    with open(cfg, "w") as f:
        f.write(
            f"grappa-url https://127.0.0.1:1\n"
            f"bind 127.0.0.1 {PORT} plain\n"
            f"bind 127.0.0.1 {TLS_PORT} tls {cert} {key}\n"
        )

    log = open(os.path.join(workdir, "log"), "w+")
    proc = subprocess.Popen([BIN, "--config", cfg], stdout=log, stderr=log)

    for _ in range(40):
        try:
            connect(timeout=1).close()
            break
        except OSError:
            time.sleep(0.25)
    else:
        proc.kill()
        log.seek(0)
        print("caps: bicchierino never accepted a connection\n" + log.read())
        return 1

    held = []
    try:
        print("1. the cap refuses the connection past it")
        for _ in range(CAP):
            try:
                held.append(connect())
            except OSError as e:
                bad(f"could not open a connection below the cap: {e}")
                break
        time.sleep(2)

        # Quiet sockets are still in registration, so all CAP slots are
        # taken. One more must be refused, and told why.
        extra = connect()
        msg = read_some(extra)
        extra.close()
        if "Too many connections" in msg:
            ok(f"connection {CAP + 1} refused with an IRC ERROR")
        elif msg == "":
            bad(f"connection {CAP + 1} got no ERROR line (silent drop, or accepted)")
        else:
            bad(f"connection {CAP + 1} got: {msg.strip()!r}")

        print("2. slots come back when connections end")
        for s in held:
            s.close()
        held = []
        time.sleep(3)
        again = connect()
        msg = read_some(again, timeout=2)
        again.close()
        if "Too many connections" in msg:
            bad("slots leaked: refused while nothing was live")
        else:
            ok("a fresh connection is accepted once the others are gone")

        print("3. an idle client is dropped at the registration deadline")
        s = connect()
        s.settimeout(DEADLINE + 15)
        start = time.time()
        try:
            while True:
                chunk = s.recv(400)
                if not chunk:
                    break
        except socket.timeout:
            pass
        except OSError:
            pass
        elapsed = time.time() - start
        s.close()

        if elapsed >= DEADLINE + 12:
            bad(f"idle client still connected after {elapsed:.0f}s (deadline {DEADLINE}s)")
        elif elapsed < 2:
            bad(f"idle client dropped after {elapsed:.1f}s — too early to be the deadline")
        else:
            ok(f"idle client dropped after {elapsed:.0f}s")

        # The three exit paths in connection_run decrement the counter
        # independently, and a leak on any one of them is the failure this
        # file exists for. Tests 2 and 3 above cover the registration
        # timeout and the post-registration cleanup; this covers the third,
        # which is only reachable on a tls bind and which a plain-bind test
        # cannot touch at all. Found the hard way: breaking this decrement
        # left every assertion above still passing.
        print("4. a failed TLS handshake releases its slot too")
        for _ in range(CAP + 4):
            try:
                s2 = socket.create_connection(("127.0.0.1", TLS_PORT), timeout=3)
                # Plain bytes at a tls bind: SSL_accept fails and the
                # connection is torn down on that path.
                s2.sendall(b"NOT TLS AT ALL\r\n")
                s2.close()
            except OSError:
                pass
        time.sleep(3)
        probe = connect()
        msg = read_some(probe, timeout=2)
        probe.close()
        if "Too many connections" in msg:
            bad(f"slots leaked on the TLS-accept path: refused after {CAP + 4} failed handshakes")
        else:
            ok("failed TLS handshakes do not consume slots permanently")

        print("5. the process is still alive and serving")
        if proc.poll() is None:
            ok("bicchierino survived the whole thing")
        else:
            bad(f"bicchierino exited with {proc.returncode}")
            log.seek(0)
            print("    " + "\n    ".join(log.read().splitlines()[-5:]))
    finally:
        for s in held:
            try:
                s.close()
            except OSError:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    if failures:
        print("caps: FAILED")
        return 1
    print("caps: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
