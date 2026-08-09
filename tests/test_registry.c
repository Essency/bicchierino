/* test_registry.c — unit tests for the connection registry.
 *
 * Uses socketpair() to create real file descriptors so registry_kill()'s
 * shutdown(SHUT_RDWR) call exercises real kernel socket state rather than
 * operating on a bare integer the kernel knows nothing about.  This matches
 * test_render.c's discipline: assert on the real fd behaviour, not on a
 * mock.
 */
#include "test.h"

#include <sys/socket.h>
#include <unistd.h>

#include "../src/registry.h"

/* ── add / remove ───────────────────────────────────────────────────── */

TEST(add_and_snapshot) {
    registry_init();

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    registry_add(sv[0], "10.0.0.1");

    struct conn_snapshot snap;
    registry_snapshot(&snap, NULL);
    CHECK(snap.count == 1);
    CHECK(snap.entries[0].fd == sv[0]);
    CHECK_STR(snap.entries[0].peer_addr, "10.0.0.1");
    CHECK(snap.entries[0].identity[0] == '\0'); /* empty until set */

    registry_remove(sv[0]);
    registry_snapshot(&snap, NULL);
    CHECK(snap.count == 0);

    close(sv[0]);
    close(sv[1]);
}

TEST(set_identity) {
    registry_init();

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    registry_add(sv[0], "192.168.1.1");
    registry_set_identity(sv[0], "sonic@azzurra");

    struct conn_snapshot snap;
    registry_snapshot(&snap, NULL);
    CHECK(snap.count == 1);
    CHECK_STR(snap.entries[0].identity, "sonic@azzurra");

    registry_remove(sv[0]);
    close(sv[0]);
    close(sv[1]);
}

/* ── snapshot filtering ─────────────────────────────────────────────── */

TEST(snapshot_filter) {
    registry_init();

    int sv1[2], sv2[2], sv3[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv3) == 0);

    registry_add(sv1[0], "10.0.0.1");
    registry_set_identity(sv1[0], "alice@net1");
    registry_add(sv2[0], "10.0.0.2");
    registry_set_identity(sv2[0], "bob@net1");
    registry_add(sv3[0], "10.0.0.3");
    registry_set_identity(sv3[0], "alice@net1");

    struct conn_snapshot snap_all;
    registry_snapshot(&snap_all, NULL);
    CHECK(snap_all.count == 3);

    struct conn_snapshot snap_alice;
    registry_snapshot(&snap_alice, "alice@net1");
    CHECK(snap_alice.count == 2);

    struct conn_snapshot snap_bob;
    registry_snapshot(&snap_bob, "bob@net1");
    CHECK(snap_bob.count == 1);
    CHECK_STR(snap_bob.entries[0].identity, "bob@net1");

    registry_remove(sv1[0]);
    registry_remove(sv2[0]);
    registry_remove(sv3[0]);
    close(sv1[0]); close(sv1[1]);
    close(sv2[0]); close(sv2[1]);
    close(sv3[0]); close(sv3[1]);
}

/* ── kill — admin path ───────────────────────────────────────────────── */

TEST(kill_admin_any_target) {
    registry_init();

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    registry_add(sv[0], "1.2.3.4");
    registry_set_identity(sv[0], "victim@net");

    /* An admin (is_admin=true) can kill any connection regardless of
     * their own identity. */
    bool killed = registry_kill(sv[0], "someadmin@net", true);
    CHECK(killed);

    /* After the kill the fd is still in the registry (the victim thread
     * removes it on its own teardown path) — but the socket itself has
     * been shut down.  registry_kill first sends an ERROR courtesy line
     * (30 bytes), then calls shutdown(SHUT_RDWR).  Drain the ERROR line
     * then verify that a subsequent recv() returns 0 (EOF), confirming
     * shutdown() was called. */
    char buf[64];
    /* First recv: may contain the ERROR line. */
    (void)recv(sv[1], buf, sizeof(buf), 0);
    /* Second recv: must be EOF (shutdown has been called). */
    ssize_t n = recv(sv[1], buf, sizeof(buf), 0);
    CHECK(n == 0);

    registry_remove(sv[0]);
    close(sv[0]);
    close(sv[1]);
}

/* ── kill — non-admin owns it ────────────────────────────────────────── */

TEST(kill_self_allowed) {
    registry_init();

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    registry_add(sv[0], "5.6.7.8");
    registry_set_identity(sv[0], "alice@net1");

    /* A non-admin whose own identity matches the target is allowed. */
    bool killed = registry_kill(sv[0], "alice@net1", false);
    CHECK(killed);

    registry_remove(sv[0]);
    close(sv[0]);
    close(sv[1]);
}

/* ── kill — non-admin tries another's connection ─────────────────────── */

TEST(kill_other_denied) {
    registry_init();

    int sv[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

    registry_add(sv[0], "9.10.11.12");
    registry_set_identity(sv[0], "bob@net1");

    /* A non-admin trying to kill a different identity's connection must
     * be denied — the registry enforces this server-side, not by trusting
     * that the client has already scoped its kill to its own identity. */
    bool killed = registry_kill(sv[0], "alice@net1", false);
    CHECK(!killed);

    /* The socket must still be alive — no shutdown was called. */
    /* Send a byte from sv[1] and try to read it from sv[0] — if shutdown
     * had been called recv would return <= 0. */
    CHECK(send(sv[1], "x", 1, 0) == 1);

    /* Non-blocking peek to verify the socket is still live. */
    char buf[4];
    ssize_t n = recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
    CHECK(n == 1);

    registry_remove(sv[0]);
    close(sv[0]);
    close(sv[1]);
}

/* ── kill — fd not found ─────────────────────────────────────────────── */

TEST(kill_not_found) {
    registry_init();

    /* A fd that was never registered returns false, even for an admin. */
    bool killed = registry_kill(9999, "anyone@net", true);
    CHECK(!killed);
}

/* ── set_identity on unknown fd is a no-op ───────────────────────────── */

TEST(set_identity_unknown_fd) {
    registry_init();
    /* Must not crash or affect anything. */
    registry_set_identity(9999, "ghost@net");

    struct conn_snapshot snap;
    registry_snapshot(&snap, NULL);
    CHECK(snap.count == 0);
}

/* ── remove unknown fd is a no-op ────────────────────────────────────── */

TEST(remove_unknown_fd) {
    registry_init();
    registry_remove(9999); /* must not crash */
    struct conn_snapshot snap;
    registry_snapshot(&snap, NULL);
    CHECK(snap.count == 0);
}

int main(void) {
    RUN(add_and_snapshot);
    RUN(set_identity);
    RUN(snapshot_filter);
    RUN(kill_admin_any_target);
    RUN(kill_self_allowed);
    RUN(kill_other_denied);
    RUN(kill_not_found);
    RUN(set_identity_unknown_fd);
    RUN(remove_unknown_fd);
    return test_report();
}
