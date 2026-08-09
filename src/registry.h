/* registry.h — process-wide connection registry.
 *
 * Tracks every live downstream IRC connection: fd, peer address (captured
 * at accept()), grappa identity ("account@network", populated once
 * PASS/USER registration completes), and connect time.
 *
 * This is a DELIBERATE ARCHITECTURAL EXCEPTION to the project-wide
 * "zero shared state between connections" design principle documented in
 * CLAUDE.md.  See that file's §Mutex exceptions for the full rationale;
 * the short version: the registry is small, uncontended (writes only on
 * connect/register/disconnect; reads only on a /grappa clients or
 * /grappa kill call), and lives explicitly behind a single mutex rather
 * than being silently threaded through some other mechanism.
 *
 * MAX_CONNECTIONS is the same hard cap main.c enforces at accept() time
 * — the registry uses a fixed-size array of that size, no dynamic
 * allocation needed.
 */
#ifndef BICCHIERINO_REGISTRY_H
#define BICCHIERINO_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define MAX_CONNECTIONS 64

/* Per-address buffer: "xxx.xxx.xxx.xxx" (IPv4) or full IPv6 textual
 * representation — INET6_ADDRSTRLEN (46) is the POSIX maximum; 64 is
 * generous past that so the field is never a source of truncation bugs. */
#define CONN_PEER_ADDR_MAX 64

/* "account@network" — both halves bounded by their own IRC-line-derived
 * limits in practice; 256 is generous past any realistic value. */
#define CONN_IDENTITY_MAX 256

/* One slot in the connection registry.  fd == -1 means the slot is free. */
struct conn_entry {
    int    fd;
    char   peer_addr[CONN_PEER_ADDR_MAX];
    char   identity[CONN_IDENTITY_MAX]; /* empty string until registration */
    time_t connected_at;
};

/* A snapshot taken under the registry lock — safe to read without holding
 * any lock after it is returned. */
struct conn_snapshot {
    struct conn_entry entries[MAX_CONNECTIONS];
    size_t            count; /* occupied slots only; entries[0..count-1] */
};

/* ── Lifecycle ──────────────────────────────────────────────────────────
 *
 * Call order: registry_init() once at startup (before any threads).
 * Per-connection: registry_add → registry_set_identity → registry_remove.
 * In between: registry_snapshot / registry_kill from any thread. */

void registry_init(void);

/* Called from the accept loop immediately after accept() — records fd and
 * peer address.  The identity field starts empty. */
void registry_add(int fd, const char *peer_addr);

/* Called once per connection after PASS/USER/NICK registration completes
 * and the grappa identity ("account@network") is known.  Ignored if fd
 * is not in the registry (harmless). */
void registry_set_identity(int fd, const char *identity);

/* Called from every exit path in connection_run — frees the slot. */
void registry_remove(int fd);

/* Snapshot of all occupied slots.  If filter_identity is non-NULL, only
 * entries whose identity exactly matches are included. */
void registry_snapshot(struct conn_snapshot *snap, const char *filter_identity);

/* Disconnect the connection identified by target_fd.
 *
 * Sends "ERROR :Disconnected by admin" (best-effort; the target may be on
 * a TLS fd where a raw write() won't go through the SSL layer — the real
 * mechanism is shutdown(SHUT_RDWR), which unblocks the target thread's
 * recv()/poll() as a normal connection-lost condition), then calls
 * shutdown(target_fd, SHUT_RDWR).
 *
 * Authorisation: if is_admin is true, any target_fd in the registry is
 * allowed; otherwise the target's identity must match caller_identity (a
 * non-admin can only kill their own duplicate logins).
 *
 * Returns true if the kill was dispatched, false if the fd was not found
 * or the caller is not authorised. */
bool registry_kill(int target_fd, const char *caller_identity, bool is_admin);

#endif /* BICCHIERINO_REGISTRY_H */
