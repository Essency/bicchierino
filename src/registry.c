/* registry.c — process-wide connection registry (see registry.h). */
#include "registry.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ── Process-global state ───────────────────────────────────────────────
 *
 * One mutex, one fixed-size array — both global to this translation unit.
 * The mutex is the SECOND deliberate exception to bicchierino's "zero
 * shared state" concurrency model; see CLAUDE.md §Mutex exceptions. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static struct conn_entry g_entries[MAX_CONNECTIONS];

void registry_init(void) {
    for (int i = 0; i < MAX_CONNECTIONS; i++)
        g_entries[i].fd = -1;
}

void registry_add(int fd, const char *peer_addr) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_entries[i].fd == -1) {
            g_entries[i].fd = fd;
            snprintf(g_entries[i].peer_addr, CONN_PEER_ADDR_MAX, "%s", peer_addr);
            g_entries[i].identity[0] = '\0';
            g_entries[i].connected_at = time(NULL);
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void registry_set_identity(int fd, const char *identity) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_entries[i].fd == fd) {
            snprintf(g_entries[i].identity, CONN_IDENTITY_MAX, "%s", identity);
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void registry_remove(int fd) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_entries[i].fd == fd) {
            g_entries[i].fd = -1;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

void registry_snapshot(struct conn_snapshot *snap, const char *filter_identity) {
    snap->count = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_entries[i].fd == -1) continue;
        if (filter_identity && strcmp(g_entries[i].identity, filter_identity) != 0) continue;
        snap->entries[snap->count++] = g_entries[i];
    }
    pthread_mutex_unlock(&g_lock);
}

bool registry_kill(int target_fd, const char *caller_identity, bool is_admin) {
    bool found   = false;
    bool allowed = false;

    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (g_entries[i].fd == target_fd) {
            found   = true;
            allowed = is_admin ||
                      strcmp(g_entries[i].identity, caller_identity) == 0;
            /* Call shutdown() WHILE STILL HOLDING g_lock — registry_remove()
             * in the victim thread also acquires g_lock, so the fd cannot be
             * closed and recycled by a new accept() before we finish here.
             * Without this, there is a TOCTOU window between releasing the
             * lock and calling shutdown() where the victim thread could run
             * registry_remove → close(fd) and the OS could hand that same fd
             * number to a brand-new connection, causing shutdown() to
             * disconnect an innocent client instead. shutdown() is a
             * non-blocking syscall and is safe to call while holding a mutex. */
            if (allowed)
                shutdown(target_fd, SHUT_RDWR);
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (!found || !allowed) return false;

    /* shutdown(SHUT_RDWR) inside the lock (above) is the sole disconnect
     * mechanism — sufficient and race-free.  No courtesy send() after the
     * lock: send() on a SHUT_RDWR socket always fails with EPIPE (dead code
     * for the intended victim), and in the narrow window between unlock and
     * send() the fd could be recycled to a new innocent connection by the OS,
     * causing send() to succeed against the wrong client. */
    return true;
}
