/* connection.h — one thread per accepted downstream IRC client.
 *
 * Lifecycle: parse IRC registration (PASS/USER/NICK, CAP tolerated and
 * ignored — bicchierino doesn't negotiate capabilities) → grappa REST
 * login → grappa WS connect + topic joins → bridge loop. See CLAUDE.md §3
 * and WIRE.md for the exact shapes; this header only exposes the thread
 * entry point.
 */
#ifndef BICCHIERINO_CONNECTION_H
#define BICCHIERINO_CONNECTION_H

#include "config.h"

struct connection_args {
    int client_fd;
    const struct bind_config *listener; /* which bind accepted this client */
    const struct config *cfg;           /* whole config, for grappa_url etc. */
};

/* pthread entry point. Takes ownership of a heap-allocated
 * `struct connection_args` (including client_fd) and frees it. Never
 * returns a value worth joining on — every connection is independent and
 * self-contained (CLAUDE.md §3: zero shared state between connections). */
void *connection_run(void *arg);

#endif /* BICCHIERINO_CONNECTION_H */
