/* main.c — listener setup and the accept loop.
 *
 * poll() over the (few, fixed) listening sockets — one per configured
 * bind — and a pthread spawned per accepted client: the blocking grappa
 * login only stalls its own thread, and poll() over a handful of
 * listeners has nothing to do with poll() vs epoll for thousands of
 * connections (that debate is about per-client fds, not this).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"
#include "connection.h"
#include "version.h"

/* Hard cap on simultaneous downstream IRC connections.  A personal
 * bouncer facade has no legitimate use case for hundreds of concurrent
 * IRC clients; this number is generous relative to any realistic
 * deployment while still bounding the resource cost an unauthenticated
 * peer can impose before it even sends a NICK line. */
#define MAX_CONNECTIONS 64

/* Process-wide count of live connection threads.  Incremented here
 * (under the accept loop, single-threaded) before pthread_create, and
 * decremented by connection_run at every exit path.  Atomic because
 * the decrements happen on the connection threads, not the accept
 * thread. */
static atomic_int g_live_connections = 0;

struct listener {
    int fd;
    const struct bind_config *bind;
};

static int open_listener(const struct bind_config *b) {
    struct sockaddr_in  addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr    *addr;
    socklen_t           addrlen;
    int                 family;

    memset(&addr4, 0, sizeof(addr4));
    memset(&addr6, 0, sizeof(addr6));

    if (inet_pton(AF_INET, b->ip, &addr4.sin_addr) == 1) {
        family           = AF_INET;
        addr4.sin_family = AF_INET;
        addr4.sin_port   = htons((uint16_t)b->port);
        addr    = (struct sockaddr *)&addr4;
        addrlen = sizeof(addr4);
    } else if (inet_pton(AF_INET6, b->ip, &addr6.sin6_addr) == 1) {
        family            = AF_INET6;
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port   = htons((uint16_t)b->port);
        addr    = (struct sockaddr *)&addr6;
        addrlen = sizeof(addr6);
    } else {
        fprintf(stderr, "bicchierino: cannot parse bind address '%s'\n", b->ip);
        return -1;
    }

    int fd = socket(family, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    if (family == AF_INET6) {
        /* Explicitly disable IPv4-mapped connections on this IPv6 socket.
         * Without IPV6_V6ONLY, Linux's default lets a `::` wildcard also
         * accept IPv4-mapped peers, silently changing what the bind line
         * means depending on OS defaults.  Bicchierino's `bind` is
         * deliberately repeatable so one process can listen on several
         * independent (ip, port, tls) combinations — a user wanting both
         * IPv4 and IPv6 on the same port writes two bind lines; the OS
         * default must not conflate them behind our back. */
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
    }

    if (bind(fd, addr, addrlen) < 0) {
        fprintf(stderr, "bicchierino: bind %s:%d: %s\n", b->ip, b->port, strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    fprintf(stderr, "bicchierino: listening on %s:%d (%s)\n", b->ip, b->port,
            b->tls ? "tls" : "plain");
    return fd;
}

int main(int argc, char **argv) {
    /* Checked before anything else, deliberately not routed through
     * config_load_from_args — a version query has no business
     * requiring a valid config file to exist first. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--version") == 0) {
            printf("bicchierino %s\n", BICCHIERINO_VERSION);
            return 0;
        }
    }

    /* A client hanging up mid-write must not kill the thread handling
     * it — send()/write() report EPIPE, which every write site here
     * already has to check for other reasons. */
    signal(SIGPIPE, SIG_IGN);

    struct config cfg;
    if (!config_load_from_args(argc, argv, &cfg)) return 1;

    /* `bind ... tls` listeners still `accept()` a plain TCP socket
     * here — the actual `SSL_accept` handshake happens inside
     * `connection_run` (connection.c), gated on `args->listener->tls`,
     * not here. Found live as a real, previously-undetected gap this
     * TODO used to describe: nothing before that fix ever wrapped the
     * accepted fd in TLS at all, so a `tls` bind silently served
     * plaintext while claiming otherwise in its own startup log line —
     * a real TLS client's handshake against it just hung forever
     * (confirmed with both a Python `ssl` client and raw `openssl
     * s_client`), never a working connection, so this was never
     * silently INSECURE in practice — no genuine TLS client could ever
     * have connected successfully — but the promise itself was false
     * for as long as this TODO existed. */
    struct listener listeners[CONFIG_MAX_BINDS];
    size_t listener_count = 0;
    for (size_t i = 0; i < cfg.bind_count; i++) {
        int fd = open_listener(&cfg.binds[i]);
        if (fd < 0) {
            for (size_t j = 0; j < listener_count; j++) close(listeners[j].fd);
            return 1;
        }
        listeners[listener_count].fd = fd;
        listeners[listener_count].bind = &cfg.binds[i];
        listener_count++;
    }

    struct pollfd pfds[CONFIG_MAX_BINDS];
    for (;;) {
        for (size_t i = 0; i < listener_count; i++) {
            pfds[i].fd = listeners[i].fd;
            pfds[i].events = POLLIN;
            pfds[i].revents = 0;
        }

        int ready = poll(pfds, (nfds_t)listener_count, -1);
        if (ready < 0) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        for (size_t i = 0; i < listener_count; i++) {
            if (!(pfds[i].revents & POLLIN)) continue;

            int client_fd = accept(listeners[i].fd, NULL, NULL);
            if (client_fd < 0) {
                perror("accept");
                continue;
            }

            /* Check and claim a connection slot atomically.
             * fetch_add returns the value BEFORE the add; if it was
             * already at the cap we undo and refuse this connection. */
            int prev = atomic_fetch_add(&g_live_connections, 1);
            if (prev >= MAX_CONNECTIONS) {
                atomic_fetch_sub(&g_live_connections, 1);
                fprintf(stderr,
                        "bicchierino: connection limit (%d) reached, refusing new client\n",
                        MAX_CONNECTIONS);
                /* Best-effort IRC ERROR before closing; may arrive as
                 * plaintext even on a tls bind (TLS hasn't been set up
                 * yet), but a refused client gets the message. */
                const char *err = "ERROR :Too many connections\r\n";
                ssize_t unused = write(client_fd, err, strlen(err));
                (void)unused;
                close(client_fd);
                continue;
            }

            struct connection_args *args = malloc(sizeof(*args));
            if (!args) {
                atomic_fetch_sub(&g_live_connections, 1);
                close(client_fd);
                continue;
            }
            args->client_fd = client_fd;
            args->listener = listeners[i].bind;
            args->cfg = &cfg;
            args->live_connections = &g_live_connections;

            pthread_t tid;
            if (pthread_create(&tid, NULL, connection_run, args) != 0) {
                perror("pthread_create");
                atomic_fetch_sub(&g_live_connections, 1);
                close(client_fd);
                free(args);
                continue;
            }
            pthread_detach(tid);
        }
    }

    for (size_t i = 0; i < listener_count; i++) close(listeners[i].fd);
    return 1;
}
