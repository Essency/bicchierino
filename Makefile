CC ?= cc

# Warnings and hardening are not overridable via CFLAGS from the
# environment, same reasoning as shottino's own Makefile: a bare
# `CFLAGS ?=` would let `make CFLAGS=-O0` silently drop -Wall/-Wextra
# along with everything else. This binary parses hostile bytes (IRC
# lines from anyone who can reach a bind, JSON/websocket frames from
# grappa) so the hardening earns its keep.
CFLAGS ?= -O2
WARNINGS := -std=c11 -Wall -Wextra -Wpedantic -Wformat=2
HARDENING := -fstack-protector-strong -D_FORTIFY_SOURCE=2
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L
CFLAGS += $(WARNINGS) $(HARDENING)

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

LDLIBS := -lssl -lcrypto -lpthread

BIN := bicchierino
OBJS := src/main.o src/config.o src/connection.o src/http.o src/ws.o src/json.o

.PHONY: all clean install

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

install: $(BIN)
	install -D -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(BIN) src/*.o
