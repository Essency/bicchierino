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

# vX.Y.Z+shorthash, entirely git-derived — deliberately no separate
# VERSION file to keep in sync with the actual tag by hand. The tag
# match pattern excludes anything that isn't a plain vX.Y.Z release tag
# (a stray annotated/lightweight tag of some other shape never gets
# mistaken for a version). Falls back to v0.0.0+unknown when there's no
# git history at all (a source tarball without .git) — an honest
# "can't tell" marker, never a stale hardcoded number. Appended to
# CPPFLAGS via `+=`, not `?=`, so it can never be silently dropped by a
# caller override the way a bare `CPPFLAGS=` would (same reasoning as
# WARNINGS/HARDENING above).
GIT_TAG := $(shell git describe --tags --match 'v[0-9]*.[0-9]*.[0-9]*' --abbrev=0 2>/dev/null || echo v0.0.0)
GIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BICCHIERINO_VERSION := $(GIT_TAG)+$(GIT_HASH)
CPPFLAGS += -DBICCHIERINO_VERSION='"$(BICCHIERINO_VERSION)"'

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

LDLIBS := -lssl -lcrypto -lpthread

BIN := bicchierino
OBJS := src/main.o src/config.o src/connection.o src/http.o src/bridge.o src/ws_client.o src/ws.o src/json.o src/jsonw.o

.PHONY: all clean install version

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

install: $(BIN)
	install -D -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

clean:
	rm -f $(BIN) src/*.o

version:
	@echo $(BICCHIERINO_VERSION)
