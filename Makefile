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
OBJS := src/main.o src/config.o src/connection.o src/http.o src/bridge.o src/ws_client.o src/ws.o src/json.o src/jsonw.o src/registry.o

# Each suite links ONLY the module under test plus what that module
# actually needs — not $(OBJS). A test binary that drags in the whole
# program stops being able to fail for one reason, and connection.c in
# particular pulls a listener and a thread into a suite that wanted to
# check a string.
#
# TEST_CFLAGS mirrors the reasoning above for CFLAGS: warnings and
# hardening are appended, never left overridable, so `make check
# CFLAGS=-O0` can't quietly drop -Wall from the tests alone. -g always,
# because the first thing anyone does with a red suite is run it under a
# debugger or a sanitizer.
TEST_CFLAGS := $(CFLAGS) -g

TESTS := tests/test_json tests/test_ws tests/test_jsonw tests/test_config tests/test_http tests/test_bridge tests/test_render tests/test_server_window tests/test_registry tests/test_grappa_admin tests/test_who tests/test_whois tests/test_isupport

.PHONY: all clean install version check

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

install: $(BIN)
	install -D -m 755 $(BIN) $(DESTDIR)$(BINDIR)/$(BIN)

check: $(TESTS)
	@fail=0; for t in $(TESTS); do \
		printf '%s: ' "$$t"; \
		./$$t || fail=1; \
	done; \
	exit $$fail

tests/test_json: tests/test_json.c tests/test.h src/json.c src/json.h
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_json.c src/json.c

tests/test_ws: tests/test_ws.c tests/test.h src/ws.c src/ws.h
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_ws.c src/ws.c

tests/test_jsonw: tests/test_jsonw.c tests/test.h src/jsonw.c src/jsonw.h
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_jsonw.c src/jsonw.c

tests/test_config: tests/test_config.c tests/test.h src/config.c src/config.h
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_config.c src/config.c

# Compiles http.c INTO the suite: the functions worth testing here
# (URL/status/Content-Length parsing, the growing buffer) are static, and
# the alternative — exporting them just to test them — widens the header
# for no caller's benefit. Needs -lssl/-lcrypto because http.c's other
# half does TLS, even though none of it is exercised.
tests/test_http: tests/test_http.c tests/test.h src/http.c src/http.h
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_http.c -lssl -lcrypto

# ws_stub.c replaces ws_client.c at link time. The REAL ws.c comes along:
# bridge_recv_buffered forwards straight into that reader, and a stubbed
# reader would only test the stub.
tests/test_bridge: tests/test_bridge.c tests/test.h tests/ws_stub.c tests/ws_stub.h src/bridge.c src/bridge.h src/json.c src/jsonw.c src/ws.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_bridge.c tests/ws_stub.c src/bridge.c src/json.c src/jsonw.c src/ws.c -lssl -lcrypto

# Compiles connection.c into the suite, so send_line — static, and the
# choke point every render arm passes through — can be driven directly.
# Needs the modules connection.c calls plus the same libraries the binary
# links; nothing is stubbed, because the property under test is what the
# real formatter puts on a real fd.
tests/test_registry: tests/test_registry.c tests/test.h src/registry.c src/registry.h
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_registry.c src/registry.c -lpthread

tests/test_render: tests/test_render.c tests/test.h src/connection.c src/registry.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_render.c src/bridge.c src/http.c src/ws_client.c src/ws.c src/json.c src/jsonw.c src/config.c src/registry.c -lssl -lcrypto -lpthread

# Compiles connection.c in to reach handle_grappa_server_window_row,
# which is static — the same approach test_http uses for the parsers.
# Links what connection.c calls, plus the libraries the binary links.
tests/test_server_window: tests/test_server_window.c tests/test.h src/connection.c src/registry.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_server_window.c src/bridge.c src/http.c src/ws_client.c src/ws.c src/json.c src/jsonw.c src/config.c src/registry.c -lssl -lcrypto -lpthread

# Compiles connection.c in to reach the static admin handlers: grappa_admin_notice,
# render_session_list, parse_positive_long, is_safe_path_segment, handle_grappa_admin.
# Same pattern as test_render and test_server_window.
tests/test_grappa_admin: tests/test_grappa_admin.c tests/test.h src/connection.c src/registry.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_grappa_admin.c src/bridge.c src/http.c src/ws_client.c src/ws.c src/json.c src/jsonw.c src/config.c src/registry.c -lssl -lcrypto -lpthread

# Compiles connection.c in to reach handle_who (static); ws_stub.c
# replaces ws_client.c at link time so bridge_push frames are captured
# for inspection without hitting a real network. Same deps as test_bridge
# plus everything connection.c calls.
tests/test_who: tests/test_who.c tests/test.h tests/ws_stub.c tests/ws_stub.h src/connection.c src/registry.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_who.c tests/ws_stub.c src/bridge.c src/json.c src/jsonw.c src/ws.c src/config.c src/registry.c src/http.c -lssl -lcrypto -lpthread

# Compiles connection.c in to reach handle_grappa_whois_bundle_event (static).
# Tests the P-0a bahamut fields added in issue #72. Same deps as test_render.
tests/test_whois: tests/test_whois.c tests/test.h src/connection.c src/registry.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_whois.c src/bridge.c src/http.c src/ws_client.c src/ws.c src/json.c src/jsonw.c src/config.c src/registry.c -lssl -lcrypto -lpthread

# Compiles connection.c in to reach handle_grappa_isupport_changed_event (static).
# Tests that STATUSMSG= in the 005 is derived from PREFIX sigils, not hardcoded (#83).
tests/test_isupport: tests/test_isupport.c tests/test.h src/connection.c src/registry.c
	$(CC) $(CPPFLAGS) $(TEST_CFLAGS) -o $@ tests/test_isupport.c src/bridge.c src/http.c src/ws_client.c src/ws.c src/json.c src/jsonw.c src/config.c src/registry.c -lssl -lcrypto -lpthread

clean:
	rm -f $(BIN) src/*.o $(TESTS)

version:
	@echo $(BICCHIERINO_VERSION)
