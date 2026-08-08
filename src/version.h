/* version.h — the running binary's own version string.
 *
 * BICCHIERINO_VERSION is supplied by the Makefile at compile time
 * (-D, derived from git describe + the short commit hash — see the
 * Makefile's own comment for the exact derivation and why there's no
 * separate VERSION file to drift out of sync with the actual tag).
 * The fallback here only fires for a build that bypassed the Makefile
 * entirely (a bare `cc` invocation over the source files directly) —
 * "bicchierino-dev" is an honest "unknown build" marker, never a stale
 * hardcoded number pretending to be a real version.
 */
#ifndef BICCHIERINO_VERSION_H
#define BICCHIERINO_VERSION_H

#ifndef BICCHIERINO_VERSION
#define BICCHIERINO_VERSION "bicchierino-dev"
#endif

#endif /* BICCHIERINO_VERSION_H */
