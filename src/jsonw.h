/* jsonw.h — the tiny bit of JSON *writing* bicchierino needs.
 *
 * Not vendored: json.c (from shottino, MIT) only reads JSON and
 * re-serializes an already-parsed value — it has no builder API for
 * constructing a fresh document from raw C strings. Every outbound
 * JSON bicchierino sends (the login body, phx_join frames, ...) is a
 * small, fixed-shape message with a handful of string fields
 * interpolated in, so a full builder would be more than this needs —
 * this one function is genuinely all of it.
 */
#ifndef BICCHIERINO_JSONW_H
#define BICCHIERINO_JSONW_H

#include <stdbool.h>
#include <stddef.h>

/* Escapes `src` as a JSON string's contents (no surrounding quotes —
 * callers write those themselves as part of the larger template) into
 * `dst`, truncating rather than overflowing if `dst_sz` is too small.
 *
 * Returns false when it truncated, true when the whole of `src` fitted.
 * This is the ONLY place that can tell: a caller comparing lengths
 * afterwards would have to re-derive the escaping to know what should
 * have fitted. Every caller here interpolates the result into a larger
 * JSON template, where a silently shortened value does not degrade the
 * message — it names something else. `dst` is always left
 * NUL-terminated, truncated or not, so a caller that decides truncation
 * is acceptable can still use it.
 *
 * dst_sz == 0 writes nothing and returns false (there is nowhere to put
 * even the terminator). */
bool json_escape_into(const char *src, char *dst, size_t dst_sz);

#endif /* BICCHIERINO_JSONW_H */
