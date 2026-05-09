#pragma once

#include <stddef.h>

/*
 * Render a code pointer as "binary+0xOFFSET" into the caller-provided
 * buffer, where OFFSET is the address relative to the containing
 * binary's load base.  This matches the form printed by
 * backtrace_symbols() and feeds straight into:
 *
 *     addr2line -e ./trinity 0xOFFSET
 *
 * which is the only sane way to resolve PCs captured from a PIE binary
 * (raw absolute addresses depend on each process's random load base).
 *
 * Falls back to a "%p"-formatted absolute address if dladdr() can't
 * resolve the pointer.  Always returns buf so the call sits naturally
 * inside a printf argument list.
 */
const char *pc_to_string(void *pc, char *buf, size_t buflen);

/*
 * Best-effort "file.c:NNN" resolution for a captured PC by shelling
 * out to addr2line(1).  Returns a pointer into the caller's buffer on
 * success, NULL on any failure (no addr2line on PATH, dladdr miss,
 * fork/pipe error, address unresolved).  Caller is expected to fall
 * back to the bare pc_to_string() form on NULL.
 *
 * Source coordinates are what an operator actually needs from the
 * per-PC dump rings: a load-relative offset whose captured PC lands
 * inside an LTO-inlined static helper would otherwise be rendered as
 * the nearest preceding global symbol (the one addr2line rounds DOWN
 * to), which mis-attributes the row to a function several inlines
 * away.  See pc_format.c for the full rationale.
 *
 * Cost: one fork+exec per call.  Suitable for periodic dump paths,
 * not for any hot path.  Caller buffer should be sized for a full
 * "/path/to/file.c:NNNN" string -- 256 bytes is comfortable.
 */
const char *pc_to_source_line(void *pc, char *buf, size_t buflen);
