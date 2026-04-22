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
