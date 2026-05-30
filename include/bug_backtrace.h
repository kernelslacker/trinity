#pragma once

#include <stdint.h>

/*
 * Per-child backtrace capture for __BUG() events.
 *
 * The child's stdout/stderr are redirected to /dev/null in init_child,
 * so any backtrace_symbols output produced from inside __BUG() is lost
 * even though the BUG header itself reaches the parent via the
 * bug_text/bug_func/bug_lineno stamp in shared childdata.  Recover the
 * backtrace by having the child stamp raw frame pointers from
 * backtrace(3) into this shared block before it starts spinning; the
 * parent re-symbolises them from its own (real-stderr) context via
 * dump_child_bug().
 *
 * 64 frames matches half of BACKTRACE_SIZE in debug.c -- trinity's
 * typical assertion sites land ~10-20 frames deep through syscall
 * dispatch + handler + sanitiser, so 64 has generous headroom while
 * keeping the per-child footprint to ~520 B.
 */
#define BUG_BACKTRACE_MAX_FRAMES	64

struct bug_backtrace {
	/* Number of valid entries in frames[].  Producer issues a release
	 * store after populating the array; consumer issues an acquire
	 * load to observe the matching frames intact.  0 means no
	 * backtrace was captured (USE_BACKTRACE unset, or child died
	 * between bug_text stamp and backtrace() return). */
	uint32_t count;
	uint32_t _pad;
	void *frames[BUG_BACKTRACE_MAX_FRAMES];
};
