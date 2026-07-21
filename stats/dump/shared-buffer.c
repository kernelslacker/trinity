#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "arch.h"
#include "arg-len-semantics.h"
#include "breadcrumb_ring.h"
#include "child-api.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "fd.h"
#include "kcov.h"
#include "minicorpus.h"
#include "params.h"
#include "pc_format.h"
#include "pids.h"
#include "reach-band.h"
#include "sequence.h"
#include "shm.h"
#include "stats.h"
#include "stats-internal.h"
#include "stats_ring.h"
#include "syscall.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "utils.h"
#include "version.h"

void dump_stats_shared_buffer_misc(void)
{
	if (parent_stats.shared_buffer_redirected)
		stat_row("shared_buffer", "args_redirected",     parent_stats.shared_buffer_redirected);
	if (parent_stats.libc_heap_redirected)
		stat_row("shared_buffer", "libc_heap_redirected", parent_stats.libc_heap_redirected);
	if (parent_stats.libc_heap_embedded_redirected)
		stat_row("shared_buffer", "libc_heap_embedded_redirected",
			 parent_stats.libc_heap_embedded_redirected);
	if (parent_stats.asb_relocate_readable_skip)
		stat_row("shared_buffer", "asb_relocate_readable_skip",
			 parent_stats.asb_relocate_readable_skip);
	if (parent_stats.asb_relocate_copy_fault)
		stat_row("shared_buffer", "asb_relocate_copy_fault",
			 parent_stats.asb_relocate_copy_fault);
	if (parent_stats.heap_pointer_outside_cache)
		stat_row("shared_buffer", "heap_pointer_outside_cache",
			 parent_stats.heap_pointer_outside_cache);
	if (parent_stats.heap_brk_stale_window_hit)
		stat_row("shared_buffer", "heap_brk_stale_window_hit",
			 parent_stats.heap_brk_stale_window_hit);
	if (parent_stats.range_overlaps_shared_rejects) {
		stat_row("shared_buffer", "range_overlaps_shared_rejects",
			 parent_stats.range_overlaps_shared_rejects);
		if (verbosity > 1)
			dump_range_overlaps_shared_top_offenders();
	}
	if (shm->stats.diag.shared_region_overflow)
		stat_row("shared_buffer", "shared_region_overflow",
			 shm->stats.diag.shared_region_overflow);
	if (parent_stats.mm_gate_post_slip)
		stat_row("shared_buffer", "mm_gate_post_slip",
			 parent_stats.mm_gate_post_slip);
	if (parent_stats.children_recycled_on_storm)
		stat_row("corruption", "children_recycled_on_storm",
			 parent_stats.children_recycled_on_storm);
	if (parent_stats.watchdog_fd_evict)
		stat_row("watchdog", "watchdog_fd_evict",
			 parent_stats.watchdog_fd_evict);

	if (verbosity > 1)
		dump_syscall_category_histogram();
}
