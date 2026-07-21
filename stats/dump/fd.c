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

static void dump_fd_lifecycle(void)
{
	if (shm->stats.fd.stale_detected || shm->stats.fd.closed_tracked ||
	    shm->stats.fd.stale_by_generation ||
	    shm->stats.fd.duped || shm->stats.fd.events_processed ||
	    shm->stats.fd.hash_reinsert_dropped ||
	    shm->stats.fd.local_hash_insert_dropped ||
	    shm->stats.epoll_volatility.lazy_armed ||
	    shm->stats.epoll_volatility.blocking_poll_skipped ||
	    shm->stats.fd.random_exhausted ||
	    shm->stats.fd.provider_invalid) {
		stat_row("fd_lifecycle", "stale_detected",      shm->stats.fd.stale_detected);
		stat_row("fd_lifecycle", "stale_by_generation", shm->stats.fd.stale_by_generation);
		stat_row("fd_lifecycle", "closed_tracked",      shm->stats.fd.closed_tracked);
		stat_row("fd_lifecycle", "duped",               shm->stats.fd.duped);
		stat_row("fd_lifecycle", "events_processed",    shm->stats.fd.events_processed);
		stat_row("fd_lifecycle", "events_dropped",      shm->stats.fd.events_dropped);
		stat_row("fd_lifecycle", "event_close_count",   shm->stats.fd.event_close_count);
		stat_row("fd_lifecycle", "event_evict_count",   shm->stats.fd.event_evict_count);
		stat_row("fd_lifecycle", "hash_reinsert_dropped", shm->stats.fd.hash_reinsert_dropped);
		stat_row("fd_lifecycle", "local_hash_insert_dropped",
			 shm->stats.fd.local_hash_insert_dropped);
		stat_row("fd_lifecycle", "epoll_lazy_armed",    shm->stats.epoll_volatility.lazy_armed);
		stat_row("fd_lifecycle", "epoll_blocking_poll_skipped",
			 shm->stats.epoll_volatility.blocking_poll_skipped);
		stat_row("fd_lifecycle", "random_exhausted",    shm->stats.fd.random_exhausted);
		stat_row("fd_lifecycle", "provider_invalid",    shm->stats.fd.provider_invalid);
	}
}

/*
 * Per-provider outstanding-fd gauge.  Only providers whose live
 * count is non-zero get a row -- a clean run with no leaks emits
 * nothing; a non-empty block at shutdown surfaces a per-provider
 * fd leak (CLOSE events lost in the fd_event ring, an OBJ_GLOBAL
 * registration whose subsequent close() bypassed remove_object_by_fd,
 * etc.).  The label comes from the registered fd_provider name so
 * the row matches --enable-fds/--disable-fds syntax; an entry whose
 * objtype has no matching provider is skipped (defensive: should
 * not happen, since the bump site fires only on a successful
 * fd_hash_insert for an is_fd_type() objtype).
 */
static void dump_fd_provider_outstanding(void)
{
	unsigned int t;

	for (t = 0; t < MAX_OBJECT_TYPES; t++) {
		unsigned long outstanding =
			shm->stats.fd.provider_outstanding[t];
		const char *name;

		if (outstanding == 0)
			continue;

		name = fd_provider_name((enum objecttype) t);
		if (name == NULL)
			continue;

		stat_row("fd_provider_outstanding", name, outstanding);
	}
}

void dump_stats_fd_tracking(void)
{
	if (parent_stats.fault_injected) {
		stat_row("fault_injection", "armed_fail_nth",  parent_stats.fault_injected);
		stat_row("fault_injection", "returned_enomem", parent_stats.fault_consumed);
	}

	dump_fd_lifecycle();

	dump_fd_provider_outstanding();

	/* Producer-side capture count for the typed-scalar bypass push.
	 * Sibling to kcov_shm->hints_flat.propagation_injected (consumer-side); see
	 * the field comment in include/stats.h.  Lives next to the
	 * fd_runtime_* family because its capture site is the same
	 * register_returned_fd dispatch -- the OBJ_KEY_SERIAL branch
	 * mirrors the value into prop_ring after handing it to the typed
	 * registrar. */
	if (shm->stats.diag.propagation_injected_key_scalar) {
		stat_row("propagation", "injected_key_scalar",
			 shm->stats.diag.propagation_injected_key_scalar);
	}
}

