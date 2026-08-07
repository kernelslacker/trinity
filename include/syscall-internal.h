#pragma once

/*
 * Private helpers shared across the dispatch/syscall-*.c files.  Not part
 * of the public syscall.h API; consumers live only in dispatch/.
 */

#include <stdbool.h>

#include "kcov.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"

/*
 * clear_stale_kcov_state - zero the kcov trace-buf header and clear
 * dispatch_args_valid for a syscall that never entered the kernel.
 *
 * Called from every kernel-never-entered path (seal failure, arg-validator
 * reject, dry-run) so kcov_collect() does not re-harvest the previous
 * call's CMP/PC records against the current rec->nr, and
 * cmp_hints_collect() does not misattribute stale dispatch_args[] to
 * this call's nr.  Three formerly identical ~12-line blocks, now one.
 */
static inline void clear_stale_kcov_state(struct kcov_child *kc,
					  struct syscallrecord *rec)
{
	if (kc != NULL && kc->active) {
		if (kc->mode == KCOV_MODE_PC && kc->trace_buf != NULL)
			__atomic_store_n(&kc->trace_buf[0], 0,
					 __ATOMIC_RELAXED);
		else if (kc->mode == KCOV_MODE_CMP &&
			 kc->cmp_trace_buf != NULL)
			__atomic_store_n(&kc->cmp_trace_buf[0], 0,
					 __ATOMIC_RELAXED);
	}
	rec->dispatch_args_valid = false;
}

/* effective_rettype() moved to syscall.h so non-dispatch consumers
 * (random_syscall/fd-group.c, persist/minicorpus-xprop.c) can share
 * the same source-of-truth helper for op-multiplexed rettype (bpf,
 * seccomp, fcntl, futex publish rec->rettype from their sanitise). */

void arena_liveness_probe(struct syscallentry *entry,
			  struct syscallrecord *rec);

bool reject_corrupt_retfd(const struct syscallentry *entry,
			  struct syscallrecord *rec);
void register_returned_fd(const struct syscallentry *entry,
			  struct syscallrecord *rec);

void enforce_count_bound(const struct syscallentry *entry,
			 struct syscallrecord *rec);
void validate_ret_bound(const struct syscallentry *entry,
			struct syscallrecord *rec);
void deactivate_enosys(struct syscallrecord *rec,
		       struct syscallentry *entry, unsigned int call);

struct childdata;

void __do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		  enum syscallstate state,
		  struct kcov_child *kc, struct childdata *child);
void do_extrafork(struct syscallrecord *rec, struct syscallentry *entry,
		  struct childdata *child);
