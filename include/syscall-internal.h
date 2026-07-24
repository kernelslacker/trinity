#pragma once

/*
 * Private helpers shared across the dispatch/syscall-*.c files.  Not part
 * of the public syscall.h API; consumers live only in dispatch/.
 */

#include <stdbool.h>

#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"

/*
 * Source of truth for the per-syscall return-type contract consumed by
 * reject_corrupt_retfd, the RZS gate in syscall_ret_validate_phase, and
 * validate_ret_bound below.
 *
 * Prefer entry->rettype: it is stamped once at table-init time in
 * copy_syscall_table() and never rewritten after, so a sibling stomp
 * targeting per-rec slots in shm cannot drift it.  rec->rettype lives
 * inside struct syscallrecord alongside rec->retval / rec->errno_post,
 * is rewritten on every dispatch from generate_syscall_args(), and is
 * directly exposed to the same value-result sibling-stomp class the
 * rzs/retfd validators are meant to catch against rec->retval.  When
 * that stomp lands on rec->rettype itself the validator misattributes
 * the corruption to a syscall whose static contract is unambiguous
 * (e.g. getpgrp returning its own pid is gated as if it had been a
 * zero-success syscall returning a non-zero value, because rec->rettype
 * was scribbled from RET_PID_T to RET_ZERO_SUCCESS between dispatch and
 * the gate).  Sourcing from entry sidesteps that class for every syscall
 * that declares a static rettype.
 *
 * Op-multiplexed entries (fcntl, futex) leave entry->rettype unset
 * (RET_NONE) and rely on their .sanitise hook to publish rec->rettype
 * per cmd at dispatch time.  Fall through to rec for those so the
 * per-cmd contract still drives the gate.
 */
static inline int effective_rettype(const struct syscallentry *entry,
				    const struct syscallrecord *rec)
{
	if (entry->rettype != RET_NONE)
		return entry->rettype;
	return rec->rettype;
}

void arena_liveness_probe(struct syscallentry *entry,
			  struct syscallrecord *rec);

bool reject_corrupt_retfd(const struct syscallentry *entry,
			  struct syscallrecord *rec);
void register_returned_fd(const struct syscallentry *entry,
			  struct syscallrecord *rec);
