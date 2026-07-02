/*
 * Sequence-chain retval substitution: rewrite one randomly chosen arg
 * slot of the current syscall record with the previous chain step's
 * retval before dispatch.c publishes the record.  Called from both
 * the fresh-args path (random_syscall_step) and the corpus-replay
 * path (replay_syscall_step) so the substitution semantics are
 * identical regardless of where the args came from.
 *
 * compute_numeric_substitute_mask is public via include/syscall.h;
 * apply_chain_substitution is cross-cluster private (declared in
 * include/random-syscall-internal.h); argtype_accepts_numeric_
 * substitute is file-scope static.
 */

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "arch.h"	// biarch
#include "arg-decoder.h"
#include "child.h"
#include "cmp-frontier.h"
#include "cmp_hints.h"
#include "cred_throttle.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "locks.h"
#include "minicorpus.h"
#include "params.h"
#include "pids.h"
#include "pre_crash_ring.h"
#include "prop_ring.h"
#include "random.h"
#include "random-syscall-internal.h"
#include "reach-band.h"
#include "rnd.h"
#include "sequence.h"
#include "shm.h"
#include "signals.h"
#include "sanitise.h"
#include "stats.h"
#include "stats_ring.h"
#include "strategy.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/*
 * Probability (in percent) that, when a substitute retval is offered by
 * the sequence-chain executor, one randomly-chosen arg slot is overwritten
 * with it.  Exposed here (rather than in sequence.c) because the substitution
 * itself happens between argument generation and dispatch, which lives in
 * this file.  Tunable independently of the chain length distribution.
 */
#define CHAIN_SUBST_PCT 30

/*
 * Substituting the previous syscall's return value (almost always a
 * small integer — fd, retval, error code) into a pointer-typed arg
 * slot produces a wild pointer.  The rendering path then SEGVs in
 * printf("%s", small_int) → strlen(0x402), or the kernel deref'es a
 * wild address, depending on which slot got stomped.  Restrict
 * substitution to slots whose argtype legitimately accepts a numeric
 * value.
 */
static bool argtype_accepts_numeric_substitute(enum argtype t)
{
	switch (t) {
	case ARG_UNDEFINED:
	case ARG_FD:
	case ARG_LEN:
	case ARG_MODE_T:
	case ARG_PID:
	case ARG_KEY_SERIAL:
	case ARG_TIMERID:
	case ARG_AIO_CTX:
	case ARG_SEM_ID:
	case ARG_MSG_ID:
	case ARG_SYSV_SHM:
	case ARG_RANGE:
	case ARG_OP:
	case ARG_LIST:
	case ARG_CPU:
	case ARG_NUMA_NODE:
	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
	case ARG_STRUCT_SIZE:
	case ARG_BUF_LEN:
	case ARG_FD_BPF_BTF:
	case ARG_FD_BPF_LINK:
	case ARG_FD_BPF_MAP:
	case ARG_FD_BPF_PROG:
	case ARG_FD_EPOLL:
	case ARG_FD_EVENTFD:
	case ARG_FD_FANOTIFY:
	case ARG_FD_FS_CTX:
	case ARG_FD_INOTIFY:
	case ARG_FD_IO_URING:
	case ARG_FD_LANDLOCK:
	case ARG_FD_MEMFD:
	case ARG_FD_MOUNT:
	case ARG_FD_MQ:
	case ARG_FD_PERF:
	case ARG_FD_PIDFD:
	case ARG_FD_PIPE:
	case ARG_FD_SIGNALFD:
	case ARG_FD_SOCKET:
	case ARG_FD_TIMERFD:
		return true;
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_PATHNAME:
	case ARG_XATTR_NAME:
	case ARG_FSTYPE_NAME:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_NODEMASK:
	case ARG_CPUMASK:
	case ARG_BUF_SIZED:
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
	case ARG_SOCKADDR:
	case ARG_MMAP:
	case ARG_SOCKETINFO:
	case ARG_STRUCT_PTR_IN:
	case ARG_STRUCT_PTR_OUT:
	case ARG_STRUCT_PTR_INOUT:
		return false;
	}
	return false;
}

/*
 * Build the numeric-substitute slot bitmap for entry's argtype[] table.
 * Called once per syscallentry at table-init time from
 * copy_syscall_table() in tables.c; the cached mask in
 * entry->numeric_substitute_mask then drives apply_chain_substitution()
 * below without re-walking argtype[] or re-running the 60-case
 * argtype_accepts_numeric_substitute() switch on every chain step.
 * Bit k (k=0..5) set means slot (k+1) accepts a numeric substitute.
 */
uint8_t compute_numeric_substitute_mask(const struct syscallentry *entry)
{
	uint8_t mask = 0;
	unsigned int i;

	if (entry == NULL)
		return 0;

	for (i = 0; i < entry->num_args && i < 6; i++) {
		if (argtype_accepts_numeric_substitute(entry->argtype[i]))
			mask |= (uint8_t)(1u << i);
	}
	return mask;
}

/*
 * Apply Phase 1 retval substitution to rec in place.  Used by both the
 * fresh-args path (random_syscall_step) and the corpus-replay path
 * (replay_syscall_step) so the chain semantics — substituted args reach
 * the kernel and show up in the trace — are identical regardless of
 * where the args came from.  No-op when no substitute is offered, the
 * dice roll comes up against, the syscall takes zero args, or no arg
 * slot has a numeric-substitute-compatible argtype.
 */
void apply_chain_substitution(struct syscallrecord *rec,
				     struct syscallentry *entry,
				     bool have_substitute,
				     unsigned long substitute_retval)
{
	unsigned int nsafe, pick, slot, i;
	uint8_t mask;

	if (!have_substitute)
		return;
	if (entry == NULL || entry->num_args == 0)
		return;
	if (rnd_modulo_u32(100) >= CHAIN_SUBST_PCT)
		return;

	mask = entry->numeric_substitute_mask;
	if (mask == 0)
		return;
	if (substitute_retval == (unsigned long)mainpid) {
		for (i = 0; i < entry->num_args && i < 6; i++) {
			if (entry->argtype[i] == ARG_PID)
				mask &= (uint8_t)~(1u << i);
		}
		if (mask == 0)
			return;
	}

	/*
	 * Same defence for protected fds (kcov PC/cmp, STDERR_FILENO, the
	 * stderr capture memfd).  sanitise_dup2 picks newfd from
	 * [256, 4095) and other ranges that overlap those slots; a
	 * successful dup2() to one of them silently closes the protected
	 * fd, and propagating its number into a downstream
	 * close()/close_range()/dup2() arg via the chain substitute
	 * finishes the job.  Mask the fd slots when substitute_retval
	 * names a protected fd so the chain steers the substitute to a
	 * non-fd slot (or skips this step entirely).
	 */
	if (fd_is_protected((int)substitute_retval)) {
		for (i = 0; i < entry->num_args && i < 6; i++) {
			if (is_fdarg(entry->argtype[i]))
				mask &= (uint8_t)~(1u << i);
		}
		if (mask == 0)
			return;
	}

	/*
	 * Pick uniformly from the eligible-slot set: count the active
	 * bits in mask, draw a uniform index in [0, nsafe), then walk
	 * mask to find the index-th set bit.  A raw __builtin_ctz(mask)
	 * pick would bias hard toward low-numbered slots -- bit 0 wins
	 * with p=0.5, bit 1 with p=0.25, and so on -- so the explicit
	 * rank walk is required to keep the draw uniform.
	 */
	nsafe = (unsigned int)__builtin_popcount(mask);
	pick = rnd_modulo_u32(nsafe);
	slot = 0;
	for (i = 0; i < 6; i++) {
		if ((mask & (1u << i)) == 0)
			continue;
		if (pick == 0) {
			slot = i + 1;
			break;
		}
		pick--;
	}

	switch (slot) {
	case 1: rec->a1 = substitute_retval; break;
	case 2: rec->a2 = substitute_retval; break;
	case 3: rec->a3 = substitute_retval; break;
	case 4: rec->a4 = substitute_retval; break;
	case 5: rec->a5 = substitute_retval; break;
	case 6: rec->a6 = substitute_retval; break;
	}
	if (minicorpus_shm != NULL)
		__atomic_fetch_add(&minicorpus_shm->chain_substitution_count,
				   1, __ATOMIC_RELAXED);
}
