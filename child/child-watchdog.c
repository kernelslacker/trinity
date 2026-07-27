/*
 * Stall detection / alarm bookkeeping carved out of child.c.  Every
 * SIGALRM the child_process() loop observes runs through check_stall()
 * to decide whether the current op has stopped making progress; the
 * per-op-type threshold table lives here alongside it.  Split out so
 * make -j can compile the watchdog path concurrently with the
 * periodic-tick and childop dispatch arm helpers.
 *
 * check_stall sheds its `static` linkage here so the child_process()
 * main loop (still in child.c) can reach it across the TU boundary;
 * declaration is in include/child-internal.h.  stall_threshold stays
 * static -- check_stall is its lone caller and both live here.
 */

#include "child.h"
#include "child-internal.h"
#include "trinity.h"

/*
 * Per-op-type stall thresholds.  Syscalls are fast, so 10 missed
 * progress checks means something is stuck.  Future op types that do
 * heavier work (fault injection, fd lifecycle stress) get more slack.
 */
static unsigned int stall_threshold(enum child_op_type op_type)
{
	switch (op_type) {
	case CHILD_OP_MMAP_LIFECYCLE:	return 30;
	case CHILD_OP_MPROTECT_SPLIT:	return 30;
	case CHILD_OP_MLOCK_PRESSURE:	return 50;
	case CHILD_OP_INODE_SPEWER:		return 40;
	case CHILD_OP_PROCFS_WRITER:		return 60;
	case CHILD_OP_MEMORY_PRESSURE:		return 30;
	case CHILD_OP_USERNS_FUZZER:		return 60;
	case CHILD_OP_SCHED_CYCLER:		return 30;
	case CHILD_OP_BARRIER_RACER:		return 30;
	case CHILD_OP_GENETLINK_FUZZER:		return 30;
	case CHILD_OP_PERF_CHAINS:		return 30;
	case CHILD_OP_TRACEFS_FUZZER:		return 60;
	case CHILD_OP_BPF_LIFECYCLE:		return 40;
	case CHILD_OP_FAULT_INJECTOR:		return 20;
	case CHILD_OP_RECIPE_RUNNER:		return 40;
	case CHILD_OP_IOURING_RECIPES:		return 40;
	case CHILD_OP_FD_STRESS:		return 30;
	case CHILD_OP_FS_LIFECYCLE:		return 60;
	case CHILD_OP_FLOCK_THRASH:		return 30;
	case CHILD_OP_PIDFD_STORM:		return 30;
	case CHILD_OP_MADVISE_CYCLER:		return 30;
	case CHILD_OP_KEYRING_SPAM:		return 30;
	case CHILD_OP_VDSO_MREMAP_RACE:		return 30;
	case CHILD_OP_NUMA_MIGRATION:		return 40;
	case CHILD_OP_CPU_HOTPLUG_RIDER:	return 50;
	case CHILD_OP_CGROUP_CHURN:		return 30;
	case CHILD_OP_MOUNT_CHURN:		return 40;
	case CHILD_OP_NAT_T_CHURN:		return 40;
	case CHILD_OP_UFFD_CHURN:		return 30;
	case CHILD_OP_IOURING_FLOOD:		return 30;
	case CHILD_OP_CLOSE_RACER:		return 30;
	case CHILD_OP_XATTR_THRASH:		return 30;
	case CHILD_OP_EPOLL_VOLATILITY:		return 30;
	case CHILD_OP_SLAB_CACHE_THRASH:	return 30;
	case CHILD_OP_TLS_ROTATE:		return 30;
	case CHILD_OP_SOCK_ULP_SOCKMAP_LAYERING:	return 30;
	case CHILD_OP_PACKET_FANOUT_THRASH:	return 30;
	case CHILD_OP_SPLICE_PROTOCOLS:		return 30;
	case CHILD_OP_RXRPC_KEY_INSTALL:	return 30;
	case CHILD_OP_AF_ALG_WEAK_CIPHER_PROBE:	return 20;
	case CHILD_OP_AF_ALG_TEMPLATE_PROBE:	return 20;
	case CHILD_OP_TTY_LDISC_CHURN:		return 30;
	default:				return 10;
	}
}

/*
 * Stall detection: count consecutive alarm timeouts without the child
 * making forward progress (op_nr advancing).  If the child is stuck,
 * exit it so the parent can respawn a fresh one.
 */
bool check_stall(struct childdata *child)
{
	if (child->op_nr == child->stall_last) {
		child->stall_count++;
	} else {
		child->stall_count = 0;
		child->stall_last = child->op_nr;
	}
	if (child->stall_count >= stall_threshold(child->op_type)) {
		output(1, "no progress for %u tries (op_type=%d), exiting child.\n",
			child->stall_count, child->op_type);
		return true;
	}
	return false;
}
