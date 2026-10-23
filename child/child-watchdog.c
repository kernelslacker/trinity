/*
 * Stall detection: every SIGALRM child_process() observes runs through
 * check_stall(), which decides whether the current op has stopped making
 * progress; the per-op-type threshold table sits alongside it.
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
	case CHILD_OP_INODE_SPEWER:		return 40;
	case CHILD_OP_PROCFS_WRITER:		return 60;
	case CHILD_OP_XATTR_THRASH:		return 30;
	case CHILD_OP_EPOLL_VOLATILITY:		return 30;
	case CHILD_OP_RXRPC_KEY_INSTALL:	return 30;
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
