/*
 * SYSCALL_DEFINE2(msgget, key_t, key, int, msgflg)
 */
#include <limits.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void post_msgget(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	/* Ordinary error return: -1 with errno set. */
	if (ret < 0)
		return;

	/*
	 * The kernel ABI guarantees msgget() returns either -1 or a
	 * non-negative int IPC id (i.e. 0..INT_MAX). A retval outside
	 * that range cannot have come from the kernel: either a
	 * sibling op has scribbled the syscallrecord retval slot with
	 * pointer-shaped junk, or the slot has been torn under us. In
	 * either case forwarding the bogus value into msgctl(IPC_RMID)
	 * would issue a remove against whatever real IPC id happens to
	 * collide with the low 31 bits of the garbage -- typically
	 * destroying an unrelated object owned by another process on
	 * the host.
	 */
	if (ret > INT_MAX) {
		output(0, "msgget oracle: returned IPC id 0x%lx out of "
			  "range (must be 0..INT_MAX)\n",
			  (unsigned long) rec->retval);
		(void) looks_like_corrupted_ptr(rec,
						(const void *) rec->retval);
		return;
	}

	msgctl((int) ret, IPC_RMID, NULL);
}

static unsigned long ipc_flags[] = {
	IPC_CREAT,
	IPC_CREAT | 0600,
	IPC_CREAT | 0644,
	IPC_CREAT | 0666,
	IPC_CREAT | IPC_EXCL | 0600,
	IPC_CREAT | IPC_EXCL | 0644,
	IPC_CREAT | IPC_EXCL | 0666,
};

struct syscallentry syscall_msgget = {
	.name = "msgget",
	.group = GROUP_IPC,
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_LIST },
	.argname = { [0] = "key", [1] = "msgflg" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].list = ARGLIST(ipc_flags),
	.post = post_msgget,
};
