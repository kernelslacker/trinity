/*
 * SYSCALL_DEFINE1(umask, int, mask)
 */
#include <stdio.h>
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Oracle: umask(mask) installs (mask & 0777) into current->fs->umask
 * under fs->lock and returns the previous value.  The procfs view of
 * the same fact is the "Umask:" line of /proc/self/status, which
 * proc_pid_status() formats from the same fs_struct->umask as a
 * 4-digit octal with a leading zero (e.g. "0022").  Both views read
 * the same backing field but via different code paths -- the syscall
 * stores under the fs->lock spinlock, procfs walks through a
 * seq_file fill that takes task_lock() to grab fs -- so a divergence
 * between the two is its own corruption shape: torn store to
 * fs->umask, stale fs_struct pointer, or anything else that desyncs
 * the cached mask from the projected one.
 *
 * No retval gate: sys_umask cannot fail, it always returns the prior
 * mask, so any call we sampled has installed the new value.  The
 * kernel masks the argument with 0777 before storing, so the
 * expected value is (rec->a1 & 0777), not the raw a1 (the syscall
 * is declared with int mask and the high bits are silently
 * discarded).  Sample one in a hundred to match the rest of the
 * oracle family; bail silently on any /proc I/O error so the
 * detector stays one-way.
 */
static void post_umask(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	unsigned long a1 = rec->a1;
	char buf[8192];
	const char *value;
	unsigned int kumask;
	unsigned int expected;

	/* Kernel ABI: sys_umask cannot fail and the kernel masks the
	 * incoming argument with 0777 before storing, so the returned
	 * previous mask is always within [0, 0777].  Anything above that
	 * is a torn return, sign-extension, or sibling-stomp on rec->retval
	 * -- not a procfs-divergence the oracle below could catch.  Reject
	 * before the ONE_IN(100) gate so every call is checked.  The
	 * snapshot above pins the value so the bound check and the
	 * diagnostic both report the same retval. */
	if (retval > 0777UL) {
		outputerr("post_umask: rejected retval 0x%lx outside [0, 0777]\n",
			  retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	expected = (unsigned int) a1 & 0777;

	if (proc_status_read(buf, sizeof(buf)) < 0)
		return;
	value = proc_status_find_field(buf, "Umask");
	if (value == NULL || sscanf(value, "%o", &kumask) != 1)
		return;

	if (kumask != expected) {
		output(0, "umask oracle: syscall installed "
		       "mask=%04o (from a1=%#lx) but "
		       "/proc/self/status Umask: %04o\n",
		       expected, a1, kumask);
		__atomic_add_fetch(&shm->stats.oracle.umask_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_umask = {
	.name = "umask",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "mask" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 07777,
	.group = GROUP_PROCESS,
	.post = post_umask,
	.rettype = RET_BORING,
};
