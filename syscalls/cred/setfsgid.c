/*
 * SYSCALL_DEFINE1(setfsgid, gid_t, gid)
 */
#include <sys/fsuid.h>
#include <sys/types.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/* Mirror of post_setfsuid for the gid side; same probe-with-(gid_t)-1 trick. */
static void post_setfsgid(struct syscallrecord *rec)
{
	gid_t want, prev, probe;

	/* --dry-run synthesizes retval -1 / ENOSYS without entering the
	 * kernel, and a fuzzed seccomp filter can return -1 with an errno on
	 * a live run.  Neither installed a new fsgid, so the probe below would
	 * be comparing against a prev we never got -- and issuing a real
	 * setfsgid() from the dry-run path, which is meant to be syscall-free.
	 */
	if (syscall_errno_failure(rec))
		return;

	if (!ONE_IN(20))
		return;

	want = (gid_t) rec->a1;
	prev = (gid_t) rec->retval;
	probe = (gid_t) setfsgid((gid_t) -1);

	if (probe != want && probe != prev) {
		output(0, "cred oracle: setfsgid(%u) returned prev=%u but "
		       "no-op probe shows current=%u\n",
		       want, prev, probe);
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setfsgid = {
	.name = "setfsgid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.post = post_setfsgid,
	.group = GROUP_CRED,
	.rettype = RET_GID_T,
};

/*
 * SYSCALL_DEFINE1(setfsgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setfsgid16 = {
	.name = "setfsgid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_CRED,
	.rettype = RET_GID_T,
};
