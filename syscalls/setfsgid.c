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

	if (!ONE_IN(20))
		return;

	want = (gid_t) rec->a1;
	prev = (gid_t) rec->retval;
	probe = (gid_t) setfsgid((gid_t) -1);

	if (probe != want && probe != prev) {
		output(0, "cred oracle: setfsgid(%u) returned prev=%u but "
		       "no-op probe shows current=%u\n",
		       want, prev, probe);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
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
	.group = GROUP_VFS,
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
	.group = GROUP_VFS,
};
