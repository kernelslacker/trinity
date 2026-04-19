/*
 * SYSCALL_DEFINE2(setregid, gid_t, rgid, gid_t, egid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/* Mirror of post_setreuid for the gid side. */
static void post_setregid(struct syscallrecord *rec)
{
	gid_t want_r, want_e, r, e, s;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	if (getresgid(&r, &e, &s) != 0)
		return;

	want_r = (gid_t) rec->a1;
	want_e = (gid_t) rec->a2;
	if (r != want_r || e != want_e) {
		output(0, "cred oracle: setregid(%u, %u) succeeded but "
		       "getresgid()={r=%u, e=%u, s=%u}\n",
		       want_r, want_e, r, e, s);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setregid = {
	.name = "setregid",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.post = post_setregid,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE2(setregid16, old_gid_t, rgid, old_gid_t, egid)
 */

struct syscallentry syscall_setregid16 = {
	.name = "setregid16",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.group = GROUP_PROCESS,
};
