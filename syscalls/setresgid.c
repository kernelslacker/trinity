/*
 * SYSCALL_DEFINE3(setresgid, gid_t, rgid, gid_t, egid, gid_t, sgid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/* Mirror of post_setresuid for the gid side. */
static void post_setresgid(struct syscallrecord *rec)
{
	gid_t want_r, want_e, want_s, r, e, s;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	if (getresgid(&r, &e, &s) != 0)
		return;

	want_r = (gid_t) rec->a1;
	want_e = (gid_t) rec->a2;
	want_s = (gid_t) rec->a3;
	if (r != want_r || e != want_e || s != want_s) {
		output(0, "cred oracle: setresgid(%u, %u, %u) succeeded but "
		       "getresgid()={r=%u, e=%u, s=%u}\n",
		       want_r, want_e, want_s, r, e, s);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setresgid = {
	.name = "setresgid",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.post = post_setresgid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE3(setresgid16, old_gid_t, rgid, old_gid_t, egid, old_gid_t, sgid)
 */

struct syscallentry syscall_setresgid16 = {
	.name = "setresgid16",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.group = GROUP_PROCESS,
};
