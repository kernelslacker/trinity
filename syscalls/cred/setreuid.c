/*
 * SYSCALL_DEFINE2(setreuid, uid_t, ruid, uid_t, euid)
 */
#include <unistd.h>
#include <sys/types.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: setreuid(r, e) — verify both ids stuck via getresuid().  trinity's
 * sanitise gives us 0..65535 for each arg, so we never pass the (uid_t)-1
 * "leave unchanged" sentinel; treat both args as required values.
 */
static void post_setreuid(struct syscallrecord *rec)
{
	uid_t r_in = (uid_t) rec->a1;
	uid_t e_in = (uid_t) rec->a2;
	uid_t want_r, want_e, r, e, s;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	if (getresuid(&r, &e, &s) != 0)
		return;

	want_r = r_in;
	want_e = e_in;
	if (r != want_r || e != want_e) {
		output(0, "cred oracle: setreuid(%u, %u) succeeded but "
		       "getresuid()={r=%u, e=%u, s=%u}\n",
		       want_r, want_e, r, e, s);
		__atomic_add_fetch(&shm->stats.oracle.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setreuid = {
	.name = "setreuid",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.post = post_setreuid,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};


/*
 * SYSCALL_DEFINE2(setreuid16, old_uid_t, ruid, old_uid_t, euid)
 */

struct syscallentry syscall_setreuid16 = {
	.name = "setreuid16",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
};
