/*
 * SYSCALL_DEFINE3(setresuid, uid_t, ruid, uid_t, euid, uid_t, suid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: all three slots set by setresuid must round-trip through
 * getresuid().  trinity always passes 0..65535 (no -1 sentinel), so every
 * arg is an expected value.
 */
static void post_setresuid(struct syscallrecord *rec)
{
	uid_t want_r, want_e, want_s, r, e, s;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	if (getresuid(&r, &e, &s) != 0)
		return;

	want_r = (uid_t) rec->a1;
	want_e = (uid_t) rec->a2;
	want_s = (uid_t) rec->a3;
	if (r != want_r || e != want_e || s != want_s) {
		output(0, "cred oracle: setresuid(%u, %u, %u) succeeded but "
		       "getresuid()={r=%u, e=%u, s=%u}\n",
		       want_r, want_e, want_s, r, e, s);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setresuid = {
	.name = "setresuid",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.post = post_setresuid,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE3(setresuid16, old_uid_t, ruid, old_uid_t, euid, old_uid_t, suid)
 */

struct syscallentry syscall_setresuid16 = {
	.name = "setresuid16",
	.num_args = 3,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_RANGE, [2] = ARG_RANGE },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.arg_params[1].range.low = 0,
	.arg_params[1].range.hi = 65535,
	.arg_params[2].range.low = 0,
	.arg_params[2].range.hi = 65535,
	.group = GROUP_PROCESS,
};
