/*
 * SYSCALL_DEFINE1(setgid, gid_t, gid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: a successful setgid(N) must leave getegid() == N.  Mirror of the
 * setuid oracle for the gid side; same silent-corruption rationale.
 */
static void post_setgid(struct syscallrecord *rec)
{
	gid_t want, got;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	want = (gid_t) rec->a1;
	got = getegid();
	if (got != want) {
		output(0, "cred oracle: setgid(%u) succeeded but getegid()=%u\n",
		       want, got);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setgid = {
	.name = "setgid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.post = post_setgid,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE1(setgid16, old_gid_t, gid)
 */

struct syscallentry syscall_setgid16 = {
	.name = "setgid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "gid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_PROCESS,
};
