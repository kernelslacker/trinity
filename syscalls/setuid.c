/*
 * SYSCALL_DEFINE1(setuid, uid_t, uid)
 */
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: after a successful setuid(N), POSIX guarantees geteuid() == N
 * regardless of whether we had CAP_SETUID (root sets all three; non-root
 * sets only euid).  A divergence here would be a credential corruption
 * bug — exactly the silent privilege-escalation shape that doesn't crash.
 */
static void post_setuid(struct syscallrecord *rec)
{
	uid_t want, got;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	want = (uid_t) rec->a1;
	got = geteuid();
	if (got != want) {
		output(0, "cred oracle: setuid(%u) succeeded but geteuid()=%u\n",
		       want, got);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setuid = {
	.name = "setuid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.post = post_setuid,
	.group = GROUP_PROCESS,
};

/*
 * SYSCALL_DEFINE1(setuid16, old_uid_t, uid)
 */

struct syscallentry syscall_setuid16 = {
	.name = "setuid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_PROCESS,
};
