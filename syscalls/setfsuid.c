/*
 * SYSCALL_DEFINE1(setfsuid, uid_t, uid)
 */
#include <sys/fsuid.h>
#include <sys/types.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Oracle: setfsuid is silent on failure (it returns the previous fsuid in
 * either case), so the standard read-back probe is setfsuid((uid_t)-1)
 * which the kernel rejects as an invalid uid and returns the *current*
 * value without changing anything.
 *
 * After a successful syscall, the current fsuid must be one of:
 *   - the value we just requested (kernel allowed the change), or
 *   - the previous fsuid (kernel disallowed the change — not a bug, just
 *     missing CAP_SETUID and the new uid not matching ruid/euid/suid).
 * Any other observed value is an anomaly: the kernel ignored both our
 * request and the prior state.
 */
static void post_setfsuid(struct syscallrecord *rec)
{
	uid_t want, prev, probe;

	if (!ONE_IN(20))
		return;

	want = (uid_t) rec->a1;
	prev = (uid_t) rec->retval;
	probe = (uid_t) setfsuid((uid_t) -1);

	if (probe != want && probe != prev) {
		output(0, "cred oracle: setfsuid(%u) returned prev=%u but "
		       "no-op probe shows current=%u\n",
		       want, prev, probe);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_setfsuid = {
	.name = "setfsuid",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.post = post_setfsuid,
	.group = GROUP_VFS,
};


/*
 * SYSCALL_DEFINE1(setfsuid16, old_uid_t, uid)
 */

struct syscallentry syscall_setfsuid16 = {
	.name = "setfsuid16",
	.num_args = 1,
	.argtype = { [0] = ARG_RANGE },
	.argname = { [0] = "uid" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65535,
	.group = GROUP_VFS,
};
