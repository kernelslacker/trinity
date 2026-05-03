/*
 * SYSCALL_DEFINE3(getresuid, uid_t __user *, ruid, uid_t __user *, euid, uid_t __user *, suid)
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_getresuid(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(uid_t));
	avoid_shared_buffer(&rec->a2, sizeof(uid_t));
	avoid_shared_buffer(&rec->a3, sizeof(uid_t));
}

/*
 * Oracle: getresuid(&ruid, &euid, &suid) writes this task's real,
 * effective, and saved uids out of current_cred()->uid / euid / suid.
 * The procfs view of the same fact is the "Uid:" line of
 * /proc/self/status, which proc_pid_status() formats from the same
 * task_struct -> real_cred linkage as four whitespace-separated
 * decimals: Real Effective Saved Filesystem.  Both views read the
 * same backing struct cred under rcu, but via different code paths
 * — sys_getresuid copies three fields out via copy_to_user, procfs
 * formats them through a seq_file fill — so a divergence between
 * the two for the same task is its own corruption shape: torn write
 * to cred, stale rcu cred pointer, or anything else that desyncs
 * the cached uids from one another.  fsuid is a separate field and
 * not part of getresuid's contract, so only the first three columns
 * are validated.  Gate on retval == 0 because failures wrote no
 * uids; sample one in a hundred to match the rest of the oracle
 * family.
 */
static void post_getresuid(struct syscallrecord *rec)
{
	FILE *f;
	char line[256];
	uid_t kruid, keuid, ksuid;
	unsigned long puid_real, puid_eff, puid_saved;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	{
		void *r = (void *)(unsigned long) rec->a1;
		void *e = (void *)(unsigned long) rec->a2;
		void *s = (void *)(unsigned long) rec->a3;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1/a2/a3. */
		if (looks_like_corrupted_ptr(r) ||
		    looks_like_corrupted_ptr(e) ||
		    looks_like_corrupted_ptr(s)) {
			outputerr("post_getresuid: rejected suspicious ruid=%p euid=%p suid=%p (pid-scribbled?)\n",
				  r, e, s);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	kruid = *(uid_t *)(unsigned long) rec->a1;
	keuid = *(uid_t *)(unsigned long) rec->a2;
	ksuid = *(uid_t *)(unsigned long) rec->a3;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Uid:", 4) == 0) {
			if (sscanf(line + 4, "%lu %lu %lu",
				   &puid_real, &puid_eff, &puid_saved) != 3) {
				fclose(f);
				return;
			}
			fclose(f);

			if ((unsigned long) kruid != puid_real ||
			    (unsigned long) keuid != puid_eff ||
			    (unsigned long) ksuid != puid_saved) {
				output(0, "getresuid oracle: syscall returned "
				       "r=%lu e=%lu s=%lu but /proc/self/status "
				       "Uid: %lu %lu %lu\n",
				       (unsigned long) kruid,
				       (unsigned long) keuid,
				       (unsigned long) ksuid,
				       puid_real, puid_eff, puid_saved);
				__atomic_add_fetch(&shm->stats.getresuid_oracle_anomalies, 1,
						   __ATOMIC_RELAXED);
			}
			return;
		}
	}
	fclose(f);
}

struct syscallentry syscall_getresuid = {
	.name = "getresuid",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.sanitise = sanitise_getresuid,
	.group = GROUP_PROCESS,
	.post = post_getresuid,
};

/*
 * SYSCALL_DEFINE3(getresuid16, old_uid_t __user *, ruid, old_uid_t __user *, euid, old_uid_t __user *, suid)
 */

struct syscallentry syscall_getresuid16 = {
	.name = "getresuid16",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "ruid", [1] = "euid", [2] = "suid" },
	.sanitise = sanitise_getresuid,
	.group = GROUP_PROCESS,
};
