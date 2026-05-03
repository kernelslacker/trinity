/*
 * SYSCALL_DEFINE3(getresgid, gid_t __user *, rgid, gid_t __user *, egid, gid_t __user *, sgid)
 */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_getresgid(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(gid_t));
	avoid_shared_buffer(&rec->a2, sizeof(gid_t));
	avoid_shared_buffer(&rec->a3, sizeof(gid_t));
}

/*
 * Oracle: getresgid(&rgid, &egid, &sgid) writes this task's real,
 * effective, and saved gids out of current_cred()->gid / egid / sgid.
 * The procfs view of the same fact is the "Gid:" line of
 * /proc/self/status, which proc_pid_status() formats from the same
 * task_struct -> real_cred linkage as four whitespace-separated
 * decimals: Real Effective Saved Filesystem.  Both views read the
 * same backing struct cred under rcu, but via different code paths
 * — sys_getresgid copies three fields out via copy_to_user, procfs
 * formats them through a seq_file fill — so a divergence between
 * the two for the same task is its own corruption shape: torn write
 * to cred, stale rcu cred pointer, or anything else that desyncs
 * the cached gids from one another.  fsgid is a separate field and
 * not part of getresgid's contract, so only the first three columns
 * are validated.  Gate on retval == 0 because failures wrote no
 * gids; sample one in a hundred to match the rest of the oracle
 * family.
 */
static void post_getresgid(struct syscallrecord *rec)
{
	FILE *f;
	char line[256];
	gid_t krgid, kegid, ksgid;
	unsigned long pgid_real, pgid_eff, pgid_saved;

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
			outputerr("post_getresgid: rejected suspicious rgid=%p egid=%p sgid=%p (pid-scribbled?)\n",
				  r, e, s);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	krgid = *(gid_t *)(unsigned long) rec->a1;
	kegid = *(gid_t *)(unsigned long) rec->a2;
	ksgid = *(gid_t *)(unsigned long) rec->a3;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "Gid:", 4) == 0) {
			if (sscanf(line + 4, "%lu %lu %lu",
				   &pgid_real, &pgid_eff, &pgid_saved) != 3) {
				fclose(f);
				return;
			}
			fclose(f);

			if ((unsigned long) krgid != pgid_real ||
			    (unsigned long) kegid != pgid_eff ||
			    (unsigned long) ksgid != pgid_saved) {
				output(0, "getresgid oracle: syscall returned "
				       "r=%lu e=%lu s=%lu but /proc/self/status "
				       "Gid: %lu %lu %lu\n",
				       (unsigned long) krgid,
				       (unsigned long) kegid,
				       (unsigned long) ksgid,
				       pgid_real, pgid_eff, pgid_saved);
				__atomic_add_fetch(&shm->stats.getresgid_oracle_anomalies, 1,
						   __ATOMIC_RELAXED);
			}
			return;
		}
	}
	fclose(f);
}

struct syscallentry syscall_getresgid = {
	.name = "getresgid",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.sanitise = sanitise_getresgid,
	.group = GROUP_PROCESS,
	.post = post_getresgid,
};


/*
 * SYSCALL_DEFINE3(getresgid16, old_gid_t __user *, rgid, old_gid_t __user *, egid, old_gid_t __user *, sgid)
 */

struct syscallentry syscall_getresgid16 = {
	.name = "getresgid16",
	.num_args = 3,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "rgid", [1] = "egid", [2] = "sgid" },
	.sanitise = sanitise_getresgid,
	.group = GROUP_PROCESS,
};
