/*
 * SYSCALL_DEFINE2(getgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include "proc-status.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_getgroups(struct syscallrecord *rec)
{
	avoid_shared_buffer_out(&rec->a2, rec->a1 * sizeof(gid_t));
}

/*
 * Oracle: getgroups(0, NULL) returns the supplementary group count for the
 * calling task, sourced from current_cred()->group_info->ngroups.  The
 * procfs view of the same fact is the "Groups:" line of
 * /proc/self/status, which proc_pid_status() / render_cap_t fill from
 * the same task_struct -> real_cred -> group_info linkage by walking
 * group_info->gid[] and emitting each gid as a decimal token.  Both
 * views read the same backing array under rcu, but via different code
 * paths — sys_getgroups returns gi->ngroups directly, procfs counts
 * tokens it formatted itself — so a divergence between the two for the
 * same task is its own corruption shape: torn write to cred, stale rcu
 * cred pointer, or another corruption shape that desyncs the count
 * from the array.  Gate on retval >= 0 because failures returned no
 * count; sample one in a hundred to match the rest of the oracle family.
 */
static void post_getgroups(struct syscallrecord *rec)
{
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	char *buf, *line, *eol;

	/*
	 * Kernel ABI: success retval is the supplementary group count for
	 * the calling task, a non-negative int capped at NGROUPS_MAX =
	 * 65536 (linux/posix_types.h). Failure returns -1UL with EFAULT or
	 * EINVAL on the syscall return path. Anything > NGROUPS_MAX on
	 * success — or any other "negative" value besides -1UL — is a
	 * structural ABI regression: a sign-extension tear, a torn read of
	 * group_info->ngroups, or -errno leaking through the return path.
	 * Reject before the ONE_IN(100) re-read oracle, which would
	 * otherwise miss it 99% of the time.
	 */
	if (retval != (unsigned long)-1L && retval > 65536UL) {
		outputerr("post_getgroups: retval %ld outside [0, NGROUPS_MAX] and != -1UL\n",
			  ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	if (ret < 0)
		return;

	/* Dynamically-sized slurp: Groups: at NGROUPS_MAX is several hundred
	 * KB of decimal-plus-space tokens, well past any sensible stack
	 * buffer.  Skip the oracle on read failure rather than risk a false
	 * positive on a partial capture. */
	buf = proc_status_slurp();
	if (buf == NULL)
		return;

	/* Anchor on a newline so a "Groups:" substring inside an earlier
	 * field cannot mis-target the parse. */
	line = strstr(buf, "\nGroups:");
	if (line != NULL) {
		char *p = line + 8;
		char *tok, *saveptr = NULL;
		int seen = 0;

		/* Bound strtok_r to this single line by NUL-terminating at the
		 * next newline; the original fgets-based code only saw one line
		 * at a time. */
		eol = strchr(p, '\n');
		if (eol != NULL)
			*eol = '\0';

		for (tok = strtok_r(p, " \t", &saveptr); tok;
		     tok = strtok_r(NULL, " \t", &saveptr))
			seen++;

		if (seen != (int) ret) {
			output(0, "groups oracle: /proc/self/status Groups: count %d but rec->retval was %ld\n",
			       seen, ret);
			__atomic_add_fetch(&shm->stats.getgroups_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}

	free(buf);
}

struct syscallentry syscall_getgroups = {
	.name = "getgroups",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.sanitise = sanitise_getgroups,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_PROCESS,
	.post = post_getgroups,
};


/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */

struct syscallentry syscall_getgroups16 = {
	.name = "getgroups16",
	.num_args = 2,
	.argtype = { [0] = ARG_LEN, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.sanitise = sanitise_getgroups,
	.rettype = RET_BORING,
	.flags = REEXEC_SANITISE_OK,
	.group = GROUP_PROCESS,
};
