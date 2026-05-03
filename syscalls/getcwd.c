/*
 * SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "arch.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "random.h"
#include "utils.h"

static void sanitise_getcwd(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, rec->a2 ? rec->a2 : page_size);
}

/*
 * Oracle: sys_getcwd writes the calling task's cwd into the user buffer by
 * walking current->fs->pwd via prepend_path() under the fs->seq read-side
 * seqlock.  /proc/self/cwd is a symlink whose ->get_link runs d_path()
 * against task->fs->pwd, reached via proc_pid_get_link() under the task's
 * task_lock.  Same backing field (fs_struct->pwd), different lock ordering
 * and different prepend_path() callers — divergence between the two for the
 * same task points at one of: a stale rcu pointer, a torn write to the
 * fs_struct, or a path-component truncation in either prepend_path() walk.
 *
 * Known false-positive source: a sibling trinity child (or this child's
 * own next op) doing chdir() between sys_getcwd's return and this post
 * hook firing.  ONE_IN(100) sampling × the low background chdir rate
 * keeps the counter signal-bearing rather than noise-dominated.
 */
static void post_getcwd(struct syscallrecord *rec)
{
	char proc_cwd[PATH_MAX];
	char user_cwd[PATH_MAX];
	ssize_t n;
	long ret;
	size_t copy_len;

	if (!ONE_IN(100))
		return;

	ret = (long)rec->retval;
	if (ret <= 0)
		return;				/* syscall failed/empty */
	if (rec->a1 == 0)
		return;				/* no user buffer */

	{
		void *buf = (void *)(unsigned long) rec->a1;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a1. */
		if (looks_like_corrupted_ptr(buf)) {
			outputerr("post_getcwd: rejected suspicious buf=%p (pid-scribbled?)\n",
				  buf);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	n = readlink("/proc/self/cwd", proc_cwd, sizeof(proc_cwd) - 1);
	if (n <= 0)
		return;				/* readlink failed */
	proc_cwd[n] = '\0';

	/* TOCTOU defeat: copy user buffer into local before compare so a
	 * concurrent thread cannot mutate it between checks. */
	copy_len = ((size_t)ret < sizeof(user_cwd))
			? (size_t)ret : sizeof(user_cwd) - 1;
	memcpy(user_cwd, (const void *)(uintptr_t)rec->a1, copy_len);
	/* sys_getcwd includes the trailing NUL in the returned length, so
	 * the string proper is copy_len-1 bytes.  Force NUL-terminate
	 * defensively. */
	user_cwd[copy_len ? copy_len - 1 : 0] = '\0';

	if (strcmp(user_cwd, proc_cwd) != 0) {
		output(0, "getcwd oracle: getcwd buf=\"%s\" but "
		       "/proc/self/cwd=\"%s\"\n", user_cwd, proc_cwd);
		__atomic_add_fetch(&shm->stats.getcwd_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getcwd = {
	.name = "getcwd",
	.num_args = 2,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "buf", [1] = "size" },
	.sanitise = sanitise_getcwd,
	.post = post_getcwd,
	.rettype = RET_PATH,
	.group = GROUP_VFS,
};
