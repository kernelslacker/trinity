/*
 * SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "arch.h"
#include "deferred-free.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "random.h"
#include "utils.h"

/*
 * Snapshot of the getcwd input args read by the post oracle, captured
 * at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer or launder an oversized retval past the size bound below.
 */
struct getcwd_post_state {
	unsigned long buf;
	unsigned long size;
};

static void sanitise_getcwd(struct syscallrecord *rec)
{
	struct getcwd_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a1, rec->a2 ? rec->a2 : page_size);

	/*
	 * Snapshot the one input arg the post oracle reads.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original buf
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->buf = rec->a1;
	snap->size = rec->a2;
	rec->post_state = (unsigned long) snap;
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
 *
 * TOCTOU defeat: the buf input arg is snapshotted at sanitise time into
 * a heap struct in rec->post_state, so a sibling that scribbles rec->a1
 * between syscall return and post entry cannot redirect the source
 * memcpy at a foreign user buffer.  The user-buffer payload at buf is
 * then copied into a stack-local before the strcmp so a concurrent
 * thread cannot mutate it between checks.
 */
static void post_getcwd(struct syscallrecord *rec)
{
	struct getcwd_post_state *snap =
		(struct getcwd_post_state *) rec->post_state;
	char proc_cwd[PATH_MAX];
	char user_cwd[PATH_MAX];
	ssize_t n;
	long ret;
	size_t copy_len;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getcwd: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * STRONG-VAL length bound: sys_getcwd on success returns the byte
	 * length (including the trailing NUL) of the path written into the
	 * user `buf`, capped at the caller-supplied `size`.  Failure
	 * returns a negative errno.  A retval > size on a positive return
	 * is a structural ABI regression -- a torn write of the length, a
	 * sibling-stomp of rec->retval between syscall return and post
	 * entry, or a path-component miscount in prepend_path().  Compare
	 * against the snapshotted size (snap->size) rather than rec->a2 so
	 * a sibling that scribbles rec->aN cannot launder an oversized
	 * retval past this gate.  Fires unconditionally, ahead of the
	 * ONE_IN(100) sample gate, so every offending retval is counted.
	 */
	if ((long)rec->retval > 0 && (unsigned long)rec->retval > snap->size) {
		outputerr("post_getcwd: rejected retval=0x%lx > size=%lu\n",
			  rec->retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

	if (!ONE_IN(100))
		goto out_free;

	ret = (long)rec->retval;
	if (ret <= 0)
		goto out_free;			/* syscall failed/empty */
	if (snap->buf == 0)
		goto out_free;			/* no user buffer */

	{
		void *buf = (void *)(unsigned long) snap->buf;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner buf
		 * field.  Reject pid-scribbled buf before deref.
		 */
		if (looks_like_corrupted_ptr(rec, buf)) {
			outputerr("post_getcwd: rejected suspicious buf=%p (post_state-scribbled?)\n",
				  buf);
			goto out_free;
		}
	}

	n = readlink("/proc/self/cwd", proc_cwd, sizeof(proc_cwd) - 1);
	if (n <= 0)
		goto out_free;			/* readlink failed */
	proc_cwd[n] = '\0';

	copy_len = ((size_t)ret < sizeof(user_cwd))
			? (size_t)ret : sizeof(user_cwd) - 1;
	memcpy(user_cwd, (const void *)(uintptr_t) snap->buf, copy_len);
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

out_free:
	deferred_freeptr(&rec->post_state);
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
