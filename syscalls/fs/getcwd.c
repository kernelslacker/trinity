/*
 * SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
 */
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "arch.h"
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
#define GETCWD_POST_STATE_MAGIC	0x47435744UL	/* "GCWD" */
struct getcwd_post_state {
	unsigned long magic;
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

	avoid_shared_buffer_out(&rec->a1, rec->a2 ? rec->a2 : page_size);

	/*
	 * Snapshot the one input arg the post oracle reads.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original buf
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_getcwd() will then gate the snap through
	 * post_state_claim_owned() and prove ownership before dereferencing
	 * any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = GETCWD_POST_STATE_MAGIC;
	snap->buf = rec->a1;
	snap->size = rec->a2;
	post_state_install(rec, snap);
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
	struct getcwd_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;
	char proc_cwd[PATH_MAX];
	char user_cwd[PATH_MAX];
	ssize_t n;
	size_t copy_len;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, GETCWD_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

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
	if (ret > 0 && retval > snap->size) {
		outputerr("post_getcwd: rejected retval=0x%lx > size=%lu\n",
			  retval, snap->size);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_release;
	}

	if (!ONE_IN(100))
		goto out_release;

	if (ret <= 0)
		goto out_release;			/* syscall failed/empty */
	if (snap->buf == 0)
		goto out_release;			/* no user buffer */

	n = readlink("/proc/self/cwd", proc_cwd, sizeof(proc_cwd) - 1);
	if (n <= 0)
		goto out_release;			/* readlink failed */
	proc_cwd[n] = '\0';

	copy_len = ((size_t)ret < sizeof(user_cwd))
			? (size_t)ret : sizeof(user_cwd) - 1;
	if (!post_snapshot_or_skip(user_cwd,
				   (const void *)(uintptr_t) snap->buf,
				   copy_len))
		goto out_release;
	/* sys_getcwd includes the trailing NUL in the returned length, so
	 * the string proper is copy_len-1 bytes.  Force NUL-terminate
	 * defensively. */
	user_cwd[copy_len ? copy_len - 1 : 0] = '\0';

	if (strcmp(user_cwd, proc_cwd) != 0) {
		output(0, "getcwd oracle: getcwd buf=\"%s\" but "
		       "/proc/self/cwd=\"%s\"\n", user_cwd, proc_cwd);
		__atomic_add_fetch(&shm->stats.oracle.getcwd_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_release:
	post_state_release(rec, snap);
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
	.bound_arg = 2,
	.flags = REEXEC_SANITISE_OK,
};
