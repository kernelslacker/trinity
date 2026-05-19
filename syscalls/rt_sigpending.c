/*
 * SYSCALL_DEFINE2(rt_sigpending, sigset_t __user *, set, size_t, sigsetsize)
 */
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "deferred-free.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the two rt_sigpending input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the oracle at a foreign set user
 * buffer or alias the sigsetsize length check.
 */
#define RT_SIGPENDING_POST_STATE_MAGIC	0x52545350UL	/* "RTSP" */
struct rt_sigpending_post_state {
	unsigned long magic;
	unsigned long set;
	unsigned long sigsetsize;
};

static void sanitise_rt_sigpending(struct syscallrecord *rec)
{
	struct rt_sigpending_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a1, rec->a2);

	/*
	 * Snapshot the two input args read by the post oracle.  Without
	 * this the post handler reads rec->a1/a2 at post-time, when a
	 * sibling syscall may have scribbled the slots:
	 * looks_like_corrupted_ptr() cannot tell a real-but-wrong heap
	 * address from the original set user buffer pointer, so the source
	 * memcpy would touch a foreign allocation that the guard never
	 * inspected, and the sigsetsize gate would resolve against a
	 * scribbled value.  post_state is private to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->magic      = RT_SIGPENDING_POST_STATE_MAGIC;
	snap->set        = rec->a1;
	snap->sigsetsize = rec->a2;
	rec->post_state = (unsigned long) snap;
}

/*
 * Oracle: rt_sigpending() copies the union of the calling thread's
 * per-thread pending mask and the per-process shared pending mask out
 * to userspace.  The procfs view of the same fact is /proc/self/status,
 * which exposes the two halves separately as "SigPnd:" (per-thread,
 * task->pending.signal) and "ShdPnd:" (shared, task->signal->shared_pending.signal).
 * Both views read the same sigpending bitmaps but through different code
 * paths — the syscall takes siglock once and copies sigorsets(thread,
 * shared), procfs walks proc_pid_status() which formats each half via
 * %016lx after taking siglock per render — so a divergence between the
 * syscall's union and (SigPnd | ShdPnd) for the same task is its own
 * corruption shape: a torn write to signal->shared_pending, a stale rcu
 * pointer to the signal_struct, or a sigset_t copy_to_user that wrote
 * past/before the live mask.  Mirror of the getppid procfs oracle pattern.
 */
static void post_rt_sigpending(struct syscallrecord *rec)
{
	struct rt_sigpending_post_state *snap =
		(struct rt_sigpending_post_state *) rec->post_state;
	char buf[2048];
	char *line;
	ssize_t n;
	int fd;
	uint64_t syscall_pending, proc_pending = 0;
	unsigned long sigpnd = 0, shdpnd = 0;
	bool have_sigpnd = false, have_shdpnd = false;
	sigset_t sset;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_rt_sigpending: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: snap survived the heap-shape gate but a
	 * sibling scribble of rec->post_state with a heap-shaped pointer
	 * to a foreign allocation would let the wrong bytes pose as a
	 * rt_sigpending_post_state.  A cookie mismatch means snap does
	 * not point at our struct -- abandon rather than feed wild bytes
	 * into the inner-field deref.
	 */
	if (snap->magic != RT_SIGPENDING_POST_STATE_MAGIC) {
		outputerr("post_rt_sigpending: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;

	if (rec->retval != 0)
		goto out_free;
	if (snap->set == 0)
		goto out_free;
	if (snap->sigsetsize != sizeof(sigset_t))
		goto out_free;

	/*
	 * Defense in depth: even with the post_state snapshot, a wholesale
	 * stomp could rewrite the snapshot's inner pointer field.  Reject
	 * a pid-scribbled set before deref.
	 */
	if (looks_like_corrupted_ptr(rec, (void *) snap->set)) {
		outputerr("post_rt_sigpending: rejected suspicious set=%p (post_state-scribbled?)\n",
			  (void *) snap->set);
		goto out_free;
	}

	memcpy(&sset, (const void *) snap->set, sizeof(sset));
	memcpy(&syscall_pending, &sset, sizeof(syscall_pending));

	/* Raw open/read instead of fopen/fgets/fclose: this post handler runs
	 * thousands of times per second under fuzz, and stdio's per-call malloc
	 * of FILE struct + IO buffer is heap traffic we don't need. */
	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		goto out_free;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		goto out_free;
	buf[n] = '\0';
	/* Anchor on a newline so a "SigPnd:"/"ShdPnd:" substring inside an
	 * earlier field cannot mis-target the parse.  Both halves must be
	 * located independently before the comparison runs. */
	line = strstr(buf, "\nSigPnd:");
	if (line != NULL) {
		if (sscanf(line + 8, "%lx", &sigpnd) == 1)
			have_sigpnd = true;
	}
	line = strstr(buf, "\nShdPnd:");
	if (line != NULL) {
		if (sscanf(line + 8, "%lx", &shdpnd) == 1)
			have_shdpnd = true;
	}

	if (!have_sigpnd || !have_shdpnd)
		goto out_free;

	proc_pending = (uint64_t)sigpnd | (uint64_t)shdpnd;

	if (syscall_pending != proc_pending) {
		output(0, "rt_sigpending oracle: syscall=0x%016lx but "
		       "/proc/self/status SigPnd|ShdPnd=0x%016lx "
		       "(SigPnd=0x%016lx ShdPnd=0x%016lx)\n",
		       (unsigned long)syscall_pending,
		       (unsigned long)proc_pending,
		       sigpnd, shdpnd);
		__atomic_add_fetch(&shm->stats.rt_sigpending_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_rt_sigpending = {
	.name = "rt_sigpending",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN },
	.argname = { [0] = "set", [1] = "sigsetsize" },
	.sanitise = sanitise_rt_sigpending,
	.post = post_rt_sigpending,
	.rettype = RET_ZERO_SUCCESS,
};
