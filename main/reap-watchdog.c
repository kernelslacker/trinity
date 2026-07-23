#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "debug.h"
#include "fd.h"
#include "kcov.h"
#include "objects.h"
#include "params.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "stats.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"
#include "reap-internal.h"

unsigned long hiscore = 0;

/*
 * "STUCK CHILD:" loud diagnostic.  One prominent greppable line
 * summarising a wedged child (pid/childno/op/wedge duration/state
 * char/wchan) plus the kernel stack from /proc/<pid>/stack when the
 * kernel exposes it to us.  Falls back to just the wchan when the stack
 * file is empty or hidden (unprivileged reader, EACCES/ENOENT/EPERM on
 * most production kernels without CAP_SYS_ADMIN).
 *
 * Distinct tag from the existing "watchdog: kill ..." (syscall-side
 * state int) and "D-state diag ..." (multi-line fd topology / fdinfo
 * spew) lines: this is the single "which pid, where, how long"
 * summary that operators grep to attribute wedged tasks.
 *
 * Runs on the parent's reap/watchdog path, before the SIGKILL, so the
 * task's /proc state still reflects the wedge.  Every read tolerates
 * the pid having exited (open/read failure -> "?" / omitted stack) so
 * the reap loop cannot be crashed by whatever state the wedged task is
 * in.  Caller gates on the per-child dstate_diag_dumped latch so this
 * fires once per stuck child, not every watchdog tick.
 */
static void scream_stuck_child(struct childdata *child, int childno,
			       pid_t pid, time_t wedge_seconds)
{
	char wchan[128];
	char stackbuf[2048];
	char filename[80];
	ssize_t stack_n = 0;
	const char *opname;
	char state;
	int fd;
	int open_errno = 0;
	int read_errno = 0;

	state = get_pid_state(childno);

	if (read_pid_wchan(pid, wchan, sizeof(wchan)) <= 0)
		snprintf(wchan, sizeof(wchan), "?");

	snprintf(filename, sizeof(filename), "/proc/%d/stack", pid);
	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		stack_n = read(fd, stackbuf, sizeof(stackbuf) - 1);
		if (stack_n < 0) {
			/* Latch read's errno before close(2), which can
			 * clobber it on failure. */
			read_errno = errno;
			stack_n = 0;
		}
		close(fd);
	} else {
		open_errno = errno;
	}
	stackbuf[stack_n] = '\0';

	if (child->op_type == CHILD_OP_SYSCALL) {
		struct syscallrecord *rec = &child->syscall;
		struct syscallentry *entry;
		unsigned int callno;
		bool do32;
		bool got;

		SREC_SNAPSHOT(rec, {
			do32 = rec->do32bit;
			callno = rec->nr;
		}, got);
		if (got) {
			entry = get_syscall_entry(callno, do32);
			opname = (entry != NULL) ? entry->name : "?";
		} else {
			opname = "?";
		}
	} else {
		opname = alt_op_name(child->op_type);
	}

	if (stack_n > 0) {
		output(0,
		       "STUCK CHILD: pid=%d childno=%d op=%s wedged %lds state=%c wchan=%s\nkernel stack:\n%s%s",
		       pid, childno, opname, (long)wedge_seconds, state, wchan,
		       stackbuf,
		       stackbuf[stack_n - 1] == '\n' ? "" : "\n");
	} else {
		/* Distinguish open-gate (EPERM: ptrace_may_access on a
		 * non-dumpable child; EACCES: CAP_SYS_ADMIN missing;
		 * ENOENT: pid exited) from read-gate from a successful
		 * empty unwind (no errno captured). */
		char errtag[48] = "";

		if (open_errno) {
			const char *n = strerrorname_np(open_errno);
			snprintf(errtag, sizeof(errtag), ": open=%s",
				 n ? n : "?");
		} else if (read_errno) {
			const char *n = strerrorname_np(read_errno);
			snprintf(errtag, sizeof(errtag), ": read=%s",
				 n ? n : "?");
		}
		output(0,
		       "STUCK CHILD: pid=%d childno=%d op=%s wedged %lds state=%c wchan=%s (kernel stack unavailable%s)\n",
		       pid, childno, opname, (long)wedge_seconds, state, wchan,
		       errtag);
	}
}

struct stuck_evict_ctx {
	int fds[6];
	unsigned int n;
};

static void stuck_evict_fd(int fd, void *ctx)
{
	struct stuck_evict_ctx *c = ctx;

	if (c->n < ARRAY_SIZE(c->fds))
		c->fds[c->n++] = fd;

	/* Remove the bad fd from the object pool so it won't be handed
	 * out again. */
	remove_object_by_fd(fd);
}

static void stuck_syscall_info(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	struct syscallentry *entry = NULL;
	struct stuck_evict_ctx ctx = { .n = 0 };
	unsigned long args[6] = { 0 };
	unsigned int callno;
	char fdstr[80];
	pid_t pid;
	bool do32;
	enum syscallstate state;
	bool got;

	pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	rec = &child->syscall;

	/* Lockless snapshot via the sequence counter.  Writers bracket
	 * coherent mutations with srec_publish_begin/end (no rec->lock
	 * involved post-strengthen); the SREC_SNAPSHOT spin pattern
	 * gives this parent-side diagnostic a coherent multi-field view
	 * without contending with the child's writer path under fleet
	 * conditions where many children wedge simultaneously. */
	SREC_SNAPSHOT(rec, {
		do32 = rec->do32bit;
		callno = rec->nr;
		state = __atomic_load_n(&rec->state, __ATOMIC_RELAXED);
		args[0] = rec->a1;
		args[1] = rec->a2;
		args[2] = rec->a3;
		args[3] = rec->a4;
		args[4] = rec->a5;
		args[5] = rec->a6;
	}, got);

	if (!got) {
		output(0, "  (snapshot give-up: writer churn)\n");
		return;
	}

	/* The name lookup is a pure table index and is meaningful in
	 * any state -- without it AFTER-state kills print cmd:? and we
	 * lose all visibility into which syscall's post-handler path
	 * stuck the child. */
	entry = get_syscall_entry(callno, do32);

	/* Always-on kill diag: the caller is about to SIGKILL this child,
	 * and without this line non-debug runs just see a child vanish.
	 * The expensive fd walk and /proc stack dump below stay gated. */
	outputerr("watchdog: kill pid:%d childno:%d nr:%u cmd:%s state:%d\n",
		  pid, childno, callno,
		  entry ? entry->name : "?", state);

	{
		/* Structured one-liner that mirrors the kill line's
		 * key:value shape and carries the fields the bare line
		 * omits: the killed child's kcov dedup generation, a
		 * boolean recording whether the stuck op was a
		 * currently-promoted canary, and the kernel wchan when
		 * /proc still exposes it.  Post-run analysis of
		 * unkillable / D-state populations grep this line to
		 * attribute wedged tasks to a (op, kcov-generation,
		 * canary-state, wchan) tuple rather than only the
		 * syscall name from the kill line above.  This does NOT
		 * change any kill/evict decision -- it is purely a
		 * record-shape extension. */
		char wbuf[128];
		const char *opname;
		bool promoted;
		bool is_syscall;

		is_syscall = (child->op_type == CHILD_OP_SYSCALL);
		if (is_syscall)
			opname = entry ? entry->name : "?";
		else
			opname = alt_op_name(child->op_type);

		promoted = canary_op_is_promoted(child->op_type);

		if (read_pid_wchan(pid, wbuf, sizeof(wbuf)) > 0)
			outputerr("watchdog: record pid:%d nr:%u op:%s"
				  " fd_gen:%" PRIu64 " canary_promoted:%d"
				  " wchan:%s\n",
				  pid, callno, opname,
				  child->kcov.current_generation,
				  promoted ? 1 : 0, wbuf);
		else
			outputerr("watchdog: record pid:%d nr:%u op:%s"
				  " fd_gen:%" PRIu64 " canary_promoted:%d\n",
				  pid, callno, opname,
				  child->kcov.current_generation,
				  promoted ? 1 : 0);
	}

	if (shm->debug == false)
		return;

	fdstr[0] = '\0';

	if (state == BEFORE && entry != NULL) {
		/* Same gate as the child-side watchdog in __do_syscall():
		 * fd_arg_mask plus the ARG_SOCKETINFO-in-slot-0 mirror.
		 * Outside that gate the syscall has no fd-bearing args at
		 * all, so leave fdstr empty rather than print "(no fds)"
		 * for every stuck non-fd syscall. */
		uint8_t gate = entry->fd_arg_mask;
		if (entry->argtype[0] == ARG_SOCKETINFO)
			gate |= 0x01;

		if (gate != 0) {
			for_each_fd_arg(entry, args, stuck_evict_fd, &ctx);

			if (ctx.n == 0) {
				snprintf(fdstr, sizeof(fdstr), "(no fds)");
			} else if (ctx.n == 1) {
				snprintf(fdstr, sizeof(fdstr), "(fd = %d)",
					 ctx.fds[0]);
				child->fd_lifetime = 0;
			} else {
				int off = snprintf(fdstr, sizeof(fdstr),
						   "(fds = ");
				unsigned int i;

				for (i = 0; i < ctx.n && off < (int)sizeof(fdstr); i++)
					off += snprintf(fdstr + off,
							sizeof(fdstr) - off,
							"%s%d", i ? "," : "",
							ctx.fds[i]);
				if (off < (int)sizeof(fdstr))
					snprintf(fdstr + off,
						 sizeof(fdstr) - off, ")");
				child->fd_lifetime = 0;
			}
		}
	}

	output(0, "child %d (pid %u. state:%d) Stuck in syscall %d:%s%s%s.\n",
		childno, pid, state, callno,
		print_syscall_name(callno, do32),
		do32 ? " (32bit)" : "",
		fdstr);
	if (state >= BEFORE)
		dump_pid_stack(pid);
}

/*
 * Check that a child is making forward progress by comparing the timestamps it
 * recorded before making its last syscall.
 * If no progress is being made, send SIGKILLs to it.
 */
static bool is_child_making_progress(struct childdata *child, int childno)
{
	struct syscallrecord *rec;
	struct timespec tp;
	time_t diff, old, now;
	pid_t pid;
	char state;

	pid = __atomic_load_n(&pids[childno], __ATOMIC_RELAXED);

	if (pid == EMPTY_PIDSLOT)
		return true;
	// bail if we've not done a syscall yet, we probably just haven't
	// been scheduled due to other pids hogging the cpu
	rec = &child->syscall;
	if (__atomic_load_n(&rec->state, __ATOMIC_RELAXED) < BEFORE)
		return true;

	/* The child writes child->tp every ~16 syscall iterations with a
	 * non-atomic clock_gettime() store; an unqualified load here races
	 * with that store and (per the C memory model) can observe a torn
	 * value even when the underlying 8-byte access is atomic on the
	 * hardware.  Use an explicit relaxed atomic load of tv_sec so the
	 * compiler cannot reorder or split the read. */
	old = __atomic_load_n(&child->tp.tv_sec, __ATOMIC_RELAXED);

	/* haven't done anything yet. */
	if (old == 0)
		return true;

	clock_gettime(CLOCK_MONOTONIC, &tp);
	now = tp.tv_sec;

	/* A timestamp in the future is impossible on CLOCK_MONOTONIC: the
	 * child stamped tp before we sampled now, so old <= now must hold.
	 * If we ever observe old > now it means the load raced with the
	 * child's store and returned a bogus value, not that the child is
	 * stalled.  Treat it as zero elapsed rather than taking abs(old-now)
	 * — the latter turns a transient race into a huge diff and SIGKILLs
	 * a healthy child. */
	if (old > now)
		diff = 0;
	else
		diff = now - old;

	/* hopefully the common case. */
	if (diff < 30)
		return true;

	/* After too many kill attempts, the child is truly stuck (D state,
	 * frozen cgroup, etc).  Hand the slot to the zombie-pending list:
	 * we will reuse it once waitpid confirms the kernel released the
	 * task.  Reusing immediately would let the still-alive D-state task
	 * write into the replacement child's childdata as soon as it wakes.
	 *
	 * This check must come before the D-state early return below,
	 * otherwise unkillable D-state children never get reaped. */
	if (__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED) >= 10) {
		register_zombie_slot(childno, pid);
		return true;
	}

	/* Uninterruptible sleep: SIGKILL cannot preempt a D-state task,
	 * but queueing it ensures the kernel delivers it the moment the
	 * task wakes from D and the syscall returns to the signal-check
	 * path.  Without this, kill_count saturates at 10 purely from
	 * passive D-state observations and register_zombie_slot fires
	 * for a task that has never had a SIGKILL pending — letting it
	 * resume execution (and write into childdata) the moment the
	 * kernel finally schedules it.  Pair every kill_count++ with an
	 * actual queued kill so the >= 10 threshold means "we tried." */
	state = get_pid_state(childno);

	/* First-detection-only forensic for ANY 30s-stalled child, D or
	 * interruptible.  The epoll/ep_item_poll wedge holder blocks in
	 * interruptible sleep on the polled fd's waitqueue, not 'D', so
	 * gating this on 'D' alone skipped exactly the task whose
	 * fd-topology names the blocking fd.  A task with zero progress for
	 * 30s is parked in its wait, so /proc/<pid>/stack is stable either
	 * way.  Read-only + latched, so no change to the kill logic. */
	if (!child->dstate_diag_dumped) {
		char wchan[128];

		scream_stuck_child(child, childno, pid, diff);
		/* Gate the verbose snapshot behind the global budget.  wchan
		 * is re-read here (scream_stuck_child does its own read) so
		 * dstate_diag_budget_take can key its per-signature cap on
		 * the real sleep symbol; on read failure the signature keys
		 * on "?" and shares a slot with other unreadable-wchan
		 * wedges, which is the intended aggregation. */
		if (read_pid_wchan(pid, wchan, sizeof(wchan)) <= 0)
			snprintf(wchan, sizeof(wchan), "?");
		if (dstate_diag_budget_take(child, wchan))
			dump_dstate_diagnostics(child, childno, pid);
		child->dstate_diag_dumped = true;
	}

	/* SHADOW-ONLY wedge accounting -- both the per-syscall pair (see
	 * comment on shm->stats.syscall_wedge.count[] in include/stats.h)
	 * and the per-childop pair (see childop_wedge_count[] in the same
	 * header).  Latched via wedge_accounted so a child that stays
	 * wedged across many watchdog ticks counts as one event on both
	 * axes.  Snapshot the syscall nr and arch via SREC_SNAPSHOT (the
	 * same lockless seq-counter primitive the dstate_diag /
	 * stuck_syscall_info paths use); a snapshot give-up under writer
	 * churn skips the bump for this child but leaves the latch unset
	 * so a subsequent tick can retry.  The bump itself is gated on
	 * state >= BEFORE: a child wedged before it has published its
	 * first syscall record has no nr to attribute the time to, and
	 * counting it against nr=0 would alias every such wedge to
	 * whatever sits at index 0 of the syscall table.
	 *
	 * wedge_start_tp is seeded from child->tp -- the child's
	 * last-progress timestamp, written by the child each loop
	 * iteration and the same field the diff>=30s check above samples.
	 * Anchoring the start at last-progress rather than at the
	 * detection moment means the accumulated wedged duration covers
	 * the FULL window the slot was unreusable (the watchdog's 30 s
	 * grace period included), so the per-syscall and per-childop
	 * top-N renders share one consistent, operator-meaningful
	 * duration definition.  child->tp is CLOCK_MONOTONIC at the
	 * child's write site so the reap-time clamp (now > start) covers
	 * any torn read of the two-long timespec without depending on
	 * wall-clock monotonicity.  The early `if (old == 0)` return above
	 * has already pinned child->tp.tv_sec > 0 at this point, so the
	 * seeded start is never the zero sentinel.
	 *
	 * op_type is captured from childdata at latch time so the
	 * per-childop close-out in reap_child() attributes the wedge to
	 * the childop that was running when the stall began, even if the
	 * slot is later (post-reap) reused by a different childop -- the
	 * latch and the post-fork clean_childdata() are sequenced on the
	 * parent.  Pairs with the reap_child() close-out that adds
	 * (now - wedge_start_tp) to BOTH
	 * syscall_wedge.total_us[wedge_nr] and
	 * childop_wedge_total_us[wedge_op_type]. */
	if (!child->wedge_accounted) {
		struct syscallrecord *wrec = &child->syscall;
		unsigned int wnr;
		bool wdo32;
		enum syscallstate wstate;
		bool wgot;

		SREC_SNAPSHOT(wrec, {
			wdo32 = wrec->do32bit;
			wnr = wrec->nr;
			wstate = __atomic_load_n(&wrec->state, __ATOMIC_RELAXED);
		}, wgot);

		if (wgot && wstate >= BEFORE && wnr < MAX_NR_SYSCALL) {
			enum child_op_type wop = child->op_type;

			if ((unsigned int)wop >= NR_CHILD_OP_TYPES)
				wop = CHILD_OP_SYSCALL;

			child->wedge_nr = wnr;
			child->wedge_do32 = wdo32;
			child->wedge_op_type = wop;
			child->wedge_start_tp = child->tp;
			child->wedge_accounted = true;
			/* Gate the per-syscall axis on CHILD_OP_SYSCALL: for
			 * non-syscall childops child->syscall.nr is stale
			 * (childops issue syscalls directly without updating
			 * child->syscall), so wnr would poison the per-syscall
			 * counter with childop-wedge noise.  The per-childop
			 * axis is authoritative for those. */
			if (wop == CHILD_OP_SYSCALL)
				__atomic_add_fetch(&shm->stats.syscall_wedge.count[wnr],
						   1UL, __ATOMIC_RELAXED);
			__atomic_add_fetch(&shm->stats.childop.wedge_count[wop],
					   1UL, __ATOMIC_RELAXED);
		}
	}

	if (state == 'D') {
		if (!child->kill_in_flight)
			stuck_syscall_info(child, childno);
		kill_pid(pid);
		__atomic_add_fetch(&child->kill_count, 1, __ATOMIC_RELAXED);
		child->kill_in_flight = true;
		return false;
	}

	/* After 30 seconds of no progress, send a kill signal. */
	if (diff >= 30) {
		if (!child->kill_in_flight)
			stuck_syscall_info(child, childno);
		debugf("child %d (pid %u) hasn't made progress in 30 seconds! Sending SIGKILL\n",
				childno, pid);
		__atomic_add_fetch(&child->kill_count, 1, __ATOMIC_RELAXED);
		child->kill_in_flight = true;
		kill_pid(pid);
	}

	/* if we're still around after 40s, repeatedly send SIGKILLs every second. */
	if (diff < 40)
		return false;

	debugf("sending another SIGKILL to child %u (pid:%u). [kill count:%u] [diff:%lu]\n",
		childno, pid,
		__atomic_load_n(&child->kill_count, __ATOMIC_RELAXED), diff);
	__atomic_add_fetch(&child->kill_count, 1, __ATOMIC_RELAXED);
	kill_pid(pid);

	return false;
}

/*
 * If we call this, all children are stalled. Randomly kill a few.
 */
static void stall_genocide(void)
{
	unsigned int want = max(1U, max_children / 4);
	unsigned int killed = 0;
	unsigned int i;

	for_each_child(i) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT)
			continue;

		if ((rnd_u32() & 1U)) {
			if (pid_alive(pid) == true) {
				kill_pid(pid);
				killed++;
			}
		}
		if (killed == want)
			break;
	}
}

unsigned int stall_count;

void check_children_progressing(void)
{
	unsigned int i;

	stall_count = 0;

	if (children == NULL)
		return;

	for_each_child(i) {
		struct childdata *child;
		unsigned long op_nr;

		child = __atomic_load_n(&children[i], __ATOMIC_ACQUIRE);
		if (child == NULL)
			continue;

		if (is_child_making_progress(child, i) == false)
			stall_count++;

		op_nr = __atomic_load_n(&child->op_nr, __ATOMIC_RELAXED);
		if (op_nr > hiscore)
			hiscore = op_nr;
	}

	if (stall_count == __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED))
		stall_genocide();
}
