/*
 * SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
	 siginfo_t __user *, uinfo, const struct timespec __user *, uts,
	 size_t, sigsetsize)
 */
#include <signal.h>
#include "output-poison.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the uinfo OUT-pointer captured at sanitise time and consumed
 * by the post handler.  Lives in rec->post_state so a sibling syscall
 * scribbling rec->a2 between the syscall returning and the post handler
 * running cannot redirect the check at a foreign user buffer.
 */
#define RT_SIGTIMEDWAIT_POST_STATE_MAGIC	0x52535457UL	/* "RSTW" */
struct rt_sigtimedwait_post_state {
	unsigned long magic;
	unsigned long uinfo;
	/*
	 * Seed for the poison pattern stamped into the uinfo OUT buffer
	 * at sanitise time.  Returned by poison_output_struct() and fed
	 * back into check_output_struct() in the post handler so a stomp
	 * of rec->aN cannot redirect the check against an unrelated heap
	 * page that happens to still carry the original (or any) byte
	 * pattern.
	 */
	uint64_t poison_seed;
};

/*
 * "Interesting" signals from the receiver's standpoint -- the ones
 * userspace actually waits on with sigtimedwait().  We populate the
 * mask 1-3 bits at a time out of this list so most calls have a
 * genuinely-restricted wait set, not a fillset-shaped catch-all.
 */
static int interesting_signals[] = {
	SIGUSR1,
	SIGUSR2,
	SIGALRM,
	SIGCHLD,
	SIGIO,
};

static void build_sigset(sigset_t *set)
{
	unsigned int draw = rnd_modulo_u32(10);
	int rtbase = SIGRTMIN;
	int rtcount = SIGRTMAX - SIGRTMIN + 1;
	unsigned int nbits, i;

	if (draw < 7) {
		/* 1-3 named bits */
		sigemptyset(set);
		nbits = 1 + rnd_modulo_u32(3);
		for (i = 0; i < nbits; i++) {
			if (RAND_BOOL()) {
				int sig = interesting_signals[
					rnd_modulo_u32(ARRAY_SIZE(interesting_signals))];
				sigaddset(set, sig);
			} else if (rtcount > 0) {
				/* SIGRTMIN..SIGRTMIN+3 weighted -- real
				 * userspace tends to pick from the low rt
				 * range for IPC. */
				int span = rtcount < 4 ? rtcount : 4;
				sigaddset(set, rtbase + (int) rnd_modulo_u32(span));
			}
		}
	} else if (draw < 8) {
		/* empty -- legal, blocks for the full timeout unless one
		 * arrives unrelated and gets requeued through the regular
		 * pending-set path. */
		sigemptyset(set);
	} else if (draw < 9) {
		/* everything but the unblockable ones -- legal, exercises
		 * the kernel's "match any pending" fastpath. */
		sigfillset(set);
		sigdelset(set, SIGKILL);
		sigdelset(set, SIGSTOP);
	} else {
		/* Pure-random byte fill.  Some bits will be reserved /
		 * unmappable; the kernel masks them off silently, but the
		 * copy_from_user / fillset internal path runs either way. */
		unsigned char *p = (unsigned char *) set;
		for (i = 0; i < sizeof(*set); i++)
			p[i] = (unsigned char) rand32();
	}
}

static void sanitise_rt_sigtimedwait(struct syscallrecord *rec)
{
	struct rt_sigtimedwait_post_state *snap;
	sigset_t *set;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	set = (sigset_t *) get_writable_address(sizeof(*set));
	if (set == NULL)
		return;
	build_sigset(set);
	rec->a1 = (unsigned long) set;
	avoid_shared_buffer_inout(&rec->a1, sizeof(sigset_t));

	/*
	 * a3 (uts) is typed ARG_TIMESPEC; the generator publishes a
	 * writable pool buffer (or NULL ~10%) for us.  NEED_ALARM caps
	 * any blocking arm a large tv_sec bucket would otherwise produce.
	 */

	/*
	 * sigsetsize legality: 90% sizeof(sigset_t) (the only value the
	 * kernel accepts on this arch), 10% intentionally-malformed so
	 * the EINVAL gate against signal_size mismatches keeps firing.
	 */
	rec->a4 = (rnd_modulo_u32(10) < 9)
		? sizeof(sigset_t)
		: (unsigned long) rand32();

	/*
	 * uinfo (a2) is the kernel's writeback target for the siginfo of the
	 * dequeued signal.  ARG_ADDRESS draws from the random pool, so scrub
	 * it against the alloc_shared regions before the syscall is issued.
	 */
	avoid_shared_buffer_out(&rec->a2, sizeof(siginfo_t));

	/*
	 * Snapshot the uinfo OUT-pointer for the post oracle.  Without this
	 * the post handler reads rec->a2 at post-time, when a sibling syscall
	 * may have scribbled the slot: looks_like_corrupted_ptr() cannot
	 * tell a real-but-wrong heap address from the original uinfo user-
	 * buffer pointer, so the source memcpy would touch a foreign
	 * allocation.  post_state is private to the post handler.
	 * post_state_install pairs the rec->post_state assign with the
	 * ownership-table register so the observable window between the
	 * two is closed; post_rt_sigtimedwait() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = RT_SIGTIMEDWAIT_POST_STATE_MAGIC;
	snap->uinfo = rec->a2;
	/*
	 * Stamp a per-call poison pattern into the user buffer the kernel
	 * is about to fill.  The post handler asks check_output_struct()
	 * whether the pattern survived intact; if it did on a success
	 * return the kernel wrote zero bytes despite reporting success.
	 * Done after avoid_shared_buffer_out() so the poison lands on the
	 * final buffer the kernel will see (the relocation may have swapped
	 * rec->a2 for a fresh page).
	 *
	 * uinfo is ARG_ADDRESS (optional) -- rec->a2 == 0 is a legitimate
	 * "caller does not care about the siginfo" call and the kernel
	 * simply returns the dequeued signal number without a copy_to_user.
	 * Skip the stamp in that case; writing through NULL would SIGSEGV
	 * inside poison_output_struct and the post handler's matching
	 * snap->uinfo == 0 gate suppresses the check for the NULL case.
	 */
	if (rec->a2 != 0)
		snap->poison_seed = poison_output_struct((void *)(unsigned long) rec->a2,
							 sizeof(siginfo_t), 0);
	post_state_install(rec, snap);
}

/*
 * Oracle: rt_sigtimedwait(2) returns the dequeued signal number on
 * success (a positive int) and -1 on failure.  When the caller passes a
 * non-NULL uinfo the kernel is required to copy the siginfo of the
 * dequeued signal out through it.  Sanitise stamps a per-call poison
 * pattern into that buffer before the syscall runs; on a success return
 * the post handler asks check_output_struct() whether the pattern
 * survived intact.  If it did, the kernel wrote zero bytes despite
 * reporting success -- a torn copy_to_user, a "return N before fill"
 * early-exit, or a mis-wired compat wrapper.  O(sizeof(siginfo_t))
 * memcmp, no re-issue; bumps the shared post_handler_untouched_out_buf
 * counter.
 */
static void post_rt_sigtimedwait(struct syscallrecord *rec)
{
	struct rt_sigtimedwait_post_state *snap;

	snap = post_state_claim_owned(rec, RT_SIGTIMEDWAIT_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	/*
	 * Success on rt_sigtimedwait is the dequeued signal number, a
	 * positive int -- NOT the RET_ZERO_SUCCESS 0-means-good idiom.
	 * The entry is RET_BORING so this handler owns its own retval
	 * gate; a <= 0 return means either -1/errno or a shape the oracle
	 * cannot interpret, so skip the buffer check.
	 */
	if ((long) rec->retval <= 0)
		goto out_free;

	/*
	 * uinfo is ARG_ADDRESS: a NULL a2 is a legitimate call that asks
	 * the kernel to return only the signal number and skip the siginfo
	 * copy-out.  No buffer means nothing to check -- returning here
	 * avoids a spurious untouched-out-buf bump on the well-formed NULL
	 * case.
	 */
	if (snap->uinfo == 0)
		goto out_free;

	if (check_output_struct_user_or_skip((void *)(unsigned long) snap->uinfo,
					     sizeof(siginfo_t),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_free:
	post_state_release(rec, snap);
}

struct syscallentry syscall_rt_sigtimedwait = {
	.name = "rt_sigtimedwait",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_TIMESPEC, [3] = ARG_LEN },
	.argname = { [0] = "uthese", [1] = "uinfo", [2] = "uts", [3] = "sigsetsize" },
	.sanitise = sanitise_rt_sigtimedwait,
	.post = post_rt_sigtimedwait,
	.flags = NEED_ALARM,
	.rettype = RET_BORING,
};
