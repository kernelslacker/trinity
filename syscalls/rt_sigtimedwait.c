/*
 * SYSCALL_DEFINE4(rt_sigtimedwait, const sigset_t __user *, uthese,
	 siginfo_t __user *, uinfo, const struct timespec __user *, uts,
	 size_t, sigsetsize)
 */
#include <signal.h>
#include <string.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

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
	sigset_t *set;

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
}

struct syscallentry syscall_rt_sigtimedwait = {
	.name = "rt_sigtimedwait",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_TIMESPEC, [3] = ARG_LEN },
	.argname = { [0] = "uthese", [1] = "uinfo", [2] = "uts", [3] = "sigsetsize" },
	.sanitise = sanitise_rt_sigtimedwait,
	.flags = NEED_ALARM,
	.rettype = RET_BORING,
};
