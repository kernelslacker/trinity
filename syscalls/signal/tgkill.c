/*
 * SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)
 */
#include <signal.h>
#include <sys/types.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "signals-safelist.h"

/*
 * The kernel's tgkill path rejects with ESRCH when the located task's
 * real tgid does not match the supplied tgid -- two independent ARG_PID
 * picks land there ~60% of the time.  Trinity's children are
 * single-threaded forks so tgid == pid for every pool entry; reuse the
 * same value for both args.  Keep a small slice of incoherent / random
 * pairs so the ESRCH / EPERM error-path gates still see traffic.
 */
static void pick_target_pair(pid_t *tgid, pid_t *pid)
{
	unsigned int draw = rnd_modulo_u32(10);
	pid_t p;

	if (draw < 6) {
		*tgid = mypid();
		*pid = mypid();
		return;
	}
	if (draw < 9) {
		p = get_random_pid_from_pool();
		*tgid = p;
		*pid = p;
		return;
	}
	*tgid = (pid_t) rand32();
	*pid = (pid_t) rand32();
}

static void sanitise_tgkill(struct syscallrecord *rec)
{
	pid_t tgid, pid;
	unsigned int draw;

	pick_target_pair(&tgid, &pid);
	rec->a1 = (unsigned long) tgid;
	rec->a2 = (unsigned long) pid;

	/*
	 * Bias toward sig==0 (existence-probe, no delivery) and the
	 * child-safe set so a self/sibling-targeted delivery does not
	 * tear down a healthy fuzz child.  A small slice picks from the
	 * crash-probe (child-fatal) bucket so the kernel-side delivery
	 * path for the obviously-fatal signals still sees traffic
	 * without dominating the run with teardowns.  tgkill has no
	 * siginfo path so there is no realtime branch to exercise here.
	 */
	draw = rnd_modulo_u32(20);
	if (draw < 6)
		rec->a3 = 0;
	else if (draw < 19)
		rec->a3 = child_safe_signals[rnd_modulo_u32(child_safe_signals_count)];
	else
		rec->a3 = child_fatal_signals[rnd_modulo_u32(child_fatal_signals_count)];
}

struct syscallentry syscall_tgkill = {
	.name = "tgkill",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_PID },
	.argname = { [0] = "tgid", [1] = "pid", [2] = "sig" },
	.sanitise = sanitise_tgkill,
	.rettype = RET_ZERO_SUCCESS,
	.flags = AVOID_SYSCALL,
};
