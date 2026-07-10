/*
 * SYSCALL_DEFINE4(rt_tgsigqueueinfo, pid_t, tgid, pid_t, pid, int, sig,
	 siginfo_t __user *, uinfo)
 */
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "signals-safelist.h"
#include "utils.h"

#ifndef SI_USER
#define SI_USER		0
#endif
#ifndef SI_QUEUE
#define SI_QUEUE	-1
#endif
#ifndef SI_TIMER
#define SI_TIMER	-2
#endif
#ifndef SI_ASYNCIO
#define SI_ASYNCIO	-4
#endif
#ifndef SI_TKILL
#define SI_TKILL	-6
#endif

/* see rt_sigqueueinfo.c for the si_code class commentary */
static const int valid_si_codes[] = {
	SI_USER,
	SI_QUEUE,
	SI_TKILL,
};

static const int invalid_si_codes[] = {
	SI_TIMER,
	SI_ASYNCIO,
	1,	/* SI_KERNEL on most arches -- rejected with EPERM */
	2,
};

static void fill_siginfo_by_class(siginfo_t *info)
{
	int code;

	memset(info, 0, sizeof(*info));

	if (rnd_modulo_u32(10) < 7)
		code = RAND_ARRAY(valid_si_codes);
	else
		code = RAND_ARRAY(invalid_si_codes);

	info->si_code = code;
	info->si_pid = mypid();
	info->si_uid = getuid();

	if (code == SI_QUEUE) {
		if (RAND_BOOL())
			info->si_int = (int) rand32();
		else
			info->si_ptr = (void *) (unsigned long) rand64();
	} else if (code == SI_USER || code == SI_TKILL) {
		/* leave union arm zero -- matches kill()/tkill() shape */
	} else {
		info->si_int = (int) rand32();
	}
}

/*
 * do_send_specific() requires the located task's real tgid to equal the
 * supplied tgid -- two independent ARG_PID picks return ESRCH ~60% of the
 * time.  Trinity's children are single-threaded forks so tgid == pid for
 * every pool entry; reuse the same value for both args.  Keep a small
 * slice of incoherent / random pairs so the ESRCH / EPERM gates still
 * see traffic.
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

static void sanitise_rt_tgsigqueueinfo(struct syscallrecord *rec)
{
	pid_t tgid, pid;
	siginfo_t *info;
	unsigned int draw;

	pick_target_pair(&tgid, &pid);
	rec->a1 = (unsigned long) tgid;
	rec->a2 = (unsigned long) pid;

	/*
	 * Bias toward sig==0 (existence-probe, no delivery), the
	 * child-safe set, and the realtime range -- realtime signals are
	 * the ones that carry siginfo all the way through to the
	 * receiver.  A small slice picks from the crash-probe (child-
	 * fatal) bucket so the kernel-side delivery path for the
	 * obviously-fatal signals still sees traffic without dominating
	 * the run with teardowns.
	 */
	draw = rnd_modulo_u32(20);
	if (draw < 4)
		rec->a3 = 0;
	else if (draw < 11)
		rec->a3 = child_safe_signals[rnd_modulo_u32(child_safe_signals_count)];
	else if (draw < 12)
		rec->a3 = child_fatal_signals[rnd_modulo_u32(child_fatal_signals_count)];
	else
		rec->a3 = SIGRTMIN + rnd_modulo_u32(SIGRTMAX - SIGRTMIN + 1);

	info = (siginfo_t *) get_writable_address(sizeof(*info));
	if (info == NULL)
		return;

	fill_siginfo_by_class(info);
	rec->a4 = (unsigned long) info;
}

struct syscallentry syscall_rt_tgsigqueueinfo = {
	.name = "rt_tgsigqueueinfo",
	.group = GROUP_SIGNAL,
	.num_args = 4,
	.argtype = { [0] = ARG_PID, [1] = ARG_PID },
	.argname = { [0] = "tgid", [1] = "pid", [2] = "sig", [3] = "uinfo" },
	.flags = AVOID_SYSCALL,	/* can disrupt signal handling */
	.sanitise = sanitise_rt_tgsigqueueinfo,
	.rettype = RET_ZERO_SUCCESS,
};
