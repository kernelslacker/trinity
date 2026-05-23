/*
 * SYSCALL_DEFINE3(rt_sigqueueinfo, pid_t, pid, int, sig, siginfo_t __user *, uinfo)
 */
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
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

static unsigned long safe_signals[] = {
	SIGHUP, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
	SIGBUS, SIGFPE, SIGUSR1, SIGSEGV, SIGUSR2, SIGPIPE,
	SIGALRM, SIGCHLD, SIGCONT, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

/*
 * si_code classes the kernel will accept on the rt_sigqueueinfo path:
 *
 *   SI_USER   -- kill()/raise()-shaped origin.  Kernel accepts when the
 *                target pid permits it (same uid or CAP_KILL).
 *   SI_QUEUE  -- the canonical sigqueue() origin.  si_value union arm
 *                (si_int / si_ptr) is the payload userland reads.
 *   SI_TKILL  -- tkill()/tgkill() origin.  Permitted from threads in
 *                the same tgid.
 *
 * The kernel rejects positive si_code (kernel-origin codes such as
 * SI_KERNEL/SEGV_MAPERR) from unprivileged callers with EPERM, and
 * rejects negative-but-non-userspace codes (SI_TIMER, SI_ASYNCIO,
 * SI_MESGQ, etc.) the same way.  We keep an "intentionally invalid"
 * bucket so the EPERM gate stays warm.
 */
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

	if (rnd_modulo_u32(10) < 7) {
		code = RAND_ARRAY(valid_si_codes);
	} else {
		code = RAND_ARRAY(invalid_si_codes);
	}

	info->si_code = code;
	info->si_pid = mypid();
	info->si_uid = getuid();

	if (code == SI_QUEUE) {
		/* sigqueue() carries a sigval_t.  Half the time use the
		 * integer arm, half the time the pointer arm so both union
		 * accessors get exercised by anything that reads back. */
		if (RAND_BOOL())
			info->si_int = (int) rand32();
		else
			info->si_ptr = (void *) (unsigned long) rand64();
	} else if (code == SI_USER || code == SI_TKILL) {
		/* SI_USER / SI_TKILL only have meaningful pid/uid fields;
		 * leave the union arm zero (matches kill()/tkill() shape). */
	} else {
		/* Invalid-class bucket: fill si_value too so any kernel
		 * path that peeks at it before rejecting still sees a
		 * deterministic shape. */
		info->si_int = (int) rand32();
	}
}

static pid_t pick_target_pid(void)
{
	unsigned int draw = rnd_modulo_u32(10);

	if (draw < 6)
		return mypid();			/* self */
	if (draw < 9)
		return get_random_pid_from_pool();	/* sibling */
	return (pid_t) rand32();		/* random -- EPERM gate */
}

static void sanitise_rt_sigqueueinfo(struct syscallrecord *rec)
{
	siginfo_t *info;

	rec->a1 = pick_target_pid();

	/* Avoid SIGKILL, SIGSTOP, SIGTERM on the default path; use safe
	 * signals or realtime range.  Realtime signals (SIGRTMIN..SIGRTMAX)
	 * are the ones that actually carry siginfo all the way through to
	 * the receiver; regular signals work but the kernel drops most
	 * fields. */
	if (RAND_BOOL())
		rec->a2 = RAND_ARRAY(safe_signals);
	else
		rec->a2 = SIGRTMIN + (rnd_modulo_u32((SIGRTMAX - SIGRTMIN + 1)));

	info = (siginfo_t *) get_writable_address(sizeof(*info));
	if (info == NULL)
		return;

	fill_siginfo_by_class(info);
	rec->a3 = (unsigned long) info;
}

struct syscallentry syscall_rt_sigqueueinfo = {
	.name = "rt_sigqueueinfo",
	.group = GROUP_SIGNAL,
	.num_args = 3,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "sig", [2] = "uinfo" },
	.flags = AVOID_SYSCALL,	/* can disrupt signal handling */
	.sanitise = sanitise_rt_sigqueueinfo,
	.rettype = RET_ZERO_SUCCESS,
};
