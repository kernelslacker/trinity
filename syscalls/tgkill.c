/*
 * SYSCALL_DEFINE3(tgkill, pid_t, tgid, pid_t, pid, int, sig)
 */
#include <signal.h>
#include <sys/types.h>
#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * Drop the synchronous-fault signals (SIGILL/SIGTRAP/SIGABRT/SIGBUS/
 * SIGSEGV) and the lifecycle-fatal trio (SIGKILL/SIGSTOP/SIGTERM) from
 * the default path -- a self-targeted or sibling-targeted deliver will
 * re-enter trinity's own fault handlers or tear down a healthy child.
 * sig==0 is the kernel's existence-probe and is covered by the dedicated
 * path in sanitise_tgkill().
 */
static unsigned long safe_signals[] = {
	SIGHUP, SIGQUIT, SIGFPE, SIGUSR1, SIGUSR2, SIGPIPE,
	SIGALRM, SIGCHLD, SIGCONT, SIGURG, SIGXCPU, SIGXFSZ,
	SIGVTALRM, SIGPROF, SIGWINCH, SIGIO, SIGSYS,
};

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
	 * ignorable safe set.  tgkill has no siginfo path so there is no
	 * realtime branch to exercise here.
	 */
	draw = rnd_modulo_u32(10);
	if (draw < 3)
		rec->a3 = 0;
	else
		rec->a3 = RAND_ARRAY(safe_signals);
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
