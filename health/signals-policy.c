/*
 * health/signals-policy.c — signal install/mask policy for parent and child.
 *
 * Owns the watchdog handlers (SIGALRM, SIGXCPU) and their pending flags, the
 * catch-all default-restore sighandler, the parent's SIGINT/SIGTERM stop
 * handler, and the installers mask_signals_child() and setup_main_signals().
 * See Documentation/signals.md.
 */
#include <signal.h>	/* sigaction, sigset_t, SA_SIGINFO, SA_RESTART */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
#include <execinfo.h>	/* backtrace() -- pre-warm libgcc_s.so.1 */
#endif

#include "trinity.h"	/* __unused__, panic() */
#include "signals.h"
#include "signals-internal.h"

#include "pids.h"	/* mainpid */
#include "shm.h"	/* shm->stats, shm->exit_reason */

volatile sig_atomic_t sigalrm_pending;
volatile sig_atomic_t xcpu_pending;

/*
 * Parent SIGINT/SIGTERM: parent_stop_reason() decides, and panic()
 * stamps the reason for main_loop to act on.  Only the parent's own pid
 * may act: a forked child keeps this handler until mask_signals_child()
 * replaces it, and the parent's SIGTERM to a canary slot child can carry
 * a uid parent_stop_reason() trusts.  getpid(), not mypid(): cached_pid
 * still holds the parent's pid in a child that has not reached
 * set_child_cache() yet.
 */
static void main_stop_handler(int sig, siginfo_t *info, __unused__ void *ctx)
{
	enum exit_reasons reason;

	if (getpid() != mainpid)
		return;

	reason = parent_stop_reason(sig, info,
			__atomic_load_n(&shm->exit_reason, __ATOMIC_ACQUIRE));
	if (reason != STILL_RUNNING)
		panic(reason);
}

static __attribute__((no_sanitize("address")))
void sighandler(int sig)
{
	/* Restore the default disposition and re-raise, so the child dies
	 * of the signal itself: the kernel emits the usual crash artefacts
	 * (signal exit, dmesg log, core if enabled) and the reaper sees
	 * WIFSIGNALED(sig).  The kernel-fault signals take
	 * child_fault_handler() instead, which outside debug mode ends the
	 * child with a clean exit status; see mask_signals_child(). */
	(void)signal(sig, SIG_DFL);
	raise(sig);
}

void sigalrm_handler(__unused__ int sig)
{
	sigalrm_pending = 1;
	/* Don't siglongjmp here.  SIGALRM is installed without
	 * SA_RESTART, so the signal interrupts the blocking syscall
	 * (it returns EINTR/ERESTARTNOHAND) and control returns to
	 * the child main loop where sigalrm_pending is checked.
	 *
	 * The old code called siglongjmp() from here, which could
	 * permanently leak glibc's allocator lock if the child was
	 * inside malloc/free at signal delivery time, causing
	 * deadlock or heap corruption on the next allocation. */
}

void sigxcpu_handler(__unused__ int sig)
{
	xcpu_pending = 1;
	/* Don't siglongjmp here.  The signal interrupts the syscall
	 * (SIGXCPU is installed without SA_RESTART), and the child
	 * main loop checks xcpu_pending on the next iteration.
	 * Longjmping from here risked orphaning locks held at the
	 * time of the signal. */
}

/*
 * Put the inner watchdog back the way the child found it, immediately
 * before each alarm(1) arm.  Two ways a child breaks its own 1-second
 * watchdog, and it fuzzes the syscalls for both:
 *
 *   rt_sigaction  -- swaps out the handler.  Repaired below; measured
 *                    by the _clobbered / _reinstalled counter pairs.
 *   rt_sigprocmask-- blocks the signal.  A blocked SIGALRM is not
 *                    delivered, it is merely pending, so the alarm
 *                    fires into nothing and the blocking syscall sleeps
 *                    on until the ~30-second outer watchdog kills the
 *                    child.  Repaired below; measured by the _unblocked
 *                    counters.
 *
 * The second one is not theory: the wedge path records SigBlk, and a
 * wedged child's mask can show SIGALRM blocked with SIGKILL and SIGSTOP
 * clear -- the kernel's own sigdelsetmask fingerprint, so it is a real
 * fuzzed mask and not a stale read.
 *
 * This deliberately narrows what rt_sigprocmask fuzzing can express:
 * the child may block SIGALRM, but not across a NEED_ALARM syscall.
 * That is the same trade the disposition reinstall already makes, for
 * the same reason -- a fuzzer that can disable its own liveness
 * mechanism spends its time wedged instead of fuzzing.  SIGKILL and
 * SIGSTOP are unblockable by the kernel for exactly this class of
 * reason; these two are trinity's equivalent.
 */
void watchdog_signals_rearm(void)
{
	struct sigaction cur;
	sigset_t unblock, old;

	/* SIGALRM: reinstall the flag-setter if a fuzzed rt_sigaction
	 * has swapped it out.  Match the mask_signals_child() install:
	 * empty mask, no SA_RESTART, so the arriving signal interrupts
	 * the blocking syscall (EINTR) and control returns to the child
	 * main loop where sigalrm_pending is checked. */
	if (sigaction(SIGALRM, NULL, &cur) == 0 &&
	    cur.sa_handler != sigalrm_handler) {
		struct sigaction sa;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = sigalrm_handler;
		(void)sigaction(SIGALRM, &sa, NULL);
		__atomic_add_fetch(&shm->stats.watchdog_signal.sigalrm_clobbered,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.watchdog_signal.sigalrm_reinstalled,
				   1, __ATOMIC_RELAXED);
	}

	/* SIGXCPU: same reinstall, same install parameters -- see
	 * mask_signals_child() for the sa_flags=0 rationale (interrupt
	 * the syscall, let the child main loop see xcpu_pending). */
	if (sigaction(SIGXCPU, NULL, &cur) == 0 &&
	    cur.sa_handler != sigxcpu_handler) {
		struct sigaction sa;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
		sa.sa_handler = sigxcpu_handler;
		(void)sigaction(SIGXCPU, &sa, NULL);
		__atomic_add_fetch(&shm->stats.watchdog_signal.sigxcpu_clobbered,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.watchdog_signal.sigxcpu_reinstalled,
				   1, __ATOMIC_RELAXED);
	}
	/*
	 * Unblock both watchdog signals.  One syscall does the repair and
	 * the measurement: SIG_UNBLOCK returns the previous mask, so a
	 * separate query is not needed on the hot path.
	 */
	sigemptyset(&unblock);
	sigaddset(&unblock, SIGALRM);
	sigaddset(&unblock, SIGXCPU);
	if (sigprocmask(SIG_UNBLOCK, &unblock, &old) == 0) {
		if (sigismember(&old, SIGALRM))
			__atomic_add_fetch(&shm->stats.watchdog_signal.sigalrm_unblocked,
					   1, __ATOMIC_RELAXED);
		if (sigismember(&old, SIGXCPU))
			__atomic_add_fetch(&shm->stats.watchdog_signal.sigxcpu_unblocked,
					   1, __ATOMIC_RELAXED);
	}
}

void mask_signals_child(void)
{
	struct sigaction sa;
	sigset_t ss, oldss;
	int i;

	/* Block all signals while we install handlers, so none is
	 * delivered against a half-built disposition table: one arriving
	 * between the catch-all sighandler install and its proper handler
	 * would die of its default action instead of being handled or
	 * ignored.  The order matters too: the catch-all loop goes first to
	 * give every signal a safe default, and the per-signal overrides
	 * below layer on top of it, so do not reorder the sigaction() calls
	 * without reviewing the window before the mask is restored. */
	sigfillset(&ss);
	sigprocmask(SIG_BLOCK, &ss, &oldss);

	for (i = 1; i < _NSIG; i++) {
		(void)sigfillset(&ss);
		sa.sa_flags = SA_RESTART;
		sa.sa_handler = sighandler;
		sa.sa_mask = ss;
		(void)sigaction(i, &sa, NULL);
	}
	/* we want default behaviour for child process signals */
	(void)signal(SIGCHLD, SIG_DFL);

	/* SIGALRM: set a flag and let the interrupted syscall return
	 * EINTR.  Installed without SA_RESTART so blocking syscalls
	 * are interrupted rather than silently restarted. */
	{
		struct sigaction alrm_sa;
		sigemptyset(&alrm_sa.sa_mask);
		alrm_sa.sa_flags = 0;
		alrm_sa.sa_handler = sigalrm_handler;
		(void)sigaction(SIGALRM, &alrm_sa, NULL);
	}

	/* Count SIGXCPUs.  Install without SA_RESTART so the signal
	 * interrupts blocking syscalls and control returns to the
	 * child main loop where xcpu_pending is checked. */
	{
		struct sigaction xcpu_sa;
		sigemptyset(&xcpu_sa.sa_mask);
		xcpu_sa.sa_flags = 0;
		xcpu_sa.sa_handler = sigxcpu_handler;
		(void)sigaction(SIGXCPU, &xcpu_sa, NULL);
	}

	/* Ignore terminal, job-control, async-IO and broken-pipe signals,
	 * plus SIGFPE/SIGXFSZ: none of these should terminate or stop a
	 * fuzzing child.  SIGINT too: the parent alone acts on a ctrl-c, and
	 * init_child_isolate_io() leaves a child with no terminal, so one
	 * that reaches it is a spoof (rt_sigqueueinfo() to itself may carry
	 * SI_KERNEL, a pty it holds as its terminal raises the real thing)
	 * and must not end the run. */
	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGFPE, SIG_IGN);
	(void)signal(SIGTSTP, SIG_IGN);
	(void)signal(SIGWINCH, SIG_IGN);
	(void)signal(SIGIO, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGXFSZ, SIG_IGN);

	/* Ignore the RT signals. */
	for (i = SIGRTMIN; i <= SIGRTMAX; i++)
		(void)signal(i, SIG_IGN);

	/*
	 * Install child_fault_handler over the catch-all sighandler for
	 * the kernel-fault signals.  The handler dumps a backtrace +
	 * psiginfo to stderr in BOTH modes; in debug it then re-raises
	 * with SIG_DFL so the kernel still drops a core, in non-debug it
	 * _exit's cleanly so the parent's reaper sees a normal exit and
	 * respawns without crash-loop noise.  The reaper still counts the
	 * crash from the fault beacon the handler stamps first
	 * (handle_child() in main/reap.c).
	 */
	{
		struct sigaction fault_sa;
		sigemptyset(&fault_sa.sa_mask);
		fault_sa.sa_flags = SA_SIGINFO;
		fault_sa.sa_sigaction = child_fault_handler;
		(void)sigaction(SIGSEGV, &fault_sa, NULL);
		(void)sigaction(SIGABRT, &fault_sa, NULL);
		(void)sigaction(SIGBUS,  &fault_sa, NULL);
		(void)sigaction(SIGILL,  &fault_sa, NULL);
	}

	/*
	 * SIGTRAP handler for the Stage-2 writer-pinning canary HW
	 * watchpoint (--writer-watch).  Installed unconditionally so the
	 * disposition is the same shape regardless of whether the perf
	 * event has been armed yet; writer_watch_arm_child() is what
	 * actually opens the perf event, whose sigtrap=1 has the kernel
	 * raise SIGTRAP here.  Without --writer-watch that never happens,
	 * and the handler ignores the SIGTRAPs a sibling sends.
	 * SA_SIGINFO so the handler can read the ucontext for the
	 * writer's RIP and the siginfo for the watched address and the
	 * sender.
	 */
	{
		struct sigaction trap_sa;
		sigemptyset(&trap_sa.sa_mask);
		trap_sa.sa_flags = SA_SIGINFO;
		trap_sa.sa_sigaction = writer_trap_handler;
		(void)sigaction(SIGTRAP, &trap_sa, NULL);
	}

	/* All handlers installed — unblock signals. */
	sigprocmask(SIG_SETMASK, &oldss, NULL);
}


void setup_main_signals(void)
{
	struct sigaction sa;
	int i;

	(void)signal(SIGCHLD, SIG_DFL);

	/*
	 * Ignore signals that children can send us via kill/tkill/tgkill.
	 * Without this, the fuzzer randomly terminates when a child happens
	 * to send a fatal signal to the parent PID.
	 * parent_ignores_sigio_as() (include/signals.h) must follow this list.
	 */
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGUSR1, SIG_IGN);
	(void)signal(SIGUSR2, SIG_IGN);
	(void)signal(SIGALRM, SIG_IGN);
	(void)signal(SIGVTALRM, SIG_IGN);
	(void)signal(SIGPROF, SIG_IGN);
	(void)signal(SIGXFSZ, SIG_IGN);
	(void)signal(SIGXCPU, SIG_IGN);
	(void)signal(SIGPIPE, SIG_IGN);
	(void)signal(SIGIO, SIG_IGN);

	/* Ignore RT signals — children fuzzing rt_sigqueueinfo,
	 * pidfd_send_signal, timer_create/settime with sigev_signo in
	 * [SIGRTMIN..SIGRTMAX], etc. can deliver any RT signal to us.
	 * Default kernel action for an unhandled RT signal is termination,
	 * which silently exits trinity ("Real-time signal N" printed by
	 * glibc).  Mirror the same loop the children use in mask_signals_child. */
	for (i = SIGRTMIN; i <= SIGRTMAX; i++)
		(void)signal(i, SIG_IGN);

	/*
	 * Use SA_SIGINFO for fault/core-dump signals so main_fault_handler()
	 * can tell real faults from signals sent by child processes fuzzing
	 * kill/tkill/tgkill or F_SETSIG (fault_signal_is_real()).
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = main_fault_handler;
	(void)sigaction(SIGABRT, &sa, NULL);
	(void)sigaction(SIGSEGV, &sa, NULL);
	(void)sigaction(SIGBUS, &sa, NULL);
	(void)sigaction(SIGILL, &sa, NULL);
	(void)sigaction(SIGFPE, &sa, NULL);
	(void)sigaction(SIGQUIT, &sa, NULL);
	(void)sigaction(SIGTRAP, &sa, NULL);
	(void)sigaction(SIGSYS, &sa, NULL);

	/* SIGINT/SIGTERM: SA_SIGINFO so main_stop_handler() can tell a
	 * terminal ctrl-c or an operator's kill from a child's. */
	sa.sa_sigaction = main_stop_handler;
	(void)sigaction(SIGINT, &sa, NULL);
	(void)sigaction(SIGTERM, &sa, NULL);

	/*
	 * Eager-load libgcc_s.so.1 by calling backtrace() once now, while
	 * malloc is healthy and no fault handler can fire.  The first
	 * backtrace() in a process triggers
	 *   libc_unwind_link_get -> __libc_dlopen_mode("libgcc_s.so.1")
	 *     -> _dl_load_cache_lookup -> strdup -> malloc
	 * If we instead reach backtrace() for the first time from the
	 * SIGABRT handler raised by a glibc malloc assertion (heap
	 * corruption -> abort), the main_arena lock is already held by
	 * this very thread.  The recursive malloc inside dlopen then
	 * deadlocks forever in lll_lock_wait_private and we lose every
	 * child to a futex_wait we cannot recover from -- the diagnostic
	 * machinery itself becomes the bug.
	 *
	 * Doing it here, in the parent before fork, ensures libgcc_s is
	 * already mapped in every child via copy-on-write inheritance, so
	 * neither child_fault_handler nor main_fault_handler can hit the
	 * dlopen path at signal time.
	 */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
	{
		void *stub[1];
		(void)backtrace(stub, 1);
	}
#endif
}
