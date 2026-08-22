/*
 * health/signals-async-safe.c — async-signal-safe formatting utilities.
 *
 * Provides the signal-number/siginfo dump, backtrace raw-PC emitter,
 * and ucontext IP/SP extractors used by the fault handlers in
 * signals-fault-handler.c and by the main-process fault handler in
 * signals-policy.c.
 *
 * All functions here touch ONLY:
 *   - caller-supplied stack buffers
 *   - write(2) / backtrace() from the POSIX 2024 §2.4.3 safe list
 *   - pure inline ucontext reads
 * No allocator, no stdio, no locale, no lock.
 */
#include <signal.h>	/* siginfo_t / stack_t */
#include <string.h>	/* memcpy of the ucontext sigmask word */
#include <sys/syscall.h>	/* SYS_sigaltstack */
#include <unistd.h>	/* write() */
#include <ucontext.h>	/* ucontext_t / REG_RIP &c for fault_beacon IP/SP capture */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
#include <execinfo.h>
#endif

#include "signals-internal.h"
#include "utils-mem.h"	/* trinity_load_base */

/*
 * Signal-safe siginfo dump shared by child_fault_handler and
 * main_fault_handler.  Hand-rolled because psiginfo() calls
 * fmemopen -> calloc and deadlocks if the signal was raised by
 * glibc's own abort() with the arena lock held (same family as
 * the libgcc_s/backtrace deadlock fixed in 81143aaeaba6).
 * See Documentation/signals.md.
 */
void write_siginfo_safely(int sig, const siginfo_t *info, const char *who)
{
	static const struct {
		int sig;
		const char *name;
	} sigtab[] = {
		{ SIGSEGV, "SIGSEGV" },
		{ SIGABRT, "SIGABRT" },
		{ SIGBUS,  "SIGBUS"  },
		{ SIGILL,  "SIGILL"  },
		{ SIGFPE,  "SIGFPE"  },
		{ SIGQUIT, "SIGQUIT" },
		{ SIGTRAP, "SIGTRAP" },
		{ SIGSYS,  "SIGSYS"  },
	};
	const char *signame = "UNKNOWN";
	char buf[256];
	struct sigsafe_buf b = { buf, sizeof(buf) };
	size_t written;
	ssize_t w;
	size_t i;

	for (i = 0; i < sizeof(sigtab) / sizeof(sigtab[0]); i++) {
		if (sigtab[i].sig == sig) {
			signame = sigtab[i].name;
			break;
		}
	}

	sigsafe_puts(&b, who);
	sigsafe_puts(&b, ": fatal signal: ");
	sigsafe_puts(&b, signame);
	sigsafe_puts(&b, " (si_code=");
	sigsafe_puti(&b, (long)info->si_code);
	sigsafe_puts(&b, ", si_addr=");
	sigsafe_putp(&b, info->si_addr);
	sigsafe_puts(&b, ", si_pid=");
	sigsafe_puti(&b, (long)info->si_pid);
	sigsafe_puts(&b, ")\n");

	written = sizeof(buf) - b.left;
	w = write(STDERR_FILENO, buf, written);
	(void)w;	/* dying anyway; can't act on a short write */
}

/*
 * Signal-delivery state at fault time.
 *
 * Why this exists: four crashes in the 7.2 run came in as SIGSEGV with
 * si_code=SI_KERNEL (128) and si_addr=0, taken while the child was
 * blocked inside a syscall.  That pair means "kernel-generated, not a
 * page fault", and the shortlist of things that produce it is mostly
 * about signal delivery itself -- an alternate stack the kernel could
 * not use, a frame it could not build, a handler running somewhere
 * unexpected.  Every candidate on that shortlist is a property of the
 * child's signal state, and none of it was in the log, so the crashes
 * could be argued about but not classified.
 *
 * Three facts, all cheap, and each says a specific thing -- verified
 * against a real kernel-delivered SIGSEGV rather than assumed, because
 * the first cut of this function labelled two of the three wrongly:
 *
 *   altstack   -- the alternate stack as sigaltstack(2) reports it now.
 *                 Its SS_ONSTACK bit is the direct answer to "is this
 *                 handler executing on the alternate stack", which is
 *                 the fact worth having.  Trinity fuzzes sigaltstack(2),
 *                 so a bogus registration here is the first thing to
 *                 rule in or out.
 *   uc_stack   -- NOT the stack this handler runs on, despite the
 *                 tempting name.  The kernel fills it from the
 *                 INTERRUPTED context, so its SS_ONSTACK means the
 *                 interrupted code was itself already on the alternate
 *                 stack, i.e. this is a nested delivery.  A plain first
 *                 signal reports flags=0 here even while the handler
 *                 runs on the alt stack.
 *   uc_sigmask -- the mask to be restored on return, i.e. what was
 *                 blocked BEFORE delivery, not during the handler.  A
 *                 signal arriving on a mask a fuzzed rt_sigprocmask()
 *                 just rewrote is the other half of the question.
 *
 * STRICTLY ASYNC-SIGNAL-SAFE: pure reads from the caller-owned
 * ucontext, one raw sigaltstack(2) query (a bare syscall, no libc
 * state), one write(2).
 */
void write_signal_delivery_state(const void *ctxp)
{
	const ucontext_t *uc = ctxp;
	stack_t cur = { 0 };
	char buf[320];
	struct sigsafe_buf b = { buf, sizeof(buf) };
	unsigned long blocked = 0;
	size_t used;
	ssize_t w;
	long rc;

	if (uc == NULL)
		return;

	/*
	 * Raw syscall rather than the libc wrapper: sigaltstack() is not
	 * on the POSIX 2024 2.4.3 list, and while glibc's is a thin
	 * marshaller today that is not a contract.  A failed query leaves
	 * the zeroed struct, which prints as an all-zero stack -- honest,
	 * and distinguishable from a real registration.
	 */
	rc = syscall(SYS_sigaltstack, (stack_t *)NULL, &cur);

	/*
	 * First word of the blocked set covers signals 1..64 on every
	 * arch trinity builds for; the beacon does not need more.
	 */
	memcpy(&blocked, &uc->uc_sigmask, sizeof(blocked));

	sigsafe_puts(&b, "SIGNAL-DELIVERY: altstack=");
	if (rc != 0) {
		sigsafe_puts(&b, "<query-failed>");
	} else {
		sigsafe_putp(&b, cur.ss_sp);
		sigsafe_puts(&b, " size=");
		sigsafe_putu(&b, (unsigned long)cur.ss_size);
		sigsafe_puts(&b, " flags=");
		sigsafe_puti(&b, (long)cur.ss_flags);
		if (cur.ss_flags & SS_DISABLE)
			sigsafe_puts(&b, " (DISABLED)");
		/* SS_ONSTACK from the query means "executing on it now". */
		sigsafe_puts(&b, (cur.ss_flags & SS_ONSTACK)
				 ? " (running-on-altstack)" : " (running-on-main-stack)");
	}

	sigsafe_puts(&b, " interrupted_stack sp=");
	sigsafe_putp(&b, uc->uc_stack.ss_sp);
	sigsafe_puts(&b, " size=");
	sigsafe_putu(&b, (unsigned long)uc->uc_stack.ss_size);
	sigsafe_puts(&b, " flags=");
	sigsafe_puti(&b, (long)uc->uc_stack.ss_flags);
	if (uc->uc_stack.ss_flags & SS_ONSTACK)
		sigsafe_puts(&b, " (NESTED: interrupted code was already on the altstack)");

	sigsafe_puts(&b, " blocked_pre=");
	sigsafe_putp(&b, (const void *)blocked);
	sigsafe_putc(&b, '\n');

	used = sizeof(buf) - b.left;
	w = write(STDERR_FILENO, buf, used);
	(void)w;	/* dying anyway; short write irrelevant */
}

/*
 * Signal-safe backtrace dump.  Replaces backtrace_symbols_fd(), which
 * is emphatically NOT on the POSIX 2024 §2.4.3 async-safe list: it
 * calls dladdr() (link_map walk under glibc's dl_load_lock and, on
 * newer glibcs, a private dl_addr lock), fopen()/fread() on
 * /proc/self/maps for PIE offsets, and malloc() for the returned
 * string table.  If the fault we're handling was raised by glibc's
 * own abort() (heap-corruption assertion, stack-smash detected) the
 * arena lock is already held by this very thread; the first
 * backtrace_symbols_fd inside the handler recursively takes malloc()
 * and deadlocks forever in lll_lock_wait_private, silencing the
 * beacon we depend on to notice the crash.  Same class as the
 * psiginfo() -> fmemopen -> calloc deadlock removed in
 * 81143aaeaba6.
 *
 * We emit RAW PCs only, followed by the PIE base they are relative to
 * so the log resolves without a second artifact.
 * backtrace() itself is pre-warmed at parent_init_signals() so
 * libgcc_s.so.1 is COW-inherited and the unwinder needs no dlopen at
 * signal time.  Single write() -- on the POSIX safe list -- for the
 * whole block so per-frame text cannot interleave with a sibling
 * worker's write onto the shared stderr memfd.
 *
 * USE_BACKTRACE_UNSAFE is an off-by-default developer knob that
 * additionally emits the pretty symbolised form via
 * backtrace_symbols_fd.  Enable only for targeted debugging where
 * the deadlock risk is understood.
 */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
void write_backtrace_raw_pcs(const char *who)
{
	void *frames[64];
	int nframes, i;
	/* header + up to 64 * "0xdeadbeefdeadbeef " (19 bytes) + trailer */
	char buf[64 * 20 + 128];
	struct sigsafe_buf b = { buf, sizeof(buf) };
	size_t used;
	ssize_t w;

	nframes = backtrace(frames, 64);

	sigsafe_puts(&b, who);
	sigsafe_puts(&b, " backtrace-raw: nframes=");
	sigsafe_puti(&b, (long)nframes);
	sigsafe_puts(&b, " pcs=");
	for (i = 0; i < nframes; i++) {
		if (i > 0)
			sigsafe_putc(&b, ' ');
		sigsafe_putp(&b, frames[i]);
	}
	/*
	 * Name the base the PCs are relative to, in this file.  The
	 * [load-bases] line goes to the parent's stderr, which is a
	 * different artifact from the per-pid bug log -- and the bug log
	 * is what gets tarred up and moved.  On its own it was
	 * unresolvable: raw PIE addresses plus a pointer to a line that
	 * lives somewhere else.  trinity_load_base is a plain unsigned
	 * long latched before the first fork, so reading it here is safe
	 * where dl_iterate_phdr() is not.
	 */
	sigsafe_puts(&b, " (RAW; subtract trinity_base=");
	sigsafe_putp(&b, (const void *)trinity_load_base);
	sigsafe_puts(&b, " to resolve)\n");

	used = sizeof(buf) - b.left;
	w = write(STDERR_FILENO, buf, used);
	(void)w;	/* dying anyway; short write irrelevant */

#ifdef USE_BACKTRACE_UNSAFE
	/*
	 * NOT async-signal-safe -- dladdr/malloc/fopen inside.  Off by
	 * default; the raw-PC line above is the reliable beacon.
	 */
	backtrace_symbols_fd(frames, nframes, STDERR_FILENO);
#endif
}
#endif

/*
 * Async-signal-safe extraction of the faulting PC / SP from the
 * ucontext_t the kernel hands to a SA_SIGINFO handler.  Pure inline
 * reads from caller-owned memory -- no libc, no allocator, no lock.
 *
 * Arches without an inline extractor fall through to NULL, which the
 * beacon consumer treats as "not captured on this build" and prints
 * an explicit placeholder; the rest of the beacon (sig / si_code /
 * si_addr / op_nr / last_syscall_nr) still surfaces.
 */
void *fault_beacon_extract_ip(const void *ctx)
{
	const ucontext_t *uc = ctx;

	if (uc == NULL)
		return NULL;
#if defined(__x86_64__)
	return (void *)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__i386__)
	return (void *)uc->uc_mcontext.gregs[REG_EIP];
#elif defined(__aarch64__)
	return (void *)uc->uc_mcontext.pc;
#else
	(void)uc;
	return NULL;
#endif
}

void *fault_beacon_extract_sp(const void *ctx)
{
	const ucontext_t *uc = ctx;

	if (uc == NULL)
		return NULL;
#if defined(__x86_64__)
	return (void *)uc->uc_mcontext.gregs[REG_RSP];
#elif defined(__i386__)
	return (void *)uc->uc_mcontext.gregs[REG_ESP];
#elif defined(__aarch64__)
	return (void *)uc->uc_mcontext.sp;
#else
	(void)uc;
	return NULL;
#endif
}
