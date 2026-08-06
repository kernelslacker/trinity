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
#include <signal.h>	/* siginfo_t */
#include <unistd.h>	/* write() */
#include <ucontext.h>	/* ucontext_t / REG_RIP &c for fault_beacon IP/SP capture */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
#include <execinfo.h>
#endif

#include "signals-internal.h"

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
 * We emit RAW PCs only; the bugs.txt post-processor resolves them
 * offline against the load bases recorded in the beacon.
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
	sigsafe_puts(&b, " (RAW, resolve offline against [load-bases])\n");

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
