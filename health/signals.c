#include <dlfcn.h>
#include <limits.h>	// PATH_MAX
#include <signal.h>
#include <stdlib.h>
#include <string.h>	// strnlen
#include <sys/mman.h>	// memfd_create, MFD_CLOEXEC
#include <sys/stat.h>	// umask
#include <sys/syscall.h>	// SYS_write (raw syscall, bypassing libc stdio)
#include <ucontext.h>	// ucontext_t / REG_RIP &c for fault_beacon IP/SP capture
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
#include <execinfo.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#endif

#include "trinity.h"	// __unused__
#include "signals.h"
#include "shm.h"
#include "pids.h"
#include "child.h"
#include "utils.h"	// guard_pages_classify (CONFIG_GUARD_SHARED only)

volatile sig_atomic_t sigalrm_pending;
volatile sig_atomic_t xcpu_pending;
volatile sig_atomic_t ctrlc_pending;

/*
 * Recovery point for asb_relocate()'s best-effort source copy.  See
 * include/signals.h and rand/random-address.c::asb_relocate() for the
 * full contract.  Definition lives here so the storage for the jmp_buf
 * is colocated with the handler that reads asb_copy_active.
 *
 * Inherited COW-private into every forked child; never touched by the
 * parent.  Plain file-scope storage rather than __thread because
 * trinity children are single-threaded processes -- no two threads in
 * the same address space race on the slot.
 */
sigjmp_buf asb_copy_recover;
volatile sig_atomic_t asb_copy_active;

/*
 * Recovery point for cmp_hints_collect()'s field-scoped ARG_TIMESPEC
 * deref.  See include/signals.h and cmp_hints.c::cmp_hints_collect()
 * for the full contract.  Definition lives here so the storage for
 * the jmp_buf is colocated with the handler that reads
 * cmp_field_read_active.
 *
 * Inherited COW-private into every forked child; never touched by the
 * parent.  Plain file-scope storage rather than __thread because
 * trinity children are single-threaded processes -- no two threads in
 * the same address space race on the slot.
 */
sigjmp_buf cmp_field_recover;
volatile sig_atomic_t cmp_field_read_active;

#ifdef CONFIG_GUARD_SHARED
/*
 * Recovery point for the kcov_enable_trace() trace_buf[0]=0 reset.
 * See include/signals.h and kcov.c::kcov_enable_trace() for the full
 * contract.  Definition lives here so the storage for the jmp_buf is
 * colocated with the handler that reads kcov_protect_active.
 *
 * COW-inherited into every forked child; never touched by the parent.
 * Plain file-scope storage rather than __thread because trinity
 * children are single-threaded.
 */
sigjmp_buf kcov_protect_recover;
volatile sig_atomic_t kcov_protect_active;
#endif

/*
 * Cached pointer to glibc's __abort_msg.  Resolved once at child init
 * so there is no link-time GLIBC_PRIVATE dependency: a glibc upgrade
 * that drops the symbol leaves this NULL and the SIGABRT handler
 * silently skips the capture.  This mirrors gdb's pattern for reading
 * the same symbol.  Neither dlvsym() nor dlsym() is async-signal-safe;
 * both are called only from init_abort_msg_capture() below.
 *
 * __abort_msg points at a glibc-internal struct whose layout has been
 * stable since 2.34: a 4-byte size field followed by a NUL-terminated
 * message in a flexible array.  The struct is mirrored locally rather
 * than pulled from a private glibc header.
 */
static struct abort_msg_s {
	unsigned int size;
	char msg[];
} **glibc_abort_msg_p;

void init_abort_msg_capture(void)
{
	/*
	 * Most distros export __abort_msg only under @GLIBC_PRIVATE
	 * with no default-version alias, so a bare dlsym() returns
	 * NULL.  Bind the private version explicitly via dlvsym(), and
	 * fall back to dlsym() for libcs that do expose an unversioned
	 * alias.
	 */
	glibc_abort_msg_p = dlvsym(RTLD_DEFAULT, "__abort_msg", "GLIBC_PRIVATE");
	if (glibc_abort_msg_p == NULL)
		glibc_abort_msg_p = dlsym(RTLD_DEFAULT, "__abort_msg");
}

/*
 * Capture glibc's __abort_msg directly into the per-pid bug log via raw
 * syscall, bypassing libc stdio and STDERR_FILENO entirely.
 *
 * Why not just write to STDERR_FILENO after dup2?  Because every child
 * inherits the SAME underlying struct file for the stderr-memfd via
 * fork: one offset, one inode.  Concurrent writev()s from N children's
 * glibc malloc_printerr -> __libc_message paths race with each other AND
 * with sibling SIGABRT handlers' lseek(0)+read drain blocks.  Most
 * messages are overwritten before the originator drains, or attributed
 * to the wrong bug log when a sibling's lseek mutates the shared offset
 * mid-drain.  Empirical capture rate sat at ~13-15% regardless of fleet
 * size.
 *
 * __abort_msg, on the other hand, is per-process: glibc's __libc_message
 * mmap()s the backing buffer in the abort()ing child's own address
 * space and populates it before raising SIGABRT.  No sharing across
 * fork, no race, no offset state.  Writing it directly into the per-pid
 * bug_fd -- which the handler just open()ed for this specific child
 * with O_APPEND -- sidesteps the shared-memfd path entirely.
 *
 * Async-signal-safe throughout:
 *   - syscall(SYS_write, ...) is the raw syscall instruction; write()
 *     itself is on POSIX 2024 §2.4.3's safe list, and the wrapper does
 *     no extra libc work beyond setting up the registers.
 *   - strnlen() walks memory looking for NUL; no allocation, no locale,
 *     no lock.  Bounded by min(m->size, ABORT_MSG_MAX) -- m->size is
 *     treated as advisory because m lives in the same glibc allocation
 *     we're salvaging post-corruption and may itself be scribbled.
 *
 * The m->msg[0] == '\0' early-out catches the rare path where glibc
 * allocated the buffer but bailed before formatting (e.g. format failed
 * inside vfprintf-on-string).  Don't emit a bare "abort_msg: \n".
 */
static void capture_abort_msg_to_buglog(int bug_fd)
{
	/*
	 * Hard upper bound on how many bytes we'll trust m->size to
	 * authorise reading.  m and m->size both live in the same glibc
	 * abort allocation we're salvaging post-corruption -- if the
	 * upstream bug is "heap got scribbled", m->size is just another
	 * scribbled field.  Real __abort_msg payloads are short single
	 * lines (a few hundred bytes); 16 KiB is far above anything glibc
	 * produces and far below any value that would let a corrupt
	 * size_t run strnlen() off a mapping.
	 */
	static const size_t ABORT_MSG_MAX = 16384;
	struct abort_msg_s *m;
	size_t cap, len;
	static const char prefix[] = "abort_msg: ";

	if (glibc_abort_msg_p == NULL)
		return;
	m = *glibc_abort_msg_p;
	if (m == NULL)
		return;
	cap = m->size;
	if (cap > ABORT_MSG_MAX)
		cap = ABORT_MSG_MAX;
	if (cap == 0 || m->msg[0] == '\0')
		return;

	len = strnlen(m->msg, cap);
	(void)syscall(SYS_write, bug_fd, prefix, sizeof(prefix) - 1);
	(void)syscall(SYS_write, bug_fd, m->msg, len);
	if (len == 0 || m->msg[len - 1] != '\n')
		(void)syscall(SYS_write, bug_fd, "\n", 1);
}

/*
 * In-process anonymous file that backs the child's stderr after
 * init_stderr_memfd() runs.  The fd is kept open past the dup2 so
 * child_fault_handler() can lseek+read the buffered text back into
 * the on-disk bug log when the child actually crashes.  -1 means
 * the memfd_create() failed (e.g. CONFIG_MEMFD_CREATE=n on a
 * stripped kernel) and stderr stays at its previous /dev/null
 * baseline -- the handler then skips the drain and produces only
 * the in-handler backtrace + siginfo, same as before this feature
 * existed.
 */
static int stderr_memfd = -1;

/*
 * Bug-log path pre-formatted at init time so the signal handler
 * never has to call snprintf() (not async-signal-safe per POSIX
 * 2024 §2.4.3).  Sized like the existing on-stack PATH_MAX + 64
 * buffer in child_fault_handler so a long trinity_tmpdir_abs() plus
 * "/trinity-bug-<pid>.log" cannot truncate.
 */
static char buglog_path[PATH_MAX + 64];

/*
 * Buffer the child's stderr writes in an anonymous in-memory file
 * so glibc's malloc_printerr / __libc_message / __fortify_fail /
 * __stack_chk_fail family text (which happens BEFORE any trinity
 * signal handler runs) survives long enough for the fault handler
 * to flush it into the on-disk bug log -- but only on a real
 * crash, so trinity's own outputerr() noise from healthy children
 * is silently discarded with the process at clean exit.
 *
 * Paired with the drain block at the top of child_fault_handler:
 * the handler open()s the bug log, lseek()s the memfd to 0, and
 * splices the buffered text into the log before its own writes.
 *
 * snprintf() is NOT async-signal-safe, so the path is formatted
 * here at init time (under the inherited non-fuzzed locale state)
 * and stashed in the file-static buglog_path[].  trinity_tmpdir_abs()
 * is used so a fuzzed chdir() can't move us off the writable tmp
 * dir mid-run; getpid() is used instead of mypid() because the
 * cached_pid backing mypid() isn't populated until set_child_cache
 * runs later in init_child_rendezvous_parent.
 *
 * On memfd_create() failure (CONFIG_MEMFD_CREATE=n or sandbox)
 * stderr stays at /dev/null per init_child_isolate_io()'s baseline:
 * the per-pid bug log still gets the in-handler backtrace + siginfo
 * via the handler's explicit open + dup2, only the pre-crash glibc
 * text capture is lost.
 *
 * The fd is intentionally NOT closed after dup2 onto STDERR_FILENO --
 * the handler reads it back from the same fd.
 */
void init_stderr_memfd(void)
{
	int fd;

	snprintf(buglog_path, sizeof(buglog_path),
		 "%s/trinity-bug-%d.log",
		 trinity_tmpdir_abs(), (int)getpid());

	fd = memfd_create("trinity-stderr", MFD_CLOEXEC);
	if (fd < 0)
		return;
	dup2(fd, STDERR_FILENO);
	stderr_memfd = fd;
}

int trinity_stderr_memfd(void)
{
	return stderr_memfd;
}

/*
 * Set while a child is inside do_syscall().  Lets the child fault
 * handler distinguish a SIGSEGV/SIGBUS/SIGILL the child fuzzed at
 * itself via kill(getpid(), SIGFOO) / tkill / tgkill /
 * rt_sigqueueinfo (SI_USER, si_pid == own pid, flag set) from a
 * real fault that just happened to fire at a moment when the child
 * was somewhere else (flag clear -- treat as a real bug, log it).
 */
volatile sig_atomic_t in_do_syscall;
volatile sig_atomic_t in_extrafork_grandchild;

/*
 * SA_SIGINFO version: only honor SIGINT generated by the kernel
 * (si_code > 0, e.g. SI_KERNEL from a terminal ctrl-c).  Any
 * userspace-sent SIGINT — including self-sent via raise()/
 * kill(getpid(), SIGINT)/tgkill(self, SIGINT) — is ignored.
 *
 * Trinity has no internal raise(SIGINT) callers, so a self-sent
 * SIGINT can only come from a child fuzzing the signal-delivery
 * syscalls and happening to pick signal 2 with its own pid as the
 * target.  Honoring those was causing spurious whole-run shutdowns:
 * the child would set ctrlc_pending, then panic(EXIT_SIGINT) on the
 * next loop iteration, the parent saw exit_reason flip, and ~77
 * fuzzing children got reaped for no real reason.
 *
 * Used by both parent and children.  The parent calls panic() directly;
 * children set ctrlc_pending and let the main loop exit cleanly.
 */
static void sigint_handler(__unused__ int sig, siginfo_t *info, __unused__ void *ctx)
{
	/* Only honor real terminal-generated SIGINT (si_code > 0).
	 * SI_USER (0) and below indicate userspace-sent — ignore as
	 * spoofable. */
	if (info->si_code > 0) {
		if (mypid() == mainpid)
			panic(EXIT_SIGINT);
		else
			ctrlc_pending = 1;
	}
}

static __attribute__((no_sanitize("address")))
void sighandler(int sig)
{
	/* Restore default disposition and re-raise so the kernel emits
	 * the usual crash artefacts (signal exit, dmesg log, core if
	 * enabled).  Silent _exit(SUCCESS) hid real fuzzer finds because
	 * the parent saw WIFEXITED(0) instead of WIFSIGNALED(sig). */
	(void)signal(sig, SIG_DFL);
	raise(sig);
}

/*
 * Async-signal-safe formatting primitives for the siginfo dump below.
 * snprintf() is NOT in POSIX 2024 §2.4.3's signal-safe set: glibc's
 * conversion path can touch locale state under an internal lock, and
 * %p/%d are not exempted -- the lock is on the format machinery, not
 * on the conversion specifier.  A fault handler that fires while the
 * thread already holds that lock from a non-handler call would
 * deadlock.  These helpers use only byte stores into a caller-owned
 * stack buffer; no allocation, no globals, no FILE state.
 */
struct sigsafe_buf {
	char *p;
	size_t left;
};

static void sigsafe_putc(struct sigsafe_buf *b, char c)
{
	if (b->left > 0) {
		*b->p++ = c;
		b->left--;
	}
}

static void sigsafe_puts(struct sigsafe_buf *b, const char *s)
{
	while (*s != '\0')
		sigsafe_putc(b, *s++);
}

static void sigsafe_putu(struct sigsafe_buf *b, unsigned long v)
{
	char tmp[24];	/* 20 digits for u64 + slack */
	int i = 0;

	do {
		tmp[i++] = (char)('0' + (v % 10U));
		v /= 10U;
	} while (v != 0);
	while (i-- > 0)
		sigsafe_putc(b, tmp[i]);
}

static void sigsafe_puti(struct sigsafe_buf *b, long v)
{
	unsigned long u;

	if (v < 0) {
		sigsafe_putc(b, '-');
		/* Two-step negate so LONG_MIN does not overflow. */
		u = (unsigned long)(-(v + 1)) + 1UL;
	} else {
		u = (unsigned long)v;
	}
	sigsafe_putu(b, u);
}

static void sigsafe_putp(struct sigsafe_buf *b, const void *p)
{
	static const char hex[] = "0123456789abcdef";
	uintptr_t v = (uintptr_t)p;
	char tmp[2 * sizeof(uintptr_t)];
	int i = 0;

	sigsafe_putc(b, '0');
	sigsafe_putc(b, 'x');
	if (v == 0) {
		sigsafe_putc(b, '0');
		return;
	}
	while (v != 0) {
		tmp[i++] = hex[v & 0xfU];
		v >>= 4;
	}
	while (i-- > 0)
		sigsafe_putc(b, tmp[i]);
}

/*
 * Signal-safe siginfo dump shared by child_fault_handler and
 * main_fault_handler.
 *
 * Don't use psiginfo() -- it calls fmemopen(), which calls calloc(),
 * which deadlocks if this signal was raised by glibc's own abort()
 * while malloc's arena lock is still held by us.  Same family as the
 * libgcc_s/backtrace deadlock fixed in 81143aaeaba6, just one frame up.
 *
 * Hand-roll a signal-safe equivalent: a lookup table covering every
 * signal either fault handler is installed for, formatting via the
 * sigsafe_* helpers above (byte stores into a stack buffer), and a
 * single write().  No allocator involvement, no stdio, no syslog.
 *
 * Used by both the child fault handler (SIGSEGV/SIGABRT/SIGBUS/SIGILL)
 * and the parent's main_fault_handler (which adds SIGFPE/SIGQUIT/
 * SIGTRAP/SIGSYS -- see setup_main_signals).  Without this in the
 * parent path, a SIGSEGV or SIGABRT raised by glibc with the arena
 * lock held (e.g. heap corruption from shm scribble, or an internal
 * assertion) would fmemopen->calloc and wedge the parent's death
 * path forever -- the fleet would then sit on a non-responsive
 * trinity main until something external SIGKILLed it.
 */
static void write_siginfo_safely(int sig, const siginfo_t *info, const char *who)
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
 * Async-signal-safe extraction of the faulting PC / SP from the
 * ucontext_t the kernel hands to a SA_SIGINFO handler.  Pure inline
 * reads from caller-owned memory -- no libc, no allocator, no lock.
 *
 * Arches without an inline extractor fall through to NULL, which the
 * beacon consumer treats as "not captured on this build" and prints
 * an explicit placeholder; the rest of the beacon (sig / si_code /
 * si_addr / op_nr / last_syscall_nr) still surfaces.
 */
static void *fault_beacon_extract_ip(const void *ctx)
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

static void *fault_beacon_extract_sp(const void *ctx)
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

/*
 * Stamp the per-child fault beacon (see include/bug_backtrace.h::
 * child_fault_beacon for the field contract and the release-store /
 * acquire-load handoff that orders the stamp into the parent's view).
 *
 * Carries the same no_sanitize attribute as child_fault_handler because
 * the first plain load of me->syscall.state intentionally bypasses
 * ASAN's shadow check -- a torn-down shm childdata mapping must not
 * escalate to SIGKILL inside this very handler.
 */
static __attribute__((no_sanitize("address")))
void stamp_fault_beacon(int sig, siginfo_t *info, void *ctx)
{
	struct childdata *me = this_child();

	/*
	 * Gate the first me-deref on me belonging to a tracked
	 * shared region.  this_child() returns a raw pointer
	 * into per-child shm childdata; a child whose shm
	 * childdata mapping has been torn down or corrupted
	 * yields a non-NULL but unmapped pointer, so the NULL
	 * check alone is insufficient -- the first plain load
	 * (me->syscall.state, &me->fault_beacon, ...)
	 * re-faults inside this very handler and the kernel
	 * escalates to SIGKILL, erasing the original crash
	 * class entirely.
	 *
	 * range_in_tracked_shared() walks shared_regions[]
	 * (and the overflow tail) linearly -- no allocator,
	 * no stdio, no lock, no this_child(), no stats_ring
	 * enqueue, no global mutation -- which is the
	 * async-signal-safe property this handler requires.
	 * range_overlaps_shared() is NOT used here: on its
	 * confirmed-overlap path it calls this_child(),
	 * stats_ring_enqueue() twice, output() under
	 * verbosity, and writes the last_reject_* globals --
	 * exactly the re-entrant / async-signal-unsafe class
	 * this gate exists to keep out of the fault handler.
	 * Containment polarity (fully inside one tracked
	 * region) also matches the shape of the probe: each
	 * childdata is registered as a single shared_regions[]
	 * entry covering its full sizeof, so a valid me
	 * passes; a wild me that merely shares a 2 MiB bitmap
	 * chunk with some tracked region is correctly
	 * rejected here where range_overlaps_shared() would
	 * over-accept.  This proves me lies in a TRACKED
	 * region; it does NOT prove the underlying page is
	 * currently mapped/readable (a child that munmap'd
	 * its own childdata while the region stays registered
	 * would still pass this gate and re-fault on the
	 * deref).  That residual is a separate root-cause
	 * concern; this gate cleanly catches the wild/stale/
	 * corrupt-me class.  On a miss the beacon stamp is
	 * skipped (dropped-beacon, surfaced by the parent's
	 * existing written==0 path) so the kernel-side crash
	 * artefacts still land instead of a silent handler
	 * double-fault.
	 */
	if (me != NULL &&
	    range_in_tracked_shared((unsigned long)me,
				    sizeof(struct childdata))) {
		struct child_fault_beacon *beacon = &me->fault_beacon;
		struct child_fault_beacon local;
		enum syscallstate st = me->syscall.state;
		int32_t snr;

		if (st == PREP || st == BEFORE || st == GOING_AWAY)
			snr = (int32_t)me->syscall.nr;
		else
			snr = -1;
		/*
		 * Build the stamp on the stack first, then publish
		 * the whole record via a single struct assignment.
		 *
		 * fault_sa in mask_signals_child() installs this
		 * handler with sa_mask = empty and no SA_NODEFER on
		 * SIGABRT/SIGBUS/SIGILL, so a different fatal signal
		 * delivered mid-stamp can run an inner copy of this
		 * handler to completion.  If we stamped field-by-
		 * field directly into the shared slot, the inner
		 * handler would publish a full record (its own
		 * release-store of .written = 1) and the outer
		 * handler's resumed plain stores would then overwrite
		 * the shared fields piecemeal, leaving a torn
		 * forensic line (signo from one fault, ip/sp from
		 * another) for the parent's acquire-load to read.
		 *
		 * With local-then-publish: an inner handler that
		 * runs to completion publishes its own self-
		 * consistent record; when the outer handler resumes,
		 * the single struct assignment from this stack
		 * snapshot rewrites the shared slot with a self-
		 * consistent outer record before the trailing
		 * release-store of .written = 1 seals it.  Either
		 * way the parent never observes a mixed record.
		 *
		 * .written is left zero in the local so the struct
		 * assignment transiently clears the published bit;
		 * the release-store below is the real publish edge.
		 */
		local.written = 0;
		local.signo = (int32_t)sig;
		local.sig_code = (int32_t)info->si_code;
		local.fault_addr = info->si_addr;
		local.fault_ip = fault_beacon_extract_ip(ctx);
		local.fault_sp = fault_beacon_extract_sp(ctx);
		local.op_nr = me->op_nr;
		local.last_syscall_nr = snr;
		*beacon = local;
		/* Release-store seals every preceding plain store
		 * into view of any parent that acquire-loads
		 * .written and sees 1. */
		__atomic_store_n(&beacon->written, 1U,
				 __ATOMIC_RELEASE);
	}
}

/*
 * Open the per-pid bug log, drain any buffered pre-crash stderr text
 * into it, then dup2 it onto STDERR_FILENO so the in-handler
 * backtrace + siginfo writes below land in the same on-disk file.
 *
 * Carries no_sanitize for parity with child_fault_handler -- not
 * strictly required (no childdata deref here), but matches the
 * attribute every other extracted helper carries so ASAN behaviour
 * is uniform across the post-extraction handler.
 */
static __attribute__((no_sanitize("address")))
void open_buglog_and_drain_stderr(int sig)
{
	int bug_fd;

	bug_fd = open(buglog_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (bug_fd >= 0) {
		/*
		 * Capture __abort_msg directly into the per-pid bug
		 * log BEFORE the shared-memfd drain.  The memfd is
		 * fork-shared (one struct file, one offset) so the
		 * writev() that glibc's __libc_message emitted to
		 * STDERR_FILENO almost certainly raced with a sibling
		 * child's drain.  __abort_msg lives in this child's
		 * private address space and has no such race -- read
		 * it now while we are guaranteed exclusive access to
		 * our own per-pid bug_fd.  See
		 * capture_abort_msg_to_buglog() above for the full
		 * rationale and the raw-syscall justification.
		 */
		if (sig == SIGABRT)
			capture_abort_msg_to_buglog(bug_fd);

		if (stderr_memfd >= 0) {
			char drain_buf[4096];
			ssize_t n, w;
			size_t drained = 0;
			static const size_t STDERR_DRAIN_MAX = 1u << 20;	/* 1 MiB */

			/*
			 * Cap the drain.  A fuzzed child can extend the
			 * stderr memfd to a huge sparse size; an
			 * uncapped read/write loop materialises the NUL
			 * holes as real bytes on tmpfs and can produce
			 * multi-GB bug logs (log-DoS).  Bound the copy
			 * at 1 MiB -- well past any plausible real
			 * diagnostic payload.
			 */
			(void)lseek(stderr_memfd, 0, SEEK_SET);
			while (drained < STDERR_DRAIN_MAX &&
			       (n = read(stderr_memfd, drain_buf,
					 sizeof(drain_buf))) > 0) {
				size_t want = (size_t)n;
				if (want > STDERR_DRAIN_MAX - drained)
					want = STDERR_DRAIN_MAX - drained;
				w = write(bug_fd, drain_buf, want);
				(void)w;	/* dying anyway; short write irrelevant */
				drained += want;
			}
		}
		dup2(bug_fd, STDERR_FILENO);
		close(bug_fd);
	}
}

#ifdef CONFIG_GUARD_SHARED
/*
 * Decode a CONFIG_GUARD_SHARED guard-page trip and emit a one-line
 * attribution naming the overflowed region, direction (leading vs
 * trailing), distance past the edge, and writer PC.  Gated on
 * SIGSEGV at function entry so a SIGBUS/SIGABRT/SIGILL still reaches
 * the in-handler diagnostic path below but is not decoded as a
 * guard trip (it isn't, by construction).
 */
static __attribute__((no_sanitize("address")))
void emit_guard_page_attribution(int sig, siginfo_t *info, void *ctx)
{
	if (sig == SIGSEGV) {
		uintptr_t region_addr;
		size_t region_size;
		bool trailing;
		unsigned long delta;

		if (guard_pages_classify((uintptr_t)info->si_addr,
					 &region_addr, &region_size,
					 &trailing, &delta)) {
			char buf[256];
			struct sigsafe_buf b = { buf, sizeof(buf) };
			size_t used;
			ssize_t w;

			sigsafe_puts(&b, "GUARD TRAP: region=");
			sigsafe_putp(&b, (void *)region_addr);
			sigsafe_puts(&b, " size=");
			sigsafe_putu(&b, (unsigned long)region_size);
			sigsafe_puts(&b, trailing ? " trailing" : " leading");
			sigsafe_puts(&b, " overflow delta=");
			sigsafe_putu(&b, delta);
			sigsafe_puts(&b, " writer=");
			sigsafe_putp(&b, fault_beacon_extract_ip(ctx));
			sigsafe_puts(&b, " si_addr=");
			sigsafe_putp(&b, info->si_addr);
			sigsafe_putc(&b, '\n');

			used = sizeof(buf) - b.left;
			w = write(STDERR_FILENO, buf, used);
			(void)w;	/* dying anyway; short write irrelevant */
		}
	}
}
#endif

/*
 * Format and emit the currently-running childop's identity
 * ("childop=<name> op_nr=<n> last_syscall_nr=<n>\n") to the
 * inherited stderr (the per-pid bug log after the dup2 above).
 *
 * Mirrors write_siginfo_safely's hand-rolled formatter: byte stores
 * into a stack buffer via the sigsafe_* helpers, single write(),
 * no stdio, no allocator, no lock.  Gates on me->syscall.state so a
 * signal that hit between syscalls emits -1 rather than the stale
 * previous-call number.
 */
static __attribute__((no_sanitize("address")))
void stamp_childop_identity(void)
{
	struct childdata *me = this_child();
	const char *opname;
	unsigned long opnr;
	int last_syscall_nr;
	char buf[160];

	if (me != NULL) {
		enum syscallstate st = me->syscall.state;

		opname = alt_op_name(me->op_type);
		opnr = me->op_nr;
		if (opname == NULL)
			opname = "unknown";
		if (st == PREP || st == BEFORE || st == GOING_AWAY)
			last_syscall_nr = (int)me->syscall.nr;
		else
			last_syscall_nr = -1;
	} else {
		opname = "unknown";
		opnr = 0;
		last_syscall_nr = -1;
	}
	{
		struct sigsafe_buf b = { buf, sizeof(buf) };
		size_t used;
		ssize_t w;

		sigsafe_puts(&b, "childop=");
		sigsafe_puts(&b, opname);
		sigsafe_puts(&b, " op_nr=");
		sigsafe_putu(&b, opnr);
		sigsafe_puts(&b, " last_syscall_nr=");
		sigsafe_puti(&b, (long)last_syscall_nr);
		sigsafe_putc(&b, '\n');

		used = sizeof(buf) - b.left;
		w = write(STDERR_FILENO, buf, used);
		(void)w;	/* dying anyway; nothing to do on short write */
	}
}

/*
 * SIGTRAP handler for the Stage-2 writer-pinning canary (perf HW
 * breakpoint armed by writer-watch.c with perf_event_attr.sigtrap=1).
 * The kernel delivers SIGTRAP SYNCHRONOUSLY in the writing thread with
 * si_code=TRAP_PERF; info->si_addr is the faulting instruction and the
 * ucontext RIP is the writer's instruction pointer (just past the
 * write on x86 hardware-data-breakpoints).  This handler dumps the
 * writer's identity and _exit()s so the trap does not re-fire when
 * the kernel resumes the interrupted thread.
 *
 * Synchronous delivery requires perf_event_attr.sigtrap=1 (kernel >=
 * 5.13).  The earlier F_SETSIG/SIGIO route is asynchronous and would
 * make info->si_addr meaningless -- explicitly NOT used.
 *
 * STRICTLY ASYNC-SIGNAL-SAFE: only write(2), the sigsafe_* helpers
 * (byte stores into caller-owned stack buffer), and pure inline reads
 * from caller-owned ucontext.  No libc malloc / stdio / locale / lock,
 * no symbolization (dladdr is unsafe -- the WRITER-PINNED line emits
 * the RAW PC; resolve it offline against the [load-bases] line
 * log_load_bases() prints at startup, same convention as the FAULT!
 * line).  The this_child() deref is gated by range_in_tracked_shared
 * exactly like stamp_fault_beacon does, so a wild/torn-down me does
 * not double-fault in this very handler.
 *
 * Caveat (documented spec limit): for a kernel-side value-result write
 * (copy_to_user via a fuzzed pointer) the breakpoint may or may not
 * trap from user-mode debug registers on every arch -- exclude_kernel=0
 * is the best the perf interface offers, but the synchronous trap is
 * not guaranteed for in-kernel writers on all configurations.  Trinity-
 * userspace writers ARE caught synchronously with the exact RIP.
 *
 * carries no_sanitize("address") for the same reason child_fault_handler
 * does: the gated me->syscall.state load intentionally bypasses ASAN's
 * shadow check.
 */
static __attribute__((no_sanitize("address")))
void writer_trap_handler(int sig, siginfo_t *info, void *ctx)
{
	char buf[256];
	struct sigsafe_buf b = { buf, sizeof(buf) };
	struct childdata *me;
	const char *opname = "unknown";
	unsigned long opnr = 0;
	int last_syscall_nr = -1;
	size_t used;
	ssize_t w;

	me = this_child();
	if (me != NULL &&
	    range_in_tracked_shared((unsigned long)me,
				    sizeof(struct childdata))) {
		enum syscallstate st = me->syscall.state;

		opname = alt_op_name(me->op_type);
		if (opname == NULL)
			opname = "unknown";
		opnr = me->op_nr;
		if (st == PREP || st == BEFORE || st == GOING_AWAY)
			last_syscall_nr = (int)me->syscall.nr;
	}

	sigsafe_puts(&b, "WRITER-PINNED: hardware write breakpoint fired");
	sigsafe_puts(&b, " addr=");
	sigsafe_putp(&b, info != NULL ? info->si_addr : NULL);
	sigsafe_puts(&b, " writer_pc=");
	sigsafe_putp(&b, fault_beacon_extract_ip(ctx));
	sigsafe_puts(&b, " (RAW, resolve offline against [load-bases])");
	sigsafe_puts(&b, " syscall_nr=");
	sigsafe_puti(&b, (long)last_syscall_nr);
	sigsafe_puts(&b, " childop=");
	sigsafe_puts(&b, opname);
	sigsafe_puts(&b, " op_nr=");
	sigsafe_putu(&b, opnr);
	sigsafe_puts(&b, " pid=");
	sigsafe_puti(&b, (long)getpid());
	sigsafe_putc(&b, '\n');

	used = sizeof(buf) - b.left;
	w = write(STDERR_FILENO, buf, used);
	(void)w;	/* dying anyway; short write irrelevant */
	(void)sig;

	/*
	 * _exit(), not return / raise.  The watched address has just been
	 * scribbled and the instruction has NOT advanced; returning would
	 * re-execute the write and re-fire SIGTRAP in a tight loop.  The
	 * parent's reaper sees a normal exit and respawns the slot.
	 */
	_exit(EXIT_SUCCESS);
}

/*
 * Final escalation step.  In debug mode restore the default
 * disposition and re-raise so the kernel emits a core file (the
 * RLIMIT_CORE bump in child.c::disable_coredumps was -D-only).
 * In non-debug, _exit(EXIT_SUCCESS) so the parent's reaper sees a
 * normal exit and respawns without crash-loop noise.
 */
static __attribute__((no_sanitize("address")))
void escalate_fault(int sig)
{
	if (shm->debug == true) {
		(void)signal(sig, SIG_DFL);
		raise(sig);
	} else {
		_exit(EXIT_SUCCESS);
	}
}

/*
 * Child-side fault handler.  Mirrors main_fault_handler in spirit but
 * preserves the existing non-debug clean-exit behaviour:
 *
 *   - Real fault (kernel-generated, si_code > 0) or self-sent (abort,
 *     stack-smash from libc):
 *       * stamp child->fault_beacon BEFORE any libc-touching call so
 *         the parent can surface the death class even when the
 *         backtrace_symbols_fd / open / dup2 chain below re-faults
 *         walking a corrupted ld.so writable segment (see
 *         include/bug_backtrace.h::child_fault_beacon)
 *       * dump backtrace + signal info to stderr so we have ANY signal
 *         in the log even when the core is unwindable (fault from
 *         stack-corruption disturbs the unwind chain — gdb on the
 *         core often gets nothing)
 *       * in debug mode: signal(SIG_DFL) + raise(sig) so the kernel
 *         dumps a core (RLIMIT_CORE was bumped to unlimited in
 *         child.c::disable_coredumps for -D)
 *       * in non-debug: _exit(EXIT_SUCCESS) — matches the legacy
 *         sighandler so the parent's reaper sees a normal exit and
 *         respawns without crash-loop noise
 *
 *   - Sibling-spoofed (process-sent, kill/tkill/tgkill/rt_sigqueueinfo
 *     fuzzing aimed at us): ignore — fuzzer noise.
 */
static __attribute__((no_sanitize("address")))
void child_fault_handler(int sig, siginfo_t *info, void *ctx)
{
	/*
	 * asb_relocate() copy-fault recovery.  Runs FIRST, before the
	 * sibling-spoof gate and before the fault beacon stamp, because
	 * the longjmp aborts the handler outright and must not leave any
	 * publish-side side effects (a beacon record, a bug-log open) on
	 * a fault we're about to retry-as-skip in the sanitiser.
	 *
	 * Gated on:
	 *   - SIGSEGV or SIGBUS only (the memcpy faults the kernel raises
	 *     for an unmapped/torn-down source; SIGILL/SIGABRT are not
	 *     produced by the speculative read and are left to the
	 *     normal crash path);
	 *   - si_code > 0, i.e. a real kernel-generated fault.  A sibling
	 *     kill/tkill that happens to deliver SIGSEGV while the flag
	 *     is set has si_code <= 0 and would resume the memcpy on
	 *     return anyway -- siglongjmp'ing on it would falsely mark
	 *     the copy as faulted and lose accuracy in the new counter;
	 *   - asb_copy_active, which asb_relocate() sets ONLY across the
	 *     memcpy itself and clears immediately after.  Any other
	 *     SIGSEGV/SIGBUS the child takes (real fuzz-found kernel bug,
	 *     crash in unrelated code) sees the flag clear and falls
	 *     through to the existing diagnostic + _exit path.
	 *
	 * sigsetjmp was installed with savemask=1 so siglongjmp restores
	 * the application's signal mask; the kernel's per-handler add-
	 * the-current-signal mask is unwound as part of that restore so
	 * a subsequent SIGSEGV in the same child still reaches this
	 * handler (no permanently-blocked SEGV after recovery).
	 */
	if (asb_copy_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(asb_copy_recover, 1);
	}

	/*
	 * cmp_hints_collect() field-scoped ARG_TIMESPEC deref recovery.
	 * Mirrors the asb_copy edge above: range_readable_user() proves
	 * the saved pointer from cached VMA state, but a sibling raw
	 * munmap/mremap can stale the cache between the gate and the
	 * tv_sec/tv_nsec loads, so the loads still fault on an
	 * unmapped/torn-down region.  Gating is identical -- SIGSEGV or
	 * SIGBUS, si_code > 0, and cmp_field_read_active set ONLY across
	 * the two field reads -- so any unrelated SIGSEGV/SIGBUS the
	 * child takes still falls through to the existing diagnostic +
	 * _exit path.
	 */
	if (cmp_field_read_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(cmp_field_recover, 1);
	}

#ifdef CONFIG_GUARD_SHARED
	/*
	 * kcov_enable_trace() trace_buf[0]=0 reset-fault recovery.  Same
	 * shape as the asb_copy / cmp_field edges above: the store is guarded
	 * by track_shared_region_tagged("kcov-pc") at registration and
	 * by the mm-sanitiser overlap gates at fuzz time, yet some path
	 * is intermittently stripping the buffer's PROT_WRITE.  Gated on
	 * SIGSEGV or SIGBUS with si_code > 0 and kcov_protect_active set
	 * ONLY across the single trace_buf[0] store.  On longjmp the
	 * caller logs the full diagnostic (live VMA prot, registration
	 * status, recent audit ring) and _exit()s with a distinct code
	 * so the fault is visible in reap statistics without crash-
	 * looping the worker.
	 */
	if (kcov_protect_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(kcov_protect_recover, 1);
	}
#endif

	if (info->si_code <= 0 && info->si_pid != mypid()) {
		/* Sibling spoof — ignore. */
		return;
	}
	/*
	 * Self-fuzzed delivery: a child running random_syscall picked
	 * kill / tkill / tgkill / rt_sigqueueinfo / pidfd_send_signal
	 * with target == own pid and signo ∈ {SIGSEGV, SIGBUS, SIGILL,
	 * SIGABRT}.  The kernel obediently delivers it and we land here
	 * with si_code == SI_USER (0) / SI_TKILL (-6) / SI_QUEUE (-1)
	 * and si_pid == getpid().  Drop silently — same _exit path the
	 * non-debug real-fault arm uses below — so the parent's reaper
	 * sees a normal exit and respawns without /tmp/trinity-bug-<pid>.log
	 * polluting the run with fuzzer-generated noise.  Without this
	 * gate, ~25-50% of bug logs in a typical run are own-pid
	 * SIGBUS/SIGILL/SIGSEGV from this exact path.
	 *
	 * Skipped if we're not currently inside do_syscall() — a
	 * self-sent fatal from outside the syscall hot path (e.g. glibc
	 * abort() from a heap-corruption assertion, or an explicit
	 * raise() from trinity itself) is a real bug that must still be
	 * logged.
	 */
	if (info->si_code <= 0 && info->si_pid == mypid() && in_do_syscall) {
		_exit(EXIT_SUCCESS);
	}
	/*
	 * do_extrafork() throwaway grand-child gate.  Hoisted to cover
	 * the beacon stamp AND the per-pid buglog open / shared stderr-
	 * memfd drain below: this_child() returns the parent worker's
	 * childdata (cached_pid is COW-inherited and never updated
	 * across the throwaway fork), so a beacon stamp would publish a
	 * fault attributed to the wrong worker, and the buglog open +
	 * memfd lseek+drain would corrupt the worker's on-disk forensic
	 * record for an unrelated fault and race with the worker's own
	 * memfd offset.  Skip straight to the in-handler stderr writes
	 * below; the grand-child has no childdata of its own to stamp
	 * into and the kernel-side crash artefacts still surface the
	 * death.
	 */
	if (in_extrafork_grandchild) {
		/*
		 * Redirect this grandchild's STDERR_FILENO to /dev/null
		 * before the shared post-skip_buglog diagnostics
		 * (backtrace_symbols_fd + write_siginfo_safely) run.
		 * Without this, a fault in a throwaway extra-fork
		 * grandchild skips the per-pid buglog block above but
		 * still appends backtrace + siginfo text to the
		 * fork-inherited stderr memfd, polluting the worker's
		 * diagnostic record for an unrelated fault.  open / dup2
		 * / close are on the POSIX 2024 §2.4.3 async-signal-safe
		 * list; the kernel-side oops still prints regardless.
		 */
		int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
		if (devnull >= 0) {
			dup2(devnull, STDERR_FILENO);
			if (devnull != STDERR_FILENO)
				close(devnull);
		}
		goto skip_buglog;
	}
	/*
	 * Stamp the fault beacon FIRST -- before umask, open, dup2,
	 * backtrace_symbols_fd, write_siginfo_safely, or anything else
	 * libc-touchy.  When the underlying root cause is a corrupted
	 * ld.so writable segment (NULL'd link_map slot, stomped GOT), the
	 * very next backtrace_symbols_fd call re-faults inside dladdr's
	 * link_map walk and the process dies before any forensic line
	 * lands on disk.  The beacon captures the death class into shared
	 * memory using only kernel-supplied siginfo + ucontext fields and
	 * a local-then-publish struct copy -- no allocator, no stdio, no
	 * lock -- so the parent's dump_child_fault_beacon() can surface
	 * the silenced class even in the re-fault case.  See
	 * include/bug_backtrace.h::child_fault_beacon for the field
	 * contract and the release-store / acquire-load handoff that
	 * orders the stamp into the parent's view.
	 */
	stamp_fault_beacon(sig, info, ctx);
	/*
	 * Reset the umask before creating any files.  The umask syscall is
	 * itself fuzzed, so a child that drew umask(0777) and then crashed
	 * would otherwise have its /tmp/trinity-bug-<pid>.log redirect file
	 * created with mode 0644 & ~0777 == 0, and the kernel/userspace
	 * coredump helper would create the core file with the same 0000
	 * mode and abort with "cannot preserve file permissions".  umask()
	 * is async-signal-safe (POSIX 2024 §2.4.3) so this is safe to call
	 * from a signal handler.  Returning the old mask is intentionally
	 * ignored — this child is about to die.
	 */
	(void)umask(0);
	/*
	 * Open the per-pid bug log and (if init_stderr_memfd() succeeded
	 * for this child) drain the buffered pre-crash stderr text into
	 * it BEFORE redirecting STDERR_FILENO at the file -- otherwise
	 * the in-handler write_siginfo_safely() / backtrace_symbols_fd()
	 * output below would land before the glibc malloc_printerr text
	 * that explains why we're here.
	 *
	 * The drain captures every stderr write the child made before
	 * faulting: glibc's __libc_message / __fortify_fail /
	 * __stack_chk_fail formatted complaints (the whole point of
	 * pre-redirecting stderr), plus every trinity outputerr() line
	 * accumulated this run.  The outputerr noise is harmless here
	 * because the on-disk bug log only materialises on a real
	 * crash -- clean exits discard the memfd with the process.
	 *
	 * buglog_path[] was pre-formatted in init_stderr_memfd() so
	 * the snprintf() doesn't happen in this handler (snprintf is
	 * not async-signal-safe per POSIX 2024 §2.4.3).  open / lseek /
	 * read / write / dup2 / close ARE all on the POSIX safe list.
	 *
	 * If init_stderr_memfd() failed (CONFIG_MEMFD_CREATE=n) or this
	 * is a child that started before that init step, stderr_memfd
	 * is -1 and we skip the drain -- the bug log still gets the
	 * in-handler backtrace + siginfo, just without the pre-crash
	 * glibc text.  If the open() itself fails (fuzzed unlink of
	 * the tmp dir, ENOSPC, ...) there is nothing to be done; the
	 * child dies silently as it would have anyway.
	 */
	open_buglog_and_drain_stderr(sig);
skip_buglog:
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
	{
		void *frames[64];
		int nframes = backtrace(frames, 64);

		backtrace_symbols_fd(frames, nframes, STDERR_FILENO);
	}
#endif
#ifdef CONFIG_GUARD_SHARED
	/*
	 * Guard-page attribution.  When --guard-shared wrapped a tracked
	 * region in PROT_NONE pages and a fuzzer write overflows past
	 * the buffer, the kernel raises SIGSEGV at the writing
	 * instruction with si_addr inside the guard page.  Walk the
	 * tracked-region table to find the abutting region and emit a
	 * single line naming WHICH region was overflowed, WHICH
	 * direction (leading=underflow vs trailing=forward overflow),
	 * how far past the edge, and the writer PC -- the one-line root
	 * cause the hunt instrument exists to produce.
	 *
	 * Skipped for non-SIGSEGV faults (a SIGBUS or SIGABRT can still
	 * reach the in-handler diagnostic path but is not a guard trip
	 * by construction).  Async-signal-safe: guard_pages_classify is
	 * a plain read of shared_regions[], the format path uses only
	 * the sigsafe_* byte builders that write_siginfo_safely below
	 * already relies on, and the output is a single write() to the
	 * inherited stderr (which dup2 redirected to the per-pid bug
	 * log a few statements above).  No allocator, no stdio, no
	 * libc lookup, no lock.
	 *
	 * The writer PC is emitted raw rather than resolved through
	 * dladdr() because dladdr is not on the POSIX 2024 sec 2.4.3
	 * safe list and the existing handler bans it for the same
	 * reason; the bugs.txt post-parser resolves PIE-relative
	 * offsets offline against the binary's load base, same idiom as
	 * fault_beacon's stored fault_ip.
	 */
	emit_guard_page_attribution(sig, info, ctx);
#endif
	write_siginfo_safely(sig, info, "trinity child");

	/*
	 * Stamp the currently-running childop's identity into the per-pid
	 * bug log so the canary queue (and post-mortem grep-mining) can
	 * attribute a SIGSEGV/SIGBUS/SIGILL/SIGABRT to a specific op
	 * rather than bottoming out at child_process+offset like the bare
	 * libgcc backtrace does.  this_child() reads a plain pointer set
	 * once per child in init_child() (see pids.c::set_child_cache);
	 * alt_op_name() is a pure switch over an enum with no allocation
	 * or locking.  Both are safe to call from this handler.
	 *
	 * Hand-roll the formatter rather than dprintf() so the write is a
	 * single syscall and uses no stdio buffering -- mirrors the
	 * write_siginfo_safely() pattern just above.  PATH_MAX is
	 * comfortably oversized for "childop=<longest-name> op_nr=<ulong>
	 * last_syscall_nr=<int>\n".
	 *
	 * last_syscall_nr is the in-flight syscall number sourced from
	 * me->syscall.nr -- the per-child syscallrecord embedded in
	 * childdata, populated by set_syscall_nr() before each dispatch.
	 * Reading a plain unsigned int from process-local shm-resident
	 * memory is async-signal-safe (no allocation, no lock, no table
	 * lookup).  We emit the NUMBER rather than the name because the
	 * number->name map (get_syscall_entry / syscalls[].name) is a
	 * pointer-chasing table walk that is not on the POSIX async-
	 * signal-safe list; the bugs.txt post-parser can resolve names
	 * offline.
	 *
	 * We gate on me->syscall.state to avoid emitting a stale number
	 * when the signal hit between syscalls.  rec->nr is only meaning-
	 * fully populated once set_syscall_nr() has run for the current
	 * iteration; states UNKNOWN (child just started, never picked) and
	 * AFTER (previous call returned, next not yet picked) both mean
	 * "no syscall in flight".  In those cases we emit -1 rather than a
	 * misleading number that points at the *previous* call.
	 */
	stamp_childop_identity();

	escalate_fault(sig);
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
 * Handler for signals that should only be fatal if they come from the
 * kernel (real fault), not from a child process sending us garbage via
 * kill/tkill/tgkill.
 *
 * si_code > 0:  kernel generated (e.g. SEGV_MAPERR) — always fatal
 * si_code <= 0: sent by a process (SI_USER, SI_TKILL, SI_QUEUE)
 *   - from ourselves (abort(), raise()): fatal — it's a real crash
 *   - from a child process: ignore — it's fuzzer noise
 */
static __attribute__((no_sanitize("address")))
void main_fault_handler(int sig, siginfo_t *info, __unused__ void *ctx)
{
	if (info->si_code > 0 || info->si_pid == mypid()) {
		/* Real fault or self-sent (e.g. glibc abort) — dump a
		 * backtrace and siginfo to stderr first so we have a handle
		 * on the crash even when no coredump lands (ulimit -c 0 or a
		 * restrictive core_pattern), then die properly. */
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
		void *frames[64];
		int nframes = backtrace(frames, 64);
		backtrace_symbols_fd(frames, nframes, STDERR_FILENO);
#endif
		write_siginfo_safely(sig, info, "trinity main");
		signal(sig, SIG_DFL);
		raise(sig);
	}
	/* Sent by a child process — ignore */
}

void mask_signals_child(void)
{
	struct sigaction sa;
	sigset_t ss, oldss;
	int i;

	/* Block all signals while we install handlers.  Without this,
	 * a signal arriving between the catch-all sighandler install
	 * and the proper handler install would silently _exit(SUCCESS),
	 * masking the real cause of the child's death. */
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
	 * fuzzing child. */
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
	 * Install child_fault_handler for the kernel-fault signals.
	 * Replaces both the catch-all sighandler (which silently
	 * _exit'd, masking the cause) and the debug-mode SIG_DFL
	 * override (which dumped a core but no inline backtrace).
	 * The handler dumps a backtrace + psiginfo to stderr in BOTH
	 * modes; in debug it then re-raises with SIG_DFL so the kernel
	 * still drops a core, in non-debug it _exit's cleanly so the
	 * parent's reaper doesn't see a crash and crash-loop.
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
	 * actually opens the perf fd and routes SIGTRAP here via
	 * F_SETSIG.  When --writer-watch is not in use the perf fd is
	 * never opened, no SIGTRAP can fire, and the handler is dead
	 * code.  SA_SIGINFO so the handler can read the ucontext for the
	 * writer's RIP and the siginfo for the watched address.
	 */
	{
		struct sigaction trap_sa;
		sigemptyset(&trap_sa.sa_mask);
		trap_sa.sa_flags = SA_SIGINFO;
		trap_sa.sa_sigaction = writer_trap_handler;
		(void)sigaction(SIGTRAP, &trap_sa, NULL);
	}

	/* trap ctrl-c — use SA_SIGINFO so we can ignore child-sent SIGINTs,
	 * same as the parent handler. Without this, children fuzzing
	 * rt_tgsigqueueinfo/kill with SIGINT cause phantom ctrl-c exits. */
	{
		struct sigaction int_sa;
		sigemptyset(&int_sa.sa_mask);
		int_sa.sa_flags = SA_SIGINFO;
		int_sa.sa_sigaction = sigint_handler;
		(void)sigaction(SIGINT, &int_sa, NULL);
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
	 */
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGUSR1, SIG_IGN);
	(void)signal(SIGUSR2, SIG_IGN);
	(void)signal(SIGALRM, SIG_IGN);
	(void)signal(SIGTERM, SIG_IGN);
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
	 * Use SA_SIGINFO for fault/core-dump signals so we can distinguish
	 * real faults (si_code > 0, from kernel) from signals sent by child
	 * processes fuzzing kill/tkill/tgkill (si_code <= 0).
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

	/* SIGINT: use SA_SIGINFO so we can ignore child-sent SIGINTs.
	 * Real ctrl-c from the terminal has si_code > 0 (SI_KERNEL). */
	sa.sa_sigaction = sigint_handler;
	(void)sigaction(SIGINT, &sa, NULL);

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
