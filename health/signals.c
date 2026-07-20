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

#include "kernel/fcntl.h"
#include "kernel/memfd.h"
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

/*
 * Recovery point for vma_split_storm's touch_random_page() one-byte
 * store.  See include/signals.h and childops/mm/vma-split-storm.c::
 * touch_random_page() for the full contract.  Definition lives here
 * so the storage for the jmp_buf is colocated with the handler that
 * reads vma_split_storm_touch_active.
 *
 * Inherited COW-private into every forked child; never touched by the
 * parent.  Plain file-scope storage rather than __thread because
 * trinity children are single-threaded processes -- no two threads in
 * the same address space race on the slot.
 */
sigjmp_buf vma_split_storm_touch_recover;
volatile sig_atomic_t vma_split_storm_touch_active;

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
 * Capture glibc's __abort_msg directly into the per-pid bug log via
 * raw syscall.  The shared stderr memfd is fork-shared and races
 * between siblings; __abort_msg is per-process (glibc mmap()s it in
 * the abort()ing child's own address space) and race-free.
 * See Documentation/signals.md.
 *
 * Async-signal-safe: raw SYS_write and strnlen only, no allocation,
 * no locale, no lock.  m->size is treated as advisory and capped at
 * ABORT_MSG_MAX because it lives in the same glibc allocation we're
 * salvaging post-corruption and may itself be scribbled.
 *
 * The m->msg[0] == '\0' early-out catches the rare path where glibc
 * allocated the buffer but bailed before formatting; don't emit a
 * bare "abort_msg: \n".
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
 * so pre-fault glibc text (malloc_printerr / __libc_message /
 * __fortify_fail / __stack_chk_fail) survives long enough for the
 * fault handler to flush it into the on-disk bug log on a real
 * crash.  Clean exits discard the memfd with the process.  Paired
 * with the drain block at the top of child_fault_handler.
 * See Documentation/signals.md.
 *
 * snprintf() is NOT async-signal-safe, so buglog_path[] is
 * pre-formatted here under the inherited non-fuzzed locale.
 * trinity_tmpdir_abs() guards against a fuzzed chdir(); getpid()
 * is used instead of mypid() because cached_pid isn't populated
 * until set_child_cache runs later in init_child_rendezvous_parent.
 *
 * The fd is intentionally NOT closed after dup2 onto STDERR_FILENO
 * -- the handler reads it back from the same fd.
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
 * main_fault_handler.  Hand-rolled because psiginfo() calls
 * fmemopen -> calloc and deadlocks if the signal was raised by
 * glibc's own abort() with the arena lock held (same family as
 * the libgcc_s/backtrace deadlock fixed in 81143aaeaba6).
 * See Documentation/signals.md.
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
static void write_backtrace_raw_pcs(const char *who)
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
	 * shared region.  this_child() can return a non-NULL but
	 * unmapped pointer (torn-down or corrupt shm childdata
	 * mapping); the NULL check alone lets the first plain load
	 * re-fault inside this very handler and the kernel escalates
	 * to SIGKILL, erasing the original crash class.
	 * See Documentation/signals.md.
	 *
	 * range_in_tracked_shared() is a linear walk of
	 * shared_regions[] with no allocator / stdio / lock /
	 * this_child() / stats_ring enqueue / global mutation --
	 * async-signal-safe.  range_overlaps_shared() is
	 * deliberately NOT used here: its confirmed-overlap path
	 * calls this_child(), enqueues stats, and writes
	 * last_reject_* globals -- exactly the re-entrant class
	 * this gate exists to keep out.  On a miss the stamp is
	 * skipped (dropped-beacon, surfaced by the parent's
	 * existing written==0 path).
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
		 * Build the stamp on the stack, then publish via a
		 * single struct assignment.  fault_sa installs this
		 * handler with sa_mask=empty and no SA_NODEFER on
		 * SIGABRT/SIGBUS/SIGILL, so an inner handler can run
		 * to completion mid-stamp; field-by-field stores into
		 * the shared slot would yield a torn record (signo
		 * from one fault, ip/sp from another) for the
		 * parent's acquire-load.  See Documentation/signals.md.
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
 * The kernel delivers SIGTRAP synchronously in the writing thread with
 * si_code=TRAP_PERF; ucontext RIP is the writer's PC.  Dumps writer
 * identity and _exit()s so the trap does not re-fire when the kernel
 * resumes the interrupted thread.  See Documentation/signals.md.
 *
 * STRICTLY ASYNC-SIGNAL-SAFE: only write(2), sigsafe_* helpers, and
 * pure inline ucontext reads.  No libc malloc / stdio / locale / lock,
 * no symbolization (dladdr is unsafe; emit RAW PC and resolve offline
 * against the [load-bases] line log_load_bases() prints at startup).
 * The this_child() deref is gated by range_in_tracked_shared exactly
 * like stamp_fault_beacon.
 *
 * Carries no_sanitize("address") like child_fault_handler: the gated
 * me->syscall.state load intentionally bypasses ASAN's shadow check.
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
 *         open / dup2 / backtrace() chain below re-faults walking a
 *         corrupted ld.so writable segment (see
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
	 * asb_relocate() copy-fault recovery.  Runs first so the
	 * siglongjmp aborts the handler outright with no publish-side
	 * side effects (beacon stamp, buglog open) on a fault we're
	 * retry-as-skipping in the sanitiser.
	 * See Documentation/signals.md.
	 *
	 * Gated on SIGSEGV/SIGBUS only (the faults the kernel raises
	 * for an unmapped source), si_code > 0 (real kernel fault --
	 * a sibling kill would resume the memcpy on return anyway),
	 * and asb_copy_active (set only across the memcpy itself).
	 * sigsetjmp was installed with savemask=1 so a subsequent
	 * SEGV in this child still reaches this handler.
	 */
	if (asb_copy_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(asb_copy_recover, 1);
	}

	/*
	 * cmp_hints_collect() field-scoped ARG_TIMESPEC deref
	 * recovery.  Cached VMA state can stale between the
	 * range_readable_user() gate and the tv_sec/tv_nsec loads
	 * if a sibling raw munmap/mremap intervenes.  Same three-way
	 * gate as asb_copy above.  See Documentation/signals.md.
	 */
	if (cmp_field_read_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(cmp_field_recover, 1);
	}

	/*
	 * vma_split_storm touch_random_page() one-byte-store
	 * recovery.  The pte-priming write can hit a sub-VMA whose
	 * most recent mprotect was PROT_READ, faulting with
	 * SIGSEGV/SEGV_ACCERR (op-bookkeeping fault, not a kernel
	 * bug).  Same three-way gate as asb_copy above.  Outside
	 * CONFIG_GUARD_SHARED so it applies to all builds.
	 * See Documentation/signals.md.
	 */
	if (vma_split_storm_touch_active && info->si_code > 0 &&
	    (sig == SIGSEGV || sig == SIGBUS)) {
		siglongjmp(vma_split_storm_touch_recover, 1);
	}

#ifdef CONFIG_GUARD_SHARED
	/*
	 * kcov_enable_trace() trace_buf[0]=0 reset-fault recovery.
	 * The store is guarded at registration and by mm-sanitiser
	 * overlap gates, yet some path intermittently strips
	 * PROT_WRITE.  Same three-way gate as asb_copy above.  On
	 * longjmp the caller logs the full diagnostic and _exit()s
	 * with a distinct code so the fault is visible in reap
	 * statistics without crash-looping the worker.
	 * See Documentation/signals.md.
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
		 * (write_backtrace_raw_pcs + write_siginfo_safely) run.
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
	 * backtrace(), write_siginfo_safely, or anything else libc-
	 * touchy.  When the underlying root cause is a corrupted ld.so
	 * writable segment (NULL'd link_map slot, stomped GOT), a
	 * subsequent unwinder call can re-fault walking that state and
	 * the process dies before any forensic line lands on disk.  (The
	 * historical worst offender here was backtrace_symbols_fd's
	 * dladdr link_map walk -- now removed; backtrace_symbols_fd is
	 * only reachable under the off-by-default USE_BACKTRACE_UNSAFE
	 * knob.)  The beacon captures the death class into shared
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
	 * Open the per-pid bug log and drain the buffered pre-crash
	 * stderr text into it BEFORE redirecting STDERR_FILENO --
	 * otherwise the in-handler write_siginfo_safely() /
	 * write_backtrace_raw_pcs() output below would land before the
	 * glibc malloc_printerr text that explains why we're here.
	 * See Documentation/signals.md.
	 *
	 * buglog_path[] was pre-formatted in init_stderr_memfd() to
	 * keep snprintf() out of this handler.  open / lseek / read /
	 * write / dup2 / close are all on the POSIX 2024 §2.4.3
	 * async-signal-safe list.  Silent no-op on stderr_memfd == -1
	 * (memfd_create() failed) or open() failure.
	 */
	open_buglog_and_drain_stderr(sig);
skip_buglog:
#if defined(USE_BACKTRACE) && !defined(__SANITIZE_ADDRESS__)
	/*
	 * RAW PCs only -- backtrace_symbols_fd() is async-unsafe and
	 * deadlocks against the arena lock on a malloc-raised abort.
	 * See write_backtrace_raw_pcs() for the full rationale.
	 */
	write_backtrace_raw_pcs("trinity child");
#endif
#ifdef CONFIG_GUARD_SHARED
	/*
	 * Guard-page attribution.  Under --guard-shared, a fuzzer
	 * write past a PROT_NONE-wrapped region traps SIGSEGV with
	 * si_addr inside the guard; emit one line naming the
	 * overflowed region, direction, distance, and writer PC.
	 * Skipped for non-SIGSEGV faults (not a guard trip by
	 * construction).  Writer PC is emitted raw (dladdr is not on
	 * the POSIX 2024 §2.4.3 safe list); the bugs.txt post-parser
	 * resolves PIE-relative offsets offline against the load base.
	 * See Documentation/signals.md.
	 */
	emit_guard_page_attribution(sig, info, ctx);
#endif
	write_siginfo_safely(sig, info, "trinity child");

	/*
	 * Stamp the currently-running childop's identity so the
	 * canary queue can attribute the crash to a specific op
	 * rather than bottoming out at child_process+offset.  Emits
	 * the syscall NUMBER, not the name (name-map is a pointer-
	 * chasing table walk not on the POSIX safe list); bugs.txt
	 * post-parser resolves names offline.  Gated on
	 * me->syscall.state so we emit -1 instead of a stale number
	 * from the previous call when the signal hit between
	 * syscalls.  See Documentation/signals.md.
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

void watchdog_reinstall_if_clobbered(void)
{
	struct sigaction cur;

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
		__atomic_add_fetch(&shm->stats.watchdog_sigalrm_clobbered,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.watchdog_sigalrm_reinstalled,
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
		__atomic_add_fetch(&shm->stats.watchdog_sigxcpu_clobbered,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.watchdog_sigxcpu_reinstalled,
				   1, __ATOMIC_RELAXED);
	}
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
		/* RAW PCs only; see write_backtrace_raw_pcs(). */
		write_backtrace_raw_pcs("trinity main");
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
