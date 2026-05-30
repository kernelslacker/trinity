#pragma once

#include <stdint.h>

/*
 * Per-child backtrace capture for __BUG() events.
 *
 * The child's stdout/stderr are redirected to /dev/null in init_child,
 * so any backtrace_symbols output produced from inside __BUG() is lost
 * even though the BUG header itself reaches the parent via the
 * bug_text/bug_func/bug_lineno stamp in shared childdata.  Recover the
 * backtrace by having the child stamp raw frame pointers from
 * backtrace(3) into this shared block before it starts spinning; the
 * parent re-symbolises them from its own (real-stderr) context via
 * dump_child_bug().
 *
 * 64 frames matches half of BACKTRACE_SIZE in debug.c -- trinity's
 * typical assertion sites land ~10-20 frames deep through syscall
 * dispatch + handler + sanitiser, so 64 has generous headroom while
 * keeping the per-child footprint to ~520 B.
 */
#define BUG_BACKTRACE_MAX_FRAMES	64

struct bug_backtrace {
	/* Number of valid entries in frames[].  Producer issues a release
	 * store after populating the array; consumer issues an acquire
	 * load to observe the matching frames intact.  0 means no
	 * backtrace was captured (USE_BACKTRACE unset, or child died
	 * between bug_text stamp and backtrace() return). */
	uint32_t count;
	uint32_t _pad;
	void *frames[BUG_BACKTRACE_MAX_FRAMES];
};

/*
 * Per-child signal-time fault beacon.
 *
 * The bug_backtrace path above captures __BUG() forensics, but __BUG is
 * a normal C function -- it has the full libc available and the child
 * stays alive spinning so the parent always observes the stamp.  The
 * fault-signal path is harsher: a SIGSEGV / SIGBUS / SIGILL / SIGABRT
 * lands in child_fault_handler, and the existing recovery
 * (open per-pid log, dup2 stderr, backtrace_symbols_fd, write siginfo)
 * walks ~5 libc-touchy frames before any forensic bit makes it to disk.
 * When the fault root cause is itself a corrupted ld.so writable
 * segment (NULL'd link_map slot, stomped GOT entry), the very first
 * backtrace_symbols_fd call re-faults inside dladdr's link_map walk
 * before write_siginfo_safely runs; the kernel then re-delivers SIGSEGV
 * and the process dies with at most a few "??" lines and no marker the
 * bug-corpus filter recognises.  The whole class is silenced.
 *
 * The beacon closes that gap.  It is stamped from child_fault_handler
 * BEFORE any libc-touching call (no umask, no open, no
 * backtrace_symbols_fd), so even when those subsequently re-fault the
 * captured context survives in shared memory and the parent prints it
 * from real stderr via dump_child_fault_beacon().
 *
 * Producer is in async-signal handler context, so the stamp uses only
 * fields the kernel handed us (siginfo, ucontext) and plain word stores
 * into this shared block -- no libc, no allocator, no lock.  The
 * release-store on .written is the last write, so the parent's
 * acquire-load on .written orders every preceding plain store into
 * view.
 */
/*
 * Note: si_addr / si_code / si_pid / si_signo are #define macros in
 * glibc's <signal.h> (the legacy compat layer expands siginfo_t field
 * names), so a literal "si_addr" inside this struct definition gets
 * rewritten to garbage whenever a translation unit includes
 * <signal.h> ahead of us.  Use prefixed names that don't collide; the
 * stamp site reads info->si_addr / info->si_code (where the macros do
 * the right thing) and assigns into these fields by their non-macro
 * names.
 */
struct child_fault_beacon {
	/* Parent edge-trigger; 0 = unstamped.  Producer issues a release
	 * store of 1 AFTER every other field has been written.  Consumer
	 * issues an acquire load to observe the populated context. */
	uint32_t written;
	int32_t signo;			/* signal number (SIGSEGV / SIGBUS / SIGILL / SIGABRT) */
	int32_t sig_code;		/* siginfo_t.si_code (kernel: SEGV_MAPERR &c; userspace-sent: SI_USER &c) */
	int32_t last_syscall_nr;	/* in-flight syscall.nr if state was PREP/BEFORE/GOING_AWAY, else -1 */
	void *fault_addr;		/* siginfo_t.si_addr (fault address) */
	void *fault_ip;			/* ucontext PC at fault; NULL on archs without an extractor */
	void *fault_sp;			/* ucontext SP at fault; NULL on archs without an extractor */
	unsigned long op_nr;		/* per-iteration child-op counter at fault */
};
