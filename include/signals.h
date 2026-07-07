#pragma once

#include <setjmp.h>
#include <signal.h>

extern volatile sig_atomic_t sigalrm_pending;
extern volatile sig_atomic_t xcpu_pending;
extern volatile sig_atomic_t ctrlc_pending;
extern volatile sig_atomic_t in_do_syscall;

/*
 * Set by do_extrafork() in the grand-child branch immediately after
 * fork(), before the grand-child enters __do_syscall().  Read by
 * child_fault_handler() to skip the fault-beacon stamp on the grand-
 * child's crash: this_child() in the grand-child returns the parent
 * worker's childdata (cached_pid is COW-inherited and never updated
 * across the throwaway fork), so without this gate a grand-child
 * SIGSEGV would publish a fault beacon attributed to the parent worker
 * -- the canary queue then bills the crash to the wrong op_nr and the
 * worker gets needlessly retired.
 *
 * The grand-child is a throwaway (~1s wall clock max, killed by the
 * parent's waitpid timeout in do_extrafork) and has no childdata of
 * its own to stamp into, so the correct action is to skip the beacon
 * entirely.  The kernel-side coredump and the regular crash log path
 * still surface the death.
 */
extern volatile sig_atomic_t in_extrafork_grandchild;

/*
 * Per-child recovery point for asb_relocate()'s best-effort source copy.
 *
 * range_readable_user() proves the source range from cached state
 * (tracked shared regions + heap snapshots), but a sibling syscall can
 * tear a MAP_SHARED region down via raw munmap/mremap without calling
 * untrack_shared_region(), leaving the cache stale.  The next
 * asb_relocate() that copies from that region faults inside memcpy with
 * SIGSEGV/SEGV_MAPERR -- a sanitiser fault, not a kernel bug -- and the
 * child dies, masking whatever real syscall behaviour we were trying to
 * fuzz on that op.
 *
 * The flag/buffer pair lets the asb_relocate() memcpy install a
 * sigsetjmp recovery point around the copy: child_fault_handler checks
 * asb_copy_active on entry, and on a real kernel SIGSEGV/SIGBUS
 * (si_code > 0) while the flag is set, siglongjmp's back to the
 * sanitiser, which falls through to the no-copy redirect path.
 *
 * Scope is intentionally narrow: the flag is set ONLY across the
 * memcpy itself, cleared immediately after, and the recovery edge
 * applies only to SIGSEGV / SIGBUS.  All other signals, and the
 * default (flag-clear) state, fall through to the existing crash-log
 * path so a real kernel-fuzzed bug still produces a bug log.
 */
extern sigjmp_buf asb_copy_recover;
extern volatile sig_atomic_t asb_copy_active;

/*
 * Per-child recovery point for cmp_hints_collect()'s field-scoped
 * RedQueen deref of an ARG_TIMESPEC saved pointer.
 *
 * The field-scoped fallback in cmp_hints_collect() reads ts->tv_sec /
 * ts->tv_nsec out of the dispatch-time buffer to match the runtime
 * operand.  The deref is already gated on range_readable_user(), which
 * proves readability from cached state (tracked shared regions + heap
 * snapshots) -- but a sibling syscall can tear down a MAP_SHARED
 * region via raw munmap/mremap without calling
 * untrack_shared_region(), leaving the cache stale.  The next
 * tv_sec/tv_nsec load then faults inside the harvest with
 * SIGSEGV/SEGV_MAPERR -- a sanitiser fault, not a kernel bug -- and
 * the whole child dies, masking whatever real syscall behaviour the
 * dispatched op was about to expose.
 *
 * The flag/buffer pair lets the field reads install a sigsetjmp
 * recovery point around the two compares: child_fault_handler checks
 * cmp_field_read_active on entry, and on a real kernel SIGSEGV/SIGBUS
 * (si_code > 0) while the flag is set, siglongjmp's back to the
 * harvest, which counts the skip and falls through to the next field.
 *
 * Scope is intentionally narrow: the flag is set ONLY across the two
 * field reads, cleared immediately after on BOTH the normal and the
 * fault-return path, and the recovery edge applies only to SIGSEGV /
 * SIGBUS with si_code > 0.  All other signals, and the default
 * (flag-clear) state, fall through to the existing crash-log path so
 * a real kernel-fuzzed bug still produces a bug log.
 */
extern sigjmp_buf cmp_field_recover;
extern volatile sig_atomic_t cmp_field_read_active;

/*
 * Per-child recovery point for vma_split_storm's touch_random_page()
 * one-byte store.
 *
 * touch_random_page() stores one byte to a random page of the op's
 * private 8 MiB region between iterations to keep ptes present for
 * the split / DONTNEED walkers.  The touched page may sit in a sub-
 * VMA whose most recent mprotect was PROT_READ, in which case the
 * store faults with SIGSEGV/SEGV_ACCERR -- a sanitiser fault from
 * the op's own bookkeeping, not a kernel bug -- and the whole child
 * dies, stamping a bogus bug log for what is by construction a
 * self-inflicted store into read-only own memory.
 *
 * The flag/buffer pair lets the store install a sigsetjmp recovery
 * point around the single byte write: child_fault_handler checks
 * vma_split_storm_touch_active on entry, and on a real kernel
 * SIGSEGV/SIGBUS (si_code > 0) while the flag is set, siglongjmp's
 * back to touch_random_page(), which clears the flag and returns.
 *
 * Scope is intentionally narrow: the flag is set ONLY across the
 * single one-byte store, cleared immediately after on BOTH the
 * normal and the fault-return path, and the recovery edge applies
 * only to SIGSEGV / SIGBUS with si_code > 0.  All other signals,
 * and the default (flag-clear) state, fall through to the existing
 * crash-log path so a real kernel-fuzzed bug still produces a bug
 * log.
 */
extern sigjmp_buf vma_split_storm_touch_recover;
extern volatile sig_atomic_t vma_split_storm_touch_active;


#ifdef CONFIG_GUARD_SHARED
/*
 * Per-child recovery point for the kcov_enable_trace() trace_buf[0]=0
 * reset write.  Investigation-only: the kcov PC buffer is registered
 * in the shared-region tracker (see track_shared_region_tagged
 * "kcov-pc") yet some run path is intermittently stripping its
 * PROT_WRITE, turning the reset store into SEGV_ACCERR/SIGBUS.  The
 * existing sanitiser gates point fingers at each other and the
 * register-time prot log says the buffer was writable at setup time,
 * so this recovery flag/buffer pair lets the store run under a
 * sigsetjmp and, on fault, dump a full diagnostic (live VMA prot from
 * /proc/self/maps, shared_regions registration status, recent audit-
 * ring history) before _exit()ing with a distinct exit code so the
 * fault is visible in the reap statistics without crash-looping the
 * worker.
 *
 * Scope is intentionally narrow: the flag is set ONLY across the
 * single trace_buf[0] store and cleared immediately after.  Any other
 * SIGSEGV/SIGBUS the child takes sees the flag clear and falls
 * through to the existing crash-log path.  Gated on CONFIG_GUARD_-
 * SHARED so the normal build is byte-unaffected.
 */
extern sigjmp_buf kcov_protect_recover;
extern volatile sig_atomic_t kcov_protect_active;
#endif

void mask_signals_child(void);
void setup_main_signals(void);
void init_abort_msg_capture(void);
void init_stderr_memfd(void);

/*
 * The internal-watchdog handlers installed once by mask_signals_child().
 * Exposed only so an arm site (alarm(1) or RLIMIT_CPU) can read back
 * the live sa_handler with sigaction(_, NULL, &cur) and detect that a
 * fuzzed rt_sigaction call has overwritten the watchdog disposition
 * before the alarm fires.  SIGALRM/SIGXCPU appear in settable_signals[]
 * and a child fuzzing rt_sigaction(SIGALRM, ...) can disarm the
 * 1-second inner watchdog -- subsequent blocking ops then ride the
 * ~30-second outer watchdog instead, accounting for most of the
 * tail-latency in the late-run childop wedge.
 *
 * No caller should ever invoke these handlers directly or take their
 * address for anything other than the sa_handler equality check.
 */
void sigalrm_handler(int sig);
void sigxcpu_handler(int sig);

/*
 * The numeric fd returned by memfd_create() inside init_stderr_memfd().
 * The fd is kept open past the dup2(STDERR_FILENO) so child_fault_handler
 * can lseek+read the buffered pre-crash text into the bug log; until that
 * drain happens it MUST be steered away from close / dup2 / dup3 /
 * close_range targets, otherwise a fuzz syscall closes the memfd before
 * the SIGABRT handler can read it and the glibc malloc_printerr line is
 * lost.  Returns -1 in parent context and in children where the
 * memfd_create() call failed (no CONFIG_MEMFD_CREATE, sandbox refusal).
 */
int trinity_stderr_memfd(void);
