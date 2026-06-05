#pragma once

#include <setjmp.h>
#include <signal.h>

extern volatile sig_atomic_t sigalrm_pending;
extern volatile sig_atomic_t xcpu_pending;
extern volatile sig_atomic_t ctrlc_pending;
extern volatile sig_atomic_t in_do_syscall;

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

void mask_signals_child(void);
void setup_main_signals(void);
void init_abort_msg_capture(void);
void init_stderr_memfd(void);

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
