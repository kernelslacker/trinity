#pragma once

#include <signal.h>

extern volatile sig_atomic_t sigalrm_pending;
extern volatile sig_atomic_t xcpu_pending;
extern volatile sig_atomic_t ctrlc_pending;
extern volatile sig_atomic_t in_do_syscall;

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
