#pragma once

#include "types.h"

#define TAINT_NAME_LEN 32

extern int kernel_taint_initial;

int get_taint(void);

void close_parent_tainted_fd(void);

/*
 * Read accessor for the parent-only cached fd (see health/taint.c).
 * Exposed so fds/fds-protected.c can keep the slot out of the fuzz
 * picker pool.  Returns -1 when the parent has not opened the file
 * (unreadable /proc entry) or after close_parent_tainted_fd() has run.
 * Child processes always see -1 here after their first get_taint()
 * runs post-fork: the cache is gated on this_child()==NULL, and the
 * inherited copy is cleared by close_parent_tainted_fd() at child
 * bring-up in open_tainted_fd().
 */
int trinity_tainted_fd_cached(void);

bool is_tainted(void);

void process_taint_arg(char *taintarg);

void init_taint_checking(void);
