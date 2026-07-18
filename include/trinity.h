#pragma once

#include <sys/types.h>
#include "types.h"

extern unsigned int num_online_cpus;
extern struct rlimit max_files_rlimit;
extern bool no_bind_to_cpu;

extern char *progname;

const char *trinity_tmpdir_abs(void);

void main_loop(void);
void reset_epoch_state(void);
void pidstatfiles_drop_in_child(void);

/* Returns the CLOCK_MONOTONIC second past which the fork-pressure
 * drain stops suppressing pid-heavy canary picks, or 0 when the drain
 * has never armed.  Defined in main/loop.c, consumed from child-canary.c.
 * Always returns 0 when --fork-pressure-drain is off; callers may
 * still short-circuit on the flag for cache locality. */
unsigned long fork_pressure_drain_active(void);

void panic(int reason);

#define __unused__ __attribute((unused))

#define FAIL 0
#define SUCCESS 1

// output stuff that's used pretty much everywhere, so may as well be here.
#define MAX_LOGLEVEL 3
#define CONT -1
void output(int level, const char *fmt, ...);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void debugf(const char *fmt, ...);
bool should_route_to_stdout(void);
