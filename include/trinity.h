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
unsigned long sum_local_op_counts(void);

void panic(int reason);

#define __unused__ __attribute((unused))

#define FAIL 0
#define SUCCESS 1

// output stuff that's used pretty much everywhere, so may as well be here.
#define MAX_LOGLEVEL 3
#define CONT -1
void output(int level, const char *fmt, ...);
void output_set_pid(pid_t pid);
void outputerr(const char *fmt, ...);
void outputstd(const char *fmt, ...);
void debugf(const char *fmt, ...);
