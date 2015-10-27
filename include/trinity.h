#pragma once

#include "types.h"

extern unsigned int num_online_cpus;
extern bool no_bind_to_cpu;

extern char *progname;

void main_loop(void);
void exit_main_fail(void);

void init_watchdog(void);

void panic(int reason);

#define __unused__ __attribute((unused))

#define FAIL 0
#define SUCCESS 1
