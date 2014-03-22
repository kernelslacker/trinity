#pragma once

#include <unistd.h>
#include <sys/types.h>

extern unsigned int num_online_cpus;

#define __unused__ __attribute((unused))

extern char *progname;

void main_loop(void);

void init_watchdog(void);
unsigned int check_if_fd(unsigned int child);

void regenerate(void);
