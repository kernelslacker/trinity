#pragma once

#include <unistd.h>
#include <sys/types.h>

extern unsigned int num_online_cpus;
extern unsigned int max_children;

#define UNLOCKED 0
#define LOCKED 1

#define __unused__ __attribute((unused))

extern char *progname;

void main_loop(void);

int check_tainted(void);

void init_watchdog(void);
unsigned int check_if_fd(unsigned int child);

void regenerate(void);
