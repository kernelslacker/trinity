#pragma once

extern unsigned int num_online_cpus;

extern char *progname;

void main_loop(void);

void init_watchdog(void);
unsigned int check_if_fd(unsigned int child);

#define __unused__ __attribute((unused))

#define FAIL 0
#define SUCCESS 1
