#pragma once

#include "child.h"
#include "syscall.h"

extern unsigned int num_online_cpus;

extern char *progname;

void main_loop(void);
void exit_main_fail(void);

void init_watchdog(void);
unsigned int check_if_fd(struct childdata *child, struct syscallrecord *rec);

void panic(int reason);

#define __unused__ __attribute((unused))

#define FAIL 0
#define SUCCESS 1
