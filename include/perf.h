#pragma once

#include "syscall.h"

int open_perf_fds(void);
int get_rand_perf_fd(void);

void sanitise_perf_event_open(int childno, struct syscallrecord *rec);

#define MAX_PERF_FDS 10
