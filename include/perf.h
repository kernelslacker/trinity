#pragma once

#include "fd.h"
#include "syscall.h"

void sanitise_perf_event_open(struct syscallrecord *rec);

int get_rand_perf_fd(void);

#define MAX_PERF_FDS 10
