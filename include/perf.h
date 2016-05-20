#pragma once

#include "syscall.h"

void sanitise_perf_event_open(struct syscallrecord *rec);

int get_rand_perf_fd(void);
