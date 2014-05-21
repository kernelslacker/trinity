#pragma once

#include "fd.h"
#include "syscall.h"

struct fd_provider perf_fd_provider;

void sanitise_perf_event_open(int childno, struct syscallrecord *rec);

#define MAX_PERF_FDS 10
