#pragma once

#include "fd.h"
#include "syscall.h"

const struct fd_provider perf_fd_provider;

void sanitise_perf_event_open(struct syscallrecord *rec);

#define MAX_PERF_FDS 10
