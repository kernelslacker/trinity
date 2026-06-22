#pragma once

#include "syscall.h"

void sanitise_perf_event_open(struct syscallrecord *rec);

int get_rand_perf_fd(void);

/*
 * Live tracepoint-id picker for the structured perf_event_attr fill.
 * Draws from the runtime-populated tracepoint_ids[] pool (seeded once
 * from /sys/kernel/tracing/events/.../id at init_pmus() time); on empty
 * pool drops to a random u32/u64 so the caller always gets a usable
 * value.  Owned by syscalls/perf_event_open.c next to the pool itself;
 * declared here so struct_catalog.c can plant it in the TRACEPOINT
 * variant's FT_PICKER field without duplicating the pool.
 */
unsigned long long random_tracepoint_config(void);
