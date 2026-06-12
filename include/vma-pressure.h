#pragma once

#include <stdbool.h>

/*
 * Global VMA-pressure watchdog.  Heavy-VMA childops
 * (vma_split_storm, mprotect_split, mmap_lifecycle, mlock_pressure,
 * madvise_cycler) can drive a child's live VMA count toward
 * /proc/sys/vm/max_map_count; once the kernel refuses further splits
 * the symptoms are diffuse ENOMEM returns from mprotect/mmap/mremap
 * that propagate as "fuzzer never reached the bug" rather than a
 * crash.  This watchdog samples the child's VMA count periodically
 * and publishes a single per-child latch the gated childops poll at
 * the top of their iteration to back off before hitting the ceiling.
 *
 * State lives in mm/vma-pressure.c; per-child BSS is COW-private
 * after fork() so no shm machinery is needed.  See that file for the
 * cost / cadence / hysteresis comment block.
 *
 * vma_pressure_sample_maybe() is the only sampler entry point: called
 * from periodic_work() in child.c with op_nr; gates internally to one
 * sample every VMA_PRESSURE_SAMPLE_PERIOD ops.
 *
 * vma_pressure_is_high() is the hot-path read: a single BSS load.  Cheap
 * enough to call at the top of every childop iteration.
 */
void vma_pressure_sample_maybe(unsigned long op_nr);
bool vma_pressure_is_high(void);
