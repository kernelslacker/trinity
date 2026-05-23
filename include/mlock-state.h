#pragma once

#include <stdbool.h>

struct map;

/*
 * Per-child memlock budget + recently-locked ring shared between the
 * mlock and munlock sanitisers.  State lives in mm/mlock-state.c as
 * static __thread storage so a childop that dispatches work onto a
 * helper thread (e.g. barrier_racer's process-shared pthread barriers)
 * does not share or race the running total with the spawning child.
 *
 * pick_length picks one of four page-aligned length buckets (single
 * page, half map, full map, over-end).  *over_end is set on the
 * (size + page_size) draw; the caller must skip both the budget
 * clamp and the ring write on that branch -- the bucket exists to
 * keep the ENOMEM "range not mapped" path warm, and either side
 * effect would mask it (clamp turns over-end back into in-bounds;
 * ring-recording would later steer munlock at a range mlock never
 * actually locked).
 *
 * pick_start returns either map->ptr (75%) or a page-aligned offset
 * one page short of the mapping end (25%) so non-base starts get
 * coverage without sacrificing the dominant base-start shape.
 *
 * clamp_len returns min(requested, RLIMIT_MEMLOCK - cumulative_locked)
 * so a "full map" bucket on a multi-MB INITIAL_ANON cannot blow the
 * cap and surrender the rest of the fuzz wave to EAGAIN.  An
 * RLIM_INFINITY cap surfaces as ULONG_MAX, short-circuiting the clamp.
 *
 * record_locked is the writer side of an 8-entry recently-locked
 * ring; the matching pick_recent reader is added with the munlock
 * subset bias.
 */
unsigned long mlock_state_pick_length(unsigned long map_size, bool *over_end);
unsigned long mlock_state_pick_start(struct map *map);
unsigned long mlock_state_clamp_len(unsigned long requested);
void mlock_state_record_locked(unsigned long start, unsigned long len);
bool mlock_state_pick_recent(unsigned long *startp, unsigned long *lenp);
void mlock_state_record_unlocked(unsigned long len);
