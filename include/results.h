#pragma once

#include <stdint.h>
#include "syscall.h"

void handle_success(struct syscallrecord *rec);
void handle_failure(struct syscallrecord *rec);
int pick_successful_fd(struct results *results);
bool fd_recently_failed(struct results *results, int fd);

/* Stamp the packed CAS-targeted fields to their "fresh slot" values.
 * len_score gets the not-seen sentinel (min == UINT32_MAX, max == 0) so a
 * reader observing min > max treats the slot as never-seen, matching the
 * `seen = false` semantics that a zero-init shm would otherwise lie about.
 * fail_run stays zero (no run in flight) -- relying on memcpy/alloc_shared
 * zero-init is sufficient there, but we set it explicitly for clarity. */
static inline void results_init_one(struct results *r)
{
	r->len_score.u.min = UINT32_MAX;
	r->len_score.u.max = 0;
	r->fail_run.raw = 0;
}

/* Decode the len_score sentinel: a fresh slot reads back min==UINT32_MAX,
 * max==0 (set by results_init_one), which any in-band (min, max) pair
 * cannot represent because store_successful_len keeps min <= max. */
static inline bool len_score_is_seen(const struct results *r)
{
	return !(r->len_score.u.min == UINT32_MAX && r->len_score.u.max == 0);
}
