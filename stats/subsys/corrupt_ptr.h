#ifndef _TRINITY_STATS_SUBSYS_CORRUPT_PTR_H
#define _TRINITY_STATS_SUBSYS_CORRUPT_PTR_H

/*
 * corrupt-pointer instrumentation counters.
 *
 * Bespoke (non-category) RAW group: the sample-cadence sequence for
 * looks_like_corrupted_ptr's rate-limited value-sampling log path, and
 * the per-call-site attribution array for the post_handler_corrupt_ptr
 * headline counter.  Kept self-contained so the whole subsystem is
 * legible from a single header; the surrounding struct stats_s composes
 * an instance of struct corrupt_ptr_stats as its "corrupt_ptr" member.
 */
struct corrupt_ptr_stats {
	/* Monotonic counter feeding the value-sampling rate-limiter inside
	 * looks_like_corrupted_ptr.  Distinct from post_handler_corrupt_ptr
	 * (which is also bumped from the rec==NULL path through
	 * post_handler_corrupt_ptr_bump and so cannot be used as the sample
	 * cadence source -- a sample log line printed from the bump helper
	 * has no value to print).  RELAXED bumps; the sample cadence does
	 * not need to be exactly every Nth rejection across a contended
	 * fleet, only roughly so. */
	unsigned long sample_seq;

	/* Per-call-site attribution buckets for the post_handler_corrupt_ptr
	 * headline counter.  Inert by default; the producer side (the
	 * post_handler_corrupt_ptr_bump_at / corrupt_ptr_site_record path
	 * in utils.c) only writes when TRINITY_CORRUPT_ATTRIB=1 is in the
	 * env, and the dump path renders the breakdown under the same gate.
	 * Indexed by enum corrupt_ptr_site (include/utils.h); kept here as a
	 * bare unsigned long array rather than declared in terms of the
	 * enum to avoid pulling utils.h into the stats header.  The slot
	 * count tracks CORRUPT_PTR_SITE__COUNT -- bumped in lockstep with
	 * the enum.  Multi-producer (any child can fire from any named
	 * site) so the writers use __atomic_add_fetch RELAXED; this lives
	 * in shm->stats rather than parent_stats for that reason. */
	unsigned long site_count[10];	/* CORRUPT_PTR_SITE__COUNT */
};

#endif	/* _TRINITY_STATS_SUBSYS_CORRUPT_PTR_H */
