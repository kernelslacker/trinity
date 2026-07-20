#ifndef _TRINITY_STATS_SUBSYS_FD_H
#define _TRINITY_STATS_SUBSYS_FD_H

#include "object-types.h"	/* MAX_OBJECT_TYPES */

/*
 * fd-pool RAW observability -- ring-pointer canary rejections, event
 * ring-full drop attribution split by producer path, per-provider
 * outstanding gauge, live-remove scan histogram, and close-range
 * enqueue accounting.
 *
 * Bespoke (non-category) RAW group.  Sibling of the fd_lifecycle
 * category (stats/categories/base.c fd_lifecycle_fields[]) -- the
 * lifecycle counters stay in the category; these RAW arrays / scalars
 * were never categorised because they are either wide arrays
 * (histogram, per-provider gauge) or scalar defense-in-depth signals
 * that surface bespoke rows in the dump path.  The surrounding
 * struct stats_s composes an instance of struct fd_stats as its
 * "fd" member.
 */
struct fd_stats {
	/* fd_event_drain_all() found a child->fd_event_ring pointer that
	 * failed the canonical-address / minimum-address sanity check.
	 * Defense-in-depth against D-state zombie write-after-reap. */
	unsigned long event_ring_corrupted;

	/* fd_event_drain_all() found a live child->fd_event_ring that
	 * differed from the mprotected canary copy taken at init time.
	 * Indicates the pointer was overwritten after init. */
	unsigned long event_ring_overwritten;

	/* fd_event_drain() rejected a child-supplied event whose payload
	 * (type tag, objtype, fd, family, ...) was outside the dispatch
	 * code's safe range.  Children write their own ring under hostile
	 * fuzzed workloads, so the parent treats every payload field as
	 * untrusted; without this guard a bad objtype OOB-writes
	 * shm->fd_regen_pending and a bad family OOB-reads net_protocols
	 * inside add_socket(). */
	unsigned long event_payload_corrupt;

	/*
	 * Per-provider outstanding-fd gauge, indexed by enum objecttype.
	 * Bumped from add_object() after a successful fd_hash_insert() for
	 * an OBJ_GLOBAL fd-typed pool; dropped from fd_event_drain()'s
	 * apply_slot() CLOSE arm using the type recorded in the parent's
	 * fd_hash entry.  Per-index value is the number of fds currently
	 * tracked by the parent for that provider -- a gauge, not a
	 * cumulative counter.  dump_stats() walks the array and prints
	 * only providers whose outstanding > 0, so a non-empty block at
	 * shutdown surfaces per-provider leaks (CLOSE events lost, fds
	 * orphaned in the global hash) without a flood of all-zero rows.
	 * Indexed by the enum so the slot ids stay stable across runs and
	 * MAX_OBJECT_TYPES sizing makes the access bounds-safe by
	 * construction.
	 */
	unsigned long provider_outstanding[MAX_OBJECT_TYPES];

	/* FD bookkeeping observability.
	 *
	 * fd_live_remove() (objects/fdhash.c) does a linear scan of
	 * parent_fd_live[0..parent_fd_live_count) on every parent-
	 * side fd retirement.  Comment at the bump site says
	 * "typical occupancy is a few hundred entries so the cost
	 * is negligible" but a planned fd live-list index should only
	 * be built once this histogram shows the scan actually
	 * expensive in practice.
	 *
	 * Single-writer (parent) — no atomics needed for
	 * correctness, but RELAXED bumps used uniformly to match
	 * the rest of the shm->stats convention so a future
	 * concurrent caller can be added without rewriting the
	 * read path.
	 *
	 * Bucket index = log2(scan_depth) with a 1-floor:
	 *   0: scan ==0 (match on first slot)
	 *   1: scan 1..1
	 *   2: scan 2..3
	 *   3: scan 4..7
	 *   4: scan 8..15
	 *   5: scan 16..31
	 *   6: scan 32..63
	 *   7: scan >=64
	 * Bumped per matched call; misses bump fd_live_remove_miss
	 * separately (a miss is a fd that hash_remove asked us to
	 * retire but no live_fd slot held — symmetry-bug signal,
	 * not a scan-cost signal). */
	unsigned long live_remove_scan_histogram[8];
	unsigned long live_remove_calls;
	unsigned long live_remove_miss;

	/* fd_event_enqueue() ring-full failure split by enqueue
	 * type.  Bumped at the spsc_ring_try_enqueue()==false site
	 * in fd-event.c, indexed by the producer-supplied
	 * fd_event_type.  Without the split the existing
	 * fd_events_dropped aggregates everything the drain
	 * observes as overflow — these three say which producer
	 * path is the source.  CLOSE_RANGE has its own counter
	 * because its producer is a different function
	 * (fd_event_enqueue_range, single fd_event_type). */
	unsigned long event_full_close;
	unsigned long event_full_evict;
	unsigned long event_full_close_range;

	/* Producer-side close-range observability:
	 * `_enqueued` is the count of FD_EVENT_CLOSE_RANGE events
	 * that successfully landed in the ring, `_length_sum` is
	 * the cumulative (hi - lo + 1) span across those events.
	 * length_sum / enqueued = avg fds collapsed per
	 * close_range event — surfaces the effective compression
	 * ratio close-range buys over the per-fd FD_EVENT_CLOSE
	 * path. */
	unsigned long event_close_range_enqueued;
	unsigned long event_close_range_length_sum;

	/* fd lifecycle tracking. */
	unsigned long stale_detected;
	unsigned long stale_by_generation;
	unsigned long closed_tracked;
	unsigned long duped;
	unsigned long events_processed;
	unsigned long events_dropped;
	/* Per-event-type counters bumped from apply_slot().  CLOSE means a
	 * child genuinely closed the fd; EVICT means the parent watchdog
	 * is expiring a stale pool slot whose fd may still be valid in a
	 * sibling.  Split so the two paths stay observable. */
	unsigned long event_close_count;
	unsigned long event_evict_count;

	/* get_random_fd() hit GET_RANDOM_FD_BUDGET outer iterations and
	 * returned -1 to its caller.  Non-zero means a child was about
	 * to tight-loop in argument generation (PREP-state record, so
	 * is_child_making_progress() can't see it) and we bailed instead.
	 * Persistent non-zero indicates fd providers exhausted, broken,
	 * or persistently returning untracked/<=2 fds. */
	unsigned long random_exhausted;

	/* get_new_random_fd() drew a NULL entry from active_providers[] (or a
	 * provider with a NULL ->get).  Every registered provider has a
	 * non-NULL compile-time ->get and the pool is filled once at init, so
	 * a NULL here means the zmalloc'd active_providers array (or
	 * num_active_providers) was scribbled by an out-of-bounds write
	 * elsewhere -- a heap-corruption canary, not a normal condition.  The
	 * draw is retried within the existing inner budget; persistent
	 * non-zero is a strong corruption signal. */
	unsigned long provider_invalid;

	/* fd_hash_reinsert() exhausted the linear-probe chain without
	 * finding a free slot and silently dropped the displaced entry.
	 * Only reachable when fd_hash_count == FD_HASH_SIZE; non-zero
	 * means we lost an fd registration during a removal-driven
	 * re-seat and the per-iter outputerr names which fd. */
	unsigned long hash_reinsert_dropped;

	/* local_fd_hash_insert() exhausted the linear-probe chain in a
	 * per-child objhead's fd_hash[] (LOCAL_FD_HASH_SIZE slots) and
	 * silently returned without inserting.  Subsequent
	 * find_local_object_by_fd() lookups for that fd will return NULL
	 * and the operation drops the object metadata.  Non-zero means
	 * a child has more concurrent fds of one type than the per-child
	 * hash can index; the existing behaviour is preserved (still a
	 * silent return) — this counter just makes the loss visible. */
	unsigned long local_hash_insert_dropped;

	/* sanitize_inherited_fds() closed an fd that the parent inherited
	 * from its launcher (or the launcher's parent) at startup.  We
	 * keep only {0,1,2} across the parent's fork boundary into the
	 * fuzz children; anything else came in from outside trinity and
	 * could end up being polled, watched, or otherwise wedged on by
	 * the reap path (e.g. a stuck-fs fd surfacing in the child-monitor
	 * watch set and blocking the parent's epoll/poll loop). */
	unsigned long parent_inherited_fds_closed;
};

#endif	/* _TRINITY_STATS_SUBSYS_FD_H */
