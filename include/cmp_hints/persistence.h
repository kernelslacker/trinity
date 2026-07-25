#pragma once

#include <sys/types.h>

#include "syscall.h"

/*
 * Fleet-wide shared cmp_ip tier.
 *
 * Cross-syscall fallback bank: keyed on canonical (KASLR-stripped)
 * cmp_ip ALONE, unlike the per-nr pools above which are keyed on
 * (nr, cmp_ip, value, size).  A single kernel comparison site that
 * fires under many syscalls (do_syscall_64 / seccomp gates, iov walk,
 * copy_from_user length checks, kcov entry gate, ...) produces the
 * SAME canonical cmp_ip regardless of which syscall drove the child;
 * the shared tier collapses those cross-nr duplicates into ONE
 * value-set entry so a cold per-nr pool can eventually warm-start
 * from constants ANY sibling syscall already learned at the same
 * check.  Validated by the overlap-mine: ~48% of cmp_ips are shared
 * across nrs and ~87% of learned entries are cross-nr duplicates.
 *
 * The per-nr pools stay AUTHORITATIVE; the shared tier is fallback /
 * warm-start ONLY -- it never displaces a per-nr entry, never gates
 * a per-nr pick, and never replaces a value the per-nr picker would
 * have served on its own.  Storage is a fixed-size open-addressed
 * hash table (CMP_SHARED_TIER_IPS buckets, power-of-two so the mask
 * beats a modulo) with bounded linear probe on collision.  Probe
 * exhaustion silently drops the record: the tier is advisory,
 * dropping is the same shape as the per-nr LRU eviction.
 *
 * Per-bucket value-set holds up to CMP_SHARED_TIER_VALUES distinct
 * (value, size) pairs at the same cmp_ip -- a busy comparison site
 * (switch dispatch, enum-family compare) legitimately carries many
 * constants, but past ~8 the incremental value flattens; overflow
 * drops silently (tier is fallback tier, not authoritative).
 *
 * Entry-path filter.  A cmp_ip that fires under every syscall (the
 * shared-with-fleet entry path: do_syscall_64, seccomp, kcov gate,
 * copy_from_user length probes, ...) is noise as a warm-start seed:
 * a value learned at "iov->iov_len < LONG_MAX" tells the picker
 * nothing about which value to feed a specific syscall arg.  Track
 * distinct-nr-count per bucket; once it crosses
 * CMP_SHARED_TIER_ENTRY_PATH_NR_MAX (~15% of MAX_NR_SYSCALL, sized
 * off the overlap mine) latch entry_path_excluded and stop counting
 * this bucket toward the shadow warm-start eligibility metric.  The
 * bucket keeps STORING contributions (so a follow-up analysis can
 * still probe the entry-path population) but is excluded from the
 * shadow observer's supply signal.
 *
 * NOT persisted by cmp_hints_save_file -- the tier is DERIVED from
 * the per-nr pools on warm-load (walk pools[][] and union each
 * live entry into the tier) and topped up on every fresh commit
 * (pool_add_locked() success), so the persisted per-nr snapshot is
 * a complete on-disk representation and no new on-disk schema is
 * needed.
 */
#define CMP_SHARED_TIER_IPS			2048U
#define CMP_SHARED_TIER_VALUES			8U
#define CMP_SHARED_TIER_ENTRY_PATH_NR_MAX	150U
#define CMP_SHARED_TIER_PROBE_MAX		8U

/*
 * Rollout gate for the shared cmp_ip tier -- same OFF / SHADOW_ONLY /
 * COMBINED ramp discipline the sibling cost_pool_selector_mode and
 * frontier_saturation_cooldown_mode rows use.
 *
 *   OFF          - default, byte-identical to a build before the tier
 *                  landed.  Every hot-path shared-tier access (both
 *                  the collect-side insert and the get-side shadow
 *                  probe) short-circuits before touching the tier
 *                  shm.  Under a fixed-seed --dry-run the pick stream
 *                  and every counter are bit-for-bit identical to a
 *                  pre-shared-tier build.
 *   SHADOW_ONLY  - the collect-side insert populates the tier (both
 *                  at warm-load from cmp_hints_load_file and live on
 *                  every fresh pool_add_locked success), and the
 *                  get-side probe bumps cmp_shared_tier_shadow_warm
 *                  start_eligible on every per-nr cold miss where the
 *                  tier has a non-entry-path IP available to seed
 *                  from.  Live selection stays unchanged: try_get
 *                  returns exactly what it would have returned
 *                  without the observer.  Zero RNG consumption on the
 *                  probe path.
 *   COMBINED     - Live serve enabled AND quarantined.  In addition
 *                  to the SHADOW_ONLY behaviour above,
 *                  cmp_shared_tier_try_serve_cold_miss() fires on a
 *                  per-nr cold miss (durable pool empty on the
 *                  requested (nr, do32), recent-tier pre-pass
 *                  returned MISS) and, gated by a
 *                  ONE_IN(CMP_SHARED_TIER_SERVE_DICE) budget,
 *                  elects an occupied non-entry-path bucket at
 *                  random and returns one of its (value, size)
 *                  pairs.  The served value is stamped
 *                  served_from_shared=1 on the per-child stash so
 *                  the credit drain routes its PC outcome to
 *                  cmp_hint_tier_shared_wins / _misses ONLY and
 *                  does NOT touch native pool per-entry / by-pool /
 *                  by-callsite / by-tier / by-age credit.  A
 *                  constant served from the shared tier NEVER
 *                  becomes native pool provenance under this path
 *                  -- promotion requires separate local
 *                  re-observation via cmp_hints_collect().  Native
 *                  warm hits are strictly preferred: the serve
 *                  fires only after every native tier (recent ring,
 *                  durable per-nr pool) has been consulted and
 *                  missed.
 *
 * Param-settable from --cmp-shared-tier=off|shadow|combined.
 */
enum cmp_shared_tier_mode {
	CMP_SHARED_TIER_MODE_OFF = 0,
	CMP_SHARED_TIER_MODE_SHADOW_ONLY = 1,
	CMP_SHARED_TIER_MODE_COMBINED = 2,
};

extern enum cmp_shared_tier_mode cmp_shared_tier_mode;

_Static_assert((CMP_SHARED_TIER_IPS & (CMP_SHARED_TIER_IPS - 1)) == 0,
	       "CMP_SHARED_TIER_IPS must be a power of two");

struct cmp_shared_tier_entry {
	unsigned long value;
	uint32_t size;		/* operand width in bytes: 1, 2, 4, or 8 */
	uint32_t pad;		/* explicit 8-byte alignment */
};

/*
 * Occupancy is gated on the `occupied` byte (RELEASE-store on claim,
 * ACQUIRE-load on read) so a lockless reader that observes occupied=1
 * is guaranteed to see cmp_ip / values[] / value_count / seen_nrs[]
 * populated behind it.  All writes on an occupied bucket happen under
 * the shared_tier_lock in cmp_hints_shared below; only the initial
 * claim uses the RELEASE-store to publish the key without needing a
 * distinct probe-side lock.
 *
 * seen_nrs[] is a 1024-bit membership bitmap indexed by syscall nr:
 * bit set => this nr has contributed to this cmp_ip before.  A fresh
 * bit-set bumps distinct_nr_count; do32 is folded into "nr" for the
 * count (a 64-bit and a 32-bit syscall at nr=N contribute the same
 * bit -- the entry-path filter is about the shape "this IP fires
 * across many callers", not "this IP fires under two architectures").
 */
struct cmp_shared_tier_bucket {
	unsigned long cmp_ip;
	uint32_t distinct_nr_count;
	uint16_t value_count;
	uint8_t occupied;
	uint8_t entry_path_excluded;
	struct cmp_shared_tier_entry values[CMP_SHARED_TIER_VALUES];
	uint8_t seen_nrs[(MAX_NR_SYSCALL + 7) / 8];
};
