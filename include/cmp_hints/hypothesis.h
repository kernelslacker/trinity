#pragma once

#include <sys/types.h>

/*
 * Typed-CMP-hypothesis store.
 *
 * Layered on top of the raw cmp-hint pools above as a PARALLEL table:
 * the raw pools stay the canonical (cmp_ip, value, size) ledger and
 * the hypothesis store represents typed inferences built FROM those
 * observations.  Kept outside struct cmp_hint_entry deliberately so the
 * raw-hint lookup path stays cache-tight and so hypothesis layout churn
 * does not perturb the recording-side fast path.
 *
 * Live observe -> select -> inject -> feedback -> transition loop:
 * cmp_hyp_observe() (from cmp_hints_flush_pending) populates entries
 * in CMP_HYP_STATE_OBSERVED; cmp_hyp_would_pick_locked() (hyp-pick.c)
 * selects the most-specific state-preferred entry at (cmp_ip, width)
 * across the EXACT > ENUM_FAMILY > BITMASK > RANGE > BOUNDARY ladder;
 * cmp_hyp_try_live_inject() (hyp-live.c) derives a typed replacement
 * via cmp_hyp_derive_value() (hyp-derive.c) -- EXACT rotates
 * {N-1, N, N+1}, ENUM_FAMILY / BITMASK / RANGE emit family / mask /
 * bound-relative values, BOUNDARY emits the N-1 / N / N+1 / +/-2
 * sweep classes -- and substitutes it for the raw pool value the
 * pick step computed; cmp_hyp_credit_outcome() (hyp-credit.c) drives
 * the OBSERVED <-> PROMOTED <-> DEMOTED transitions and the terminal
 * DEMOTED -> RETIRED at sustained-miss threshold, which the picker
 * and the PROMOTED-bypass channel of the inject arm route on.
 */
enum cmp_hypothesis_kind {
	CMP_HYP_EXACT,
	CMP_HYP_RANGE,
	CMP_HYP_BOUNDARY,
	CMP_HYP_BITMASK,
	CMP_HYP_ENUM_FAMILY,
	CMP_HYP_ALIGNMENT,
	CMP_HYP_LENGTH,
	CMP_HYP_FOREIGN_VALUE,
	CMP_HYP_KIND_NR,
};

enum cmp_hypothesis_state {
	CMP_HYP_STATE_OBSERVED,		/* landing state at cmp_hyp_observe(); eligible for
					 * the picker (fallback when no PROMOTED entry
					 * exists at (cmp_ip, width) for the same kind)
					 * and therefore for the live inject arm --
					 * cmp_hyp_credit_outcome() promotes on first
					 * win, demotes after miss threshold */
	CMP_HYP_STATE_TESTING,		/* reserved per-pick waystation.  Declared for
					 * downstream use; the credit-side state machine
					 * does not currently drive entries in or out of
					 * this state (see hyp-credit.c) and the picker
					 * treats TESTING as OBSERVED */
	CMP_HYP_STATE_PROMOTED,		/* produced a PC-edge / transition / corpus win;
					 * top-tier picker preference and unlocks the
					 * PROMOTED-bypass channel in hyp-live.c */
	CMP_HYP_STATE_DEMOTED,		/* repeatedly consumed without useful outcome;
					 * hidden from the picker except via the
					 * CMP_HYP_DEMOTED_RETRY_DENOM reroll that keeps
					 * revival reachable */
	CMP_HYP_STATE_RETIRED,		/* stale, invalid, or superseded -- terminal;
					 * skipped by the picker */
	CMP_HYP_STATE_NR,
};

/*
 * Demote miss threshold lives in cmp_hyp_credit_outcome()'s scoring
 * pass (`ms >= 8`).  Retirement is the dead-end after sustained noise:
 * a DEMOTED hypothesis that crosses 8x the demote threshold without
 * earning ANY win is RETIRED and removed from the picker pool.  Kept
 * here so the picker / dump code can reference the same constant. */
#define CMP_HYP_RETIRE_MISS_THRESHOLD	64U

/*
 * Reason partition for the LIVE typed-hypothesis inject path.  Each
 * value names a distinct site on the path from cmp_hyp_try_live_inject()
 * through the caller's accept-range gate.  The downstream reasons
 * (NO_MATCH, DERIVE_FAIL, ACCEPT_REJECT) and the head-gate failure
 * reasons (NOT_PLATEAU, DICE_MISS) bump on early-return; the channel
 * reasons (BOOTSTRAP, PROMOTED_BYPASS) bump on channel-fire SUCCESS to
 * expose which non-plateau channel admitted the call.  The sum across
 * head-gate failure reasons + (BOOTSTRAP + PROMOTED_BYPASS) +
 * (NO_MATCH + DERIVE_FAIL + ACCEPT_REJECT) + cmp_hyp_live_injected gives
 * the total typed-eligible invocations of the inject arm minus the
 * channel-A plateau opens that did not bump any channel counter (those
 * are visible as live_inject_gate_passed minus BOOTSTRAP minus
 * PROMOTED_BYPASS).
 *
 * NOT_PLATEAU/DICE_MISS now bump only when ALL channels fail to open:
 * NOT_PLATEAU when plateau was off (channels B and C both lost their
 * dice), DICE_MISS when plateau was on but channel A and the bypass
 * channels all lost.
 */
enum cmp_hyp_live_inject_reason {
	CMP_HYP_LIVE_INJECT_REASON_NOT_PLATEAU,	  /* plateau off AND all bypass channels lost their dice */
	CMP_HYP_LIVE_INJECT_REASON_DICE_MISS,	  /* plateau on AND every channel's dice lost */
	CMP_HYP_LIVE_INJECT_REASON_NO_MATCH,	  /* no qualifying hyp at (cmp_ip, width): picker NULL, or PROMOTED-only channel C contender at a site with no PROMOTED entry */
	CMP_HYP_LIVE_INJECT_REASON_DERIVE_FAIL,	  /* cmp_hyp_derive_value() bailed */
	CMP_HYP_LIVE_INJECT_REASON_ACCEPT_REJECT, /* caller's accept-range gate rejected derived value */
	CMP_HYP_LIVE_INJECT_REASON_BOOTSTRAP,	  /* channel B opened: bootstrap dice fired regardless of plateau */
	CMP_HYP_LIVE_INJECT_REASON_PROMOTED_BYPASS, /* channel C opened: PROMOTED hyp present and bypass dice fired */
	CMP_HYP_LIVE_INJECT_REASON_NR,
};

/*
 * RANGE-identity discriminators.  Carried per-entry on CMP_HYP_RANGE
 * hypotheses so dedup keys the entry by an inferred logical-probe
 * identity rather than by literal compare operands -- value churn at
 * any single comparison site, and multiple sites that observe the same
 * logical range, both collapse to ONE entry.  Zero for non-RANGE
 * kinds; their dedup keys are unchanged.
 *
 * KCOV records only operand values, NOT the compare OPERATOR, so
 * direction is INFERRED heuristically from the accumulated cluster
 * (exemplar position relative to lo/hi).  CMP_RANGE_DIR_UNKNOWN is
 * the honest answer when no clear edge signal exists -- an
 * un-inferable probe is keyed under UNKNOWN rather than force-fit to
 * a guessed direction.
 */
enum cmp_range_direction {
	CMP_RANGE_DIR_UNKNOWN = 0,
	CMP_RANGE_DIR_ASCENDING,	/* most-recent exemplar at the high end */
	CMP_RANGE_DIR_DESCENDING,	/* most-recent exemplar at the low end */
};

/*
 * Signedness is part of identity (same discipline as the
 * discriminated-arg width/sign handling): a 4-byte signed range whose
 * bounds straddle the signed/unsigned boundary is NOT the same probe
 * as an 8-byte unsigned range with the same numeric bounds.  Inferred
 * from whether either bound has the sign bit of its width set.
 */
enum cmp_range_signedness {
	CMP_RANGE_SIGN_UNSIGNED = 0,
	CMP_RANGE_SIGN_SIGNED,
};

/*
 * Relation class describes how the kernel-side compare uses the
 * range.  KCOV records only matching observed operands, so every
 * cluster the observer accumulates is INSIDE by construction; the
 * other classes ship for the future consumer-side probe ladder
 * (outside / single-bound / wrap-around arms) and stay populated
 * by later inference passes.
 */
enum cmp_range_relation {
	CMP_RANGE_REL_INSIDE = 0,	/* value lies within [lo, hi] */
	CMP_RANGE_REL_OUTSIDE,
	CMP_RANGE_REL_BOUND,
	CMP_RANGE_REL_WRAP,
	CMP_RANGE_REL_UNKNOWN,
};

/*
 * Common shape across every hypothesis kind.  Fields not relevant to a
 * given kind are zero (e.g. mask is unused by CMP_HYP_EXACT, lo/hi by
 * CMP_HYP_BITMASK).  Counters are saturating uint64_t for shadow-phase
 * accumulation -- the active inference + feedback layers will land in
 * the follow-up units and bound the lifetime + decay policy.
 *
 * cmp_ip is current-kernel-only and optional: cross-kernel persistence
 * drops it on load (the kallsyms fingerprint on the on-disk file
 * already invalidates IP keys across rebuilds), so consumers must
 * tolerate a zero ip on a warm-started entry.
 *
 * range_direction / range_signedness / range_relation are populated
 * only for CMP_HYP_RANGE entries and participate in their dedup key;
 * for every other kind they are zero and ignored.
 */
struct cmp_hypothesis {
	unsigned int nr;
	bool do32;
	uint8_t width;			/* operand width in bytes: 1, 2, 4, or 8 */
	uint8_t kind;			/* enum cmp_hypothesis_kind */
	uint8_t state;			/* enum cmp_hypothesis_state */
	uint8_t score_bucket;
	uint8_t range_direction;	/* enum cmp_range_direction (RANGE only) */
	uint8_t range_signedness;	/* enum cmp_range_signedness (RANGE only) */
	uint8_t range_relation;		/* enum cmp_range_relation (RANGE only) */
	uint64_t cmp_ip;
	uint64_t lo;
	uint64_t hi;
	uint64_t mask;
	uint64_t exemplar;
	uint64_t seen_count;
	uint64_t consumed_count;
	/*
	 * Per-hypothesis SHADOW outcome counters.  Bumped by
	 * cmp_hyp_credit_outcome() on the would-have-been-chosen hypothesis
	 * resolved from a (cmp_ip, value, width) tuple at credit time.  Per
	 * the [11-feedback-loop] discipline cmp_novelty_wins is kept
	 * SEPARATE from pc_wins so harvested-but-flat CMP novelty cannot
	 * masquerade as a PC-edge conversion.  Saturating semantics: bumps
	 * are RELAXED, a u64 cannot realistically wrap inside any single
	 * fuzz run.  All fields are zero until a credit fires; the live
	 * pick path does NOT read them.
	 */
	uint64_t pc_wins;
	uint64_t transition_wins;
	uint64_t cmp_novelty_wins;
	uint64_t corpus_save_wins;
	uint64_t misses;
	uint64_t disabled_skips;
	uint64_t destructive_skips;
	uint64_t context_skips;
	uint64_t last_used_generation;
};

/*
 * Hard caps per syscall + per kind.  Keeps the store bounded under the
 * worst-case fuzz workload: a single syscall whose comparisons explode
 * across every kind can populate at most CMP_HYP_KIND_NR *
 * CMP_HYP_PER_KIND entries, and no single kind can starve the others
 * out of its slots.  cmp_hyp_observe() honours the partition via
 * per_kind_count[]: an exhausted kind bumps cmp_hyp_kind_full and
 * leaves the other kinds free, while an exhausted total bumps
 * cmp_hyp_pool_full.
 *
 * CMP_HYP_PER_KIND was raised from 2 to 16 after first telemetry: at 2,
 * cmp_hyp_kind_full ran ~2x cmp_hyp_observations (the EXACT and
 * ENUM_FAMILY lanes fire on every observation and saturate their two
 * slots almost immediately), so nearly every observation was dropped at
 * insert and the parallel store stayed effectively empty.  16 gives each
 * kind room for the distinct comparison sites a busy syscall exercises
 * while staying memory-bounded.
 *
 * Footprint is sizeof(struct cmp_hypothesis) (144 B) * CMP_HYP_PER_KIND *
 * CMP_HYP_KIND_NR per pool, over a hyp_pools[MAX_NR_SYSCALL][2] grid.  At
 * 16 that is 144 * 16 * 8 = 18432 B of entries per pool, ~18472 B per
 * pool with the header, and ~36 MiB across the 2048-pool grid (up from
 * ~4.6 MiB at 2).  The grid is shared memory allocated once at init; the
 * biarch [*][1] half is unused on uniarch builds, mirroring the existing
 * cmp_hint_pool grid's identical waste.
 */
#define CMP_HYP_PER_KIND	16U
#define CMP_HYP_PER_SYSCALL	(CMP_HYP_KIND_NR * CMP_HYP_PER_KIND)

struct cmp_hyp_pool {
	unsigned int count;
	unsigned int per_kind_count[CMP_HYP_KIND_NR];
	struct cmp_hypothesis entries[CMP_HYP_PER_SYSCALL];
};

/*
 * SHADOW per-hypothesis feedback outcome menu.  Each enumerator names a
 * channel cmp_hyp_credit_outcome() can credit to the would-have-been-
 * chosen hypothesis at the matching (nr, do32, cmp_ip, value, width)
 * tuple.  CMP_NOVELTY is deliberately a peer of PC_WIN rather than a
 * variant: harvested-but-flat novelty must never be folded into PC-edge
 * conversion accounting ([11-feedback-loop] discipline).  CORPUS_SAVE /
 * DESTRUCTIVE_SKIP / CONTEXT_SKIP are part of the published menu so the
 * struct is laid out for the consumer + skip-site wiring that lands in
 * follow-up units; until then those channels never fire and the per-
 * hypothesis counters stay zero.
 */
enum cmp_hyp_outcome {
	CMP_HYP_OUTCOME_PC_WIN,
	CMP_HYP_OUTCOME_TRANSITION_WIN,
	CMP_HYP_OUTCOME_CMP_NOVELTY,
	CMP_HYP_OUTCOME_CORPUS_SAVE,
	CMP_HYP_OUTCOME_MISS,
	CMP_HYP_OUTCOME_DISABLED,
	CMP_HYP_OUTCOME_DESTRUCTIVE_SKIP,
	CMP_HYP_OUTCOME_CONTEXT_SKIP,
	CMP_HYP_OUTCOME_NR,
};
