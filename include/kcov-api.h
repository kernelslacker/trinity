#pragma once

/* Public KCOV API: lifecycle, enable/disable, collect, plateau,
 * persistence, canary.  Split out of include/kcov.h.  All prototypes
 * assume struct kcov_child and struct kcov_shared visibility, which
 * kcov.h re-exports through the facade. */

#include "kcov-types.h"
#include "kcov-shared.h"

/* Called once from init_shm() to allocate shared coverage state. */
void kcov_init_global(void);

/* Called per-child to try to open/mmap the kcov fd.
 * child_id is a unique per-child identifier used for remote handles.
 * Sets kc->active = true only if kcov is usable. */
void kcov_init_child(struct kcov_child *kc, unsigned int child_id);

/* Called per-child on exit to clean up. */
void kcov_cleanup_child(struct kcov_child *kc);

/* Forward declaration -- kcov.h cannot include child.h (child.h
 * includes kcov.h for struct kcov_child), so the flush stub takes
 * a forward-declared childdata pointer. */
struct childdata;

/* Drain the per-child kcov_child_local_stats counters into the
 * shared kcov_shared atomics.  No-op stub today -- no bumper has been
 * migrated to the staging counters yet, so the flush has nothing to
 * publish. */
void kcov_child_flush_stats(struct childdata *child);

/* Bracket the actual syscall() call with these. No-ops if !active. */
void kcov_enable_trace(struct kcov_child *kc);
void kcov_enable_cmp(struct kcov_child *kc);
void kcov_enable_remote(struct kcov_child *kc, unsigned int child_id, unsigned int nr);
void kcov_disable(struct kcov_child *kc);

/* EXTRA_FORK bypass hook.  Called from do_extrafork() after the
 * grandchild ran the real syscall outside the parent worker's kcov
 * bracket.  Two responsibilities:
 *
 *   1. Zero the trace count header at trace_buf[0] (or cmp_trace_buf[0]
 *      for CMP-mode children) without touching the kcov ioctls so the
 *      next kcov_collect() / kcov_collect_cmp() on this child does not
 *      re-read the stale count left by the previous bracketed call
 *      and re-account the same PCs / cmp records against the current
 *      slot.  No-op when KCOV is disabled or the slot is inactive.
 *
 *   2. Bump per_syscall_extrafork_calls[nr] so the EXTRA_FORK dispatch
 *      is denominator-visible: without this the syscall has neither a
 *      per_syscall_calls[] bump (kcov_collect() skipped) nor a
 *      per_syscall_edges[] bump, and downstream edges/calls ratios
 *      mis-class it as dead weight.  Does NOT try to attribute
 *      grandchild coverage back to the parent -- that is a much larger
 *      change requiring a second kcov fd on the throwaway pid. */
void kcov_note_extrafork(struct kcov_child *kc, unsigned int nr);

bool kcov_bracket_begin(struct kcov_child *kc);
unsigned long kcov_bracket_end(struct kcov_child *kc,
				unsigned long op_nr);
unsigned long kcov_trace_pos(struct kcov_child *kc);
unsigned long kcov_sample_new_edges(struct kcov_child *kc, unsigned long *cursor);

/*
 * CMP-mode childop dispatch bracket.  Mode-exclusive counterpart of
 * the PC-side kcov_bracket_begin/end above: a child is PC-mode or
 * CMP-mode for life (kcov_init_child fixes the split with
 * KCOV_CMP_CHILD_RECIPROCAL), so on any single dispatch only one of
 * the two brackets opens; they share kc->bracket_owned for nesting
 * detection.
 *
 * kcov_cmp_bracket_begin returns true when the bracket took
 * ownership of the cmp_fd (caller must pair with
 * kcov_cmp_bracket_end), and false on every reject arm:
 *
 *   - kc inactive or shared state unavailable.  Bumps
 *     childop_cmp_brackets_skipped_inactive.
 *   - kc->mode != KCOV_MODE_CMP.  Bumps
 *     childop_cmp_brackets_skipped_pc_mode -- PC-mode children land
 *     on the PC bracket above; this one is the CMP-mode counterpart.
 *   - !kc->cmp_capable (probe failed or runtime KCOV_ENABLE flipped
 *     it false).  Bumps childop_cmp_brackets_skipped_incapable.
 *   - kc->bracket_owned already set (an outer bracket -- PC or CMP
 *     -- is in flight).  Bumps
 *     childop_cmp_brackets_skipped_nested.
 *
 * On a successful begin the per-bracket record / insert counters in
 * kcov.c are reset to zero so the §3.2 anti-domination caps measure
 * one childop dispatch at a time.
 */
bool kcov_cmp_bracket_begin(struct kcov_child *kc);
void kcov_cmp_bracket_end(struct kcov_child *kc);

/*
 * trinity_cmp_syscall() macro wraps a single childop syscall under
 * an open kcov_cmp_bracket.  The macro calls childop_cmp_reset()
 * immediately before the wrapped syscall (storing 0 to
 * cmp_trace_buf[0] so the next syscall overwrites from slot 0 -- the
 * kernel appends from the count word) and childop_cmp_collect()
 * immediately after, attributing the harvested records to the
 * supplied __NR_X.  Both helpers no-op on any child whose
 * bracket_owned bit is not set, so a stray call outside a bracket is
 * a counted skip rather than a misattribution.
 */
void childop_cmp_reset(struct kcov_child *kc);
void childop_cmp_collect(struct kcov_child *kc, unsigned int nr);

/* Per-bracket record + insert caps for the §3.2 anti-domination
 * defence.  Records exceeding the cap on a single bracket are
 * counted (kcov_shm->childop_cmp_record_cap_hits) and dropped from
 * harvest; insert-cap hits bump the matching insert counter.  Sized
 * generously vs typical childop fan-out (10..100 syscalls per
 * dispatch) so a normal childop never hits the caps; the caps catch
 * a runaway ioctl/sendmsg pulled into a childop. */
#define CHILDOP_CMP_BRACKET_RECORDS_CAP 1024U
#define CHILDOP_CMP_BRACKET_INSERTS_CAP 256U

/*
 * Per-childop KCOV attribution mode (--childop-kcov-attribution).
 *
 *   OFF  - childop dispatch path is unchanged; nothing is bracketed
 *          and childop_edges_clean[] stays at zero.  Consumers that
 *          read the clean signal (adapt_budget, canary queue) see
 *          zero edges per call in this mode and behave as they would
 *          on a build without KCOV: budget multipliers stay at unity
 *          and canary windows always demote on "zero_edges".  Use
 *          only when the bracket path itself is the suspect.
 *   DUAL - default.  Bracket every eligible childop and publish the
 *          per-call delta to childop_edges_clean[].  The existing
 *          global edges_found before/after delta path keeps writing
 *          childop_edges_discovered[] / childop_calls_with_edges[]
 *          as a diagnostic comparator -- operators can watch the
 *          discovered/clean ratio per op to validate the bracket
 *          coverage before remaining consumers (plateau snapshot)
 *          follow.
 *   ON   - reserved for retiring the discovered diagnostic counter.
 *          Currently identical to DUAL.
 */
enum childop_kcov_attribution_mode {
	CHILDOP_KCOV_ATTR_OFF = 0,
	CHILDOP_KCOV_ATTR_DUAL,
	CHILDOP_KCOV_ATTR_ON,
};

extern enum childop_kcov_attribution_mode childop_kcov_attr_mode;

/*
 * Childop CMP harvest mode (--childop-cmp-harvest).  Mirrors the
 * --kcov-transition-coverage / --frontier-saturation-cooldown A/B
 * pattern: a default-OFF behaviour-neutral knob that opens the
 * §3.2 hybrid bracket on a CMP-mode child at the childop dispatch
 * gate when flipped on.
 *
 *   OFF  - default.  The childop dispatch path is byte-identical to
 *          a build without this knob: kcov_cmp_bracket_begin is
 *          never called from child.c, no KCOV_ENABLE/DISABLE ioctls
 *          fire on the cmp_fd at childop boundaries, no
 *          trinity_cmp_syscall wrapper writes to the quarantine
 *          lane, and every childop_cmp_* shadow counter stays at
 *          zero.
 *   ON   - open the bracket on every CMP-mode child whose dispatch
 *          reaches the existing op_uses_outer_bracket gate; childop
 *          syscalls routed through trinity_cmp_syscall harvest
 *          their CMP operands into the quarantined
 *          childop_recent_pools[nr][do32] lane.  The lane is
 *          non-persisted and does NOT evict the durable
 *          per-syscall pool; promotion is a separate per-nr
 *          quota-gated C6 step.  Migration of individual childops
 *          to route through trinity_cmp_syscall is a per-childop
 *          C5 step earned by the §4 conversion chain.
 *
 * The two modes are kept distinct from --childop-kcov-attribution
 * (PC-side) -- a child is PC-mode OR CMP-mode for life
 * (kcov_init_child fixes the assignment), so the PC bracket and the
 * CMP bracket are mutually exclusive per child and dispatch from
 * the same child.c gate selects on kc->mode.
 */
enum childop_cmp_harvest_mode {
	CHILDOP_CMP_HARVEST_OFF = 0,
	CHILDOP_CMP_HARVEST_ON,
};

extern enum childop_cmp_harvest_mode childop_cmp_harvest_mode;

/*
 * --childop-cmp-consume knob mode.  Gates the SHADOW consume-side
 * resolver childop_cmp_value() at the childop field sites (see
 * cmp_hints/childop_consume.c and childops/net/rxrpc-key-install.c).
 *
 *   CHILDOP_CMP_CONSUME_OFF
 *      Default.  childop_cmp_value() short-circuits before any
 *      cmp_hints_try_get_ex() call and returns the caller's rng
 *      fallback verbatim.  Every childop_cmp_consume_* counter above
 *      stays at zero and the field-site pick stream is byte-for-byte
 *      identical to a build without this knob.
 *
 *   CHILDOP_CMP_CONSUME_ON
 *      Shadow-only: the resolver probes the durable per-nr pool via
 *      cmp_hints_try_get_ex() and bumps _would_pick / _would_miss /
 *      _would_value_differs on the outcome, but STILL returns the
 *      caller's rng fallback -- no arg is changed, no downstream
 *      behaviour differs.  The C0/C2 shadow ships this switch so
 *      the opportunity size is measurable before the C3/C4 live
 *      consume slice earns its own re-nod.
 *
 * The two modes are kept distinct from --childop-cmp-harvest: harvest
 * is producer-side (kernel CMP records into the quarantined childop
 * pool); consume is consumer-side (the resolver reads the pool and
 * shadow-scores what it would return).  The pool is shared, so a run
 * with harvest OFF and consume ON reads whatever the durable per-nr
 * pool was seeded with (warm-start, non-childop sites) -- it is not
 * a bug that consume can bump _would_pick with harvest off.
 */
enum childop_cmp_consume_mode {
	CHILDOP_CMP_CONSUME_OFF = 0,
	CHILDOP_CMP_CONSUME_ON,
};

extern enum childop_cmp_consume_mode childop_cmp_consume_mode;

/* Per-call PC-edge result struct, optionally filled by kcov_collect().
 *
 * The legacy new_edge_count out-param returns bucket_bits only -- the count
 * of (edge, bucket) bit-flips this call drove into kcov_shm->bucket_seen[].
 * That conflates "reached new code" with "flipped a new hit-count bucket on
 * already-warm code".  The result struct splits the signal three ways so
 * consumers can pick the right one without diffing global shm counters
 * (racy under concurrent children) or re-walking the trace:
 *
 *   bucket_bits
 *       Identical to the legacy new_edge_count: number of bucket-mask bit
 *       transitions 0->1 in bucket_seen[] this call.  A re-hit of a known
 *       PC that lands in a never-seen bucket still bumps this.
 *   distinct_edges
 *       True first-sighting count: number of PCs this call drove from
 *       bucket_seen[edge] == 0 (no bucket bit ever set) to non-zero.
 *       Filters out the bucket-churn component of bucket_bits, leaving
 *       only "new code reached" events.  Mirrors at the per-call
 *       granularity what kcov_shm->coverage.distinct_edges tracks globally.
 *   local_distinct_pcs
 *       Count of dedup_inc() first-sight events: distinct PCs walked
 *       in this call's trace buffer regardless of whether the global
 *       bitmap had already seen them.  A measure of the trace's own
 *       width independent of cross-run / cross-child history.
 *   transition_edges_real_local
 *       Number of transition slots this call flipped from 0 -> 1,
 *       filtered to the local kcov mode (zero for remote-mode traces
 *       per the kcov_transition_reward_mode contract).  Returned to
 *       the caller so the per-strategy reward attribution path can
 *       bump shm->stats.transition_edge_*_by_strategy[] without
 *       re-walking the trace; the strategy that owns the credit is
 *       only known to the caller via child->strategy_at_pick.  Zero
 *       when kcov_transition_coverage_mode is OFF (no transitions
 *       were counted) or kcov_transition_reward_mode is OFF (reward
 *       path disabled).
 *
 * All four are populated when result is non-NULL; pass NULL when only
 * the legacy bucket-bits signal is wanted.  No extra atomics: the
 * counters fall out of the existing PC walk. */
struct kcov_pc_result {
	unsigned long bucket_bits;
	unsigned long distinct_edges;
	unsigned long local_distinct_pcs;
	unsigned long transition_edges_real_local;
	/* Per-call PC trace length post-cap (count of PCs the kernel wrote
	 * into trace_buf this call, clamped at KCOV_TRACE_SIZE - 1 when the
	 * buffer filled).  Exposed so post-collect bookkeeping can recognise
	 * near-truncation calls -- a syscall whose trace approached the
	 * buffer ceiling executed a meaningful amount of kernel code even
	 * when bucket_bits / distinct_edges came back zero, the "deep but
	 * warm" shape the per_syscall_diag[].max_trace_size high-water mark
	 * tracks across the run.  Same cost discipline as the other fields:
	 * the value is the same `count` the trace_truncated / max_trace_size
	 * accounting above already computed, so populating it costs one
	 * extra store. */
	unsigned long trace_size;
};

/* After disabling, collect PCs and update the global bitmap.
 *
 * Returns true if new coverage was found (i.e. this call set at least one
 * never-seen bucket bit); the returned bool collapses the per-call count
 * to a {0,1} signal that the caller's name-and-shame attribution paths
 * already expect.
 *
 * If new_edge_count is non-NULL it is written with the actual number of
 * bucket bits this call flipped — the real edge-count signal, distinct
 * from the bool return.  Callers needing only the boolean signal pass
 * NULL.  Computed during the same pass that updates kcov_shm->coverage.edges_found,
 * so it costs no extra atomics: the caller would otherwise have to read
 * the global counter before/after and diff it, which is racy under
 * concurrent children that also bump the global.
 *
 * If result is non-NULL it is filled with the per-call counts described
 * on struct kcov_pc_result: bucket_bits (same value the new_edge_count
 * out-param would receive), distinct_edges (true first-sighting count,
 * filters bucket-churn out of bucket_bits), and local_distinct_pcs
 * (dedup_inc() first-sight events).  Pass NULL when only the legacy
 * bucket-bits signal is wanted; new_edge_count and result may be used
 * together or independently.
 *
 * nr is the syscall number for per-syscall edge tracking.  do32 is the
 * KCOV mode bit indicating 32-bit-record collection (snapshotted from the
 * child's current syscall record at set_syscall_nr time, matching how
 * kcov_collect_cmp already receives it).  Threaded into dedup_inc() and
 * reserved for per-syscall diagnostic indexing. */
bool kcov_collect(struct kcov_child *kc, unsigned int nr, bool do32,
		  unsigned long *new_edge_count,
		  struct kcov_pc_result *result);

/* After disabling, drain the CMP buffer into the per-syscall hint pool
 * and bump the CMP-records-collected counter.  No-op when cmp_capable
 * is false.  is_explorer is forwarded to bandit_cmp_observe() so the
 * explorer pool's novelty observations skip per-arm reward attribution
 * (they ran a different strategy than the bandit's current arm).
 * strategy_at_pick is the enum strategy_t snapshotted in set_syscall_nr
 * when this syscall was picked (or -1 for explorers / pre-first-pick);
 * forwarded so bandit_cmp_observe attributes CMP novelty to the arm
 * that picked the call rather than re-reading shm->current_strategy
 * (which may have rotated mid-syscall).
 *
 * Returns the count of bloom-novel KCOV_CMP_CONST constants observed
 * on this call (the bandit_cmp_observe return value).  0 means no
 * novelty; any positive value means "this call exercised at least one
 * new compile-time-constant comparison and is a candidate for
 * CMP-source corpus save".  Returns 0 when cmp_capable is false, the
 * buffer is empty, or the kernel only produced non-CONST records. */
unsigned long kcov_collect_cmp(struct kcov_child *kc, unsigned int nr,
			       bool do32, bool is_explorer,
			       int strategy_at_pick);

/*
 * Per-child kcov PC fd and cmp fd are protected from fuzz close /
 * dup2 / dup3 / close_range targeting via fd_is_protected() /
 * lowest_protected_fd_in_range() in include/fd.h -- the same registry
 * that protects STDERR_FILENO and the stderr capture memfd.  See those
 * declarations for the contract.
 */

/* Returns true if syscall nr hasn't found new edges recently.
 * Used by syscall selection to deprioritize saturated syscalls. */
bool kcov_syscall_is_cold(unsigned int nr);

/* Returns the recommended skip percentage (0-90) for syscall nr based on
 * how stale its coverage is.  0 means "not cold, don't skip"; otherwise
 * the value grows with the staleness gap so persistently cold syscalls
 * are deprioritized harder than ones that just crossed the threshold. */
unsigned int kcov_syscall_cold_skip_pct(unsigned int nr);

/* Sliding-window edge-rate plateau check.  Self-gates on
 * KCOV_PLATEAU_WINDOW_SEC, so the caller can invoke it once per
 * main_loop tick alongside the other periodic samplers.  Emits a
 * one-line PLATEAU warning to stats.log when the per-window edge
 * discovery rate drops below KCOV_PLATEAU_ENTER_THRESHOLD and a matching
 * PLATEAU CLEARED line when the rate climbs back above
 * KCOV_PLATEAU_EXIT_THRESHOLD (hysteresis band).  On the PLATEAU rising
 * edge it also fires strategy_plateau_response(), which forces a
 * strategy rotation into the plateau-intervention layer (RRC-biased
 * replay, anti-prior accept gating, or uniform random in a flat
 * round-robin -- the rotation does not pin a mode based on the
 * hypothesis classifier).  Interventions unwind on CLEARED. */
void kcov_plateau_check(void);

/* Mid-run snapshot cadence for kcov_bitmap_maybe_snapshot().  The bitmap
 * is 8 MB and writing it is bursty I/O, so the triggers are coarser than
 * the minicorpus snapshot interval: 1000 new edges OR 300s since the
 * last save, whichever fires first.  Hardcoded -- no operator knob,
 * fleet boxes shouldn't need to retune. */
#define KCOV_BITMAP_SNAPSHOT_EDGES		1000UL
#define KCOV_BITMAP_SNAPSHOT_INTERVAL_SEC	300UL

/* Warm-start persistence for the kcov_shm bucket_seen[] hit-count bitmap
 * and the edges_found counter.  Save/load are gated on a kernel-binary
 * fingerprint -- sha256 over /proc/kallsyms with the address column
 * stripped -- so a rebuilt kernel (even with an unchanged utsname.release
 * / utsname.version pair) gets a fresh bitmap instead of loading stale
 * data against a different edge layout.  The address-stripping step
 * makes the fingerprint identical whether kallsyms is read as root or
 * non-root (kptr_restrict zeroes the addresses for the latter) and also
 * invariant across KASLR vs nokaslr boots of the same build.  Stale or
 * unreadable files are silently discarded and the loader returns false;
 * cold-start is the legitimate first-run state. */
bool kcov_bitmap_save_file(const char *path);
bool kcov_bitmap_load_file(const char *path);
const char *kcov_bitmap_default_path(void);

/* Fill OUT[32] with the cached kallsyms-derived kernel fingerprint
 * (sha256 over /proc/kallsyms with the leading address column stripped
 * and module / BPF runtime symbols filtered out -- see the comment on
 * kcov_fingerprint_kernel() for the precise filter rules).  First call
 * streams /proc/kallsyms and caches; subsequent calls memcpy from the
 * cache.  Returns false (with OUT untouched) when /proc/kallsyms is
 * unreadable; caller should treat that as "warm-start disabled this
 * run".  Exposed so cross-run-state files outside kcov.c (e.g. the
 * cmp-hints pool) can stamp the same fingerprint into their headers
 * and stay in lock-step with the kcov-bitmap warm-start invariants. */
bool kcov_get_kernel_fp(uint8_t out[32]);

/* Read-only accessor for the runtime kernel-text base resolved by
 * kcov_init_global from /proc/kallsyms.  Zero means the lookup failed
 * (kallsyms unreadable, _text/_stext absent, or kptr_restrict zeroed
 * every address) and the run is hashing kernel addresses raw.  Exposed
 * so cross-run-state writers outside kcov.c (the cmp-hints pool) can
 * stamp the same value into their on-disk headers and reject a
 * canonical-vs-raw mismatch on load, matching the kcov-bitmap header's
 * kaslr_base field. */
uint64_t kcov_kaslr_base_value(void);

/* Strip the runtime KASLR base from a kernel comparison-instruction
 * address before it enters the cmp-hints bloom + per-syscall pool +
 * persisted state file.  Companion to kcov_canon_pc (the PC-coverage
 * canonicaliser) -- same arithmetic, separate named entry point so the
 * cmp-hint canonicalisation invariant can be enforced in isolation by
 * scripts/check-static/cmp-hints-canonicalise-cmp-ip.sh.  Returns the
 * argument unchanged on systems where kcov_kaslr_base stayed zero. */
unsigned long kcov_canon_cmp_ip(unsigned long ip);

/* Wire periodic mid-run snapshots of the bucket_seen bitmap to PATH.
 * Subsequent kcov_bitmap_maybe_snapshot() calls become live; a no-op
 * before this is called.  Path is copied. */
void kcov_bitmap_enable_snapshots(const char *path);

/* Cheap per-tick gate: writes the snapshot if either trigger has elapsed
 * since the last successful save, otherwise returns immediately.  Called
 * from the parent's stats tick and from kcov_plateau_check() when a
 * plateau is first entered. */
void kcov_bitmap_maybe_snapshot(void);

/* Mid-run cadence for kcov_bitmap_canary_check(): how often the parent
 * popcount-scans bucket_seen[] to verify the by-construction identity
 * popcount(bucket_seen) == edges_found.  Bits in bucket_seen[] never
 * clear in healthy operation, so a measurable deficit is evidence of a
 * stray writer scribbling bits and the operator wants to see it surface
 * near the corruption window instead of at the next save.  300s mirrors
 * the bitmap snapshot interval -- the canary is a cheap (~ms) prefix to
 * the same write the snapshot path will run -- and the in-source
 * threshold KCOV_BITMAP_CANARY_DEFICIT below keeps memory-ordering
 * noise from being mistaken for damage.  Hardcoded; no operator knob. */
#define KCOV_BITMAP_CANARY_INTERVAL_SEC		300UL

/* Per-check tolerance for the popcount-vs-edges_found deficit.  The
 * kcov_collect() hot path bumps edges_found RELAXED after the matching
 * fetch_or on bucket_seen[], so a canary scan racing with steady-state
 * writers can observe a small short-lived skew without any corruption
 * present (writes still propagating across CPUs, store-buffer fold-in,
 * scan cursor passing a byte before the bit transition becomes visible).
 * 1024 sits well above the realistic per-scan jitter on a busy fleet
 * host (high ~10s of bits) and well below any plausible wild-write
 * blast radius (a single page-clear is 32k bits), so the threshold
 * distinguishes the two without arming a false-positive alarm. */
#define KCOV_BITMAP_CANARY_DEFICIT		1024UL

/* Self-rate-limited integrity probe: sample edges_found, popcount the
 * full bucket_seen[] table, alarm when the deficit (edges_before -
 * popcount) exceeds KCOV_BITMAP_CANARY_DEFICIT.  Always bumps the
 * per-check denominator stat; bumps the deficit-alarm numerator on
 * mismatch and emits a one-line CANARY warning to stats.log with the
 * deficit magnitude so the operator can correlate against the wild-
 * write window.  Called once per main_loop tick alongside the other
 * periodic samplers; the KCOV_BITMAP_CANARY_INTERVAL_SEC gate keeps
 * the 8 MB scan from running on every tick. */
void kcov_bitmap_canary_check(void);
