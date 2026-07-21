#pragma once

#include "locks.h"
#include "struct_catalog.h"
#include "syscall.h"

/*
 * Coverage-guided argument retention (mini-corpus).
 *
 * When a syscall invocation discovers new KCOV edges, its argument
 * values are saved in a per-syscall ring buffer. During argument
 * generation, a saved arg set may be replayed with small mutations
 * instead of generating entirely fresh values.
 *
 * SAFETY: Only syscalls WITHOUT a sanitise callback are eligible.
 * 65 of 346 syscalls have sanitise callbacks that allocate and stash
 * pointers into arg slots. Replaying those stale pointer values
 * would cause use-after-free. The has_sanitise check gates both
 * save and replay.
 */

/* Why an arg set is admitted to the corpus.
 *
 * PC: the original signal -- kcov_collect() returned a new PC-bucket
 * edge for this syscall.  Gold standard for "this argument
 * neighbourhood reaches code we hadn't reached before".
 *
 * CMP: a new bloom-distinct compile-time-constant comparison fired
 * for this syscall (bandit_cmp_observe returned > 0) but no new
 * PC-bucket edge.  Catches argument neighbourhoods that exercise new
 * comparisons even when the resulting branch lands inside
 * already-covered PC buckets -- the exact gap revealed by the
 * cmp_rising_pc_flat plateau diagnostic.
 *
 * ERRNO: a per-syscall errno bucket fired for the first time in this
 * run window (excluding EFAULT, the userspace-pointer noise floor).
 * Errno buckets encode validator-gate progress
 * (EFAULT -> EINVAL -> EPERM/EBADF -> EAGAIN/0) for syscalls where
 * PC-edge reward is too sparse to drive admission.  Gated behind the
 * --corpus-save-errno-grad-live A/B flag: when off (default) the
 * trigger only bumps the would-save shadow counter and does not
 * admit; when on it admits as a normal CORPUS_SAVE_REASON_ERRNO save.
 *
 * The numeric IDs back saves_by_reason[]: re-ordering or inserting a
 * new reason between PC and CMP would silently re-bucket existing
 * stats.  Append-only.
 */
enum corpus_save_reason {
	CORPUS_SAVE_REASON_PC = 0,
	CORPUS_SAVE_REASON_CMP = 1,
	CORPUS_SAVE_REASON_ERRNO = 2,
	CORPUS_SAVE_NR_REASONS,
};

/* Number of arg snapshots retained per syscall number.
 *
 * 8 was sized for the original syscall set and very short runs.  Anything
 * busier — long fuzzing sessions, or syscalls that find new edges in
 * bursts — evicted promising snapshots before they got a chance to be
 * replayed.  32 slots (~1.8 MB total shared memory across MAX_NR_SYSCALL
 * rings) widens the replay window without burning meaningful memory. */
#define CORPUS_RING_SIZE 32

struct corpus_entry {
	unsigned long args[6];
	unsigned int num_args;
	/* Replays of this entry that have produced novel coverage in the
	 * past.  Used by the sharpened mutator-win attribution path
	 * (minicorpus_mut_attrib_commit): the FIRST productive replay of an
	 * entry establishes the entry's intrinsic novelty baseline and is
	 * NOT credited to any mutator op -- the saved args already pointed
	 * at unexplored territory, the mutation didn't cause it.  Subsequent
	 * productive replays cross the baseline and credit the mutator.
	 *
	 * Atomic accessed via __atomic_*.  Initialised to 0 by the memset
	 * in minicorpus_save_with_reason; warm-start loader zeroes it
	 * explicitly when overwriting a recycled ring slot whose old entry
	 * had accumulated baseline. */
	unsigned int novel_replay_hits;
	/* Provenance tag: true iff the args were captured while the saving
	 * child was inside redqueen_reexec_step (i.e. child->in_reexec was
	 * set when minicorpus_save_with_reason ran).  Observability only --
	 * no mutator / selection / injection path consults this; it exists
	 * so a later replay of this entry can mark the replaying child as
	 * being on a RedQueen-sourced trajectory, which lets
	 * frontier_record_new_edge() credit downstream PC-edge wins to a
	 * separate rq_sourced_pcedge_wins_per_syscall[] counter.  Zeroed
	 * along with the rest of the struct by the memset in
	 * minicorpus_save_with_reason; warm-start loader leaves it at the
	 * persisted value (no separate clear needed). */
	bool rq_sourced;
	/* Provenance tag: true iff the entry was admitted via
	 * CORPUS_SAVE_REASON_ERRNO -- the errno-gradient-save trigger
	 * that fires on the first non-EFAULT errno bucket per syscall per
	 * run window.  Observability only -- propagates through
	 * minicorpus_replay() into childdata::replay_errno_sourced so
	 * frontier_record_new_edge() can credit downstream PC-edge wins to
	 * errno_sourced_pcedge_wins_per_syscall[], the errno-source
	 * counterpart of the rq_sourced wins array.  Zeroed by the memset
	 * in minicorpus_save_with_reason; warm-start loader leaves it at
	 * the persisted value (the on-disk format carries only args/num_args,
	 * so a warm-started entry reads as PC-sourced, matching rq_sourced). */
	bool errno_sourced;
};

struct corpus_ring {
	lock_t lock;
	unsigned int head;		/* next write slot (mod CORPUS_RING_SIZE) */
	unsigned int count;		/* entries stored (max CORPUS_RING_SIZE) */
	struct corpus_entry entries[CORPUS_RING_SIZE];
	/* Writer-pinning canary (see --writer-pin-sweep).  Reserved
	 * field, NOT padding: stamped once at minicorpus_init() with
	 * WP_CANARY_MAGIC and never legitimately written again.  The
	 * per-syscall sweep in syscall_ret_validate_phase() reads it
	 * (and the count<=CORPUS_RING_SIZE invariant) to detect wild
	 * writes into the shared minicorpus region; the address of the
	 * violated word is the deliverable that feeds the Stage-2
	 * --writer-watch HW breakpoint.  Default-off path is byte-
	 * identical apart from the one-time init stamp (8 bytes per
	 * ring, ~8 KB total). */
	uint64_t wp_canary;
};

/* WPCANARY! (LE).  Picked for human-readability in a hexdump and so a
 * random scribble is statistically very unlikely to forge it. */
#define WP_CANARY_MAGIC	0x5750434e41525921ULL

/* Number of distinct primitive mutator cases inside mutate_arg().
 * The numerical IDs (0=bit-flip, 1=add, 2=sub, 3=boundary, 4=byte-shuffle,
 * 5=keep, 6=bswap-add, 7=bswap-sub, 8=fd-swap) are stable — weighted
 * scheduling counters are indexed by them and any reordering must be
 * reflected in mut_trials/mut_wins below.
 *
 * Cases 6/7 are endian-aware add/sub: byte-swap the value at a
 * randomly-picked width (16/32/64), apply the delta, swap back.  This
 * reaches arithmetic neighbours of values that the kernel interprets
 * with ntohs/ntohl (sockaddr ports, raw IP headers, netfilter rules,
 * netlink BE attrs) — values that look like noise to a native-endian
 * add/sub mutator.
 *
 * Case 8 is fd-pool cross-pollination: only meaningful for fd-typed
 * args (ARG_FD and the typed ARG_FD_* family).  With ~50% probability
 * it replaces the slot with a different live fd drawn from the global
 * pool — any flavour, not necessarily the slot's declared type — so
 * the kernel sees fd cross-feeds (e.g. a timerfd handed to an io_uring
 * register call).  The other ~50% applies a small integer mutation
 * inline so the slot still sees arithmetic-neighbour exploration.  The
 * weighted scheduler zeros this case for non-fd args, so picks here
 * are never wasted on numeric slots. */
#define MUT_NUM_OPS 9

/* Maximum mutation stacking depth per argument (see pick_stack_depth()). */
#define STACK_MAX 4

struct minicorpus_shared {
	struct corpus_ring rings[MAX_NR_SYSCALL];
	/* Per-mutator-case productivity counters used by weighted pick:
	 *   mut_trials[op] = times case `op` was selected fleet-wide
	 *   mut_wins[op]   = times a call whose mutations included `op`
	 *                    discovered new coverage
	 * Both updated via __atomic ops; consumed by weighted_pick_case()
	 * in minicorpus.c. */
	unsigned long mut_trials[MUT_NUM_OPS];
	unsigned long mut_wins[MUT_NUM_OPS];
	/* Structure-aware mutator productivity, parallel to
	 * mut_trials/mut_wins.  Bumped only when mutate_arg picked op `i`
	 * AND the arg's type carried structural metadata (ARG_LIST /
	 * ARG_OP / ARG_RANGE) so the type-aware variant fired instead of
	 * the byte-level op.  The ratio mut_structured_wins[i] /
	 * mut_structured_trials[i] is the structured win rate per op; the
	 * difference against the aggregate mut_wins[i] / mut_trials[i]
	 * shows whether structured firings outperform the unstructured
	 * fallback.  Measurement-only: these are not consumed by the
	 * bandit yet; compare the structured win rate against the
	 * aggregate mutator win rate before promoting them into scheduling
	 * input.  Coupled arg slots (FD, ADDRESS, PTR, LEN) never satisfy
	 * the structural-metadata gate so they cannot bump these counters
	 * even by accident. */
	unsigned long mut_structured_trials[MUT_NUM_OPS];
	unsigned long mut_structured_wins[MUT_NUM_OPS];
	/*
	 * Per-tag productivity for the struct-buffer post-fill mutator
	 * (struct_field_mutate_one).  Bumped exactly once per mutated call
	 * (the gated entry point picks at most one field per invocation),
	 * so attribution is exact and there is no stack-depth inflation to
	 * subtract.  Separate from the MUT_NUM_OPS counters above because
	 * the injection point is different (post-fill in-buffer vs
	 * top-level scalar) and a later bandit pass needs to weight the two
	 * arms independently.  Indexed by enum field_tag with FT_NUM_TAGS
	 * as the trailing sentinel; skip-listed tag slots simply stay
	 * zero because their fields are filtered out at candidate
	 * collection time.  RELAXED atomics; read at dump_stats() time
	 * the same shape as saves_by_reason[].
	 */
	unsigned long mut_struct_field_trials[FT_NUM_TAGS];
	unsigned long mut_struct_field_wins[FT_NUM_TAGS];
	/* Replay-path measurement counters for the mutation trio.
	 * All updated via __atomic RELAXED; read at dump_stats() time. */
	unsigned long replay_count;		/* replays that ran (returned true) */
	unsigned long replay_wins;		/* replays that found new coverage */
	unsigned long splice_hits;		/* per-arg splice firings */
	unsigned long splice_wins;		/* replays with splice that found new coverage */
	/* Cross-syscall value propagation (xprop): bumped once per per-arg
	 * draw that pulled a value from another syscall's corpus pool (see
	 * minicorpus_pick_from_other_syscall).  Sibling to splice_hits --
	 * splice shuffles values within one snapshot, xprop shuffles them
	 * across syscalls.  RELAXED atomic. */
	unsigned long xprop_hits;
	unsigned long xprop_wins;		/* replays with xprop that found new coverage */
	/* xprop source/target type-hit rate accounting.
	 * xprop_attempts is the denominator (bumped at every entry into
	 * minicorpus_pick_from_other_syscall regardless of outcome); the
	 * three reject counters split the !hit path by reason so the
	 * type-hit rate is xprop_hits / xprop_attempts and the dominant
	 * reject cause is the largest of the three.  These exist to
	 * surface the realised hit-rate the typed cross-syscall
	 * propagation row is gated on (the typed-bucket index is
	 * only worth building if the current uniform-pick path is
	 * actually dominated by type-mismatch rejects). */
	unsigned long xprop_attempts;
	unsigned long xprop_reject_target_not_fdarg;
	unsigned long xprop_reject_src_self;
	unsigned long xprop_reject_src_empty;
	/* Distribution of stacking depths chosen by pick_stack_depth().
	 * Index is the depth value (1..STACK_MAX); index 0 is unused. */
	unsigned long stack_depth_histogram[STACK_MAX + 1];

	/* Sequence-chain telemetry.  chain_iter_count is bumped
	 * once per chain dispatched; chain_substitution_count is bumped
	 * each time a step's arg slot was overwritten with the previous
	 * step's return value.  The ratio measures the realised substitution
	 * frequency and lets the gating probability inside the chain
	 * executor be tuned against observed coverage outcomes. */
	unsigned long chain_iter_count;
	unsigned long chain_substitution_count;

	/* Edge-count high-water-mark for the last periodic mid-run snapshot.
	 * minicorpus_maybe_snapshot() compares kcov_shm->coverage.edges_found against
	 * this value and, when the gap reaches MINICORPUS_SNAPSHOT_EDGES, races
	 * to advance the field via compare-exchange.  The single CAS winner
	 * triggers the save; losers see the new high-water-mark on their next
	 * call and early-return until another window's worth of edges
	 * accumulates. */
	unsigned long edges_at_last_snapshot;

	/* Per-reason corpus-save counters.  Bumped inside
	 * minicorpus_save_with_reason() once the entry has been admitted
	 * (post-corpus_args_replayable filter and post-ring-insert) so the
	 * count reflects entries that actually made it into the ring, not
	 * candidates that were rejected.  Lets dump_stats answer "is the
	 * CMP-source promotion path firing, and at what rate vs the
	 * original PC-source path?".
	 *
	 * Indexed by enum corpus_save_reason.  RELAXED atomics: dashboards
	 * read these once per dump, no ordering constraint with the entry
	 * insert that just preceded the bump. */
	unsigned long saves_by_reason[CORPUS_SAVE_NR_REASONS];

	/* Ring-overwrite count per reason.  Bumped
	 * inside minicorpus_save_with_reason() when the admitting
	 * ring already held CORPUS_RING_SIZE entries (cur_count ==
	 * CORPUS_RING_SIZE), so the incoming save is overwriting the
	 * oldest existing slot.  Indexed by the *incoming* save's
	 * reason — i.e. the save that caused the eviction — so the
	 * ratio evicts_by_reason[r] / saves_by_reason[r] is the
	 * realised "fraction of reason-r saves that displaced
	 * something" rate the stratified mini-corpus replacement
	 * row is gated on (a high CMP-evict rate means
	 * CMP saves are pushing PC saves out at FIFO discipline). */
	unsigned long evicts_by_reason[CORPUS_SAVE_NR_REASONS];

	/* Replay wins binned by source-entry age at
	 * pick time.  Bumped from minicorpus_mut_attrib_commit()
	 * on found_new when a replay source slot was tracked.
	 * Bucket index = floor(log2(age_in_slots)) + 1, saturating
	 * at the last bucket; age is (head - 1 - slot) mod
	 * CORPUS_RING_SIZE captured at minicorpus_replay() pick
	 * time, so bucket 0 is the newest entry and the highest
	 * bucket the oldest CORPUS_RING_SIZE-1 distance.
	 *   0: age 0    (newest)
	 *   1: age 1
	 *   2: age 2..3
	 *   3: age 4..7
	 *   4: age 8..15
	 *   5: age 16..31  (oldest in a 32-slot ring)
	 * Surfaces whether wins concentrate in fresh entries
	 * (FIFO is fine) or spread across the ring (a protected
	 * top-K is justified), the question the
	 * stratified mini-corpus replay policy hangs on. */
	unsigned long replay_wins_by_age[6];

	/* Plateau intervention (cmp_rising_pc_flat): count of
	 * replay slot picks that took the recent-K narrowed path because
	 * the classifier had the fleet in the CMP_RISING_PC_FLAT regime.
	 * Tracks how many replays were biased toward CMP-source material
	 * during plateau windows; cross-reference with mut_attrib_cmp_wins
	 * to see whether the bias correlated with win attribution.  Bumps
	 * only when the burst predicate is active AND the ring held at
	 * least K_RECENT entries (small rings fall through to the default
	 * uniform-over-count pick).  RELAXED atomic. */
	unsigned long cmp_rising_replay_picks;

	/* Mutator wins attributed to CMP-source novelty (i.e. the subset
	 * of mut_wins[] that came from CMP-novel calls rather than
	 * PC-novel calls).  Tracked here as a single scalar -- not a
	 * per-case array -- because we only need the aggregate to verify
	 * the new attribution path is firing.  The bandit-weighting math
	 * in weighted_pick_case() keeps reading mut_wins[]/mut_trials[]
	 * unchanged so the picker's behaviour stays untouched by this
	 * accounting addition. */
	unsigned long mut_attrib_cmp_wins;

	/* SHADOW measurement for the Phase C.3 structure-aware arm picker.
	 * mut_structured_shadow_samples is bumped each time mutate_arg
	 * picks an op on a slot whose argtype + arg_param metadata makes
	 * it eligible for structured firing (ARG_LIST / ARG_OP / ARG_RANGE
	 * with a non-degenerate values / range payload).  Of those samples,
	 * mut_structured_shadow_divergences counts the subset where a
	 * parallel shadow picker -- one that adds the existing
	 * mut_structured_trials / mut_structured_wins per-op stats as a
	 * second Beta arm alongside the live mut_trials / mut_wins arm and
	 * draws from the doubled 2 * MUT_NUM_OPS pool -- would have selected
	 * a different op than the live picker did.  The shadow draw does
	 * not influence the live pick; mutate_arg keeps calling
	 * weighted_pick_case() exactly as before and the live op is what
	 * fires.  Read at dump_stats() time; RELAXED atomics.  Promoting
	 * the structured arm to the live picker will consume this
	 * measurement, not be gated on a separate knob -- the SHADOW commit
	 * exists so the promotion's downstream effect on op distribution
	 * can be quantified before behaviour changes.
	 *
	 * Arm-gated by the per-child mut_structured_arm_b stamp (see
	 * include/child.h): only Arm B children call the shadow picker, so
	 * mut_structured_shadow_samples / mut_structured_shadow_divergences
	 * accumulate exclusively from the Arm B half of the fleet.  Arm A
	 * children short-circuit before the shadow draw, leaving mutate_arg's
	 * RNG byte-identical to the pre-shadow control.  The realised cohort
	 * split is captured in mut_structured_arm_{a,b}_children below so a
	 * small-fleet ONE_IN(2) split that landed lopsided can be normalised
	 * out of the divergence rate. */
	unsigned long mut_structured_shadow_samples;
	unsigned long mut_structured_shadow_divergences;

	/* A/B cohort split for the SHADOW structure-aware arm picker.
	 * mut_structured_arm_{a,b}_children is bumped once per child in
	 * init_child_runtime_config so the operator can normalise the Arm B
	 * shadow divergence rate against the realised population split (the
	 * ONE_IN(2) stamp has fleet-scale variance and a small fleet can land
	 * lopsided).  No symmetric arm_a fire counter exists by design: the
	 * control arm short-circuits before the shadow draw, so the only
	 * fire-side counter is mut_structured_shadow_divergences above (which
	 * is itself Arm-B-only because samples is Arm-B-only). */
	unsigned int  mut_structured_arm_a_children;
	unsigned int  mut_structured_arm_b_children;

	/* Monotonic mutation counter.  Bumped via __atomic_fetch_add on every
	 * ring-entry insert (minicorpus_save) and every entry admitted from the
	 * warm-start loader (minicorpus_load_file).  minicorpus_save_file
	 * compares this against a parent-private baseline; when equal, the
	 * on-disk image is bit-for-bit identical to what we already wrote and
	 * the save is skipped.  RELAXED order is sufficient -- the counter only
	 * gates whether to write, not what to write (the per-ring lock taken by
	 * the serialiser provides the ordering for the entries[] contents). */
	unsigned long mutations;

	/* Parent-tick scan accelerator; incremented before ring->lock acquire,
	 * decremented after release.  check_all_locks may skip the family when
	 * zero. */
	unsigned long held_count;

	/* Post-replay perturbation counters (see MINICORPUS_PERTURB_DENOM
	 * below).  replay_perturbed_count is bumped once per replay on
	 * which a light FT_FLAGS/FT_RANGE neighbour mutation actually
	 * landed on a cataloged struct-ptr arg; replay_perturbed_wins is
	 * bumped in minicorpus_mut_attrib_commit when such a replay found
	 * new coverage.  The verbatim yield is derived by subtracting the
	 * perturbed counters from replay_count / replay_wins above, so
	 * both arms are readable from one dump without a symmetric
	 * verbatim counter.  Bumped RELAXED, read at dump time.  Exists
	 * so the perturbed-vs-verbatim edge yield ratio can be measured
	 * before anyone promotes perturbation to always-on. */
	unsigned long replay_perturbed_count;
	unsigned long replay_perturbed_wins;

	/* Aggregate count of lockless-reader num_args validator failures;
	 * non-zero means torn reads ARE happening at this rate.  Bumped on
	 * each [1, 6] out-of-range snapshot.num_args observed by the xprop
	 * pick, replay common, and replay burst readers (the three sites
	 * that dropped ring->lock).  Single field rather than per-ring: the
	 * counter exists to answer "is the validator firing at a non-trivial
	 * rate fleet-wide?" at dashboard scale, not "which ring is hot
	 * enough to tear", so 1024 atomic counter slots for per-syscall
	 * granularity would buy nothing currently consumed.  RELAXED. */
	unsigned long replay_torn_rejects;
};

extern struct minicorpus_shared *minicorpus_shm;

/* Called once from init_shm() to allocate shared corpus storage. */
void minicorpus_init(void);

/* Stage-1 detector for the writer-pinning canary (--writer-pin-sweep).
 * Scans every ring's wp_canary against WP_CANARY_MAGIC and the
 * documented count<=CORPUS_RING_SIZE invariant.  On the first
 * violation, writes the violated word's address into *bad_addr and the
 * observed bad value into *bad_val, then returns true.  Returns false
 * if the region is intact (or minicorpus_shm is NULL).
 *
 * Cache-friendly: one strided pass, pure loads, no atomic ops.  Async-
 * signal-safe (no libc, no allocator) -- called from
 * syscall_ret_validate_phase() in normal child context, but the no-libc
 * property keeps it usable from anywhere if a future caller wants it.
 *
 * NB: a sweep hit names the VICTIM/observer context, not the wild
 * writer.  Stage-2 --writer-watch is the writer-namer; this sweep just
 * hands an address to Stage 2. */
bool minicorpus_wp_sweep(unsigned long *bad_addr, uint64_t *bad_val);

/* Save a syscall's args into the corpus ring for its syscall number.
 * Only call when entry->sanitise == NULL.  Thin wrapper that records
 * the save against the PC-source bucket -- equivalent to
 * minicorpus_save_with_reason(rec, CORPUS_SAVE_REASON_PC) and kept as
 * the legacy entry point so existing call sites (the PC-edge gate in
 * random-syscall.c) don't have to change. */
void minicorpus_save(struct syscallrecord *rec);

/* Save a syscall's args into the corpus ring with the @reason that
 * triggered the save.  Same admission filter as minicorpus_save() --
 * sanitise-callback syscalls and pointer-heavy argtypes are still
 * rejected, so CMP-source saves carry the same replay-safety
 * guarantees as PC-source saves.  Bumps saves_by_reason[reason] on
 * successful insert. */
void minicorpus_save_with_reason(struct syscallrecord *rec,
				 enum corpus_save_reason reason);

/* Try to replay a saved arg set with mutations into rec.
 * Returns true if replay was performed, false if no corpus entry
 * was available or the dice roll said to generate fresh args.
 * Only call when entry->sanitise == NULL. */
bool minicorpus_replay(struct syscallrecord *rec);

/* Post-replay perturbation fraction (1-in-N gate).  Single tunable so
 * an operator can trivially lift or drop the perturbation rate; also
 * lets the perturbation be disabled outright by driving the roll to
 * never fire (define to 0 -- ONE_IN() short-circuits on zero).
 * Kept small so verbatim replay stays the dominant path. */
#define MINICORPUS_PERTURB_DENOM	32U

/* Mark the current process's pending mutator attribution as having
 * applied a post-replay perturbation on a cataloged struct-ptr arg.
 * Consumed and cleared by the next minicorpus_mut_attrib_commit()
 * call, which bumps replay_perturbed_wins iff found_new was set.
 * At most one perturbation per replay by construction (the caller
 * picks a single field per invocation).  The count-side bump
 * (replay_perturbed_count) is the caller's responsibility so the
 * count is a "landed" measurement, not a "flagged" one -- attribution
 * and count would drift if a caller marked but then decided not to
 * perturb, so they are held on opposite sides of the same event. */
void minicorpus_replay_perturbation_mark(void);

/* Apply the per-arg mutator chain (cross-arg splice + weighted-stack
 * mutate + fd safety) to args[6] in place.  Used by both per-syscall
 * mini-corpus replay and chain-corpus replay so the mutation engine
 * and its productivity counters are shared.  @entry supplies argtype[]
 * and num_args; pass NULL-checked entry.  @nr is the syscall table
 * index — consumed by the xprop branch to scope the cross-syscall
 * source pool. */
void minicorpus_mutate_args(unsigned long args[6], struct syscallentry *entry,
		unsigned int nr);

/* Mutator-case attribution.
 *
 * mutate_arg() accumulates per-case pick counts in a process-local stash
 * during arg generation.  After the syscall completes the post-coverage
 * path calls commit() exactly once, folding the stash into shm-wide
 * trials and (if found_new) wins, then clearing the stash.  Skipping the
 * commit on a syscall would mis-attribute its mutations to the next
 * syscall's coverage event. */
void minicorpus_mut_attrib_commit(bool found_new);

/* Tag the current process's pending mutator attribution as having
 * been driven by CMP-source novelty (rather than the default PC-source
 * novelty).  Called between mutate_arg() and
 * minicorpus_mut_attrib_commit() on calls where the post-syscall
 * coverage signal was CMP-bloom novelty.  The flag is consumed and
 * cleared by the next commit() call; commit() bumps
 * minicorpus_shm->mut_attrib_cmp_wins once iff found_new && the flag
 * was set, so we can tell PC-sourced wins from CMP-sourced wins in
 * stats without changing the bandit-weighting inputs (mut_wins[] /
 * mut_trials[]) it consults. */
void minicorpus_mut_attrib_set_cmp_source(void);

/* Tag the current process's pending mutator attribution as having
 * applied a post-fill struct-field mutation with tag @tag.  Called
 * by struct_field_mutate_one() right after a mutation lands; consumed
 * and cleared by the next minicorpus_mut_attrib_commit() call, which
 * bumps mut_struct_field_trials[tag] unconditionally and
 * mut_struct_field_wins[tag] iff the commit's found_new flag is set.
 * At most one tag per call -- struct_field_mutate_one only ever mutates
 * a single field per invocation -- so attribution is exact and there is
 * no per-stack-pick inflation to subtract. */
void minicorpus_struct_field_attrib(enum field_tag tag);

/* Persist the in-memory corpus rings to a file at @path.
 * Writes via a per-pid .tmp file and renames atomically — safe under
 * concurrent callers (CAS in minicorpus_maybe_snapshot serialises
 * normal periodic saves, the per-pid suffix is belt-and-braces against
 * a periodic save racing the on-shutdown save).  Returns true on
 * success, false on any I/O failure (caller should treat as advisory). */
bool minicorpus_save_file(const char *path);

/* Load a previously-persisted corpus from @path into the rings.
 * Discards entries silently when the file is missing, the magic/version
 * header doesn't match, the kernel major.minor differs from the running
 * kernel, or a per-entry CRC fails.
 *
 * @loaded and @discarded receive counts for stats reporting; either may
 * be NULL.  Returns true if at least one entry was loaded. */
bool minicorpus_load_file(const char *path,
		unsigned int *loaded, unsigned int *discarded);

/* Default per-arch persistence path (e.g. ~/.cache/trinity/corpus/x86_64).
 * Returned pointer is owned by the callee and remains valid until the
 * next call.  Returns NULL if no suitable path can be derived (no $HOME,
 * mkdir failure, etc.). */
const char *minicorpus_default_path(void);

/* Coverage-delta gap (in newly-discovered edges, fleet-wide) between
 * periodic mid-run snapshots.
 *
 * Why mid-run snapshots: the on-shutdown save in trinity.c only runs on
 * graceful exit.  An shm-corruption trip or hard crash mid-run skips
 * the save entirely and the entire accumulated corpus is lost.  The
 * 2026-04-21 shm-corruption tree dropped ~810k edges of state this way.
 *
 * Triggering off coverage delta rather than wall-time keeps the save
 * cadence proportional to actual fuzzing progress: an idle or stalled
 * run doesn't burn I/O on snapshots that capture nothing new, while a
 * productive burst snapshots quickly enough to bound loss.
 *
 * 10k is the loss-vs-overhead trade.  Smaller gaps cap loss tighter
 * but spend more I/O bandwidth on the save path; larger gaps risk
 * losing more progress per crash.  The previous 100k value was tuned for
 * sustained steady-state runs that don't reflect typical crash-prone
 * fuzzing: at peak edge rate (~10-30k/min) the window was ~10min, but
 * post-saturation edge growth slows to a near-stall and the gap stretched
 * to many tens of minutes -- longer than most short runs survive before
 * an OOM-kill or hard crash.  10k captures the early-burst phase well
 * before crashes typically land, and the wall-clock floor below catches
 * the saturated-rate case. */
#define MINICORPUS_SNAPSHOT_EDGES 10000

/* Wall-clock secondary trigger for minicorpus_maybe_snapshot(): caps the
 * worst-case loss-on-crash at 5 minutes of corpus updates regardless of
 * edge-discovery rate.  Companion to MINICORPUS_SNAPSHOT_EDGES; the two
 * are ORed inside minicorpus_maybe_snapshot() so a productive burst still
 * fires the cheap edge-trigger fast path several times per 5min window
 * during early-run discovery, while a saturated steady-state run that
 * finds no new edges for an hour still snapshots once every 5min instead
 * of going arbitrarily long without persistence. */
#define MINICORPUS_SNAPSHOT_INTERVAL_SEC 300UL

/* Configure the path that minicorpus_maybe_snapshot() will save to.
 * Call once from the parent before fork (the path string is copied into
 * a process-local buffer, so children inherit it via COW).  Pass NULL
 * to disable mid-run snapshots — callers honour --no-warm-start by not
 * calling this. */
void minicorpus_enable_snapshots(const char *path);

/* Check the per-snapshot coverage gap and, if reached, race to claim
 * the next snapshot via compare-exchange.  The single winning caller
 * runs minicorpus_save_file() to the configured path; everyone else
 * early-returns.  Cheap fast path on the no-trigger case (one atomic
 * load each from kcov_shm->coverage.edges_found and the high-water-mark, plus
 * a comparison).  Safe to call from any child after every kcov edge
 * event. */
void minicorpus_maybe_snapshot(void);

/* Mid-run cadence for minicorpus_mut_attrib_canary_check(): how often
 * the parent scans the MUT_NUM_OPS mutation-attribution counters to
 * verify the by-construction inequality mut_wins[i] <= mut_trials[i]
 * (and the structured equivalent).  300s mirrors
 * KCOV_BITMAP_CANARY_INTERVAL_SEC -- a stray writer scribbling a
 * wins[] word silently inverts the ratio until the next stats dump
 * notices, and the scan itself is O(MUT_NUM_OPS) so there is no
 * reason to run it any more often than the other periodic integrity
 * probes.  Hardcoded; no operator knob. */
#define MUT_ATTRIB_CANARY_INTERVAL_SEC		300UL

/* Per-op tolerance for the wins-vs-trials inequality.  The win bump
 * is lexically nested under the trial bump in minicorpus.c, both
 * RELAXED, so a reader can observe a producer's wins[] increment
 * before its matching trials[] increment becomes visible -- at most
 * one such in-flight pair per CPU thread per op.  512 sits well
 * above the realistic per-scan skew on the fleet's hottest hosts
 * (hundreds of hw threads, only a small fraction inside the
 * trial->win window at any instant) and well below any plausible
 * scribbled-word inflation (a stray store into a counter word
 * manufactures thousands of counts), so the threshold distinguishes
 * memory-ordering noise from damage without arming a false-positive
 * alarm. */
#define MUT_ATTRIB_INVERSION_TOL		512UL

/* Self-rate-limited integrity probe: walk the per-op
 * mut_trials/mut_wins (and mut_structured_trials/mut_structured_wins)
 * pairs and alarm when wins exceed trials by more than
 * MUT_ATTRIB_INVERSION_TOL.  Bumps stats.mut_attrib_inversion_caught
 * once per inverted op per scan and emits a one-line CANARY witness
 * to stats.log the first time the canary trips in a run, naming the
 * op, the observed counts, and the tolerance so the operator can
 * correlate against the wild-write window.  Read-only with respect
 * to the bandit's own RELAXED loads of the same counters.  Called
 * once per main_loop tick alongside the other periodic samplers;
 * the MUT_ATTRIB_CANARY_INTERVAL_SEC gate keeps the tiny scan from
 * running on every tick. */
void minicorpus_mut_attrib_canary_check(void);
