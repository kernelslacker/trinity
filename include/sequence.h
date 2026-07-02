#pragma once

#include "child.h"
#include "locks.h"
#include "syscall.h"

/*
 * Sequence-aware fuzzing.
 *
 * Phase 1 dispatches a 2-4 syscall chain per fuzzer iteration instead of
 * a single call.  Between consecutive calls, the previous call's return
 * value may be substituted into one randomly-chosen arg slot of the next
 * call.  Phase 2 mines productive chains into a corpus so that future
 * iterations can replay them with mutation, closing the AFL-style queue
 * feedback loop at chain granularity rather than the per-call granularity
 * that the existing minicorpus already covers.  Phase 3 (deferred) will
 * add resource-type dependency tracking so that chains can be generated
 * with structural awareness of which calls produce and consume which
 * kinds of resource.
 *
 * Set ENABLE_SEQUENCE_CHAIN to 0 to fall back to the legacy one-call-per
 * iteration dispatch for A/B coverage comparison.
 */
#define ENABLE_SEQUENCE_CHAIN 1

/*
 * Hard cap on chain length.  pick_chain_length() draws from {2,3,4} via
 * a geometric distribution biased toward 2.  The cap is also the step-
 * array size used in the chain corpus: each saved chain entry is stored
 * inline in a fixed-size slot of the chain_corpus_ring (see below), so
 * keeping the cap at 4 bounds the per-slot footprint and the total shm
 * cost of the ring.
 */
#define MAX_SEQ_LEN 4

bool run_sequence_chain(struct childdata *child);

/*
 * Sequence chain corpus (Phase 2).
 *
 * When a freshly-randomised chain produces new KCOV edges in any of its
 * steps, the chain (per-step nr/do32bit/args/retval) is captured into a
 * global shared-memory ring of saved chains.  Subsequent iterations may
 * replay a saved chain with per-arg mutation instead of generating a
 * fresh one.  Save-on-new-coverage is the right trigger because it is
 * the same signal the per-call minicorpus already uses to decide which
 * arg snapshots are worth retaining; piggybacking on it means the chain
 * corpus inherits the same "interesting input" definition that the rest
 * of the fuzzer is already optimising against.
 *
 * The chain entries are stored inline in fixed-size slots of the ring
 * itself (struct chain_corpus_ring::slots[], see below).  The whole
 * ring -- header plus the inline slot array -- lives in a single
 * alloc_shared region so all forked children share one source of truth,
 * and the working set stays bounded as the ring overwrites old entries.
 *
 * The corpus is intentionally a separate structure from minicorpus_shared:
 * minicorpus is per-syscall-nr arg snapshots, this is per-chain-shape
 * syscall sequences.  Mixing them would conflate two different replay
 * policies under the same lock and slot accounting.
 */
struct chain_step {
	unsigned int nr;
	bool do32bit;
	unsigned long args[6];
	unsigned long retval;
};

/*
 * Reason a chain was admitted to the corpus.  Chain-local, intentionally
 * SEPARATE from include/minicorpus.h's CORPUS_SAVE_REASON_ enum so the
 * chain-side and per-syscall-side accounting can evolve independently —
 * chains carry structural shape (a 2-4 step sequence) on top of per-step
 * args, so the productivity question for the chain corpus is whether the
 * SEQUENCE earned admission, not whether any single step's args did.
 *
 * CHAIN_SAVE_PC: at least one step in the chain flipped a fresh PC-edge
 *   bucket bit (the historical save signal).
 * CHAIN_SAVE_TRANSITION: at least one step in the chain produced a
 *   reward-eligible local-mode transition delta
 *   (kcov_pc_result::transition_edges_real_local > 0) without flipping a
 *   new PC-edge bit.  Under a warm PC-edge plateau the transition stream
 *   is often the only available "the sequence changed kernel state in a
 *   way we hadn't observed" signal.
 * CHAIN_SAVE_CMP: at least one step in the chain produced new bloom-novel
 *   KCOV_CMP_CONST records (per-step new_cmp from kcov_collect_cmp).
 * CHAIN_SAVE_ERRNO_SHIFT / CHAIN_SAVE_RETVAL_LINK: reserved enum slots,
 *   not currently wired into the save-decision predicate.  Counters
 *   exist so future predicates flip the gate without an enum reshuffle.
 */
enum chain_save_reason {
	CHAIN_SAVE_PC = 0,
	CHAIN_SAVE_TRANSITION,
	CHAIN_SAVE_CMP,
	CHAIN_SAVE_ERRNO_SHIFT,		/* reserved, not wired */
	CHAIN_SAVE_RETVAL_LINK,		/* reserved, not wired */
	CHAIN_SAVE_NR_REASONS,
};

struct chain_entry {
	unsigned int len;			/* number of valid steps (1..MAX_SEQ_LEN) */
	unsigned int save_reason;		/* enum chain_save_reason that admitted this entry */
	struct chain_step steps[MAX_SEQ_LEN];
};

/*
 * Ring depth for saved chains.
 *
 * 256 inline chain_entry slots size the whole ring at ~74 KiB of shared
 * memory (see the sizing note on struct chain_corpus_ring::slots[]).
 * Larger than minicorpus's per-syscall ring count of 32 because the
 * chain corpus is a single global pool rather than one ring per syscall
 * — replay diversity comes from ring depth, not from per-syscall
 * partitioning.
 */
#define CHAIN_CORPUS_RING_SIZE 256

struct chain_corpus_ring {
	lock_t lock;
	unsigned int head;			/* next write slot mod CHAIN_CORPUS_RING_SIZE */
	unsigned int count;			/* entries stored, max CHAIN_CORPUS_RING_SIZE */
	unsigned long save_count;		/* chains saved on new-coverage (atomic) */
	unsigned long replay_count;		/* chains dispatched as replays (atomic) */
	/*
	 * Step-granular replay attribution counter.  replay_count above
	 * tracks chains; replay_steps_dispatched tracks individual replayed
	 * syscall steps that actually reached dispatch_step.  Replayed steps
	 * bypass set_syscall_nr() so they do not stamp child->strategy_at_pick
	 * and the post-syscall bandit-attribution sites deliberately skip
	 * them — this counter lets operators see how much of the workload
	 * has gone through that no-attribution path.
	 */
	unsigned long replay_steps_dispatched;	/* per-step replays dispatched (atomic) */

	/*
	 * Per-reason save / replay-win counters.  chain_save_by_reason[r] is
	 * bumped once per admitted save under reason r (PC / TRANSITION / CMP
	 * today; ERRNO_SHIFT / RETVAL_LINK slots reserved).
	 * chain_replay_win_by_reason[r] is bumped on each replay iteration
	 * whose dispatched chain (a) was originally saved under reason r and
	 * (b) earned any novelty signal on at least one step.  Both arrays
	 * are RELAXED atomics — dashboards read once per dump and there is
	 * no cross-counter ordering invariant.
	 *
	 * The ratio chain_replay_win_by_reason[r] / chain_save_by_reason[r]
	 * answers "is the non-PC-saved subset of the corpus paying for the
	 * extra ring footprint, or is it a sink for replays that never find
	 * anything?".  A near-zero ratio for TRANSITION/CMP after a warm
	 * window's worth of data is the signal to tighten the replay rate
	 * scaling in run_sequence_chain() or to retire a save reason.
	 */
	unsigned long chain_save_by_reason[CHAIN_SAVE_NR_REASONS];
	unsigned long chain_replay_win_by_reason[CHAIN_SAVE_NR_REASONS];

	/*
	 * Per-(reason, syscall_nr) admission stamp.  Holds the
	 * shm->syscalls_at_last_switch value observed at the most recent
	 * admit for (reason, nr); chain_corpus_save() refuses a fresh admit
	 * when the current value matches, capping admissions at 1 per
	 * (reason, nr) per rotation window.  Keeps a CMP- or transition-
	 * flood on one hot syscall from sweeping PC-saved chains out of the
	 * ring inside a single rotation.  RELAXED atomic loads/stores;
	 * racing admissions in the same window may both observe an old
	 * stamp and both admit — bounded slop, not correctness.
	 */
	unsigned long chain_save_window_id[CHAIN_SAVE_NR_REASONS][MAX_NR_SYSCALL];

	/*
	 * Inline storage: a flat array of fixed-size entries living in this
	 * shm region directly.  Holding the entries inline rather than
	 * behind a pointer table keeps the obj heap out of the chain corpus
	 * entirely, so the obj heap can stay mprotect'd RO post-init even
	 * though chain_corpus_save() runs in child context.
	 */
	struct chain_entry slots[CHAIN_CORPUS_RING_SIZE];
};

extern struct chain_corpus_ring *chain_corpus_shm;

void chain_corpus_init(void);
void chain_corpus_save(const struct chain_step *steps, unsigned int len,
		       unsigned int reason, unsigned int trigger_nr);

/*
 * On-disk persistence for the chain corpus (cross-run warm-start).
 *
 * chain_corpus_save_file() serialises every occupied slot of the ring
 * under a versioned, arch-tagged header and atomically renames the
 * result to @path.  chain_corpus_load_file() reads a previously-saved
 * image, refuses incompatible headers outright, drops individual
 * chains that fail re-validation (unknown syscall nr, argtype set no
 * longer replay-safe), and admits the survivors into the ring using
 * the same release-store publish sequence chain_corpus_save() uses.
 *
 * chain_corpus_default_path() builds an XDG-anchored, arch- and
 * kernel-release-tagged path so a saved chain corpus is never
 * accidentally reused across incompatible kernels or arches.  Returns
 * NULL on any allocation / snprintf / mkdir failure.  The returned
 * pointer is owned by an internal static buffer.
 */
bool chain_corpus_save_file(const char *path);
bool chain_corpus_load_file(const char *path,
			    unsigned int *loaded, unsigned int *discarded);
const char *chain_corpus_default_path(void);

/*
 * Mid-run snapshot cadence for chain_corpus_maybe_snapshot().  Chain
 * admits are already rate-limited to one per (reason, syscall_nr) per
 * rotation window, so the ring grows an order of magnitude slower than
 * the cmp-hints pool; the generation trigger is scaled down to match.
 * Snapshots fire only when BOTH 32 newly-admitted chains have
 * accumulated AND 600s have elapsed since the last save.  Either gate
 * alone is insufficient -- the generation gate would over-fire during
 * the initial fill before the ring saturates, and the time gate alone
 * would keep writing near-identical payloads on a saturated ring where
 * the per-(reason, nr) cap is holding admits below the generation
 * threshold.  Hardcoded -- no operator knob, fleet boxes shouldn't
 * need to retune.
 */
#define CHAIN_CORPUS_SNAPSHOT_NEW		32UL
#define CHAIN_CORPUS_SNAPSHOT_INTERVAL_SEC	600UL

/*
 * Wire periodic mid-run snapshots of the chain corpus to PATH.
 * Subsequent chain_corpus_maybe_snapshot() calls become live; a no-op
 * before this is called.  Path is copied.  Mirrors
 * cmp_hints_enable_snapshots()'s crash-resilience role -- the
 * end-of-run save in trinity.c only fires on clean shutdown, so a
 * kill or crash mid-run would otherwise lose every chain admitted
 * since the last successful save.
 */
void chain_corpus_enable_snapshots(const char *path);

/*
 * Cheap per-tick gate: writes the snapshot if both triggers have
 * elapsed since the last successful save, otherwise returns
 * immediately.  Called from the parent's stats tick alongside the
 * cmp-hints snapshot.
 */
void chain_corpus_maybe_snapshot(void);

/*
 * Snapshot a random saved chain into @out.  Returns true on success
 * (out->len populated, out->steps[] copied), false if the corpus is
 * empty.  The snapshot is intentionally lockless -- see the long
 * comment in chain_corpus_pick() (sequence.c) for the race tolerance
 * argument.  Callers MUST validate out->len before indexing
 * out->steps[]: a torn lockless read or wild write into the shared
 * slot can leave len outside [1, MAX_SEQ_LEN].  run_sequence_chain()
 * does that validation and falls back to a fresh chain on failure.
 */
bool chain_corpus_pick(struct chain_entry *out);

/*
 * Resource-type dependency tracking (Phase 3).
 *
 * Small, high-confidence producer/consumer table for fd-like resources.
 * Consulted by the chain executor when --chain-resource-typing is not
 * OFF: after a step whose (nr, args) match a known producer, the next
 * chain link is either shadow-counted (SHADOW) or probabilistically
 * overridden (LIVE) with a random consumer of the same resource kind.
 *
 * Kinds are deliberately coarse: one enum value per fd-family that has
 * a distinct producer/consumer split we already ship syscall coverage
 * for.  A universal resource schema is out of scope for this row --
 * the per-kind chain_restype_replay_win counter is the productivity
 * signal that decides which families to extend into.
 *
 * CHAIN_RESTYPE_NR is the count sentinel; the array-shaped stats live
 * in struct stats_s under this enum's cardinality.
 */
enum chain_resource_kind {
	CHAIN_RESTYPE_EPOLL_FD = 0,
	CHAIN_RESTYPE_TIMERFD,
	CHAIN_RESTYPE_EVENTFD,
	CHAIN_RESTYPE_IO_URING_FD,
	CHAIN_RESTYPE_PIDFD,
	CHAIN_RESTYPE_SOCKET_TCP,
	CHAIN_RESTYPE_BPF_MAP_FD,
	CHAIN_RESTYPE_NR,
};

/*
 * Resolve the producer/consumer NR tables at startup.  Called from
 * chain_corpus_init() so the resolution happens once, after
 * select_syscall_tables() has copied the compiled-in table and
 * before any child forks -- matching the ordering cmp_hints_init
 * already relies on for its strip-list resolver.
 *
 * Unknown syscall names (compat gap on this arch) are dropped
 * silently: an entry that never lands in the active table becomes
 * a producer/consumer slot filled with the -1 sentinel, and the
 * classify / pick helpers skip those slots.
 */
void chain_restype_init(void);

/*
 * Classify the just-dispatched step as a resource producer.  Returns
 * the enum value on match, -1 on no match.  Consulted by the chain
 * executor after each successful step (rec->retval >= 0 already
 * filtered by the caller) so a producer that returned an errno-style
 * failure is not counted -- feeding a -EBADF into a downstream
 * consumer would waste the bias slot.
 *
 * @args and @retval are the step's dispatched args and kernel-side
 * return.  Socket-tcp keys on (args[0], args[1] & 0xff), not just NR,
 * so both are required.
 */
int chain_restype_classify_producer(unsigned int nr, bool do32bit,
				    const unsigned long args[6],
				    unsigned long retval);

/*
 * Draw a random consumer NR for @kind.  @do32bit hints which table to
 * pick from; a returned consumer with an all-slot -1 (no known
 * consumer resolved on this arch) is signalled by -1.  Otherwise the
 * caller stages the returned NR into the next chain step's dispatch
 * via random_syscall_step_biased().
 */
int chain_restype_pick_consumer(enum chain_resource_kind kind,
				bool do32bit_hint);
