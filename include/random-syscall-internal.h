#ifndef _TRINITY_RANDOM_SYSCALL_INTERNAL_H
#define _TRINITY_RANDOM_SYSCALL_INTERNAL_H

/*
 * Internal interface shared by the random-syscall cluster files under
 * random_syscall/ (pick-common.c, pickers.c, chain-subst.c,
 * strategy-accounting.c, dispatch.c).
 *
 * Public entry points (random_syscall, random_syscall_step,
 * random_syscall_step_biased, replay_syscall_step,
 * set_syscall_nr_random, compute_numeric_substitute_mask,
 * choose_syscall_table) live in include/child.h and include/syscall.h.
 * Everything declared here is cross-cluster private glue that the
 * follow-up cluster carves add as they move code out.  Not a public
 * header: only files under random_syscall/ are expected to include it.
 */

#include <stdbool.h>

struct childdata;
struct syscallrecord;
struct syscallentry;
struct kcov_pc_result;

/* pick-common.c -- table selection and validation helpers, shared by
 * the three picker arms in pickers.c.  choose_syscall_table is public
 * via include/syscall.h; the rest are cluster-private.
 *
 * load_active_syscall_count centralises the RELAXED load + validate +
 * log for the shm active-syscall counts.  Callers detect corruption
 * via the returned value being > MAX_NR_SYSCALL and route into their
 * existing FAIL / skip path; the raw observed value is returned so
 * forensics from the log line and the caller's decision are
 * consistent. */
unsigned int load_active_syscall_count(const unsigned int *shm_count,
				       const char *arch_label);
void note_validation_success(unsigned int syscallnr, bool do32);
void note_validation_failure(unsigned int syscallnr, bool do32);
bool expensive_accept(unsigned int nr, bool do32);
void cost_pool_selector_shadow_note(bool do32);
void cost_pool_selector_live_note(unsigned int nr, bool do32);
void cost_pool_selector_predraw_note(unsigned int nr, bool do32);
bool syscall_in_group(unsigned int nr, bool do32, unsigned int target_group);

/*
 * Acceptance-weight scale for the cold/untried-syscall fallback path in
 * set_syscall_nr_coverage_frontier().  Engaged when the frontier ring
 * is silent (max_weight <= 2) so the picker has a per-syscall signal
 * to steer on instead of degenerating to plain uniform draw -- see the
 * fallback gate for the full rationale.
 *
 * Sized at 256 so the integer-divide inverse-productivity transform
 * (SCALE - floor(SCALE * edges / calls)) resolves at ~0.4%/step: even
 * a syscall with a handful of productive calls in the high-thousands
 * range stays distinguishable from a never-tried slot instead of
 * flooring the divide to 0 and collapsing to MAX.  256 is also the
 * Q8.8 unit used by adapt_budget's mult table -- staying on a
 * power-of-two keeps the rnd_modulo_u32(SCALE + 1) draw in the same
 * Lemire fast-path the soft-max path already uses.
 *
 * Shared between the frontier-picker cluster (frontier_cold_weight,
 * cmp_frontier_weight, set_syscall_nr_coverage_frontier): both weight
 * helpers cap their return at FRONTIER_COLD_SCALE and the coverage-
 * frontier accept gate consumes the same scale when mixing that
 * weight into its acceptance probability.
 */
#define FRONTIER_COLD_SCALE 256

/*
 * static inline so each translation unit that includes this header
 * gets its own copy without ODR headaches.  Used by the frontier
 * weight helpers and by the coverage-frontier accept gate.
 */
static inline unsigned ilog2_ul(unsigned long x)
{
	return x ? (unsigned)(63 - __builtin_clzl(x)) : 0;
}

/* pick-heuristic.c -- STRATEGY_HEURISTIC arm dispatched from
 * set_syscall_nr in pickers.c.  Uniform draw + layered biases (group
 * affinity, kcov cold-skip); trinity's pre-rotation default. */
bool set_syscall_nr_heuristic(struct syscallrecord *rec,
			      struct childdata *child);

/* pickers.c -- top-level picker dispatch, called from dispatch_step
 * in dispatch.c.  set_syscall_nr_random is public via
 * include/syscall.h; set_syscall_nr_coverage_frontier and the
 * frontier weight helpers (frontier_cold_weight, cmp_frontier_weight)
 * are file-scope static inside pickers.c. */
bool set_syscall_nr(struct syscallrecord *rec, struct childdata *child);

/* chain-subst.c -- rewrite rec->aN in place for chain-substituted
 * arguments before dispatch.c publishes the record.
 * compute_numeric_substitute_mask is public via include/syscall.h;
 * argtype_accepts_numeric_substitute is file-scope static inside
 * chain-subst.c. */
void apply_chain_substitution(struct syscallrecord *rec,
			      struct syscallentry *entry,
			      bool have_substitute,
			      unsigned long substitute_retval);

/* strategy-accounting.c -- strategy-window rotation and per-call
 * reward / cohort attribution.  Called from dispatch.c on every
 * parent syscall; remote_adaptive_decide is queried from
 * dispatch_step before the raw call to decide whether to publish the
 * remote-adaptive path. */
void maybe_rotate_strategy(void);
bool remote_adaptive_decide(unsigned int nr,
			    struct syscallentry *entry,
			    bool static_remote);
void account_reexec_ab_cohort(struct childdata *child, unsigned long new_cmp);
void account_per_syscall_new_edges(struct childdata *child,
				   struct syscallrecord *rec,
				   unsigned long new_edge_count);
void account_warm_reserve(struct childdata *child,
			  struct syscallrecord *rec,
			  bool new_edges, unsigned long new_cmp,
			  const struct kcov_pc_result *pcres);
void account_cold_overflow_would_save(struct syscallentry *entry,
				      struct syscallrecord *rec,
				      unsigned long new_cmp);
void account_pc_edge_only(struct childdata *child,
			  struct syscallrecord *rec,
			  unsigned long new_edge_count,
			  unsigned int rescue_cold_skip_pct_before);
void account_transition_reward(struct childdata *child,
			       struct syscallrecord *rec,
			       const struct kcov_pc_result *pcres);
void account_fd_and_group(struct childdata *child,
			  struct syscallentry *entry,
			  struct syscallrecord *rec,
			  bool found_local_coverage);

#endif /* _TRINITY_RANDOM_SYSCALL_INTERNAL_H */
