#pragma once

/* Sub-struct of struct kcov_shared, embedded as .per_syscall.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_per_syscall {
/* Per-syscall count of CALLS that produced at least one new edge.
 * NOT a real edge bucket count — a syscall that uncovers 50 distinct
 * new edges in one call bumps this by 1, not by 50.  The real
 * bucket-edge count is the kcov_collect() new_edge_count out-param,
 * accumulated into per-strategy and per-pool fields elsewhere.  The
 * field name predates the call-count vs edge-count distinction; kept
 * for ABI compatibility with the cold-skip heuristic and the
 * top-syscalls dump in stats.c. */
/* [nr][do32 ? 1 : 0] -- 32-bit and 64-bit paths bump their own
 * slot so IA32 compat entries no longer merge with the 64-bit
 * total; readers that want the pre-split per-nr value sum both
 * dims via per_syscall_edges_total() / _calls_total() below. */
unsigned long per_syscall_edges[MAX_NR_SYSCALL][2];
unsigned long per_syscall_calls[MAX_NR_SYSCALL][2];
/* EXTRA_FORK dispatches (execve, execveat, vfork) run their real
 * syscall in a throwaway grandchild that do_extrafork() spawns
 * OUTSIDE the parent worker's kcov_enable / syscall / kcov_disable
 * bracket, so kcov_collect() never fires for them and both
 * per_syscall_calls[nr] and per_syscall_edges[nr] stay at zero
 * for the life of the run.  Without a dedicated denominator these
 * syscalls read as permanently dead in edges/calls productivity
 * ratios (0 edges out of 0 tracked calls) even though the fuzzer
 * IS dispatching them thousands of times.  Bumped once per
 * EXTRA_FORK bypass from kcov_note_extrafork() below so consumers
 * (stats.c JSON emit, downstream analysis) can distinguish "dead
 * syscall" from "coverage-inherently-unmeasurable via kcov". */
unsigned long per_syscall_extrafork_calls[MAX_NR_SYSCALL];
unsigned long last_edge_at[MAX_NR_SYSCALL];
/* Snapshot of per_syscall_edges at the previous stats interval.
 * Used to compute per-interval growth rate of the call-count signal
 * above. */
unsigned long per_syscall_edges_previous[MAX_NR_SYSCALL][2];
/* Warm-loaded priors from the previous session's bitmap save.
 * Never bumped during this run -- frozen at warm-start.  Empty
 * (all-zero) on cold-start or when the priors blob in the bitmap
 * file failed its CRC check.  Consumers treat these as soft
 * priors -- current-run evidence in per_syscall_edges[] /
 * per_syscall_calls[] overrides them as soon as it accumulates. */
unsigned long per_syscall_edges_prior[MAX_NR_SYSCALL][2];
unsigned long per_syscall_calls_prior[MAX_NR_SYSCALL][2];
/* Per-syscall warm-known hit counter.  Bumped from kcov_collect()
 * when the kernel emitted PCs into the trace buffer for this
 * call (count > 0) but no new bucket bit flipped (found_new ==
 * false) -- i.e. the syscall is exercising kernel code that's
 * already in bucket_seen[].  Useful both as a liveness signal
 * (the syscall is doing real work even if no new coverage) and
 * as a divisor for productivity ratios.  Conflates "warm from
 * prior session" with "already-seen this run"; the loss matters
 * less than the cold-skip gate's need to distinguish dead
 * syscalls from quietly-exercised ones. */
unsigned long per_syscall_warm_known_hits[MAX_NR_SYSCALL];
/* Sum of per_syscall_warm_known_hits[] across all nr.  Run-wide
 * counter for the periodic stats dump so the warm-known signal
 * is visible without iterating MAX_NR_SYSCALL slots.  Write-dead:
 * migrated to the per-child stats_ring drain into
 * parent_stats.total_warm_known_hits; the field is retained so
 * the shared-mapping ABI does not shift. */
unsigned long total_warm_known_hits;
/* Per-syscall SHADOW-ONLY clean-vs-noisy attribution counters.  The
 * existing per_syscall_edges[] is a per-thread, per-call, trace-
 * isolated "clean" signal (kcov_collect() bumps it only on the
 * found_new branch, from this task's own trace walk).  What was
 * missing was a per-syscall analogue of the global-delta counter the
 * childop path already carries in childop_edges_discovered[]: how
 * many new edges accrued to the shared bucket_seen[] hash across all
 * children during this syscall's enable/disable window, regardless
 * of which child was the dedup-race winner.  The ratio of the two
 * (clean numerator, sampled global-delta denominator) is the
 * attribution-confidence signal Phase 2 will consume; Phase 1
 * records it alongside the existing counters and NO selection or
 * scoring code reads it.
 *
 *   per_syscall_edges_noisy[nr]     Sum of edges_found deltas across
 *                                   the sampled windows for this nr.
 *                                   Bumped from dispatch/syscall.c
 *                                   around the syscall's enable/
 *                                   disable pair only on the 1-in-N
 *                                   sampled call (see
 *                                   frontier_noise_sample in
 *                                   include/params.h).
 *   per_syscall_noisy_samples[nr]   Count of windows actually
 *                                   sampled for this nr; the
 *                                   denominator that lets a reader
 *                                   scale per_syscall_edges_noisy
 *                                   back up by N to estimate the
 *                                   full-population delta.
 *   per_syscall_edges_clean_remote[nr]
 *                                   Subset of the per_syscall_edges
 *                                   found_new bumps that fired under
 *                                   kc->remote_mode -- the remote-
 *                                   context cross-attribution split
 *                                   (kernel copies coverage from
 *                                   remote contexts into this task's
 *                                   trace_buf, so the credited edge
 *                                   may not be causally tied to this
 *                                   syscall's own kernel work).
 *                                   (per_syscall_edges - this) is
 *                                   the local-only clean signal.
 *
 * Sampling default: frontier_noise_sample==0 (feature fully off);
 * the sampled edges_found loads are the only new hot-path cost, so
 * the default build issues zero new loads and stays byte-identical
 * on selection to the pre-row baseline.  SHADOW-ONLY: no live
 * picker or accept-gate reads any of these three counters. */
unsigned long per_syscall_edges_noisy[MAX_NR_SYSCALL];
unsigned long per_syscall_noisy_samples[MAX_NR_SYSCALL];
unsigned long per_syscall_edges_clean_remote[MAX_NR_SYSCALL];
};
