#pragma once

/* Sub-struct of struct kcov_shared, embedded as .hints_flat.
 * Layout is offset-sensitive; do not reorder fields. */

struct kcov_hints_flat {
/* Per-record CMP hints skipped because the calling child's seen-bloom
 * indicated the (cmp_ip, value, size) tuple had already been pushed
 * to the per-syscall pool within the recent window.  Each skip avoids
 * a pool_lock + linear-scan dedup-refresh round-trip; the per-record
 * granularity (vs per-cmp_hints_collect-call) makes the saved work
 * directly comparable to cmp_records_collected. */
unsigned long cmp_hints_bloom_skipped;
/* Per-record CMP hints skipped because cmp_hints_strip[nr] is set
 * for the calling syscall -- the entire trace buffer is short-
 * circuited at cmp_hints_collect() entry, bypassing both the bloom
 * lookup and the pool_add_locked path.  Targets are syscalls whose
 * comparisons fire on task_struct / cred / ucounts / aio-table
 * internal state set by prior syscalls or kernel init, not on
 * values driven by the current syscall's argument surface; the
 * resulting pool entries are unreachable from any consumer and
 * only displace useful constants via LRU eviction.  Bumped at the
 * per-record granularity (same units as cmp_hints_bloom_skipped
 * and cmp_records_collected) so the avoided work is directly
 * comparable across the three counters. */
unsigned long cmp_hints_strip_skipped;
/* Per-record CMP hints that produced an actual content change in a
 * per-syscall pool — either a fresh insert into a non-full pool or an
 * evict-replace once the pool was saturated.  Dedup-refresh hits (the
 * tuple was already in the pool, only its last_used stamp was bumped)
 * are NOT counted.  This is the right denominator for "how much unique
 * signal did KCOV_TRACE_CMP actually contribute": cmp_records_collected
 * counts every raw record the kernel emitted (hugely inflated by
 * repetition on hot syscalls), bloom_skipped counts the per-child
 * short-circuits, and unique_inserts is what's left — the records that
 * survived bloom + pool dedup and changed pool state. */
unsigned long cmp_hints_unique_inserts;
/* cmp_hints_try_get() return values that the calling argument
 * generator actually committed to the produced syscall argument
 * (returned the hint directly, or OR'd it into a flags mask).
 * Aggregated across all callsites -- granularity is per-counter,
 * not per-callsite, because the operator question this answers
 * ("does the hint pipeline reach syscall args at all?") doesn't yet
 * need the per-callsite split.  Subset of cmp_hints_try_get_returned:
 * the gap between the two is callsites that pulled a hint but then
 * discarded it (none today, but the slot exists for future
 * branchier consumers). */
unsigned long cmp_hints_injected;
/* Bumped by gen_undefined_arg when prop_ring_try_get returns
 * a value the per-child propagation ring captured from an
 * earlier syscall return.  Sibling counter to cmp_hints_injected:
 * same callsite, different value source (trinity-observed return
 * vs kernel KCOV_TRACE_CMP).  Cumulative; stats.c reports the
 * per-window delta alongside the cmp_hints counters. */
unsigned long propagation_injected;
/* Per-callsite split of the flat propagation_injected scalar above,
 * indexed by enum prop_injected_callsite.  Bumped in lock-step with
 * the flat counter at each of the two producer sites in
 * generate-args.c (handle_arg_op -> ARG_OP, gen_undefined_arg ->
 * ARG_UNDEFINED).  Aggregated across all syscalls; the "which
 * argtype-handler is responsible for the bulk of prop_ring
 * deliveries" question is callsite-shaped, not syscall-shaped, so
 * the flat scalar above answers the rate question and this array
 * answers the attribution question.  Shape mirrors
 * cmp_hint_callsite_injected[] below. */
unsigned long propagation_injected_callsite[PROP_INJECTED_CALLSITE_NR];
/* cmp_hints_try_get() calls that the chaos-mode gate forced to
 * return false.  Bumped after the shm/nr guard, before the pool
 * lookup, when cmp_hints_chaos_active() is true for the current
 * rotation window.  Subtracted from the apparent attempt->returned
 * funnel: a window where chaos is active inflates attempts without
 * a matching returned bump and the difference shows up here.
 * Cumulative -- chaos windows fire on a fixed modulo of the bandit
 * window rotation, so the delta over a stats interval is roughly
 * try_get_attempts * (1 / CHAOS_WINDOW_MODULO) in steady state. */
unsigned long cmp_hints_chaos_suppressed;
/* Chaos-mode state.  Window count + active flag both live in shm
 * so all children see the same chaos schedule -- the CAS-winning
 * child in maybe_rotate_strategy updates them, every child reads
 * the flag in cmp_hints_try_get.  When these were file-scope
 * statics in cmp_hints.c each child had its own copy and the
 * schedule never crossed a fork: cmp_hints_chaos_suppressed
 * stayed at 0 across long multi-child runs. */
unsigned long cmp_hints_chaos_window_count;
unsigned int  cmp_hints_chaos_active;
};
