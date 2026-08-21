#ifndef _TRINITY_STATS_SUBSYS_EBPF_GEN_H
#define _TRINITY_STATS_SUBSYS_EBPF_GEN_H

/*
 * eBPF program-generator counters.  fds/bpf provisioning
 * (maps_provided / progs_provided) plus net/bpf/ebpf.c generator
 * side-effects: map_fd substitution, helper-call emission, and the
 * map-value deref idiom (total + read/write breakdown).  See
 * fds/bpf.c and net/bpf/ebpf.c.  The surrounding struct stats_s
 * composes an instance of struct ebpf_gen_stats as its "ebpf_gen"
 * member.  Distinct from bpf_lifecycle_stats (BPF object lifecycle
 * inside the childop / fd-pool machinery).
 */
struct ebpf_gen_stats {
	/* fds/bpf provisioning counters: cumulative count of fds we
	 * successfully published into the global object pool, including
	 * regenerations after stale-fd teardown.  Tells you how much of
	 * trinity's fd-providing infrastructure BPF actually contributes
	 * -- zero means the kernel rejected every load and the BPF cross-
	 * subsystem surface (SO_ATTACH_BPF, PERF_EVENT_IOC_SET_BPF, etc.)
	 * is unreachable. */
	unsigned long maps_provided;
	unsigned long progs_provided;

	/* Cumulative count of BPF_PROG_LOAD calls that returned a negative fd
	 * with errno != EINVAL (typically EACCES from the verifier, EPERM, or
	 * E2BIG).  Non-zero here and zero in progs_provided means every load
	 * is failing past the EINVAL-early-exit paths.  Counts only non-EINVAL
	 * failures; -EINVAL outcomes are tracked separately in
	 * bpf_prog_load_einval. */
	unsigned long bpf_prog_load_rejected;

	/* Cumulative count of BPF_PROG_LOAD calls that returned -EINVAL for
	 * any reason before the verifier is reached (CHECK_ATTR failure,
	 * unknown prog_flags, btf_get_by_fd error, log-clause mismatch, etc.).
	 * Separated from bpf_prog_load_rejected (errno != EINVAL) so EINVAL
	 * noise does not mask verifier-reject EACCES in the steady state.
	 * Note: bpf_prog_load_rejected counts non-EINVAL failures only; run-
	 * over-run comparisons spanning the rename commit should account for
	 * the semantic narrowing of that counter. */
	unsigned long bpf_prog_load_einval;

	/* net/bpf/ebpf.c generator: cumulative count of programs that prepended
	 * an LD_MAP_FD loading a real bpf-map fd from the trinity object pool
	 * (Phase 3.3).  Bumped whenever the 5% base substitution rate or the
	 * tier2 dedicated map-exercise sub-strategy fires AND the pool had at
	 * least one map fd to hand out -- empty-pool falls back silently to
	 * scalar-only generation and is not counted here. */
	unsigned long map_fd_substituted;

	/* Phase 3.4: bumped each time the eBPF generator emits a typed
	 * helper call -- either via tier1's HELPER_CALL_WEIGHT_PCT lottery
	 * or the tier2 dedicated helper-call sub-strategy.  Counts only
	 * successful emissions; picks that bailed because no satisfiable
	 * helper existed in the current reg state (e.g. ARG_MAP_PTR with
	 * an empty map-reg slot) or the remaining buffer couldn't fit the
	 * arg-setup + CALL + EXIT do not increment this. */
	unsigned long helper_call_emitted;

	/* Phase 3.4.5: bumped each time the generator emits the map-value
	 * NULL-check + deref idiom after a map_lookup_elem.  Total counter
	 * plus a read/write breakdown: deref_read counts LDX_W loads of
	 * the value, deref_write counts STX_W stores; sum equals
	 * deref_emitted.  Gated on the 3% MAP_VAL_DEREF_WEIGHT_PCT lottery
	 * AND a live PTR_OR_NULL_TO_MAP_VALUE in R0 from a recent lookup,
	 * so the observed rate sits well below the lottery weight -- bumps
	 * here track the slice of programs that actually reach the
	 * verifier's check_map_access / map-value runtime path. */
	unsigned long map_value_deref_emitted;
	unsigned long map_value_deref_read;
	unsigned long map_value_deref_write;
};

#endif	/* _TRINITY_STATS_SUBSYS_EBPF_GEN_H */
