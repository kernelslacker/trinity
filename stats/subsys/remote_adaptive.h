#ifndef _TRINITY_STATS_SUBSYS_REMOTE_ADAPTIVE_H
#define _TRINITY_STATS_SUBSYS_REMOTE_ADAPTIVE_H

/*
 * Adaptive remote-KCOV mode A/B disposition counters, bumped from
 * dispatch_step in random-syscall.c on every productive-signal call
 * into the PC-mode + remote_capable path so the operator can A/B
 * compare the static remote-mode policy (per-syscall
 * KCOV_REMOTE_HEAVY flag + ONE_IN(remote_reciprocal)) against the
 * adaptive policy (per-syscall remote_pc_edge_calls /
 * local_pc_edge_calls ratio against the REMOTE_ADAPTIVE_PROMOTE_
 * MARGIN_* threshold, gated by REMOTE_ADAPTIVE_MIN_REMOTE_CALLS /
 * MIN_LOCAL_CALLS sample floors).  All counters bump in lock-step
 * from BOTH the Arm A cohort (control) and Arm B (treatment); the
 * live remote_mode flip diverges only on Arm B.
 *
 *  samples                 : total computations -- one bump per
 *    dispatch_step entry into the PC-mode + remote_capable path.
 *  would_demote            : adaptive would flip remote_mode from
 *    true to false because syscall is KCOV_REMOTE_HEAVY-flagged AND
 *    its lifetime remote sample has crossed MIN_REMOTE_CALLS without
 *    producing a single edge.
 *  would_promote           : adaptive would flip remote_mode from
 *    false to true because syscall is NOT HEAVY-flagged, both sample
 *    floors crossed, remote sample non-empty, AND remote edge rate
 *    beats local by PROMOTE_MARGIN_*.
 *  agree                   : adaptive matches static (neither
 *    demote nor promote fires).  Sum {_would_demote, _would_promote,
 *    _agree} == _samples by construction.
 *  would_gate_promote      : shadow disposition for a proposed
 *    plateau gate on the promote branch -- strict subset of
 *    _would_promote, counts would-be divergence between today's
 *    always-promote and a "promote only under remote-dominant
 *    plateau" rule.
 *  would_force             : adaptive widens the promote branch
 *    under PLATEAU_HYPOTHESIS_REMOTE_DOMINANT and flips remote_mode
 *    from false to true using the looser plateau-emergency floor.
 *    Mutually exclusive with _would_promote on the same call.
 *
 * The surrounding struct stats_s composes an instance of struct
 * remote_adaptive_stats as its "remote_adaptive" member.
 */
struct remote_adaptive_stats {
	unsigned long samples;
	unsigned long would_demote;
	unsigned long would_promote;
	unsigned long agree;
	unsigned long would_gate_promote;
	unsigned long would_force;
};

#endif	/* _TRINITY_STATS_SUBSYS_REMOTE_ADAPTIVE_H */
