#pragma once

/*
 * Childop CMP-harvest syscall wrapper.
 *
 * trinity_cmp_syscall(nr, ...) replaces trinity_raw_syscall(nr, ...)
 * at childop syscall sites that participate in the §3.2 KCOV_CMP
 * hybrid harvest path (see projects/trinity/childop-cmp-integration-
 * design.md).  The wrapper is a thin shell around
 * trinity_raw_syscall that:
 *
 *   1. resets cmp_trace_buf[0] to 0 immediately before the syscall
 *      via childop_cmp_reset(), so the kernel appends this syscall's
 *      CMP records from slot 0 (the kernel writes from the count
 *      word);
 *   2. invokes trinity_raw_syscall (honouring -x, identical to the
 *      raw wrapper's contract) to issue the syscall;
 *   3. calls childop_cmp_collect() to walk the produced records and
 *      insert (cmp_ip, value, size) tuples into the quarantined
 *      childop_recent_pools[nr][do32=false] lane keyed by the REAL
 *      __NR_X passed at the callsite.
 *
 * Both helpers no-op on any child whose kc->bracket_owned bit is not
 * set, so a trinity_cmp_syscall() call outside an open
 * kcov_cmp_bracket degrades to plain trinity_raw_syscall() behaviour
 * (one extra branch-predicted helper call).  The actual harvest only
 * fires when --childop-cmp-harvest=on AND the dispatching childop
 * sits behind the child.c op_uses_outer_bracket gate AND the child
 * is CMP-mode.
 *
 * The §3.2 all-routed invariant says every syscall a childop issues
 * inside an open kcov_cmp_bracket MUST go through this wrapper -- an
 * unwrapped helper syscall landing inside a reset/syscall/collect
 * window would be misattributed to the wrapping nr.  Per-childop
 * migration to this wrapper is a separate per-op step landed by C5
 * in the design phasing; until a childop has audited every syscall
 * it issues in its dispatch (including teardown) for routing, it
 * MUST NOT be moved off trinity_raw_syscall.
 *
 * this_child() is available inside both helpers; the wrapper does
 * not need the caller to thread struct kcov_child * through every
 * site, mirroring the trinity_raw_syscall ergonomics.
 */

#include "cmp_hints.h"
#include "kcov.h"
#include "syscall-gate.h"
#include "child.h"

#define trinity_cmp_syscall(nr, ...) \
	__extension__ ({ \
		long _tcsr; \
		struct childdata *_tcsc = this_child(); \
		struct kcov_child *_tcsk = (_tcsc != NULL) ? &_tcsc->kcov : NULL; \
		childop_cmp_reset(_tcsk); \
		_tcsr = trinity_raw_syscall((nr), ##__VA_ARGS__); \
		childop_cmp_collect(_tcsk, (unsigned int)(nr)); \
		_tcsr; \
	})

/*
 * SHADOW consume-side resolver for the childop CMP path.
 *
 * childop_cmp_value(nr, use, old, fallback) is the CONSUMER-side
 * counterpart to trinity_cmp_syscall(): a caller inside a childop's
 * field-emit path calls it with the rng value it was about to
 * commit, and it returns the value to actually commit.  In THIS
 * build the return is unconditionally the fallback -- the resolver
 * is shadow-only, no arg is changed, no downstream behaviour
 * differs.  The point is to size the consume-side opportunity via
 * the kcov_shm childop_cmp_consume_* counters:
 *
 *   --childop-cmp-consume=off (default)
 *      Short-circuit before any cmp_hints_try_get_ex() call and
 *      return fallback verbatim.  Every childop_cmp_consume_*
 *      counter stays at zero; a fixed-seed pick stream at the
 *      callsite is byte-for-byte identical to a build without this
 *      knob.
 *
 *   --childop-cmp-consume=on
 *      Probe the durable per-nr pool via cmp_hints_try_get_ex(nr,
 *      do32=false, use, old, allow_hyp_inject=false, accept=NULL,
 *      arg_idx=0, callsite=CMP_HINT_CALLSITE_OTHER, &resolved);
 *      bump childop_cmp_consume_would_pick[nr] on a true return and
 *      childop_cmp_consume_would_miss[nr] on false; on a true
 *      return, additionally bump childop_cmp_consume_would_value_
 *      differs[nr] iff resolved != fallback (a live consume at
 *      this site would have actually changed the arg).  Return
 *      fallback in both cases.
 *
 * do32 is hard-coded to false: childops issue native 64-bit
 * syscalls only -- see the harvest-side comment in
 * childop_cmp_collect() for the same reasoning.  nr-only keying
 * (pilot single-semantic); a future slice adds nr+cmd / nr+field
 * keying and gates ioctl / keyctl / fcntl childops on it.
 *
 * The four conversion-chain counters (candidate_accepted /
 * arg_changed / outcome_changed / new_cov) declared in kcov_shm
 * next to the would-* triple have NO bump site in this build --
 * they wait for the C3/C4 live-consume slice.
 */
unsigned long childop_cmp_value(unsigned int nr, enum cmp_hint_use use,
				unsigned long old, unsigned long fallback);
