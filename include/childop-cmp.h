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
