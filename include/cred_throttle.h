#pragma once

#include <stdbool.h>

/*
 * Credential-syscall observability oracle + opt-in throttle.
 *
 * Oracle (always on, pure observability): the bumper called from
 * handle_syscall_ret() tracks per-class call / success / EPERM / EINVAL
 * counts so the periodic dump can show which credential classes are
 * burning attempts with zero successes (the diagnostic signature of a
 * non-root run outside a useful userns mapping: the picker selects the
 * class at full rate, the kernel rejects every attempt with EPERM or
 * EINVAL).  Selection distribution is unchanged by the oracle alone.
 *
 * Throttle (default off, gated on --cred-throttle): when the flag is on
 * AND a credential class has accumulated enough evidence to be classified
 * "provably impossible" (>= CRED_THROTTLE_MIN_CALLS attempts, zero
 * successes, EPERM+EINVAL dominate >= 90% of the attempts), the picker
 * gate rejects (CRED_THROTTLE_REJECT_DENOM-1) / CRED_THROTTLE_REJECT_DENOM
 * of subsequent picks of that class so the bandit can spend the budget
 * on syscalls that can still produce coverage.  Flag off keeps the
 * gate's atomic short-circuit before any read of the per-class state, so
 * default behaviour is byte-identical to today.
 *
 * Credential class set (default 9 syscalls -- the full setre+ seteg+
 * setres+ family plus setgroups, sourced from the 787,942-attempts /
 * 0-successes setregid finding) is intentionally narrow so the throttle
 * only acts on the family the analysis identified.  Expanding the set
 * (e.g. to capset / unshare) requires explicit additions to
 * cred_class_name[] in cred_throttle.c.
 */
enum cred_class {
	CRED_CLASS_SETREGID = 0,
	CRED_CLASS_SETREUID,
	CRED_CLASS_SETRESUID,
	CRED_CLASS_SETRESGID,
	CRED_CLASS_SETGID,
	CRED_CLASS_SETUID,
	CRED_CLASS_SETFSUID,
	CRED_CLASS_SETFSGID,
	CRED_CLASS_SETGROUPS,
	CRED_CLASS_NR,
};

extern const char *const cred_class_name[CRED_CLASS_NR];

/* Minimum number of completed calls in a class before the throttle's
 * "provably impossible" gate engages.  Below this floor the throttle
 * stays off so the oracle has a chance to observe a single late success
 * (e.g. a userns CAP_SETUID grant that landed mid-run) before the
 * downweight latches. */
#define CRED_THROTTLE_MIN_CALLS 64

/* Per-class hard-failure fraction (EPERM + EINVAL) of total attempts
 * required to declare the class "provably impossible".  Expressed as a
 * percentage so the eventual operator/Dave tweak can be a single number.
 * 90 means "9 out of every 10 attempts must hit EPERM or EINVAL with
 * zero observed successes". */
#define CRED_THROTTLE_HARD_FAIL_PCT 90

/* Reject-rate denominator for an engaged throttle.  31/32 == 96.875%
 * rejection, i.e. the class still gets sampled at ~3% so a late userns
 * grant or capability gain can still produce a success that retires the
 * throttle on the next oracle re-check. */
#define CRED_THROTTLE_REJECT_DENOM 32U

struct syscallentry;

/* Returns CRED_CLASS_NR if entry is not in the credential class set.
 * Otherwise returns the matching enum cred_class value. */
int cred_class_for_entry(const struct syscallentry *entry);

/* Cached (nr, do32bit) -> cred_class resolver.  First call per slot
 * walks cred_class_for_entry(); subsequent calls hit a single
 * RELAXED-atomic byte load.  Returns CRED_CLASS_NR for slots that have
 * been resolved as non-credential. */
int cred_class_for_nr(unsigned int nr, bool do32);

/* Always-on oracle bump.  Called from handle_syscall_ret() once per
 * completed credential syscall, parallel to the per_syscall_errno
 * histogram bump.  bucket is the ERRNO_BUCKET_* index already computed
 * at the call site. */
void cred_oracle_record(const struct syscallentry *entry,
			unsigned int errno_bucket);

/* Picker-side throttle predicate.  Always returns false when
 * --cred-throttle is off (single RELAXED load on the flag, short-
 * circuits before touching any per-class state) so the default picker
 * distribution is byte-identical to a build without this row.  When the
 * flag is on, returns true with probability (REJECT_DENOM-1)/REJECT_DENOM
 * for credential syscalls whose oracle counters classify the class as
 * provably impossible; otherwise false. */
bool cred_throttle_should_reject(unsigned int nr, bool do32);
