/*
 * userns_run_in_ns() -- fork a transient grandchild, install an
 * identity user namespace plus caller-requested secondary namespaces,
 * then run a caller callback inside that ephemeral namespace stack.
 *
 * The persistent trinity child that calls this helper NEVER changes
 * its own user namespace.  The unshare(CLONE_NEWUSER) happens in a
 * short-lived grandchild that _exit()s when the callback returns.
 *
 * Design rationale (why the transient-fork shape, the capability
 * firewall safety argument, and the callback shared-state contract):
 * Documentation/userns-bootstrap.md
 *
 * target_ns_flags: zero or more CLONE_NEW* flags to be passed to a
 * second unshare() call after the userns is up.  Zero is accepted and
 * means "userns only".  Any flags rejected by the kernel collapse the
 * call to a transient setup failure (return -EAGAIN).
 *
 * fn / arg: the callback runs once inside the namespace stack.  Its
 * return value is ignored.  fn must not touch trinity shared state in
 * ways that assume the host credential profile -- the credentials
 * inside the grandchild differ.
 *
 * Returns:
 *    0      fn(arg) ran inside the namespace stack.
 *   -EPERM  unshare(CLONE_NEWUSER) was refused by the kernel (the
 *           typical cause is a hardened policy:
 *           user.max_user_namespaces=0 or
 *           kernel.unprivileged_userns_clone=0).  The caller should
 *           latch CHILDOP_LATCH_NS_UNSUPPORTED and stop retrying for
 *           the lifetime of the trinity child.
 *   -EAGAIN transient setup failure -- fork() failed, an id-map or
 *           setgroups write failed, the secondary unshare() failed,
 *           or the grandchild died unexpectedly.  Caller should skip
 *           this iteration but must NOT latch; the failure is not
 *           policy and may not recur on the next iteration.
 */
#ifndef _TRINITY_USERNS_BOOTSTRAP_H
#define _TRINITY_USERNS_BOOTSTRAP_H

#include "reap-thresholds.h"

/*
 * Maximum wall-clock seconds any fn(arg) callback passed to
 * userns_run_in_ns() is permitted to run.  The grandchild explicitly
 * resets SIGALRM to SIG_DFL before arming alarm(USERNS_CALLBACK_ALARM_S)
 * because signal handlers are inherited across fork() and the trinity
 * child installs a SIGALRM flag-setter (health/signals-policy.c) that
 * would otherwise absorb the alarm without terminating the process.
 * With SIG_DFL restored, a blocked fn() is killed outright and the
 * parent's waitpid() returns within this many seconds.  Callers that
 * legitimately need longer should split their work across multiple
 * userns_run_in_ns() calls.
 *
 * USERNS_PARENT_ALARM_S is the secondary timeout set by the parent
 * before calling waitpid_eintr().  It is intentionally smaller than
 * REAP_STALL_THRESHOLD_S (the reap-watchdog.c kill threshold) so that
 * the grandchild's own alarm fires first in the normal case; the parent
 * alarm is a belt-and-suspenders escape for the unlikely event that the
 * grandchild's alarm fails to fire.  Note that waitpid_eintr() retries
 * through EINTR, so the parent alarm cannot interrupt the wait
 * permanently; the grandchild-side SIG_DFL reset is the primary
 * enforcement mechanism.
 *
 * Both constants are derived from REAP_STALL_THRESHOLD_S (the reap-
 * watchdog stall kill threshold, defined in include/reap-thresholds.h).
 * USERNS_PARENT_ALARM_S must fire well before the reaper SIGKILLs the
 * trinity child at REAP_STALL_THRESHOLD_S seconds of no progress;
 * USERNS_CALLBACK_ALARM_S must be smaller still so the grandchild's own
 * alarm fires before the parent alarm.  The _Static_asserts below enforce
 * these constraints at compile time in every TU that includes this header.
 */

#define USERNS_PARENT_ALARM_S    12u
#define USERNS_CALLBACK_ALARM_S   8u

_Static_assert(USERNS_PARENT_ALARM_S < REAP_STALL_THRESHOLD_S,
	       "parent alarm must fire before reaper kills");
_Static_assert(USERNS_CALLBACK_ALARM_S < USERNS_PARENT_ALARM_S,
	       "callback alarm must fire before parent alarm");

int userns_run_in_ns(int target_ns_flags, int (*fn)(void *), void *arg);

#endif
