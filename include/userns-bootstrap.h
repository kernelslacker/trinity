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

int userns_run_in_ns(int target_ns_flags, int (*fn)(void *), void *arg);

#endif
