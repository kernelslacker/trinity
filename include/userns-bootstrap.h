/*
 * userns_run_in_ns() -- fork a transient grandchild, install an
 * identity user namespace plus caller-requested secondary namespaces,
 * then run a caller callback inside that ephemeral namespace stack.
 *
 * The persistent trinity child that calls this helper NEVER changes
 * its own user namespace.  The unshare(CLONE_NEWUSER) happens in a
 * short-lived grandchild that _exit()s when the callback returns.
 *
 * Rationale: trinity's persistent fuzz child runs with the host's
 * credentials so privileged syscalls reach the privileged code paths
 * the fuzzer is built to exercise.  Unsharing CLONE_NEWUSER in place
 * (the anti-pattern in childops/statmount-idmap-overflow.c's
 * unshare_ns_once()) would permanently demote the persistent child and
 * the cap-drop oracle would stop observing the credential state the
 * rest of the run depends on.  The transient-fork shape (modelled on
 * childops/userns-fuzzer.c's inner_child_main()) confines the
 * namespace change to a process whose death tears every namespace
 * back down with it.
 *
 * Safety: the grandchild only ever holds capabilities scoped to the
 * fresh user namespace.  Those caps are kernel-firewalled against the
 * init user namespace -- every privileged syscall targeting a host
 * resource still goes through ns_capable() against init_user_ns and
 * is rejected.  Running ops in the grandchild therefore does NOT
 * defeat trinity's cap-drop intent.  It exposes the separate (and
 * historically vulnerable) ns_capable()-gated attack surface that the
 * persistent, fully-privileged child cannot reach.
 *
 * target_ns_flags: zero or more CLONE_NEW* flags to be passed to a
 * second unshare() call after the userns is up.  Zero is accepted and
 * means "userns only".  Any flags rejected by the kernel collapse the
 * call to a transient setup failure (return -EAGAIN).
 *
 * fn / arg: the callback runs once inside the namespace stack.  Its
 * return value is ignored -- the caller already knows what work it
 * dispatched; failure modes from the caller's own syscalls belong to
 * the caller's accounting (stat counters, oracles).  fn must not
 * touch trinity shared state in ways that assume the host credential
 * profile -- the credentials inside the grandchild differ.
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
