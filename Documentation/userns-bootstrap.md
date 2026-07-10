# userns-bootstrap design notes

Companion to `include/userns-bootstrap.h`.  The header keeps the
one-line summary, per-parameter contract, and return-code table
(load-bearing caller docs stay next to the declaration); this
document holds the multi-paragraph rationale for the transient-fork
shape and its capability-firewall safety argument.

## Why a transient grandchild fork

Trinity's persistent fuzz child runs with the host's credentials so
privileged syscalls reach the privileged code paths the fuzzer is
built to exercise.  Unsharing `CLONE_NEWUSER` in place (the
anti-pattern in `childops/fs/statmount-idmap-overflow.c`'s
`unshare_ns_once()`) would permanently demote the persistent child
and the cap-drop oracle would stop observing the credential state
the rest of the run depends on.

The transient-fork shape (modelled on
`childops/misc/userns-fuzzer.c`'s `inner_child_main()`) confines the
namespace change to a process whose death tears every namespace back
down with it.  The persistent trinity child that calls the helper
NEVER changes its own user namespace: the `unshare(CLONE_NEWUSER)`
happens in a short-lived grandchild that `_exit()`s when the callback
returns.

## Safety: capability firewall against init_user_ns

The grandchild only ever holds capabilities scoped to the fresh user
namespace.  Those caps are kernel-firewalled against the init user
namespace -- every privileged syscall targeting a host resource
still goes through `ns_capable()` against `init_user_ns` and is
rejected.

Running ops in the grandchild therefore does NOT defeat trinity's
cap-drop intent.  It exposes the separate (and historically
vulnerable) `ns_capable()`-gated attack surface that the persistent,
fully-privileged child cannot reach -- which is the whole point of
the helper.

## Callback contract

The `fn(arg)` callback runs once inside the namespace stack.  Its
return value is ignored -- the caller already knows what work it
dispatched; failure modes from the caller's own syscalls belong to
the caller's accounting (stat counters, oracles).

`fn` must not touch trinity shared state in ways that assume the
host credential profile -- the credentials inside the grandchild
differ.
