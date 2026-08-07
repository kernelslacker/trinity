# Design Note: Userns-Scoped Admin Lane

## Background

The audit committed in b1f25328dc9e classifies every admin-gated surface into
three classes based on the kernel-side capability gate:

- **Class 1** (`capable(CAP_*)`, 39 entries) — routes to
  `ns_capable(&init_user_ns, cap)` at task level.  Permanently dead under
  capset-to-empty because the child holds no capabilities in `init_user_ns`.

- **Class 2** (`ns_capable(obj->user_ns, CAP_*)` where *obj* is
  child-creatable, 186 entries) — the resolved `user_ns` is the owner of the
  object, not `init_user_ns`.  Structurally reachable when the child is the
  owner of the object's enclosing namespace.

- **Class 3** (`ns_capable(&init_user_ns, ...)` or object always host-owned,
  61 entries) — dead, equivalent to class 1 for the same reason.

The two subtypes of class-2 surfaces that are first-in-line for the unlock are:

| Gate | Representative surfaces | Required namespaces |
|---|---|---|
| `GENL_UNS_ADMIN_PERM` → `ns_capable(net->user_ns, CAP_NET_ADMIN)` | batadv (~15 cmds), ovs (~14 cmds), l2tp (8 cmds), tipc (~12 cmds), mptcp_pm (9 cmds), ethtool (~25 cmds), wireguard (2 cmds), nl80211 (~96 cmds), netdev BIND_RX | CLONE_NEWUSER + CLONE_NEWNET |
| `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` | FIFREEZE, FITHAW | CLONE_NEWUSER + CLONE_NEWNS + child-owned mount |

Class-3 surfaces (`GENL_ADMIN_PERM`) route through `netlink_capable()` which
always resolves to `&init_user_ns` — these are **not** unlockable by this lane.
See b1f25328dc9e for the full gate-taxonomy table.

---

## Unlock Mechanism

### Network-namespace surfaces (GENL_UNS_ADMIN_PERM)

`GENL_UNS_ADMIN_PERM` resolves via `netlink_ns_capable(skb, net->user_ns, cap)`
where `net = genl_info_net(info)` — the network namespace of the sending
socket.  The kernel looks up `net->user_ns`, not `init_user_ns`.

Unlock sequence for the child:

```
unshare(CLONE_NEWUSER | CLONE_NEWNET)
write /proc/self/uid_map: "0 <host-uid> 1"
write /proc/self/setgroups: "deny"
write /proc/self/gid_map: "0 <host-gid> 1"
```

After the write, the child's new user namespace is identity-mapped and the
child is uid 0 *inside that namespace*.  By userns semantics
(`ns_capable(ns, cap)` returns true when `task_ns_capable(task, ns, cap)` is
satisfied and the task's effective user namespace is `ns` or an ancestor), the
child holds a full capability set inside its own user namespace.  Any socket
opened in this child now has `sock_net(sk)->user_ns` pointing at the child's
user namespace — every `GENL_UNS_ADMIN_PERM` command sent on that socket
passes the gate.

### Mount-namespace surfaces (FIFREEZE / FITHAW)

`FIFREEZE` and `FITHAW` call `ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` where
`sb` is the superblock of the frozen filesystem.  `sb->s_user_ns` is set at
mount time to the `user_ns` of the mount namespace in which the filesystem was
mounted.

Unlock sequence:

```
unshare(CLONE_NEWUSER | CLONE_NEWNS)
write uid_map / setgroups / gid_map (identity map)
mount("tmpfs", <path>, "tmpfs", 0, NULL)   /* inside the new mntns */
open(<path>); ioctl(fd, FIFREEZE)
```

The tmpfs `sb->s_user_ns` is set to the child's user namespace at mount time.
`ns_capable(sb->s_user_ns, CAP_SYS_ADMIN)` is satisfied by the child in its
own user namespace.

**FIFREEZE safety constraint**: the child must freeze only its own privately
mounted tmpfs, never a host filesystem.  If the child holds a file descriptor
to a host-mounted filesystem (e.g. opened before the mntns unshare), the ioctl
could freeze the host fs even after the unshare.  The lane must restrict the
target fd to those created inside the private mntns — either by opening the
mount point after the `mount()` call, or by verifying `sb->s_user_ns` matches
the expected userns before issuing the ioctl.  Accidental cross-mount freezes
are the principal hazard for this surface and must be audited before any
FIFREEZE childop opts in.

---

## Safety Constraints

### 1. Gate on max_user_namespaces > 0

Many hardened distro configurations set `user.max_user_namespaces=0` or
`kernel.unprivileged_userns_clone=0`.  Under those policies `unshare(CLONE_NEWUSER)`
returns `EPERM`.  The lane must read `/proc/sys/user/max_user_namespaces` once
at child setup time (or detect `EPERM` from the first `unshare` attempt) and
latch a `no_userns_lane` flag in shared memory.  All subsequent children short-
circuit without attempting the unshare.  A silently-`EPERM` lane is the exact
failure mode documented in b1f25328dc9e — the lane must not introduce it at a
different abstraction level.

### 2. Cap-drop is load-bearing; the lane MUST NOT grant host caps

The capset-to-empty drop in `init_child_setup_sandbox()` is the foundation of
the cap-drop oracle (`child/child-capdrop-oracle.c`).  The oracle fires periodic
probes (`bpf(BPF_PROG_LOAD, KPROBE)`, `mount()`, `setsockopt(SO_RCVBUFFORCE)`,
`capget` read-back) that are designed to fail on a correctly-sandboxed child
and alarm on success.

The userns-admin lane does **not** hand the child `CAP_SYS_ADMIN` on the host.
The mechanism is:

```
unshare(CLONE_NEWUSER|CLONE_NEWNET)   /* new userns + new netns */
write uid_map / setgroups / gid_map   /* identity map */
/* capset(empty) still runs here */
```

After `capset(empty)`, the child holds zero capabilities in `init_user_ns`
(the oracle's probes use `init_user_ns`-scoped gates and remain valid).  The
child holds a full capability set *in its own user namespace* by userns
semantics — `capable()` (which checks `init_user_ns`) still returns false;
`ns_capable(child_userns, cap)` returns true.  The cap-drop oracle fires
correctly because:

- The `bpf(BPF_PROG_LOAD, KPROBE)` gate calls `capable(CAP_SYS_ADMIN)` →
  `ns_capable(&init_user_ns, ...)` → false (no caps in `init_user_ns`).
- The `mount()` probe hits `may_mount()` which calls `ns_capable(mnt_userns,
  CAP_SYS_ADMIN)` for the *host* mount namespace user_ns — `init_user_ns` —
  also false.
- The `SO_RCVBUFFORCE` probe calls `ns_capable(sock_net(sk)->user_ns,
  CAP_NET_ADMIN)`; if the socket was opened *before* the `unshare` it belongs
  to the host netns → `init_user_ns` → false.  Oracle sockets must be opened
  before the unshare, or the probe must be skipped when the ns anchor has
  changed (see below).
- The `capget` read-back directly asserts permitted+effective+inheritable are
  empty — this is unambiguous regardless of userns state.

The `capdrop_oracle_capture_init_ns_anchors()` call runs immediately after the
`capset(empty)` drop, AFTER any unshare.  When the lane is active, the
captured ns anchors reflect the *child's* user/mnt/net namespace identities
(not `init_user_ns`).  The oracle's per-probe ns-anchor comparison gates
already handle this: if the sampled namespace identity no longer matches the
anchor (i.e. a subsequent alt-op legitimately re-unshares), the gated probes
are skipped.  When the lane is active, the `mount` and `net_admin` probes are
skipped for the lifetime of the child because the anchor itself was captured
inside the new namespace — this is correct behaviour and does not mask a
cap-drop regression (the `capget` read-back remains unconditional and catches
any actual drop failure).

### 3. Preventing cross-contamination between the host-cap and userns-cap lanes

The two privilege lanes must not interfere:

- Children that **do not** have `userns_admin_lane` set run the existing
  sandbox unmodified — no unshare beyond the existing mnt/net/ipc/io random
  set, no uid_map write.  The cap-drop oracle behaves identically to today.

- Children that **do** have `userns_admin_lane` set run the extended sandbox
  (unshare + map write) before the cap-drop.  These children are structurally
  separated from the host-cap surface: after `capset(empty)` they cannot reach
  class-1 or class-3 surfaces any more than an unextended child can.  The
  ns_capable-gated surfaces are reachable inside the child's private namespaces;
  they are not reachable from the host perspective.

- The opt-in flag on `struct syscallentry` is the sole control point.  No
  childop sets it until it has been audited to confirm it does not leak userns
  credentials back into host-scoped objects.  The flag is never set by the
  generic random-fuzz path; it is a per-childop annotation applied explicitly.

---

## Surface Ordering — First Customer

**First customer: GENL_UNS_ADMIN_PERM network surfaces.**

These are the lowest-friction starting point:

- `unshare(CLONE_NEWUSER|CLONE_NEWNET)` plus an identity uid/gid map write is
  the complete setup; no secondary mounts, no filesystem teardown.
- The gate resolves `net->user_ns` from the sending socket's netns, which is
  guaranteed to be the child's private netns after the unshare.  There is no
  ambiguity about which `user_ns` the kernel will use.
- The cap-drop oracle `mount` and `net_admin` probes are cleanly gated by the
  ns-anchor machinery (described above).
- Failure modes are limited: the child either gets `EPERM` (userns disabled,
  handled by the latch) or successfully enters the lane and fuzzes genl write
  cmds.

Specifically, within the `GENL_UNS_ADMIN_PERM` group, the **batadv** and
**l2tp** genl families are the first opt-in candidates: both have small,
well-understood cmd sets (15 and 8 cmds respectively) and their handlers
operate entirely within the child's private netns without touching host
routing tables.  nl80211 (~96 cmds) is the largest surface but requires
a mac80211 virtual PHY in the private netns — a pre-condition that needs its
own childop setup; it follows after the simpler families are confirmed working.

**Second customer: FIFREEZE / FITHAW.**

These are more interesting from a VFS/superblock perspective but require the
additional constraint audit (stray-mount safety) described in the safety
section above.  The childop must open the target fd strictly inside the private
mntns, restrict the frozen fs to a freshly-mounted tmpfs, and verify the
ioctl's file argument was not opened before the namespace transition.

---

## Implementation Shape (Phase 2 scaffolding)

The scaffold adds:

1. `bool userns_admin_lane` field on `struct syscallentry` (default `false`;
   no existing entry sets it).

2. A helper `maybe_enter_userns_admin_lane()` in `child-init-sandbox.c` that:
   - reads the `no_userns_lane` latch from shared memory; returns immediately
     if set.
   - reads `/proc/sys/user/max_user_namespaces`; if the value is `<= 0` or
     unreadable, sets the latch and returns.
   - calls `unshare(CLONE_NEWUSER | CLONE_NEWNET)`.
   - writes uid_map, setgroups, gid_map for an identity map.
   - on `EPERM` from the unshare: sets the `no_userns_lane` latch and returns.

3. The call site in `init_child_setup_sandbox()` is placed **after** the
   existing mnt/ipc/io/net random unshare block and **before** the
   `capset(empty)` drop.  `capdrop_oracle_capture_init_ns_anchors()` runs
   after the cap-drop, as today, capturing the post-unshare namespace state.

4. The helper is gated on whether the selected syscall entry (if the session
   is restricted to a single entry via `-c`) has `userns_admin_lane` set.
   In unrestricted mode no entry sets the flag, so the helper is a no-op for
   all current runs.
