# Cgroup and startup-isolation options

Companion to `main/params/help.c` and `utils/self_cgroup_*.c`.  Trinity
carves a self-cgroup at startup and puts the child fleet under its
own memory limits so a runaway worker cannot OOM the parent (which
is the process holding all the fuzzing state).  These options tune
that containment or opt out of it.  The `--help` output carries only
a one-line contract per option; the split between children and
parent reservations lives here.

Every memory option accepts three spellings:

- `max`  -- no cap
- `N%`   -- percent of `MemTotal`
- `N[KMG]` -- absolute bytes with a K / M / G suffix

## --memory-high

`children/memory.high` back-pressure threshold (workers cgroup).
Soft limit -- crossing it stalls the offending worker with reclaim
pressure but does not OOM it.  Default: 50%.

## --memory-max

Memory budget for the worker fleet: `children/memory.max = <this>`.
The parent gets a small soft reservation of its own,

    parent_high = min(200M, this / 16)

written to `parent/memory.high` with no hard cap, and sits outside the
workers' cgroup so worker OOM does not take the parent.  Hard limit --
exceeding it OOM-kills the workers (the whole pool at once in split
mode, where `children/memory.oom.group=1`).  Default: 60%.

## --memory-swap-max

`children/memory.swap.max` cap (workers cgroup).  Bounds the swap
Trinity's workers may consume; keeps a runaway allocator from
thrashing the host.  Default: 20%.

## --no-cgroup

Skip self-cgroup creation entirely.  No in-binary memory
containment; a runaway worker can OOM the parent and take the whole
run with it.  Use only when the host is providing containment (for
example, when Trinity is already running inside a systemd scope with
its own limits).

## --no-startup-isolation

Skip the parent-side `unshare(CLONE_NEWNET|CLONE_NEWNS)` +
`MS_PRIVATE` remount that the root-launched fuzzer does in
`init_pre_fork()`.  Children still take the per-child unshare path.
Default off; non-root runs never attempt parent-side isolation
regardless.

Root runs need this option to fuzz the generic-netlink families the
kernel registers without `netnsok`.  Those families exist only in the
initial network namespace: outside `init_net`, `ctrl_dumpfamily()`
leaves them out of the `CTRL_CMD_GETFAMILY` dump, and their messages
fail with `ENOENT`.  Each child resolves genl family ids from that
dump in its own netns, so a child outside `init_net` never picks
them.  The registered grammars affected:

- `thermal`
- `vdpa`
- `cifs`
- `NET_DM` (drop monitor)
- `802.15.4 MAC` (the legacy IEEE 802.15.4 family, not `nl802154`)
- `NCSI`
- `nfc`
- `NLBL_MGMT`, `NLBL_CIPSOv4`, `NLBL_UNLBL`, `NLBL_CALIPSO` (NetLabel)

A default root run puts every child in the parent's private netns,
so none of these is ever fuzzed.  With `--no-startup-isolation`, only
the children that skip the per-child `unshare(CLONE_NEWNET)` (a coin
flip at child start-up) stay in `init_net` and can pick them.
Non-root children stay in `init_net` because that unshare fails with
`EPERM`, unless the binary carries the `make setcap` file
capabilities, in which case the same coin flip applies.
