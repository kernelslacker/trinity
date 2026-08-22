# childops/ — Scripted/stateful per-child fuzz workloads for Trinity

Trinity's default fuzzing loop (`random_syscall/`) picks one syscall in
isolation per iteration. Some kernel bug classes (UAF/refcount races,
teardown-vs-lookup races, multi-step object lifecycles) only surface when a
specific *sequence* of syscalls runs with real state threaded through it.
childops/ is where those scripted sequences live: each file implements one
"childop" — a self-contained C function, dispatched instead of a random
syscall for the current fork'd child, that drives a fixed or semi-fixed
sequence against one kernel subsystem/feature/race window.

8 dispatched ops in 8 `.c` files, plus two shared helper translation units,
grouped into per-domain subdirectories: `fs/` (3), `net/` (2, plus
`net/netlink/` 1 helper), `io_uring/` (1 + 1 helper), `misc/` (1), `mm/` (1).

The set is deliberately small. An earlier tree carried 168 dispatched ops;
runtime coverage data showed most of them producing no new edges over a full
run while the picker's dormant gate progressively starved them, so only the
ops with measured edge yield were kept. Adding one back is fine — the bar is
evidence that it reaches something the random-syscall path does not.

## Files

### Structural pattern

Each dispatched op is one `.c` file exporting a single
`bool <op>(struct childdata *)` entry point. Registration is by extern
symbol through the X-macro registry in `include/childop.def`, which expands
into the enum, the dispatch table, the name lookup, the outer-KCOV-bracket
eligibility switch, and the picker's slot/dormant-gate arrays. There is no
path coupling: the Makefile needs a glob line per directory, and a new op
needs a `childop.def` row.

### Dispatched ops

- `fs/inode-spewer.c` — inode/dentry cache churn.
- `fs/procfs-writer.c` — pseudo-filesystem write surfaces, allow/deny ruled.
- `fs/xattr-thrash.c` — extended-attribute churn.
- `io_uring/send-zc-churn.c` — zero-copy send churn over a forked loopback
  peer.
- `misc/epoll-volatility.c` — epoll set churn against volatile fds.
- `mm/pagecache-canary-check.c` — pagecache integrity canary.
- `net/rxrpc-key-install.c` — rxrpc key install/rotate.
- `net/vsock-transport-churn.c` — vsock transport churn, including a variant
  that runs in a fresh netns via a `userns_run_in_ns()` grandchild.

### Shared helpers (not dispatched)

- `io_uring/ring.c` (+ `ring.h`) — ring setup/teardown.
- `net/netlink/netlink-util.c` — netlink send/recv plumbing and `ns_since()`.

## Notes

- `iouring_send_zc_churn` and `vsock_transport_churn` both fork. They are the
  membership of the canary picker's pid-heavy suppression set
  (`child/child-canary-policy.c`); anything else that grows an inner fork
  belongs there too.
