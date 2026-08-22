# childops/net/ — Networking Childops

## Sub-directories
- [netlink/](netlink/CLAUDE.md) (1) — netlink send/recv plumbing, shared.

## Files (2 dispatched)
- `rxrpc-key-install` — rxrpc key install/rotate.
- `vsock-transport-churn` — vsock transport churn. The fresh-netns variant
  runs inside a `userns_run_in_ns(CLONE_NEWNET)` grandchild so
  `vsock_loopback`'s per-netns state is exercised; that grandchild is a
  fork, which puts this op in the canary picker's pid-heavy suppression set.

## Notes
- Shared netlink/genl/nfnetlink scaffolding headers (`childops-genl.h`,
  `childops-netlink.h`) live in `include/`.
