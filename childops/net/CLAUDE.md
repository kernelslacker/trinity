# childops/net/ — Networking Childops

## Files (2 dispatched)
- `rxrpc-key-install` — rxrpc key install/rotate.
- `vsock-transport-churn` — vsock transport churn. The fresh-netns variant
  runs inside a `userns_run_in_ns(CLONE_NEWNET)` grandchild so
  `vsock_loopback`'s per-netns state is exercised; that grandchild is a
  fork, which puts this op in the canary picker's pid-heavy suppression set.
