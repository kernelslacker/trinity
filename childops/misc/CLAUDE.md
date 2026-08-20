# childops/misc/ — Miscellaneous Childops

Scripted workloads that don't fit a single subsystem cluster — BPF program lifecycle, IPC (futex/shm/pipe), keyrings, perf events, namespaces/cgroups, and process/fd/scheduler stress. One workload per file, dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c`.

## Files (32)
- **BPF**: `bpf-lifecycle`, `bpf-cgroup-attach`.
- **IPC**: `futex-storm`, `futex-pi-requeue-rollback`, `sysv-shm-orphan-race`, `pipe-thrash`, `ipcns-ucount-exhaustion`.
- **namespaces / cgroups**: `cgroup-churn`, `netns-teardown-churn`, `netns-mountns-setup-probe`, `userns-fuzzer`.
- **process / task**: `fork-storm`, `pidfd-storm`, `signal-storm`, `sched-cycler`, `cpu-hotplug-rider`, `cred-transition-churn`.
- **fd / poll**: `fd-stress`, `close-racer`, `epoll-volatility`, `epoll-nest-race`.
- **memory / refcount audit**: `slab-cache-thrash`, `refcount-auditor`.
- **devices / misc**: `deep-path-nesting`, `pci-bind`, `kvm-run-churn`, `kvm-reclaim-race`, `tty-ldisc-churn`, `perf-event-chains`, `keyring-spam`, `fault-injector`, `barrier-racer`.
