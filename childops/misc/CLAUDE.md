# childops/misc/ — Miscellaneous Childops

Scripted workloads that don't fit a single subsystem cluster — BPF program lifecycle, IPC (futex/shm/pipe), keyrings, perf events, namespaces/cgroups, and process/fd/scheduler stress. One workload per file, dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c`.

## Files (25)
- **BPF**: `bpf-lifecycle`, `bpf-cgroup-attach`.
- **IPC**: `futex-storm`, `sysv-shm-orphan-race`, `pipe-thrash`.
- **namespaces / cgroups**: `cgroup-churn`, `netns-teardown-churn`, `userns-fuzzer`.
- **process / task**: `fork-storm`, `pidfd-storm`, `signal-storm`, `sched-cycler`, `cpu-hotplug-rider`.
- **fd / poll**: `fd-stress`, `close-racer`, `epoll-volatility`.
- **memory / refcount audit**: `slab-cache-thrash`, `refcount-auditor`.
- **devices / misc**: `pci-bind`, `kvm-run-churn`, `tty-ldisc-churn`, `perf-event-chains`, `keyring-spam`, `fault-injector`, `barrier-racer`.
