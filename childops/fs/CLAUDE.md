# childops/fs/ — Filesystem Childops

Scripted VFS/filesystem stress workloads: mount lifecycle, inode/dentry churn, block/ublk device lifecycle, xattr, file locks, and the pseudo-filesystems (proc/sys/trace). One workload per file, dispatched by symbol via `op_dispatch[]` in `child/child-altop-table.c` (no path coupling — the enum→function table wires them at link time).

## Files (13)
- `mount-churn` / `umount-race` — mount/unmount lifecycle + teardown races.
- `fs-lifecycle` — filesystem create/populate/destroy cycle.
- `inode-spewer` — inode/dentry cache churn.
- `blkdev-lifecycle-race` / `ublk-lifecycle` — block-device and userspace-block-device lifecycle.
- `xattr-thrash` — extended-attribute churn.
- `flock-thrash` — file-lock contention.
- `procfs-writer` / `sysfs-string-race` / `tracefs-fuzzer` — pseudo-filesystem write/read surfaces.
- `statmount-idmap-overflow` — `statmount()` + idmapped-mount edge cases.
- `hfs-mount-fuzz` — crafted-image mount fuzzer for a legacy on-disk format (HFS).
