# childops/fs/ — Filesystem Childops

Scripted VFS/filesystem workloads. One workload per file, dispatched by
symbol through the `include/childop.def` registry (no path coupling).

## Files (3)
- `inode-spewer` — inode/dentry cache churn.
- `procfs-writer` — proc/sys/debugfs write surfaces behind an allow/deny
  ruleset; the deny rules are suffix-matched and the allow rules are prefix-
  matched, so an allow prefix can shadow a deny suffix (the op warns when it
  detects one).
- `xattr-thrash` — extended-attribute churn.
