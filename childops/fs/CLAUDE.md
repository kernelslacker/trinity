# childops/fs/ — Filesystem Childops

## Files
- `procfs-writer` — proc/sys/debugfs write surfaces behind an allow/deny
  ruleset; the deny rules are suffix-matched and the allow rules are prefix-
  matched, so an allow prefix can shadow a deny suffix (the
  `procfs-writer-allow-deny-overlap` check-static gate pins those overlaps).
