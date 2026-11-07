# args/pools/ — Argument-content pools

## Files

| File | Role |
|---|---|
| pathnames.c | `ARG_PATHNAME` pathname pool (mirrors the testfiles the fd layer creates). |
| kallsyms-symbols.c | Kernel text-symbol name/address pool from `/proc/kallsyms`, for the kprobe_multi scalar fill. |
| exec-paths.c | Executable-file path pool from the bin directories, for the uprobe_multi path fill. |
| blob_corpus.c | Per-(nr, do32) opaque-blob content corpus behind `include/blob_corpus.h`: one fixed-capacity table under a lock, first-match lookup with no random draw; store and eviction in `blob_corpus_promote_pending()`. |
| blob_mutator.c | The `--blob-mutator` engine for opaque `ARG_BUF_SIZED` args: the OFF / FILL / HAVOC / CMPDICT ladder of `include/blob_mutator.h`. |
| blob_mutator_arith.c, blob_mutator_block.c, blob_mutator_flip.c | The HAVOC arms: arithmetic and length edits, block-scoped runs capped at `BLOB_HAVOC_BLOCK_MAX`, byte and bit flips; shared contract in `blob_mutator-internal.h`. |
| blob_mutator_helpers.c | The engine's position picker, splat-form value transforms, and the static magic table the CMPDICT arm tries before its learned pull. |
| devices.c | `/proc/devices` and `/proc/misc` parse, and `map_dev()`, which names the driver behind a device node for the ioctl fuzzer. |
| fstype.c | Filesystem-type name strings for the fsopen/mount family, from the loaded types `syscalls/fs/mount/mount.c` reads and a built-in baseline. |
| xattr.c | Extended-attribute names, value and list buffer sizes, values and set flags for the xattr syscalls. |
