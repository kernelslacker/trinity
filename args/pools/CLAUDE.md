# args/pools/ — Argument-content pools

The data pools the `args/` generators draw from — pathname strings, xattr names, opaque blob content, and device/blockdev/fstype enumerations. Built at startup (from `/proc`, `/sys`, the file index) and sampled during argument generation. Distinct from `args/` itself: args/ is the argtype dispatch logic; args/pools/ is the *content* it hands out.

## Files (11 files + internal header, ~3,066 LOC)

| File | Lines | Role |
|---|---|---|
| pathnames.c | 815 | `ARG_PATHNAME` pathname pool (mirrors the testfiles the fd layer creates). |
| blob_mutator.c | 584 | `--blob-mutator` content engine for opaque `ARG_BUF_SIZED` buffers; arm selection and `blob_fill()`. |
| blob_corpus.c | 279 | Per-(nr, do32) opaque-blob content corpus: fixed-capacity table, lock-serialised store/evict, snapshot lookup. |
| blob_mutator_arith.c | 201 | Arithmetic/length-oriented HAVOC arms (add/subtract small magnitudes at byte/word/dword width). |
| blob_mutator_helpers.c | 133 | Shared blob-mutator helpers: position picker, splat-form value transforms, static-magic table for the CMPDICT arm. |
| blob_mutator_block.c | 127 | Block-scoped HAVOC arms (bounded memset runs to 0x00/0xff, and friends). |
| blob_mutator_flip.c | 98 | Byte and bit flipper HAVOC arms. |
| blob_mutator-internal.h | 69 | Shared contract for the `blob_mutator*.c` cluster. |
| xattr.c | 417 | Valid xattr name-string generation. |
| devices.c | 173 | Parses `/proc/devices` for the ioctl fuzzer. |
| blockdevs.c | 125 | Block-device enumeration. |
| fstype.c | 114 | Filesystem-type name strings for the fsopen/mount family. |

## Notes
- Pools are built at startup via a `/proc` + `/sys` + file-index walk; `-V` limits the walk for faster local runs.
- They feed the `args/` generators (ARG_PATHNAME / ARG_BUF_SIZED / ARG_FSTYPE / ioctl device pools) — args/ decides *which* generator runs; args/pools/ supplies the content it draws.
