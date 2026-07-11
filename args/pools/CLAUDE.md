# args/pools/ — Argument-content pools

The data pools the `args/` generators draw from — pathname strings, xattr names, opaque blob content, and device/blockdev/fstype enumerations. Built at startup (from `/proc`, `/sys`, the file index) and sampled during argument generation. Distinct from `args/` itself: args/ is the argtype dispatch logic; args/pools/ is the *content* it hands out.

## Files (6 files, ~2,237 LOC)

| File | Lines | Role |
|---|---|---|
| pathnames.c | 797 | `ARG_PATHNAME` pathname pool (mirrors the testfiles the fd layer creates). |
| blob_mutator.c | 612 | `--blob-mutator` content engine for opaque `ARG_BUF_SIZED` buffers. |
| xattr.c | 416 | Valid xattr name-string generation. |
| devices.c | 173 | Parses `/proc/devices` for the ioctl fuzzer. |
| blockdevs.c | 125 | Block-device enumeration. |
| fstype.c | 114 | Filesystem-type name strings for the fsopen/mount family. |

## Notes
- Pools are built at startup via a `/proc` + `/sys` + file-index walk; `-V` limits the walk for faster local runs.
- They feed the `args/` generators (ARG_PATHNAME / ARG_BUF_SIZED / ARG_FSTYPE / ioctl device pools) — args/ decides *which* generator runs; args/pools/ supplies the content it draws.
