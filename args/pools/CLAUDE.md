# args/pools/ — Argument-content pools

## Files

| File | Role |
|---|---|
| pathnames.c | `ARG_PATHNAME` pathname pool (mirrors the testfiles the fd layer creates). |
| blockdevs.c | Block-device enumeration. |
| kallsyms-symbols.c | Kernel text-symbol name/address pool from `/proc/kallsyms`, for the kprobe_multi scalar fill. |
