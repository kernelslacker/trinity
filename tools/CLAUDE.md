# tools/ — Socket Cache Dump Analyzer

Standalone offline utility, entirely separate from the main trinity binary and build. Not linked into trinity's runtime or its Makefile graph — has its own tiny Makefile that builds a single executable.

## Files (2 files, ~225 LOC)

| File | Lines | Role |
|---|---|---|
| analyze-sockets.c | 224 | Reads a binary cache file of `{family, type, protocol}` triples (each a raw `unsigned int`) and pretty-prints each as symbolic names |
| Makefile | 43 | Builds `analyze-sockets` from the single source file; standard trinity CFLAGS/warnings, no dependency on the rest of the tree beyond `../include/utils.h` |

## What it does

`main()` takes a filename argument and calls `open_sockets()`, which reads the file in fixed 12-byte (`3 * sizeof(int)`) records until EOF. For each record it decodes:
- `family` via a local `families[]` table (PF_UNSPEC..PF_VSOCK) — no fallback for unknown families (`get_family_name()` returns NULL, printed as `(null)`)
- `type` via `decode_type()` (SOCK_STREAM/DGRAM/RAW/RDM/SEQPACKET/DCCP/PACKET, else "Unknown(N)")
- `protocol` via `get_proto_name()`, family-specific: IP protocol table for AF_INET/AF_INET6, netlink protocol table for AF_NETLINK, else "Unknown(N)"

Prints one line per entry and a final count of entries read. `IPPROTO_L2TP` is hand-defined locally (115) to avoid pulling in `<linux/l2tp.h>`, which collides with libc's `<netinet/in.h>` via `<linux/in.h>`.

## Integration points

None found. Grepping the rest of the repo turns up no code that writes a matching cache file (no `add_socket`-adjacent persistence in `fds/sockets.c`, `net/unblocker.c`, or elsewhere) and nothing references `analyze-sockets` outside this directory's own Makefile/.gitignore. This is a manually-invoked, disconnected diagnostic tool — likely predates or targets a socket-cache format the live fuzzer no longer writes, or one produced ad hoc by a patched build.

## Summary

A ~225-line one-shot decoder for a simple binary socket-descriptor cache format (family/type/protocol triples). Self-contained, builds independently, and has no live producer in the current codebase — treat as a legacy/manual debugging aid rather than part of the active fuzzing pipeline.
