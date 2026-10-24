# net/bpf/ — BPF / eBPF Program Generation

## Files

| File | Lines | Role |
|---|---|---|
| bpf.c | 500 | Classic BPF (`struct sock_filter`) generator for socket filters (`SO_ATTACH_FILTER`) and seccomp; builds instruction sequences, invokes the disassembler at high verbosity. |
| disasm.c | 448 | Classic BPF disassembler (`bpf_disasm_all`), used only for debug logging of what `bpf.c` generated. |

## Key invariants
- **Two generators, no shared code.** Classic BPF (bpf.c, cBPF) targets socket filters/seccomp; eBPF (the `ebpf*.c` cluster) targets `BPF_PROG_LOAD` and is tiered to separately stress the verifier's acceptance and rejection paths. Each side has its own private header: `internal.h` is included only by `bpf.c` and `disasm.c`, `ebpf-internal.h` only by the eBPF cluster.
- **eBPF tiering is deliberate** — valid-program synthesis, boundary synthesis, and pure chaos are one generator split one tier per TU; the "is this still verifier-valid" logic and the "deliberately break this" logic are siblings behind the same internal header, sharing the liveness, helper-descriptor and map-fd machinery.

## Interactions
- Consumers, all by symbol (link-safe): `syscalls/bpf-prog.c` (`bpf_gen_filter`, `ebpf_gen_program`), `syscalls/process/seccomp.c` (`bpf_gen_seccomp`), `syscalls/socket/setsockopt.c` (`bpf_gen_filter`), and the struct-mutation path through `struct_catalog/bpf-prog.c` and `args/struct_fill.c` (`ebpf_gen_program_into`).
- `net/proto/xdp.c` uses `xdp-umem-track.c`.
