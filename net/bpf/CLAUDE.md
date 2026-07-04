# net/bpf/ — BPF / eBPF Program Generation

Two independent, uncoupled program generators for the socket/seccomp/BPF surface, plus the classic-BPF disassembler and the AF_XDP umem tracker. Distinct from `net/proto/`: those *attach* these programs (KCM classifiers, socket filters, XDP); this dir *generates* them.

## Files (4 files + internal header)

| File | Lines | Role |
|---|---|---|
| ebpf.c | 1266 | Independent eBPF generator (`BPF_PROG_LOAD`-style), three explicit tiers: Tier 1 verifier-valid (forward jumps, liveness, bounded stack, valid helper calls), Tier 2 boundary/edge-case (near-limit complexity, unchecked map lookups, ALU overflow), Tier 3 chaos (invalid opcodes, backward jumps, OOB registers, malformed 128-bit loads) — targets the verifier and JIT directly. |
| bpf.c | 554 | Classic BPF (`struct sock_filter`) generator for socket filters (`SO_ATTACH_FILTER`) and seccomp; builds instruction sequences, invokes the disassembler at high verbosity. |
| disasm.c | 447 | Classic BPF disassembler (`bpf_disasm_all`), used only for debug logging of what `bpf.c` generated. |
| xdp-umem-track.c | 95 | Fixed 256-slot table tracking AF_XDP umem fd/ptr/len triples; used by `net/proto/xdp.c`. |
| internal.h | 153 | Private shared declarations + opcode-bit fallback macros for the `bpf.c`/`disasm.c` classic pair only. |

## Key invariants
- **Two generators, no shared code.** Classic BPF (bpf.c, cBPF) targets socket filters/seccomp; eBPF (ebpf.c) targets `BPF_PROG_LOAD` and is tiered to separately stress the verifier's acceptance and rejection paths. `internal.h` is private to the classic pair only.
- **eBPF tiering is deliberate** — valid-program synthesis, boundary synthesis, and pure chaos live in one TU across three tiers; the "is this still verifier-valid" logic and the "deliberately break this" logic sit side by side.

## Interactions
- Wide consumer fan-out, all by symbol (link-safe): `syscalls/{bpf,seccomp,prctl,setsockopt,io_uring_register-payloads}.c`, `childops/{bpf-lifecycle,bpf-cgroup-attach,sock-ulp-sockmap-layering,veth-asymmetric-xdp,afxdp-churn}.c`, `fds/bpf.c`, `struct_catalog/bpf.c`.
- `net/proto/kcm.c` pulls in `bpf.c` output (KCM sockets can attach a BPF classifier); `net/proto/xdp.c` uses `xdp-umem-track.c`.
