# net/bpf/ — BPF / eBPF Program Generation

Two independent, uncoupled program generators for the socket/seccomp/BPF surface, plus the classic-BPF disassembler and the AF_XDP umem tracker. Distinct from `net/proto/`: those *attach* these programs (KCM classifiers, socket filters, XDP); this dir *generates* them.

## Files (10 .c files + 2 internal headers, ~2,715 LOC)

The eBPF generator is no longer one file: it was carved into
`ebpf-*.c`, one tier (and one shared concern) per translation unit,
behind `ebpf-internal.h`.

| File | Lines | Role |
|---|---|---|
| bpf.c | 522 | Classic BPF (`struct sock_filter`) generator for socket filters (`SO_ATTACH_FILTER`) and seccomp; builds instruction sequences, invokes the disassembler at high verbosity. |
| disasm.c | 448 | Classic BPF disassembler (`bpf_disasm_all`), used only for debug logging of what `bpf.c` generated. |
| ebpf-tier1.c | 404 | Tier 1 (valid): programs the verifier should accept — forward-only jumps, register liveness, bounded stack access, valid helper calls, proper exit. Its helper-call and map-value-deref emitters are reused by tier 2. |
| ebpf-tier2.c | 244 | Tier 2 (boundary): structurally valid programs that push verifier limits — spill/fill storms, long ALU chains, jump ladders, mixed ALU32/ALU64, JMP32 variations, and a dedicated helper-call probe. |
| ebpf-helpers.c | 207 | Helper descriptor tables and the helper picker. The tables and their construction macros stay file-static; only the getter, the insn-cost helper and the satisfiability picker are exported. |
| ebpf-internal.h | 186 | Private shared declarations for the `ebpf*.c` fileset only. |
| ebpf-tier3.c | 164 | Tier 3 (chaos): invalid opcodes, backward jumps, OOB registers, malformed 128-bit loads, atomic-imm family probes. No attempt at validity. |
| internal.h | 153 | Private shared declarations + opcode-bit fallback macros for the `bpf.c`/`disasm.c` classic pair only. |
| ebpf.c | 126 | What is left of the generator spine: the tier pick and the fill-into-buffer entry point. |
| xdp-umem-track.c | 96 | Fixed 256-slot table tracking AF_XDP umem fd/ptr/len triples; used by `net/proto/xdp.c`. |
| ebpf-regs.c | 85 | Register-liveness bookkeeping and the stack-offset picker, shared by tier 1 and tier 2. |
| ebpf-map-fd.c | 80 | The map-fd substitution policy and the `LD_MAP_FD` pseudo-insn pair emitter it feeds — a decision the tiers do not need to understand. |

## Key invariants
- **Two generators, no shared code.** Classic BPF (bpf.c, cBPF) targets socket filters/seccomp; eBPF (the `ebpf*.c` cluster) targets `BPF_PROG_LOAD` and is tiered to separately stress the verifier's acceptance and rejection paths. Each side has its own private header: `internal.h` is included only by `bpf.c` and `disasm.c`, `ebpf-internal.h` only by the eBPF cluster.
- **eBPF tiering is deliberate** — valid-program synthesis, boundary synthesis, and pure chaos are one generator split one tier per TU; the "is this still verifier-valid" logic and the "deliberately break this" logic are siblings behind the same internal header, sharing the liveness, helper-descriptor and map-fd machinery.

## Interactions
- Wide consumer fan-out, all by symbol (link-safe): `syscalls/bpf.c`, `syscalls/process/{seccomp,prctl}.c`, `syscalls/socket/setsockopt.c`, `syscalls/io_uring/io_uring_register-payloads.c`, `childops/misc/{bpf-lifecycle,bpf-cgroup-attach}.c`, `childops/net/{sock-ulp-sockmap-layering,veth-asymmetric-xdp,afxdp-churn}.c`, `fds/bpf.c`, `struct_catalog/bpf.c`.
- `net/proto/kcm.c` pulls in `bpf.c` output (KCM sockets can attach a BPF classifier); `net/proto/xdp.c` uses `xdp-umem-track.c`.
