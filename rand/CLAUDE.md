# rand/ — Randomness and Value-Generation Core

The base layer every arg generator sits on top of: PRNG state/seeding,
munged random integers, a static a-priori "interesting values" corpus,
value mutation strategies, random address/length/page generation, and
content-aware text payload generation. Everything downstream (args/,
struct_catalog/, mm/, syscalls/, childops/) draws its randomness through
this directory rather than calling libc rand() directly.

## Files (10 files, ~2,923 LOC)

| File | Lines | Role |
|---|---|---|
| random.c | 316 | Core munged integer generators: `rand16()`/`rand32()`/`rand64()`, bitmask helpers (`set_rand_bitmask`, `rand_single_bit[64]`, `randbits[64]`), byte-repeat (`rept_byte`) |
| interesting-numbers.c | 262 | Static a-priori boundary-value corpus: `get_boundary_value()`, `get_negative_edge_value()`, `get_sizeof_boundary_value()` (overflow-in-multiplication probes), `get_interesting_{8,16,32}bit_value()`, `get_interesting_value()` (64-bit + per-arch canonical/non-canonical address probes) |
| text-payloads.c | 563 | Content-aware string generators for kernel string parsers: long-run strings, embedded NUL, printf format-string attacks, numeric-boundary strings, path traversal, cpu-list/bitmap-list syntax, binary control chars, plus a per-kind stateful name lane (netdev/key-desc/xattr/bpf-obj/mq/netlink-table) that bridges into name-pool.c |
| random-address.c | 759 | Address/buffer generation and safety: writable scratch pool (`get_writable_address`, `get_non_null_address`), shared-buffer/libc-heap relocation (`avoid_shared_buffer_{out,inout}`), iovec array builder (`alloc_iovec`) with per-entry shape picker (NULL/tiny/pagecross/shared/pool/invalid/valid-map), iovec/msghdr second-pass scrub against sibling-scribble corruption |
| random-page.c | 262 | Buffer-dirtying generators: `generate_rand_bytes()` (10 strategies incl. garbage, printable text, numeric-ASCII, fabricated pseudo-struct, printk format specifiers with %p extensions), `generate_random_page()` |
| name-pool.c | 252 | Lock-free shared per-kind name ring (create-then-reference statefulness): `name_pool_record()` / `name_pool_draw_mutated()` with 5 mutation ops (exact/flip-byte/truncate/case-flip/suffix-grow) |
| mutate.c | 166 | Value mutation strategies targeting kernel bug classes: truncate, sign-extend, alignment perturbation, negate, byte-swap, single-bit flip, arith delta, cross-width extend; `shift_flag_bit()` for flag-adjacency probing |
| random-length.c | 155 | Length/size generators: `get_len()` (boundary/sizeof-boundary/typesize/masked-random blend), `get_len_relative()` (object-size-capped variant for kernel-WRITES-buffer safety) |
| seed.c | 142 | PRNG seeding and reproducibility: `init_seed()` (urandom or `-s`), `set_seed()` (per-child seed via splitmix32-style `seed_combine`), `reseed()` (parent bumps shm seed on child crash) |
| rand-warn.c | 46 | Runtime tripwire: `--wrap=rand` catches any libc `rand()` callsite that slipped past the static `no-libc-rand.sh` grep (e.g. via macro expansion), warns once per child, forwards to libc |

## Key design decisions

1. **Inline splitmix64 PRNG (`include/rnd.h`), not libc `rand()`** — `rnd_u64()`/`rnd_u32()`/`rnd_modulo_u32()` (Lemire debiased bounded draw) are static-inline, taking `rand()` (~3-4% of profiled runtime) out of the hot path. State is a plain process-global `uint64_t rnd_state`, so `fork()` gives each child an independent copy for free.
2. **Two-layer seed reproducibility (seed.c)** — parent seed (urandom or `-s`) combines with per-child number via a splitmix32-style avalanche mixer (`seed_combine`) so nearby (seed, childno) pairs land far apart; both `srand()` (for not-yet-migrated `rand()` callers) and `rnd_seed()` are driven from the same combined value, keeping `-s` reproduction intact across both RNG generations. On child crash, `reseed()` bumps the shm seed by `max_children` so all children converge on a new synchronized generation without seed-space collision.
3. **libc `rand()` is banned in two layers** — a build-time grep (`scripts/check-static/no-libc-rand.sh`) rejects new source-level callsites outside `rand/`; a link-time `--wrap=rand` (rand-warn.c) catches anything that still reaches libc `rand()` via macro expansion or an unvisited header. `srand()` is the one deliberate exception (seed.c), since libc's LFSR is not used for generation, only compatibility.
4. **Munged-value generators build width up** — `rand16()` picks from {byte, single-bit, randbits, raw draw, byte-repeated} then applies probabilistic post-mix gates (sign flip, divide, mask); `rand32()`/`rand64()` layer on top of the narrower generator plus feed in `get_interesting_32bit_value()`/`get_interesting_value()` as one of their draw arms — so the static "interesting" corpus is one branch inside the general-purpose integer generator, not a separate code path callers must remember to invoke.
5. **`interesting-numbers.c` is a static a-priori corpus** — boundary values (0/1/INT_MAX/page_size±1/hugepage sizes/per-arch canonical address edges) are hardcoded from domain knowledge of common kernel bug classes (off-by-one, sign extension, allocation-size overflow), independent of any specific target kernel build.
6. **mutate.c targets kernel-specific bug classes, not generic arithmetic** — truncate/sign-extend/alignment/cross-width mutations mirror how the kernel casts between integer widths and handles page/cacheline alignment internally, rather than blind bit-flipping.
7. **name-pool.c: relaxed-atomic ring, snapshot-before-mutate** — per-kind fixed ring with `write_idx`/`filled` counters under RELAXED atomics; readers snapshot the slot into a local buffer before applying a mutation op, since the on-pool bytes can be overwritten concurrently by another child's `record()` (each child has its own lazily-allocated pool — pools are not shared across children).
8. **random-address.c pools are deliberately isolated from fuzz targets** — the writable scratch pool and iovec-array pool are `MAP_PRIVATE|MAP_ANON`, `track_shared_region()`'d, and never `add_object()`'d, so mm-syscall sanitisers refuse fuzzed addresses that would land inside them and `get_random_object()` walks can never select them as a target. `asb_relocate()` additionally guards the copy-in path with `sigsetjmp`/`siglongjmp` against races where a sibling child tears down a tracked shared region.
9. **`get_len_relative()` bounds by construction** — every arm of its object-size-relative distribution returns a value `<= objsize`, so a kernel-WRITES-buffer caller can never be handed a length that scribbles past the buffer, even on its `get_len()` fallback blend arm (which clamps the result).

## Integration points

- `args/gen_arg_scalar.c`, `args/handle_arg.c` — primary consumers of `mutate_value()`, `get_boundary_value()`/interesting-value family, and `get_len()`/`get_len_relative()` for ARG_LEN generation
- `blob_mutator.c`, `minicorpus.c` — pull interesting/boundary values and `generate_random_page()` into corpus/blob mutation paths
- `args/generate-args.c`, `args/argtype_table.c`, `args/gen_arg_time.c`, `args/scrub.c`, `args/struct_fill.c` — address generation (`get_writable_address`, `get_non_null_address`, `get_address`) and shared-buffer scrubbing wired into arg production
- `struct_catalog/*.c` (aio, catalog, futex, kexec, landlock, perf, quota, registry, socket, time, validate) — heavy consumers of `get_address()`/`get_writable_address()` family for struct-field pointer fill
- `mm/maps.c`, `childops/mmap-lifecycle.c`, `childops/mprotect-split.c`, `deferred-free.c` — address-space childops draw from the writable pool and honor `track_shared_region()` exclusions
- `ioctls/*.c` (autofs, btrfs, dm, i2c-dev, kvm-vcpu, kvm-vm, scsi, sg, ioctls.c) and hundreds of `syscalls/*.c` — broad consumers of address/length/page generators (grep shows 150+ syscalls/*.c call sites)
- `net/proto-*.c`, `childops/*-churn.c` (30+ files) — `generate_random_page()`/`generate_rand_bytes()` for wire-format payload fuzzing
- `childops/*` name-consuming set (afxdp-churn, altname-thrash, bridge-*, flowtable-encap-vlan, ip6erspan/ip6gre, ipv6-ndisc-proxy, keyring-spam, l2tp-ifname-race, netlink-monitor-race, nftables-churn, nl80211-churn, psp-key-rotate, tc-*, veth-asymmetric-xdp, vrf-fib-churn, vxlan-encap), plus `syscalls/{add_key,bpf,keyctl,mq_open,request_key,setsockopt-optval-builders}.c`, `xattr.c`, `net/proto/pppox.c` — record/reuse names via name-pool.c's per-kind ring
- `childops/{ipvs-sysctl-writer,procfs-writer,tracefs-fuzzer}.c` — direct consumers of `gen_text_payload()` for sysfs/procfs/tracefs string-parser fuzzing
- `child-init.c`, `child.c`, `main/loop.c`, `main/spawn.c`, `trinity.c`, `utils/shm.c` — seed lifecycle: `init_seed()` at startup, `set_seed()` per fork, `reseed()` on crash detection
- `syscalls/{fchmodat2,file_getattr,file_setattr,getxattrat,listxattrat,removexattrat,setxattrat}.c` — direct `mutate_value()`/`shift_flag_bit()` callers for xattr/attr flag fuzzing

### Relationship to cmp_hints/

`rand/interesting-numbers.c` and `cmp_hints/` are complementary, non-overlapping sources feeding the same downstream arg slots — no shared code or data structures between them:

- **rand/interesting-numbers.c** is a *static, a-priori* corpus: boundary values baked in from general domain knowledge of C/kernel bug classes (INT_MAX, page_size±1, hugepage sizes, canonical address edges). It is target-agnostic — the same table fires regardless of which kernel or which build is under test, and regardless of what that kernel has ever been observed comparing against.
- **cmp_hints/** is a *dynamic, observed* corpus: it harvests the actual constants a running kernel compares fuzzer-derived values against (via KCOV_TRACE_CMP), builds per-syscall/per-field pools of those constants, and biases re-injection toward values a specific kernel binary is known to branch on.
- In practice they stack: `rand32()`/`rand64()` in random.c fold `get_interesting_32bit_value()`/`get_interesting_value()` in as one of several draw arms unconditionally: cmp_hints then separately intercepts arg production (`args/cmp_hint_inject.c`) to override or blend in a live-observed constant when one is available for that syscall/field. Neither directory calls into the other; interesting-numbers.c has zero references from cmp_hints/*.c.

## Areas of attention

1. **random-address.c is oversized for its concerns** (759 LOC) — combines the writable-pool allocator, shared-buffer relocation (with a `sigsetjmp` fault-recovery window), iovec-shape picking, iovec/msghdr scrub, and iovec-pool lifecycle in one file. The `alloc_iovec()`/`pick_iovec_entry_shape()`/`fill_iov_entry_map_backed()` cluster alone is ~350 lines of tightly-coupled per-direction (KERNEL_READ vs KERNEL_WRITE) bucket-weight logic that would be easy to get subtly wrong when adding a new shape.
2. **PRNG is not cryptographically strong by design** — splitmix64 is chosen explicitly for speed and small state, not statistical rigor; the code comments this as an accepted tradeoff ("output quality is more than enough for fuzz argument generation"). This is a reasoned tradeoff, not an oversight, but it means all downstream randomness (including address/length choices that interact with ASLR-adjacent logic) inherits a non-CSPRNG source.
3. **Deliberate small biases documented, not bugs** — `rand16()`/`rand32()`/`rand64()` note ~0.3 percentage-point bias in their "1-in-25" post-mix gates (using `% 25` against an 8-bit slice rather than a bounded draw) and accept it explicitly as "acceptable for a fuzz-flavour gate." Anyone tightening RNG determinism/statistical guarantees elsewhere in the tree should not assume these paths are uniform.
4. **Seed reproducibility depends on two RNG generations staying in lockstep** — `set_seed()` calls both `srand(mixed)` and `rnd_seed(mixed)` from the same combined value specifically so `-s` reproduction survives the migration from libc `rand()` to `rnd_u32()`. Any future change that reseeds one without the other silently breaks `-s` reproducibility without a compile-time signal — the only enforcement is the comment and rand-warn.c's runtime tripwire, which only fires on the wrong function being *called*, not on the wrong one being *seeded*.
5. **name-pool.c per-child, non-shared pools** — each child lazily allocates its own name pool on first use (not shared across the fleet), so the create-then-reference statefulness that motivates the reuse arm only works within a single child's syscall stream. This is documented as intentional, but is a scoping detail future callers could misread as "global name corpus."

## Summary

rand/ is Trinity's foundation layer: a fast non-cryptographic PRNG (splitmix64) with reproducible per-child seeding, layered under munged integer generators (random.c) that blend in a static "interesting values" corpus (interesting-numbers.c) alongside kernel-bug-class-targeted mutation (mutate.c), safe address/length/page generation with active defenses against fuzzed pointers corrupting Trinity's own bookkeeping (random-address.c), and content-aware text payload generation for kernel string parsers (text-payloads.c) backed by a stateful cross-syscall name-reuse ring (name-pool.c). It underpins virtually every arg generator, struct-catalog filler, and childop in the tree, and is architecturally distinct from — but designed to compose with — cmp_hints/'s dynamically-observed constant corpus.
