# rand/ — Randomness and Value-Generation Core

## Files

| File | Role |
|---|---|
| random.c | Core munged integer generators: `rand16()`/`rand32()`/`rand64()`, bitmask helpers (`set_rand_bitmask`, `rand_single_bit[64]`, `randbits[64]`), byte-repeat (`rept_byte`) |
| interesting-numbers.c | Static a-priori boundary-value corpus: `get_boundary_value()`, `get_negative_edge_value()`, `get_sizeof_boundary_value()` (overflow-in-multiplication probes), `get_interesting_{8,16,32}bit_value()`, `get_interesting_value()` (64-bit + per-arch canonical/non-canonical address probes) |
| random-address.c | Address/buffer generation and safety: writable scratch pool (`get_writable_address`, `get_non_null_address`, `range_in_writable_pool`), shared-buffer/libc-heap relocation (`avoid_shared_buffer_{out,inout}`), iovec array builder (`alloc_iovec`, `range_in_iovec_pool`) with per-entry shape picker (NULL/tiny/pagecross/shared/pool/invalid/valid-map), iovec/msghdr second-pass scrub against sibling-scribble corruption |
| random-length.c | Length/size generators: `get_len()` (boundary/sizeof-boundary/typesize/masked-random blend), `get_len_relative()` (object-size-capped variant for kernel-WRITES-buffer safety) |

## Key design decisions

2. **Seed reproducibility (seed.c)** — parent seed (urandom or `-s`) combines with per-child number via a splitmix32-style avalanche mixer (`seed_combine`) so nearby (seed, childno) pairs land far apart; `rnd_seed()` and the `--blob-ab-mode` stream's `rnd_blob_seed()` are driven from the same combined value, so `-s` reproduces every per-child stream. On child crash, `reseed()` bumps the shm seed by `max_children` so all children converge on a new synchronized generation without seed-space collision.
4. **Munged-value generators build width up** — `rand16()` picks from {byte, single-bit, randbits, raw draw, byte-repeated} then applies probabilistic post-mix gates (sign flip, divide, mask); `rand32()`/`rand64()` layer on top of the narrower generator plus feed in `get_interesting_32bit_value()`/`get_interesting_value()` as one of their draw arms — so the static "interesting" corpus is one branch inside the general-purpose integer generator, not a separate code path callers must remember to invoke.
5. **`interesting-numbers.c` is a static a-priori corpus** — boundary values (0/1/INT_MAX/page_size±1/hugepage sizes/per-arch canonical address edges) are hardcoded from domain knowledge of common kernel bug classes (off-by-one, sign extension, allocation-size overflow), independent of any specific target kernel build.
6. **mutate.c targets kernel-specific bug classes, not generic arithmetic** — truncate/sign-extend/alignment/cross-width mutations mirror how the kernel casts between integer widths and handles page/cacheline alignment internally, rather than blind bit-flipping.
7. **name-pool.c: relaxed-atomic ring, snapshot-before-mutate** — per-kind fixed ring with `write_idx`/`filled` counters under RELAXED atomics; readers snapshot the slot into a local buffer before applying a mutation op, since the on-pool bytes can be overwritten concurrently by another child's `record()` (each child has its own lazily-allocated pool — pools are not shared across children).
8. **random-address.c pools are deliberately isolated from fuzz targets** — the writable scratch pool and iovec-array pool are `MAP_PRIVATE|MAP_ANON`, `track_shared_region()`'d, end at a `PROT_NONE` guard page (a kernel write run off a pool's end faults instead of landing in the next mapping), and are never `add_object()`'d, so mm-syscall sanitisers refuse fuzzed addresses that would land inside them and `get_random_object()` walks can never select them as a target. `asb_relocate()` additionally guards the copy-in path with `sigsetjmp`/`siglongjmp` against races where a sibling child tears down a tracked shared region.
9. **`get_len_relative()` bounds by construction** — every arm of its object-size-relative distribution returns a value `<= objsize`, so a kernel-WRITES-buffer caller can never be handed a length that scribbles past the buffer, even on its `get_len()` fallback blend arm (which clamps the result).

## Integration points

- `args/gen_arg_scalar.c`, `args/handle_arg.c` — primary consumers of `mutate_value()`, `get_boundary_value()`/interesting-value family, and `get_len()`/`get_len_relative()` for ARG_LEN generation
- `args/pools/blob_mutator*.c` — pull interesting/boundary values and `generate_random_page()` into corpus/blob mutation paths
- `args/generate-args.c`, `args/argtype_table.c`, `args/gen_arg_time.c`, `args/scrub.c`, `args/struct_fill.c` — address generation (`get_writable_address`, `get_non_null_address`, `get_address`) and shared-buffer scrubbing wired into arg production
- `struct_catalog/*.c` (catalog, perf, registry, time, validate) — heavy consumers of `get_address()`/`get_writable_address()` family for struct-field pointer fill
- `mm/maps-*.c`, `persist/deferred-free.c` — address-space code draws from the writable pool and honors `track_shared_region()` exclusions
- `ioctls/*.c` (autofs, btrfs, dm, i2c-dev, scsi, sg, ioctls.c) and 100+ files under `syscalls/` — broad consumers of address/length/page generators (grep shows 150+ syscalls/*.c call sites)
- `net/` (25 files under `net/proto/`, `net/netlink/` and `net/sockaddr.c`) and the `inode-spewer`, `procfs-writer` and `rxrpc-key-install` childops — `generate_random_page()`/`generate_rand_bytes()` for wire-format payload fuzzing
- `syscalls/{keyctl/add_key,keyctl/keyctl,keyctl/request_key,mq/mq_open,bpf,socket/setsockopt-optval-builders}.c`, `args/pools/xattr.c`, `net/proto/pppox.c` — record/reuse names via name-pool.c's per-kind ring
- `childops/fs/procfs-writer.c` — direct consumer of `gen_text_payload()` for procfs/sysfs/debugfs string-parser fuzzing
- `child/child-init-freeze.c`, `child/child.c`, `main/loop.c`, `main/spawn.c`, `utils/shm.c` — seed lifecycle: `init_seed()` at startup, `set_seed()` per fork, `reseed()` on crash detection
- `syscalls/fs/path/fchmodat2.c`, `syscalls/fs/stat/file_getattr.c`, `syscalls/fs/stat/file_setattr.c`, `syscalls/xattr/getxattrat.c`, `syscalls/xattr/listxattrat.c`, `syscalls/xattr/removexattrat.c`, `syscalls/xattr/setxattrat.c` — direct `shift_flag_bit()` callers for xattr/attr flag fuzzing

### Relationship to cmp_hints/

`rand/interesting-numbers.c` and `cmp_hints/` are complementary, non-overlapping sources feeding the same downstream arg slots — no shared code or data structures between them:

- **rand/interesting-numbers.c** is a *static, a-priori* corpus: boundary values baked in from general domain knowledge of C/kernel bug classes (INT_MAX, page_size±1, hugepage sizes, canonical address edges). It is target-agnostic — the same table fires regardless of which kernel or which build is under test, and regardless of what that kernel has ever been observed comparing against.
- **cmp_hints/** is a *dynamic, observed* corpus: it harvests the actual constants a running kernel compares fuzzer-derived values against (via KCOV_TRACE_CMP), builds per-syscall pools of those constants, and biases re-injection toward values a specific kernel binary is known to branch on.
- In practice they stack: `rand32()`/`rand64()` in random.c fold `get_interesting_32bit_value()`/`get_interesting_value()` in as one of several draw arms unconditionally: cmp_hints then separately intercepts arg production (`args/cmp_hint_inject.c`) to override or blend in a live-observed constant when one is available for that syscall/field. Neither directory calls into the other; interesting-numbers.c has zero references from cmp_hints/*.c.

## Areas of attention

1. **random-address.c is oversized for its concerns** (894 LOC) — combines the writable-pool allocator, shared-buffer relocation (with a `sigsetjmp` fault-recovery window), iovec-shape picking, iovec/msghdr scrub, and iovec-pool lifecycle in one file. The `alloc_iovec()`/`pick_iovec_entry_shape()`/`fill_iov_entry_map_backed()` cluster alone is ~325 lines of tightly-coupled per-direction (KERNEL_READ vs KERNEL_WRITE) bucket-weight logic that would be easy to get subtly wrong when adding a new shape.
3. **Deliberate small biases documented, not bugs** — `rand16()`/`rand32()`/`rand64()` note ~0.3 percentage-point bias in their "1-in-25" post-mix gates (using `% 25` against an 8-bit slice rather than a bounded draw) and accept it explicitly as "acceptable for a fuzz-flavour gate." Anyone tightening RNG determinism/statistical guarantees elsewhere in the tree should not assume these paths are uniform.
4. **Every RNG stream must be seeded from the combined value** — `set_seed()` seeds the main stream (`rnd_seed(mixed)`) and the `--blob-ab-mode` stream (`rnd_blob_seed(mixed)`) from the same (shm seed, childno) value so `-s` reproduces both. A new process-local stream that is not seeded there silently breaks `-s` reproducibility without a compile-time signal — rand-warn.c's runtime tripwire only fires on libc `rand()` being *called*, not on a stream going unseeded.
5. **name-pool.c per-child, non-shared pools** — each child lazily allocates its own name pool on first use (not shared across the fleet), so the create-then-reference statefulness that motivates the reuse arm only works within a single child's syscall stream. This is documented as intentional, but is a scoping detail future callers could misread as "global name corpus."
