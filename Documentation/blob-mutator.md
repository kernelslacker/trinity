# --blob-mutator design notes

Companion to `include/blob_mutator.h` and `args/blob_mutator.c`.  The
header keeps the enum, the two op-count caps, and the `blob_fill()`
per-parameter contract; this document holds the multi-paragraph
rationale for *why* the content-authoring lane exists and how each
rung of the OFF -> FILL -> HAVOC -> CMPDICT ladder is shaped.

## Why a content-authoring lane

The `ARG_BUF_SIZED` generator in `generate-args.c` hands the kernel a
writable pool buffer paired with a published length, but leaves the
bytes themselves at whatever residue happens to sit in the writable
pool slot.  Parsers reading byte 0 first (TLV tag, version, opcode,
...) early-out on the empty residue almost always, so the content
lane is the limiting reagent on the blob coverage surface today.

## Ladder rungs

Each rung lays its work on top of the prior rung's floor.

`OFF` is the default.  The `ARG_BUF_SIZED` hook skips `blob_fill()`
entirely: no mode-load past the early return, no RNG draw, no byte
write.  Fixed-seed dry-run is byte-identical to a build before the
row -- the mode load itself consumes no RNG.  This is the A/B
baseline.

`FILL` calls `generate_rand_bytes()` on the owned buffer.  Reuses the
`random-page.c` content generator (separator-walking, size-bucketed)
-- no new RNG primitive is introduced.

`HAVOC` layers a bounded byte-mutation pass on top of `FILL`:
bit-flip, byte-flip, set-interesting byte / word / dword drawn from
`get_boundary_value()` / `get_interesting_value()`.  Op count is
CAPPED at `BLOB_HAVOC_MAX_OPS` so the pass cannot run unbounded;
every write is clamped inside `[0, len)`.

`CMPDICT` layers a bounded buffer-redqueen pass on top of `HAVOC`.
Each of the (capped at `BLOB_CMPDICT_MAX_INSERTS`) iterations
coin-flips between two sources:

- The built-in well-known-magic table (ext4 / XFS / BTRFS / squashfs
  / ELF / gzip super-block and header magics that a kernel parser
  checks BEFORE the `KCOV_TRACE_CMP`-instrumented compare, so a
  learned pool cannot bootstrap them), with a fixed width baked into
  the entry.
- The learned per-nr `cmp_hints` pool via
  `cmp_hints_try_get(nr, do32, ...)` with a random width drawn from
  `{1, 2, 4, 8}` bytes.

In both cases the value is splatted little-endian at a random offset
inside the buffer.  A table draw whose baked width does not fit `len`
falls back to the learned path silently.  Pulls that miss the per-nr
pool (empty / chaos-suppressed / corrupted) are skipped silently and
DO NOT bump the `blob_dict_inserts` counter; committed static-table
splats bump `blob_static_magic_inserts` and committed learned-pool
splats bump `blob_dict_inserts`, so the observed ratio is the source
split.  Every write is clamped so that `pos + width <= len`.

`CMPDICT` is less reproducible under a fixed seed than FILL / HAVOC
because the cmp-hint pool state depends on values the kernel has
handed back at run time, not on RNG sequence alone.

## Safety envelope

`blob_fill()` writes only inside the `get_writable_struct(size)`
allocation the caller hands it.  No pointer-like aliasing is
introduced -- pure byte content into trinity-owned RW data.

## Cap rationale

`BLOB_HAVOC_MAX_OPS` bounds the havoc pass so its worst-case work
per `ARG_BUF_SIZED` call stays `O(BLOB_HAVOC_MAX_OPS)`, independent
of `len` -- a large blob cannot make the pass run away.

`BLOB_CMPDICT_MAX_INSERTS` bounds the CMPDICT rung the same way:
each insert is one `cmp_hints_try_get` pull plus at most one
little-endian splat of width `<= 8`; worst case stays
`O(BLOB_CMPDICT_MAX_INSERTS)`, independent of `len` and of how rich
the per-nr cmp pool is.
