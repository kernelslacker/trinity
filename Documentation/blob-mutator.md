# --blob-mutator design notes

Companion to `include/blob_mutator.h` and `args/pools/blob_mutator.c`.
The header keeps the enum, the two op-count caps, and the
`blob_fill()` per-parameter contract; this document holds the
multi-paragraph rationale for *why* the content-authoring lane
exists and how each rung of the OFF -> FILL -> HAVOC -> CMPDICT
ladder is shaped.

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

`FILL` first tries `blob_corpus_try_get_base(nr, do32, ...)` to seed
the owned buffer from the per-`(nr, do32)` blob corpus.  On a miss
(empty pool, no key match) it falls back to `generate_rand_bytes()`
on the same buffer, which reuses the `random-page.c` content
generator (separator-walking, size-bucketed) -- no new RNG primitive
is introduced.  The hit path bumps `blob_base_from_corpus`, the miss
path bumps `blob_base_from_random`, so the ratio is the observable
"how often did we get a productive base?" gauge.

`HAVOC` layers a bounded byte-mutation pass on top of `FILL`.  Each
iteration picks one of sixteen arms with uniform probability:

- Bit-flip: XOR one bit at a random position.
- Byte-flip: overwrite one byte with a fresh random byte.
- Set-interesting at each of the four recorded cmp widths
  {1, 2, 4, 8}: stamp a value drawn (coin-flipped) from
  `get_boundary_value()` or `get_interesting_value()` at a bounded
  position, clamped so `pos + width <= len`.  Four arms, one per
  width.
- Arithmetic ±1..35 at each of the three widths {1, 2, 4}: read the
  little-endian value at a bounded position, add or subtract a
  magnitude in `[1, 35]`, wrap at width, write back.  Six arms
  (three widths × add/subtract) targeting length / counter / index
  fields the plain byte-flip arms tend to push far outside any
  parser-accepted range.
- Memset-run: fill a bounded run with 0x00 or 0xff (coin-flipped);
  run length clamped to `BLOB_HAVOC_BLOCK_MAX` bytes and to the tail
  from `pos`.
- Self-splice copy: `memmove()` a bounded region over another region
  inside the same buffer; run length clamped to `BLOB_HAVOC_BLOCK_MAX`
  and to `len`.  Builds repeated / duplicated structure fresh-random
  FILL never produces on its own.
- Region-swap: swap two non-overlapping bounded regions byte-by-byte
  through a scratch byte; run length clamped to `len / 2` and to
  `BLOB_HAVOC_BLOCK_MAX`.  Overlapping picks are skipped.
- Prefix-len: stamp a width-`w` value at offset 0 with `w` in
  `{1, 2, 4, 8}` (clamped so `w <= len`) and endianness coin-flipped
  LE/BE per iteration.  The value is uniformly picked over eight
  candidates: `len`, `len + 1`, `len - 1`, `len / 2`, `0`, a small
  int in `[1, 16]`, `get_boundary_value()`, or
  `get_interesting_value()`.  Reaches the length-gated parse path
  downstream of a leading length / size check at offset 0 (TLV entry
  length, netlink `nla_len`, on-wire packet-header size).  Every
  commit of this arm bumps `blob_havoc_prefix_len_ops`.

Op count per invocation is drawn from `[1, BLOB_HAVOC_MAX_OPS]`.
Every write is clamped inside `[0, len)`.

`CMPDICT` layers a bounded buffer-redqueen pass on top of `HAVOC`.
Each of the (capped at `BLOB_CMPDICT_MAX_INSERTS`) iterations
coin-flips between two sources:

- The built-in well-known-magic table (ext4 / XFS / BTRFS / squashfs
  / ELF / gzip super-block and header magics that a kernel parser
  checks BEFORE the `KCOV_TRACE_CMP`-instrumented compare, so a
  learned pool cannot bootstrap them), with a fixed width baked into
  the entry.
- The learned per-nr `cmp_hints` pool via
  `cmp_hints_try_get_sized(nr, do32, ...)` which returns both the
  constant AND the operand width the kernel's cmp instruction
  recorded (one of `{1, 2, 4, 8}`).  Honoring the recorded width
  matches what the kernel's cmp actually reads -- a magic learned
  at a 2-byte compare is written as two bytes, not blindly widened.

In both cases the resolved `(value, width)` pair is passed through
`pick_splat_form()`, which draws one of four splat forms over an
eight-slot roll: plain little-endian (5/8), big-endian byte-swap at
width (1/8), value + 1 at width wrapping (1/8), value - 1 at width
wrapping (1/8).  The three transform arms are additive coverage for
the LE-only exact-value blind spot: BE reaches on-wire surface that
gates on big-endian fields (family/version u16, port u16, netlink
attribute headers); ±1 at width covers off-by-one boundary
neighbours over length / size / offset constants.  The transform is
value-only; bounds are already resolved before it runs.  A width-1
BE splat is arithmetically the same as plain LE but is still
selected and still credited so the arm-selection distribution stays
observable.

A table draw whose baked width does not fit `len` falls through to
the learned path.  A learned pull that misses (empty pool,
chaos-suppressed, corrupted), returns an unsupported width, or
returns a recorded width that does not fit `len`, is skipped
silently -- a narrowed splat would write a partial constant the
kernel's cmp cannot match at its true width.  Neither miss bumps a
counter, so `blob_dict_inserts` and `blob_static_magic_inserts`
both measure committed splats.  A committed splat that used a
non-plain transform arm (across both sources) bumps
`blob_dict_transform_inserts` in addition to the source-side
counter, giving the transform-vs-plain ratio without disturbing the
existing static-vs-learned ratio.  Every write is clamped so that
`pos + width <= len`.

`CMPDICT` is less reproducible under a fixed seed than FILL / HAVOC
because the cmp-hint pool state depends on values the kernel has
handed back at run time, not on RNG sequence alone.

## Safety envelope

`blob_fill()` writes only inside the `get_writable_struct(size)`
allocation the caller hands it.  No pointer-like aliasing is
introduced -- pure byte content into trinity-owned RW data.

## Cap rationale

`BLOB_HAVOC_MAX_OPS` bounds the number of havoc iterations per
`ARG_BUF_SIZED` call.  Single-position arms are O(1) per iteration;
the block-scoped arms (memset-run, self-splice copy, region-swap)
touch up to `BLOB_HAVOC_BLOCK_MAX` bytes each.  Worst-case bytes
touched per `blob_fill()` is therefore
`O(BLOB_HAVOC_MAX_OPS * BLOB_HAVOC_BLOCK_MAX)` -- 64 × 64 = 4 KiB,
comfortably below any `ARG_BUF_SIZED` allocation and independent of
`len`.

`BLOB_CMPDICT_MAX_INSERTS` bounds the CMPDICT rung the same way:
each insert is one source pull plus at most one width-`<= 8`
little-endian splat (possibly value-transformed); worst case stays
`O(BLOB_CMPDICT_MAX_INSERTS)`, independent of `len` and of how rich
the per-nr cmp pool is.
