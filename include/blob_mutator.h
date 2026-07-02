#pragma once

#include <stdbool.h>
#include <stddef.h>

/* --blob-mutator: content-authoring lane for opaque buffer args.
 *
 * The ARG_BUF_SIZED generator in generate-args.c hands the kernel a
 * writable pool buffer paired with a published length, but leaves the
 * bytes themselves at whatever residue happens to sit in the writable
 * pool slot.  Parsers reading byte 0 first (TLV tag, version, opcode,
 * ...) early-out on the empty residue almost always, so the content
 * lane is the limiting reagent on the blob coverage surface today.
 *
 * The flag ladder is OFF -> FILL -> HAVOC -> CMPDICT, each rung
 * laying its work on top of the prior rung's floor:
 *
 *   OFF      - default.  The ARG_BUF_SIZED hook skips blob_fill()
 *              entirely: no mode-load past the early return, no RNG
 *              draw, no byte write.  Fixed-seed dry-run is byte-
 *              identical to a build before the row -- the mode load
 *              itself consumes no RNG.  This is the A/B baseline.
 *   FILL     - generate_rand_bytes() the owned buffer.  Reuses the
 *              random-page.c content generator (separator-walking,
 *              size-bucketed) -- no new RNG primitive.
 *   HAVOC    - FILL plus a bounded byte-mutation pass: bit-flip,
 *              byte-flip, set-interesting byte / word / dword drawn
 *              from get_boundary_value() / get_interesting_value().
 *              Op count is CAPPED at BLOB_HAVOC_MAX_OPS so the pass
 *              cannot run unbounded; every write is clamped inside
 *              [0, len).
 *   CMPDICT  - HAVOC plus a bounded buffer-redqueen pass.  Each of
 *              the (capped at BLOB_CMPDICT_MAX_INSERTS) iterations
 *              coin-flips between two sources: (a) the built-in
 *              well-known-magic table (ext4 / XFS / BTRFS / squashfs
 *              / ELF / gzip super-block and header magics that a
 *              kernel parser checks BEFORE the KCOV_TRACE_CMP-
 *              instrumented compare, so a learned pool cannot
 *              bootstrap them) with a fixed width baked into the
 *              entry, and (b) the learned per-nr cmp_hints pool via
 *              cmp_hints_try_get(nr, do32, ...) with a random width
 *              drawn from {1, 2, 4, 8} bytes.  In both cases the
 *              value is splatted little-endian at a random offset
 *              inside the buffer.  A table draw whose baked width
 *              does not fit len falls back to the learned path
 *              silently.  Pulls that miss the per-nr pool
 *              (empty / chaos-suppressed / corrupted) are skipped
 *              silently and DO NOT bump the blob_dict_inserts
 *              counter; committed static-table splats bump
 *              blob_static_magic_inserts and committed learned-pool
 *              splats bump blob_dict_inserts, so the observed ratio
 *              is the source split.  Every write is clamped so that
 *              pos + width <= len.  Less reproducible under a fixed
 *              seed than FILL / HAVOC because the cmp-hint pool
 *              state depends on values the kernel has handed back at
 *              run time, not on RNG sequence alone.
 *
 * Safety: blob_fill() writes only inside the get_writable_struct(size)
 * allocation the caller hands it.  No pointer-like aliasing is
 * introduced -- pure byte content into trinity-owned RW data.
 */
enum blob_mutator_mode {
	BLOB_MUTATOR_OFF = 0,
	BLOB_MUTATOR_FILL = 1,
	BLOB_MUTATOR_HAVOC = 2,
	BLOB_MUTATOR_CMPDICT = 3,
};

extern enum blob_mutator_mode blob_mutator_mode;

/* Cap on havoc ops per blob.  Bounded so the pass cannot run away on
 * a large blob -- keeps the worst-case work per ARG_BUF_SIZED call
 * O(BLOB_HAVOC_MAX_OPS), independent of len. */
#define BLOB_HAVOC_MAX_OPS	64

/* Cap on cmp-dict inserts per blob.  Each insert is one cmp_hints_try_get
 * pull plus at most one little-endian splat of width <= 8; bounded so
 * the CMPDICT rung's worst case stays O(BLOB_CMPDICT_MAX_INSERTS),
 * independent of len and of how rich the per-nr cmp pool is. */
#define BLOB_CMPDICT_MAX_INSERTS	16

/*
 * Author content into a writable buffer.
 *
 *   buf  - the trinity-owned writable allocation
 *   len  - bytes the caller has reserved at buf (the get_writable_struct
 *          size).  Every write is clamped to [0, len); len == 0 returns
 *          immediately.
 *   nr   - the syscall number for the arg being generated.  Consumed
 *          by the CMPDICT rung to pick the per-syscall cmp-hint pool;
 *          the FILL / HAVOC rungs ignore it.
 *   do32 - true when the arg's CMP-pool lane is the 32-bit lane.
 *          Consumed by the CMPDICT rung to select the matching per-nr
 *          pool half; the FILL / HAVOC rungs ignore it.
 */
void blob_fill(unsigned char *buf, size_t len, unsigned int nr, bool do32);

/* Self-check run at init from shm.c (mirror struct_field_mutate_self_check):
 * BUG()s on internal invariant violation so a broken build cannot ship. */
void blob_mutator_self_check(void);
