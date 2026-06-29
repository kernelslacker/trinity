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
 * Build 1 introduces a tri-state in use plus a reserved fourth mode
 * (CMPDICT, no-op) so the parse table is stable across the planned
 * Build 2 rung:
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
 *   CMPDICT  - RESERVED for Build 2 (cmp-pool dictionary inserts).
 *              Parsed from day 1 so the flag ladder is stable; in
 *              this build it behaves identically to FILL.
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

/*
 * Author content into a writable buffer.
 *
 *   buf  - the trinity-owned writable allocation
 *   len  - bytes the caller has reserved at buf (the get_writable_struct
 *          size).  Every write is clamped to [0, len); len == 0 returns
 *          immediately.
 *   nr   - the syscall number for the arg being generated.  Reserved
 *          for the Build 2 CMPDICT rung's per-syscall dictionary; the
 *          FILL / HAVOC rungs ignore it.
 *   do32 - true when the arg's CMP-pool lane is the 32-bit lane.
 *          Reserved for the Build 2 CMPDICT rung; the FILL / HAVOC
 *          rungs ignore it.
 */
void blob_fill(unsigned char *buf, size_t len, unsigned int nr, bool do32);

/* Self-check run at init from shm.c (mirror struct_field_mutate_self_check):
 * BUG()s on internal invariant violation so a broken build cannot ship. */
void blob_mutator_self_check(void);
