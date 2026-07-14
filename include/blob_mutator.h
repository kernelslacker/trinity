#pragma once

#include <stdbool.h>
#include <stddef.h>

/* --blob-mutator: content-authoring lane for opaque buffer args.
 *
 * Design rationale: Documentation/blob-mutator.md
 *
 * Ladder rungs (each layers on top of the prior):
 *   OFF      - default; ARG_BUF_SIZED hook skips blob_fill() entirely,
 *              no RNG draw, no byte write.  A/B baseline.
 *   FILL     - generate_rand_bytes() the owned buffer via the
 *              random-page.c content generator.
 *   HAVOC    - FILL plus a bounded byte-mutation pass (bit/byte flip
 *              and interesting-value stamps), capped at
 *              BLOB_HAVOC_MAX_OPS; every write clamped to [0, len).
 *   CMPDICT  - HAVOC plus a bounded buffer-redqueen pass drawing from
 *              a static well-known-magic table and the learned per-nr
 *              cmp_hints pool, capped at BLOB_CMPDICT_MAX_INSERTS;
 *              every splat clamped to pos + width <= len.
 *
 * Safety: blob_fill() writes only inside the get_writable_struct(size)
 * allocation the caller hands it.  No pointer-like aliasing.
 */
enum blob_mutator_mode {
	BLOB_MUTATOR_OFF = 0,
	BLOB_MUTATOR_FILL = 1,
	BLOB_MUTATOR_HAVOC = 2,
	BLOB_MUTATOR_CMPDICT = 3,
};

extern enum blob_mutator_mode blob_mutator_mode;

/*
 * --blob-ab-mode: within-run A/B harness (default off, opt-in only).
 *
 * When set, each blob_fill() invocation coin-flips between HAVOC and
 * CMPDICT for that fill (regardless of blob_mutator_mode), routes all
 * of its RNG draws through the dedicated rnd_blob_state stream (so
 * the main syscall-selection stream stays identical to what it would
 * have been without the flag), and stashes the picked mode on
 * child->blob_ab_mode_last so the dispatch site can credit the
 * resulting per-call new_edges to the mode that produced them.  A
 * null result (rates equal across modes) is as valid a finding as a
 * separation.
 *
 * When absent (default): the caller gate in gen_arg_time.c and the
 * body of blob_fill() bypass the ab path entirely; blob mutation is
 * byte-identical to today and the main RNG stream is untouched by
 * this row.
 */
extern bool blob_ab_mode;

enum blob_ab_child_mode {
	BLOB_AB_MODE_NONE = 0,
	BLOB_AB_MODE_HAVOC,
	BLOB_AB_MODE_CMPDICT,
};

/* Cap on havoc ops per blob; keeps worst-case work O(cap),
 * independent of len. */
#define BLOB_HAVOC_MAX_OPS	64

/* Cap on cmp-dict inserts per blob; keeps worst-case work O(cap),
 * independent of len and of the per-nr cmp pool size. */
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
