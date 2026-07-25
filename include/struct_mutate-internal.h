#pragma once

/*
 * Internal header shared between args/struct_mutate.c (production
 * candidate walk + dispatch) and args/struct_mutate_selftest.c
 * (startup selftests + FT_PTR_STRUCT depth-cap coverage over a
 * sandbox catalog).
 *
 * The two TUs stayed in one file for years because trinity has no
 * separate unit-test binary; splitting requires exporting a small
 * private surface (the candidate type + collector prototype + the
 * test-only lookup override).  Kept private to args/ -- consumers
 * outside the args cluster continue to use the public API in
 * include/struct_catalog.h (struct_field_mutate_one,
 * struct_field_mutate_self_check).
 */

#include "args-internal.h"		/* STRUCT_FILL_MAX_FIELDS */
#include "struct_catalog.h"		/* struct struct_field, struct struct_desc */

struct syscallrecord;

/*
 * Depth cap for the recursive walk: parent + two child levels (depths
 * 0, 1, 2).  Each level can in principle contribute
 * STRUCT_FILL_MAX_FIELDS candidates; multiply for the upper bound on
 * the candidate array.  Catalog structs today reach at most 2 levels
 * (msghdr -> iovec); the extra slot is a forward-compat safety margin
 * for future deeper nests.  Bounded recursion is also the
 * cyclic-catalog safety net -- a future cyclic entry can't trap the
 * collector beyond the cap.
 */
#define STRUCT_MUTATE_DEPTH_CAP		3U
#define STRUCT_MUTATE_MAX_CANDIDATES	(STRUCT_FILL_MAX_FIELDS * \
					 STRUCT_MUTATE_DEPTH_CAP)

/*
 * One candidate mutable field.  buf remembers which buffer the field
 * lives in (top-level or an FT_PTR_STRUCT / FT_EMBEDDED_STRUCT child
 * sub-buffer reachable via the depth walk).  weight defaults to 1
 * when the catalog leaves mutate_weight unset.
 */
struct mutate_candidate {
	unsigned char *buf;
	const struct struct_field *field;
	unsigned int weight;
};

/*
 * Candidate collector: variant-resolves at each level, walks
 * mutable-tag fields into out[], and recurses through FT_PTR_STRUCT
 * / FT_EMBEDDED_STRUCT children up to STRUCT_MUTATE_DEPTH_CAP.
 * Exposed for the selftest's variant-scope and depth-cap invariants;
 * the production caller (mutate_one_unconditional) lives in the same
 * TU and calls it directly.
 */
unsigned int collect_mutable_candidates(unsigned char *buf,
					unsigned int size,
					const struct struct_desc *desc,
					struct syscallrecord *rec,
					unsigned int depth,
					struct mutate_candidate *out,
					unsigned int out_max);

/*
 * Test-only lookup override.  When non-NULL, mutate_lookup_desc()
 * routes FT_PTR_STRUCT child-desc resolution through this pointer
 * instead of struct_catalog_lookup(), so a selftest can drive
 * collect_mutable_candidates over a sandbox catalog without polluting
 * the real struct_catalog lookup table.  Must be cleared to NULL
 * before returning from the selftest; production callers observe the
 * default (real catalog) path only when this stays NULL.  Set from
 * args/struct_mutate_selftest.c exclusively -- no production caller.
 */
extern const struct struct_desc *(*mutate_struct_lookup_override)(const char *);

/*
 * Per-tag mutation primitives.  Live in args/struct_mutate.c; exposed
 * here so the selftest can drive each primitive directly (rather than
 * going through the public struct_field_mutate_one() gate, which
 * would need retry loops to work around the 12% mutation-probability
 * gate and turn a deterministic assertion into a probabilistic one).
 * No production caller outside args/struct_mutate.c.
 */
void mutate_field_flags(unsigned char *buf, const struct struct_field *f);
void mutate_field_enum(unsigned char *buf, const struct struct_field *f);
void mutate_field_vocab(unsigned char *buf, const struct struct_field *f);
void mutate_field_range(unsigned char *buf, const struct struct_field *f);
void mutate_field_srange(unsigned char *buf, const struct struct_field *f);
void mutate_field_raw(unsigned char *buf, const struct struct_field *f);
