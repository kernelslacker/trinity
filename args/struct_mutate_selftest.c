/*
 * Startup self-checks for args/struct_mutate.c's per-tag primitives
 * and the collector's skip-list / variant-scope / depth-cap
 * invariants, plus the variant-aware FT_ADDRESS reachability walk in
 * struct_catalog/address.c.
 *
 * Carved out of args/struct_mutate.c: for years the selftest lived
 * at the tail of the same TU because trinity had no separate
 * unit-test binary and every asserted invariant had to be checked at
 * process start (from utils/shm.c) or not at all.  With the tests/
 * test-bin seam in place the selftest is also driven by the test
 * binary with a fixed RNG seed under ASAN; production still calls
 * struct_field_mutate_self_check() at parent init (same one-shot
 * call from init_shm_publish_and_subsystems() as before).
 *
 * Each primitive is exercised with a hand-built struct_field over a
 * sandbox buffer (i.e. zero coupling to the production catalog) so
 * the assertions don't depend on catalog field choices that may
 * shift.  Iteration counts are large enough that reject-sampling
 * primitives (FT_ENUM / FT_VOCAB) get many independent draws; rng
 * coverage of sub-byte cases (FT_RAW bit picks, FT_RANGE direction)
 * is hit by the same loop count without needing a separate sweep.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "args-internal.h"
#include "debug.h"		// BUG
#include "random.h"
#include "rnd.h"
#include "struct_catalog.h"
#include "struct_mutate-internal.h"
#include "syscall.h"

#define STRUCT_MUTATE_SELFTEST_ITERS	256U

static void selftest_flags(void)
{
	uint64_t mask = 0x0000000000ABCDEFULL;
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_flags",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_FLAGS,
		.mutate_weight	= 1,
		.u.flags	= { .mask = (unsigned long) mask },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = (uint32_t) (rnd_u32() & (uint32_t) mask);
		uint32_t after;
		uint32_t diff;
		uint32_t bits;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_flags(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if ((after & ~(uint32_t) mask) != 0)
			BUG("mutate_field_flags wrote outside mask");

		diff = before ^ after;
		bits = (uint32_t) __builtin_popcount(diff);
		if (bits != 1)
			BUG("mutate_field_flags toggled != 1 bit");
		if ((diff & ~(uint32_t) mask) != 0)
			BUG("mutate_field_flags toggled out-of-mask bit");
	}
}

static void selftest_enum(void)
{
	static const unsigned long vals[] = { 1, 7, 42, 100, 9999 };
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_enum",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_ENUM,
		.mutate_weight	= 1,
		.u.enum_	= { .vals = vals, .n = ARRAY_SIZE(vals) },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = (uint32_t) vals[rnd_modulo_u32(ARRAY_SIZE(vals))];
		uint32_t after;
		unsigned int j;
		bool in_vocab = false;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_enum(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if (after == before)
			BUG("mutate_field_enum failed to swap value");
		for (j = 0; j < ARRAY_SIZE(vals); j++) {
			if ((uint32_t) vals[j] == after) {
				in_vocab = true;
				break;
			}
		}
		if (!in_vocab)
			BUG("mutate_field_enum wrote non-vocab value");
	}
}

static void selftest_vocab(void)
{
	static const char *const vocab[] = { "alpha", "beta", "gamma", "delta" };
	unsigned char field_buf[16];
	struct struct_field f = {
		.name		= "selftest_vocab",
		.offset		= 0,
		.size		= sizeof(field_buf),
		.tag		= FT_VOCAB,
		.mutate_weight	= 1,
		.u.vocab	= {
			.vocab		= vocab,
			.vocab_len	= ARRAY_SIZE(vocab),
			.element_stride	= sizeof(field_buf),
		},
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		const char *start = vocab[rnd_modulo_u32(ARRAY_SIZE(vocab))];
		unsigned int j;
		bool in_vocab = false;

		memset(field_buf, 0, sizeof(field_buf));
		memcpy(field_buf, start, strlen(start));
		mutate_field_vocab(field_buf, &f);

		if (field_buf[sizeof(field_buf) - 1] != 0)
			BUG("mutate_field_vocab dropped trailing NUL");

		for (j = 0; j < ARRAY_SIZE(vocab); j++) {
			if (strcmp((const char *) field_buf, vocab[j]) == 0) {
				in_vocab = true;
				break;
			}
		}
		if (!in_vocab)
			BUG("mutate_field_vocab wrote non-vocab string");
	}
}

static void selftest_range(void)
{
	unsigned char field_buf[4];
	struct struct_field f = {
		.name		= "selftest_range",
		.offset		= 0,
		.size		= 4,
		.tag		= FT_RANGE,
		.mutate_weight	= 1,
		.u.range	= { .lo = 10, .hi = 20 },
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		uint32_t before = 10 + rnd_modulo_u32(11);
		uint32_t after;
		int32_t delta;

		memcpy(field_buf, &before, sizeof(before));
		mutate_field_range(field_buf, &f);
		memcpy(&after, field_buf, sizeof(after));

		if (after < 10 || after > 20)
			BUG("mutate_field_range stepped outside [lo, hi]");
		delta = (int32_t) after - (int32_t) before;
		if (delta < -1 || delta > 1 || delta == 0)
			BUG("mutate_field_range step != +/- 1");
	}
}

static void selftest_raw(void)
{
	unsigned char ring[8];
	struct struct_field f = {
		.name		= "selftest_raw",
		.offset		= 2,
		.size		= 4,
		.tag		= FT_RAW,
		.mutate_weight	= 1,
	};
	unsigned int i;

	for (i = 0; i < STRUCT_MUTATE_SELFTEST_ITERS; i++) {
		unsigned char before[sizeof(ring)];
		unsigned int j;
		unsigned int touched = 0;

		for (j = 0; j < sizeof(ring); j++)
			ring[j] = (unsigned char) rnd_u32();
		memcpy(before, ring, sizeof(ring));

		mutate_field_raw(ring, &f);

		/*
		 * Bytes outside [f->offset, f->offset + f->size) must be
		 * byte-identical -- the field-scope guarantee is the whole
		 * point of FT_RAW's "do not contaminate the neighbour" rule.
		 */
		for (j = 0; j < sizeof(ring); j++) {
			if (j >= f.offset && j < f.offset + f.size)
				continue;
			if (ring[j] != before[j])
				BUG("mutate_field_raw touched out-of-field byte");
		}
		for (j = f.offset; j < f.offset + f.size; j++)
			if (ring[j] != before[j])
				touched++;
		if (touched != 1)
			BUG("mutate_field_raw flipped != 1 byte");
	}
}

/*
 * Skip-list invariant: a struct whose only fields carry skip-listed
 * tags must round-trip byte-identical across many gated invocations
 * of struct_field_mutate_one().  The candidate collector should yield
 * zero candidates and the gated entry point should short-circuit; any
 * regression that promoted a coupled tag (PTR_*, LEN_*, ADDRESS, FD,
 * BPF_PROGRAM) into the candidate set would re-introduce the
 * (ptr, len) / address / fd desync the schema fill exists to prevent.
 *
 * The mutation rate is high enough that 10k * STRUCT_FIELD_MUTATE_PCT
 * gate passes is on the order of 1200 -- a single mistakenly-allowed
 * skip-list candidate would flip a byte with overwhelming probability.
 */
static void selftest_skiplist(void)
{
	unsigned char buf[64];
	unsigned char snapshot[sizeof(buf)];
	struct struct_field skiplist_fields[] = {
		{
			.name		= "ptr",
			.offset		= 0,
			.size		= 8,
			.tag		= FT_PTR_BYTES,
			.mutate_weight	= 100,
			.u.ptr_bytes	= { .max_bytes = 16 },
		},
		{
			.name		= "len",
			.offset		= 8,
			.size		= 4,
			.tag		= FT_LEN_BYTES,
			.mutate_weight	= 100,
			.u.len_of	= { .buf_field = "ptr" },
		},
		{
			.name		= "fd",
			.offset		= 16,
			.size		= 4,
			.tag		= FT_FD,
			.mutate_weight	= 100,
		},
		{
			.name		= "addr",
			.offset		= 24,
			.size		= 8,
			.tag		= FT_ADDRESS,
			.mutate_weight	= 100,
		},
	};
	struct struct_desc desc = {
		.name		= "selftest_skiplist",
		.struct_size	= sizeof(buf),
		.fields		= skiplist_fields,
		.num_fields	= ARRAY_SIZE(skiplist_fields),
	};
	unsigned int i;

	for (i = 0; i < sizeof(buf); i++)
		buf[i] = (unsigned char) rnd_u32();
	memcpy(snapshot, buf, sizeof(buf));

	for (i = 0; i < 10000U; i++)
		struct_field_mutate_one(buf, sizeof(buf), &desc, NULL);

	if (memcmp(buf, snapshot, sizeof(buf)) != 0)
		BUG("struct_field_mutate_one mutated a skip-listed field");
}

/*
 * Variant-scope invariant: when the resolved desc carries variants
 * keyed off a buffer-derived discriminator, collect_mutable_candidates
 * must only emit fields from the resolved variant -- never the parent's
 * shared field list, never sibling variants.  A regression that
 * forgot to resolve the variant (passing NULL buf, or skipping the
 * resolver entirely) would silently splatter mutations across the
 * dead union envelope.
 *
 * Builds a sandbox tagged-union desc with two variants keyed on byte
 * zero (1 -> "alpha" variant, 2 -> "beta" variant); flips the
 * discriminator and asserts the candidate set names the matching
 * field exclusively.
 */
static void selftest_variant_scope(void)
{
	static const struct struct_field alpha_fields[] = {
		{
			.name		= "alpha",
			.offset		= 4,
			.size		= 4,
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	};
	static const struct struct_field beta_fields[] = {
		{
			.name		= "beta",
			.offset		= 4,
			.size		= 4,
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	};
	static const struct union_variant variants[] = {
		{
			.discrim_value	= 1,
			.name		= "alpha_v",
			.fields		= alpha_fields,
			.num_fields	= ARRAY_SIZE(alpha_fields),
		},
		{
			.discrim_value	= 2,
			.name		= "beta_v",
			.fields		= beta_fields,
			.num_fields	= ARRAY_SIZE(beta_fields),
		},
	};
	struct struct_desc desc = {
		.name			= "selftest_variant",
		.struct_size		= 16,
		.variants		= variants,
		.num_variants		= ARRAY_SIZE(variants),
		.buffer_discrim_offset	= 0,
		.buffer_discrim_size	= 1,
	};
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	unsigned char buf[16];
	unsigned int n;

	memset(buf, 0, sizeof(buf));
	buf[0] = 1;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 1 || strcmp(cands[0].field->name, "alpha") != 0)
		BUG("variant scope failed for alpha discriminator");

	buf[0] = 2;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 1 || strcmp(cands[0].field->name, "beta") != 0)
		BUG("variant scope failed for beta discriminator");

	/*
	 * Unknown discriminator: no variant resolves, the collector
	 * falls back to desc->fields[] -- which is empty here -- so
	 * the candidate set must be zero.  Catches a regression that
	 * leaked sibling variant fields into the no-match arm.
	 */
	buf[0] = 99;
	n = collect_mutable_candidates(buf, sizeof(buf), &desc, NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	if (n != 0)
		BUG("variant no-match leaked candidates");
}

/*
 * Depth-cap invariant: the recursive walk reaches the parent and its
 * first two FT_PTR_STRUCT descendants (depths 0, 1, 2) and stops
 * before depth 3.  Catches a regression that lifted or removed the
 * cap (unbounded recursion) or applied it off-by-one (only depths
 * 0/1 contribute).
 *
 * Builds a 4-deep sandbox chain via the mutate_struct_lookup_override
 * hook so the test desc resolves without polluting the production
 * struct_catalog.  Each level has one FT_FLAGS leaf; a working depth
 * cap of 3 yields exactly 3 candidates.
 */
struct selftest_depth_chain {
	unsigned char *next;
	uint32_t       leaf;
} __attribute__((packed));

static const struct struct_field selftest_depth_fields[4][2] = {
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_1" },
		},
		{
			.name		= "leaf0",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_2" },
		},
		{
			.name		= "leaf1",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_3" },
		},
		{
			.name		= "leaf2",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
	{
		{
			.name		= "next",
			.offset		= 0,
			.size		= sizeof(unsigned char *),
			.tag		= FT_PTR_STRUCT,
			.mutate_weight	= 1,
			.u.ptr_struct	= { .struct_name = "selftest_depth_unreached" },
		},
		{
			.name		= "leaf3",
			.offset		= sizeof(unsigned char *),
			.size		= sizeof(uint32_t),
			.tag		= FT_FLAGS,
			.mutate_weight	= 1,
			.u.flags	= { .mask = 0xFFU },
		},
	},
};

static const struct struct_desc selftest_depth_descs[4] = {
	{
		.name		= "selftest_depth_0",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[0],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_1",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[1],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_2",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[2],
		.num_fields	= 2,
	},
	{
		.name		= "selftest_depth_3",
		.struct_size	= sizeof(struct selftest_depth_chain),
		.fields		= selftest_depth_fields[3],
		.num_fields	= 2,
	},
};

static const struct struct_desc *selftest_depth_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(selftest_depth_descs); i++)
		if (strcmp(selftest_depth_descs[i].name, name) == 0)
			return &selftest_depth_descs[i];
	return NULL;
}

static void selftest_depth_cap(void)
{
	struct selftest_depth_chain chain[4];
	struct mutate_candidate cands[STRUCT_MUTATE_MAX_CANDIDATES];
	unsigned int n;
	unsigned int i;
	unsigned int leaf_seen = 0;

	memset(chain, 0, sizeof(chain));
	chain[0].next = (unsigned char *) &chain[1];
	chain[1].next = (unsigned char *) &chain[2];
	chain[2].next = (unsigned char *) &chain[3];
	chain[3].next = NULL;
	for (i = 0; i < 4; i++)
		chain[i].leaf = 0;

	mutate_struct_lookup_override = selftest_depth_lookup;
	n = collect_mutable_candidates((unsigned char *) &chain[0],
				       sizeof(chain[0]),
				       &selftest_depth_descs[0], NULL, 0,
				       cands, STRUCT_MUTATE_MAX_CANDIDATES);
	mutate_struct_lookup_override = NULL;

	if (n != 3)
		BUG("depth-walk did not contribute exactly 3 candidates");

	for (i = 0; i < n; i++) {
		if (strncmp(cands[i].field->name, "leaf", 4) != 0)
			BUG("depth-walk emitted a non-leaf candidate");
		/*
		 * leaf3 lives in chain[3], which is depth 3 -- past the
		 * cap.  Its name must never appear in the candidate set.
		 */
		if (strcmp(cands[i].field->name, "leaf3") == 0)
			BUG("depth-walk reached depth-3 field");
		leaf_seen |= 1U << (cands[i].field->name[4] - '0');
	}
	/* leaf0 (bit 0), leaf1 (bit 1), leaf2 (bit 2) all present. */
	if (leaf_seen != 0x7U)
		BUG("depth-walk did not visit all three reachable leaves");
}

/*
 * Variant-aware reachability gate: struct_desc_has_address_field()
 * powers the nested-address-scrub mask, which decides whether the
 * runtime scrub walks a given (syscall, arg) slot at all.  Before the
 * variant walk landed, an FT_ADDRESS that lived only inside a variant
 * (e.g. perf_event_attr.bp_addr on the BREAKPOINT arm) was invisible
 * to the reachability gate -- the mask stayed zero, the scrub never
 * ran, and an in-struct kernel-deref pointer was free to alias the
 * shared sibling buffer.
 *
 * This selftest pins the three variant locations the walker must now
 * follow (variant->fields, variant->base->fields, nested_variant->
 * fields) plus a negative case where no FT_ADDRESS is reachable.  The
 * runtime scrub in scrub_struct_addresses() mirrors the same
 * traversal shape, so guarding the reachability walker also guards
 * the live scrub against the same regression class.
 */
static void selftest_variant_address_walk(void)
{
	static const struct struct_field fields_with_addr[] = {
		{
			.name	= "va_addr",
			.offset	= 8,
			.size	= sizeof(unsigned long),
			.tag	= FT_ADDRESS,
		},
	};
	static const struct struct_field fields_no_addr[] = {
		{
			.name		= "va_flags",
			.offset		= 8,
			.size		= 4,
			.tag		= FT_FLAGS,
			.u.flags	= { .mask = 0xFFU },
		},
	};

	/* Case A: FT_ADDRESS lives only in variant->fields[]. */
	{
		static const struct union_variant variants[] = {
			{
				.discrim_value	= 1,
				.name		= "addr_v",
				.fields		= fields_with_addr,
				.num_fields	= ARRAY_SIZE(fields_with_addr),
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_variant_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (!struct_desc_has_address_field(&desc))
			BUG("variant-only FT_ADDRESS missed by reachability walker");
	}

	/* Case B: FT_ADDRESS lives only in variant->base->fields[]. */
	{
		static const struct union_variant base = {
			.name		= "addr_base",
			.fields		= fields_with_addr,
			.num_fields	= ARRAY_SIZE(fields_with_addr),
		};
		static const struct union_variant variants[] = {
			{
				.discrim_value	= 1,
				.name		= "outer_v",
				.fields		= fields_no_addr,
				.num_fields	= ARRAY_SIZE(fields_no_addr),
				.base		= &base,
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_base_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (!struct_desc_has_address_field(&desc))
			BUG("variant->base FT_ADDRESS missed by reachability walker");
	}

	/* Case C: FT_ADDRESS lives only in nested_variants[k]->fields[]. */
	{
		static const struct union_variant nested[] = {
			{
				.discrim_value	= 7,
				.name		= "nested_addr_v",
				.fields		= fields_with_addr,
				.num_fields	= ARRAY_SIZE(fields_with_addr),
			},
		};
		static const struct union_variant variants[] = {
			{
				.discrim_value		= 1,
				.name			= "outer_v",
				.fields			= fields_no_addr,
				.num_fields		= ARRAY_SIZE(fields_no_addr),
				.nested_discrim_offset	= 4,
				.nested_discrim_size	= 1,
				.nested_variants	= nested,
				.num_nested_variants	= ARRAY_SIZE(nested),
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_nested_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (!struct_desc_has_address_field(&desc))
			BUG("nested_variant FT_ADDRESS missed by reachability walker");
	}

	/* Case D: no FT_ADDRESS anywhere -- walker must return false. */
	{
		static const struct union_variant variants[] = {
			{
				.discrim_value	= 1,
				.name		= "noaddr_v",
				.fields		= fields_no_addr,
				.num_fields	= ARRAY_SIZE(fields_no_addr),
			},
		};
		static const struct struct_desc desc = {
			.name			= "selftest_va_no_addr",
			.struct_size		= 16,
			.buffer_discrim_offset	= 0,
			.buffer_discrim_size	= 1,
			.variants		= variants,
			.num_variants		= ARRAY_SIZE(variants),
		};

		if (struct_desc_has_address_field(&desc))
			BUG("reachability walker false-positive on variant without FT_ADDRESS");
	}
}

void struct_field_mutate_self_check(void)
{
	selftest_flags();
	selftest_enum();
	selftest_vocab();
	selftest_range();
	selftest_raw();
	selftest_skiplist();
	selftest_variant_scope();
	selftest_depth_cap();
	selftest_variant_address_walk();
}
