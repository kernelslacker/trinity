/*
 * Struct catalog and offset mapping for CMP-guided struct filling.
 *
 * When KCOV CMP tracing reveals a constant that the kernel compared
 * against a struct field, we want to know which field was involved so
 * that future mutations can target that specific field.
 *
 * This module provides:
 *   - A static catalog of known struct types with field offset/size data.
 *   - A table mapping (syscall name, arg index) -> struct type.
 *   - A fast nr->desc lookup built at init time.
 *   - struct_field_for_cmp(): guess which field a CMP value belongs to.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "syscall.h"

/*
 * Semantic field-type taxonomy.
 *
 * Fields default to FT_RAW (the zero value), which preserves the
 * historical per-field random-byte fill.  Other tags carry kernel-ABI
 * vocabulary so the schema-aware fill path can produce values that
 * survive first-pass validators (size, enum bounds, flag-mask checks,
 * length-of-sibling checks, magic-version checks, fd validity).
 *
 * Implemented today: FT_RAW (fall-through), FT_FLAGS, the
 * pointer/length pair (FT_PTR_BYTES, FT_PTR_ARRAY, FT_PTR_STRUCT
 * paired with FT_LEN_BYTES / FT_LEN_COUNT).  Other tag values are
 * reserved so the catalog can be annotated incrementally; the fill
 * switch falls through to FT_RAW for tags it does not yet understand.
 */
enum field_tag {
	FT_RAW = 0,		/* current per-field random splat (default) */
	FT_ENUM,		/* pick from u.enum_.vals */
	FT_RANGE,		/* uniform [u.range.lo, u.range.hi] */
	FT_FLAGS,		/* OR a random subset of u.flags.mask bits */
	FT_PTR_BYTES,		/* pointer to byte buffer sized by sibling len field (bytes) */
	FT_PTR_ARRAY,		/* pointer to array of elements counted by sibling len field */
	FT_PTR_STRUCT,		/* pointer to one cataloged struct, length in bytes */
	FT_LEN_BYTES,		/* length-in-bytes of paired buffer field */
	FT_LEN_COUNT,		/* length-in-element-count of paired array field */
	FT_FD,			/* fd-shaped slot */
	FT_MAGIC,		/* pick from a curated constant set */
	FT_VERSION_MAGIC,	/* pick from a curated size/version set */
	FT_ADDRESS,		/* writable / scrubbable region */
	FT_TAGGED_UNION,	/* per-discriminator subset of fields */
};

/* One field within a cataloged struct. */
struct struct_field {
	const char	*name;
	unsigned int	 offset;
	unsigned int	 size;
	enum field_tag	 tag;
	uint8_t		 mutate_weight;
	union {
		struct { const unsigned long *vals; unsigned int n; } enum_;
		struct { unsigned long lo, hi; } range;
		struct { unsigned long mask; } flags;
		/* FT_PTR_BYTES: pointer to a buffer of [1, max_bytes] bytes. */
		struct {
			const char	*len_field;
			bool		 optional;
			bool		 null_terminated;
			unsigned int	 max_bytes;
		} ptr_bytes;
		/* FT_PTR_ARRAY: pointer to [1, max_count] elements of named struct. */
		struct {
			const char	*len_field;
			const char	*elem_struct;
			unsigned int	 max_count;
		} ptr_array;
		/* FT_PTR_STRUCT: pointer to one cataloged struct. */
		struct {
			const char	*len_field;
			const char	*struct_name;
			bool		 optional;
		} ptr_struct;
		/* FT_LEN_BYTES / FT_LEN_COUNT: report paired buffer's chosen size. */
		struct {
			const char	*buf_field;
			bool		 optional;
		} len_of;
		const unsigned long *vals;		/* FT_MAGIC, FT_VERSION_MAGIC */
	} u;
};

/*
 * Per-discriminator-value subset of fields for a tagged-union struct.
 * When struct_desc->variants is non-NULL the schema-aware fill resolves
 * the live discriminator value (typically a syscall arg read off rec)
 * and walks the matching variant's fields[] in place of the shared
 * desc->fields[].  effective_size lets the kernel-side size byte be
 * driven by the per-variant ABI rather than sizeof(union) -- left zero
 * by variants that don't care.
 */
struct union_variant {
	unsigned long		   discrim_value;
	const char		  *name;
	const struct struct_field *fields;
	unsigned int		   num_fields;
	unsigned int		   effective_size;
};

/* A cataloged struct type with full field layout. */
struct struct_desc {
	const char		 *name;
	unsigned int		  struct_size;
	const struct struct_field *fields;
	unsigned int		  num_fields;
	/*
	 * Tagged-union plumbing.  All zero (default) means "not a tagged
	 * union" -- pre-existing structs keep their flat fields[] semantics.
	 * discrim_arg_idx is 1-based and names which syscall arg slot
	 * carries the discriminator value at fill time.
	 */
	unsigned int		   discrim_arg_idx;
	const struct union_variant *variants;
	unsigned int		   num_variants;
	/*
	 * Buffer-relative discriminator: used when the value lives at a
	 * fixed offset inside the just-filled buffer itself (e.g.
	 * sockaddr_storage's ss_family at offset 0) rather than in a
	 * syscall arg.  Consulted only when discrim_arg_idx == 0;
	 * buffer_discrim_size of 1/2/4 selects width, zero disables.
	 */
	unsigned int		   buffer_discrim_offset;
	unsigned int		   buffer_discrim_size;
};

/*
 * Static mapping of (syscall name, 1-based arg index) -> struct type.
 * Terminated by .syscall_name == NULL.
 */
struct syscall_struct_arg {
	const char		 *syscall_name;
	unsigned int		  arg_idx;	/* 1-based */
	const struct struct_desc *desc;
};

/* All cataloged struct types. */
extern const struct struct_desc struct_catalog[];
extern const unsigned int struct_catalog_count;

/* Syscall -> struct arg mapping table. */
extern const struct syscall_struct_arg syscall_struct_args[];

/*
 * Find the struct_desc for a given struct name.
 * Returns NULL if not in the catalog.
 */
const struct struct_desc *struct_catalog_lookup(const char *name);

/*
 * Find which struct (if any) syscall nr uses at arg_idx (1-based).
 * do32bit selects the 32-bit or 64-bit table on biarch builds.
 * Returns NULL if not cataloged.
 * Must be called after struct_catalog_init().
 */
const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit);

/*
 * Given a CMP hint value and a struct descriptor, return the index of
 * a field whose size can naturally contain the value, or -1 if no
 * field matches.  Used to associate a kernel CMP constant with the
 * struct field most likely being compared.  When desc carries a
 * tagged-union variant set and rec is non-NULL, the candidate pool is
 * scoped to the live variant resolved from rec; otherwise the full
 * desc->fields[] is sampled.  Passing rec == NULL preserves the
 * pre-variant behaviour for non-union structs.
 *
 * Field reference: the returned index addresses either the resolved
 * variant's fields[] (when scoped) or desc->fields[] (when not).
 * Callers that want to read the field directly must mirror the same
 * lookup; an opaque-index API would force the same walk on the read
 * side without any reuse benefit.
 */
struct syscallrecord;
int struct_field_for_cmp(const struct struct_desc *desc,
			 struct syscallrecord *rec, unsigned long val);

/*
 * Resolve which union_variant applies to a given (desc, rec, buf) tuple.
 * Two discriminator sources are supported, in priority order:
 *
 *   - desc->discrim_arg_idx > 0: read a syscall arg off rec.  buf is
 *     unused on this path.  rec must be non-NULL.
 *   - desc->buffer_discrim_size > 0: read the discriminator from
 *     buf + desc->buffer_discrim_offset at the indicated width.  Used
 *     when the live discriminator was just written into the buffer by
 *     the scalar pass (e.g. sockaddr_storage's ss_family).  buf must
 *     be non-NULL on this path; pass NULL to opt out (e.g. from CMP
 *     paths that run before the next fill).
 *
 * Returns NULL when desc carries no variants, when the active
 * discriminator source is unreadable, or when the discriminator value
 * matches no variant.
 */
const struct union_variant *
struct_desc_resolve_variant(const struct struct_desc *desc,
			    struct syscallrecord *rec,
			    const unsigned char *buf);

/*
 * Schema-aware per-field fill for a cataloged struct.  Three passes
 * (scalar / pointer / length) resolve tag-driven coupling without an
 * init-time topological sort; FT_RAW fields keep the historical
 * per-field random splat byte-for-byte.  When desc carries variants,
 * the live discriminator on rec selects which variant's fields[] is
 * walked; the parent rec is also threaded into nested FT_PTR_STRUCT
 * fills so a child struct reads the same syscall args.
 *
 * Public so per-syscall sanitisers (e.g. sanitise_bpf's default arm)
 * can lean on schema fill for cmds they don't customise; arg-gen
 * callers in generate-args.c continue to use this directly.
 */
void struct_field_fill_schema_aware(unsigned char *buf, unsigned int size,
				    const struct struct_desc *desc,
				    struct syscallrecord *rec);

/*
 * Build the fast nr->desc lookup table by resolving syscall names in
 * syscall_struct_args[] against the active syscall table.
 * Must be called after select_syscall_tables().
 */
void struct_catalog_init(void);

/*
 * Linear search through syscall_struct_args[] for an entry matching
 * (name, arg_idx) and return its struct_desc.  Returns NULL if no
 * mapping exists.  Suitable for table-init paths that run before
 * struct_catalog_init() has populated the nr-indexed table; per-
 * dispatch consumers should use struct_arg_lookup() instead.
 */
const struct struct_desc *struct_arg_lookup_by_name(const char *name,
						    unsigned int arg_idx);

/*
 * True if desc (or any cataloged struct reachable from desc via
 * FT_PTR_STRUCT / FT_PTR_ARRAY) carries an FT_ADDRESS field.  Used at
 * table-init time to decide whether nested address-scrub needs to walk
 * the struct on every dispatch.  Bounded recursion guards against
 * future catalog entries with cyclic references.
 */
bool struct_desc_has_address_field(const struct struct_desc *desc);
