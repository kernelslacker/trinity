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

/* A cataloged struct type with full field layout. */
struct struct_desc {
	const char		 *name;
	unsigned int		  struct_size;
	const struct struct_field *fields;
	unsigned int		  num_fields;
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
 * the first field whose size can naturally contain the value, or -1 if
 * no field matches.  Used to associate a kernel CMP constant with the
 * struct field most likely being compared.
 */
int struct_field_for_cmp(const struct struct_desc *desc, unsigned long val);

/*
 * Build the fast nr->desc lookup table by resolving syscall names in
 * syscall_struct_args[] against the active syscall table.
 * Must be called after select_syscall_tables().
 */
void struct_catalog_init(void);
