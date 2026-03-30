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
#include "syscall.h"

/* One field within a cataloged struct. */
struct struct_field {
	const char	*name;
	unsigned int	 offset;
	unsigned int	 size;
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
 * Returns NULL if not cataloged.
 * Must be called after struct_catalog_init().
 */
const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx);

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
