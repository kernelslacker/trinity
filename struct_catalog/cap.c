/*
 * struct_catalog/cap.c -- capability-shaped struct field tables.
 *
 * Carved out of struct_catalog.c as another leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the cap leaf
 * data only -- struct __user_cap_header_struct and
 * struct __user_cap_data_struct (capset / capget).  Symbols flip from
 * static const to const so the spine's .fields = user_cap_*_fields
 * references resolve via the externs in struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never empty.  <linux/capability.h> brings the two
 * __user_cap_*_struct definitions referenced by the FIELD() macros.
 */

#include <stddef.h>
#include <linux/capability.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct __user_cap_header_struct (capset, capget)                    */
/* ------------------------------------------------------------------ */

const struct struct_field user_cap_header_fields[USER_CAP_HEADER_FIELDS_N] = {
	FIELD(struct __user_cap_header_struct, version),
	FIELD(struct __user_cap_header_struct, pid),
};

/* ------------------------------------------------------------------ */
/* struct __user_cap_data_struct (capset, capget)                      */
/* ------------------------------------------------------------------ */

const struct struct_field user_cap_data_fields[USER_CAP_DATA_FIELDS_N] = {
	FIELD(struct __user_cap_data_struct, effective),
	FIELD(struct __user_cap_data_struct, permitted),
	FIELD(struct __user_cap_data_struct, inheritable),
};
