/*
 * struct_catalog/ldt.c -- LDT (struct user_desc) struct field table.
 *
 * Carved out of struct_catalog.c as the final leaf TU of the file
 * split: the central spine (struct_catalog[], syscall_struct_args[])
 * and all logic stay in struct_catalog.c; this TU owns the
 * x86-only LDT leaf data only -- struct user_desc, the arg2 of
 * modify_ldt on its write_ldt (func == 1) arm.  The symbol flips
 * from static const to const so the spine's
 * .fields = user_desc_fields reference resolves via the extern
 * declared in struct_catalog-internal.h.
 *
 * struct_catalog.h and arch.h are included unconditionally so this
 * TU is never an empty object on non-x86 builds; the LDT header and
 * table body live behind the same X86 guard the spine entry uses
 * for this family.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef X86
#include <asm/ldt.h>		/* struct user_desc -- modify_ldt arg2 */

/* ------------------------------------------------------------------ */
/* struct user_desc (modify_ldt write_ldt arm, func == 1)              */
/* ------------------------------------------------------------------ */
/*
 * x86-only LDT entry descriptor.  Only the three addressable u32 fields
 * (entry_number / base_addr / limit) get FIELD entries -- the trailing
 * seg_32bit / contents / read_exec_only / limit_in_pages / seg_not_present
 * / useable / lm members are sub-byte bitfields and have no stable
 * offsetof, so they stay outside the schema-aware fill's reach.  The
 * bespoke sanitise_modify_ldt() arm already curates those bits; this
 * registration is attribution-only so struct_field_for_cmp() can steer
 * CMP-learned constants at entry_number / base_addr / limit rather than
 * at a coincidentally-same-width slot.
 *
 * entry_number is FT_RANGE-bounded to [0, LDT_ENTRIES) to match the
 * kernel's switch domain; base_addr / limit stay FT_RAW since the kernel
 * accepts any 32-bit value.
 */
const struct struct_field user_desc_fields[] = {
	FIELDX(struct user_desc, entry_number, FT_RANGE,
	       .u.range.lo = 0,
	       .u.range.hi = LDT_ENTRIES - 1,
	       .mutate_weight = 60),
	FIELD(struct user_desc, base_addr),
	FIELD(struct user_desc, limit),
};
#endif
