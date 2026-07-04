/*
 * struct_catalog/kexec.c -- kexec-shaped struct field tables.
 *
 * Tables are `const` (not `static const`) so the spine's designated-init
 * `.fields =` references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU is
 * never empty.
 */

#include <stddef.h>
#include <linux/kexec.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct kexec_segment (kexec_load segments array element)            */
/* ------------------------------------------------------------------ */

/*
 * kexec_load(unsigned long entry, unsigned long nr_segments,
 *            struct kexec_segment __user *segments, unsigned long flags)
 * a3 is an array of kexec_segment descriptors.  argtype[2] is
 * ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
 * sanitise_kexec_load() in syscalls/kexec_load.c keeps owning the live
 * fill: nr drawn from [1, 4], per-entry buf from get_writable_address()
 * at a 4K-16K bucket paired with bufsz, and mem stamped at a fixed
 * physical-address-shaped offset the kernel validates.
 *
 * Registration is attribution-only, mirroring the in-tree iovec /
 * msgbuf / sigset_t / lsm_ctx entries: the bespoke sanitiser keeps
 * owning the live fill -- this only feeds the CMP-attribution path.
 * buf+bufsz are tagged iovec-style (kernel-dereferenced user buffer
 * paired with its byte length).  mem+memsz stay FT_RAW: mem is a
 * physical destination address rather than a user-space pointer the
 * kernel dereferences from this slot, so FT_ADDRESS would mis-tag it.
 * The schema-aware fill path never runs against this slot regardless,
 * so the tags exist purely to steer struct_field_for_cmp() at the
 * named slots rather than at coincidentally-same-width neighbours.
 */
const struct struct_field kexec_segment_fields[KEXEC_SEGMENT_FIELDS_N] = {
	FIELDX(struct kexec_segment, buf, FT_ADDRESS),
	FIELDX(struct kexec_segment, bufsz, FT_LEN_BYTES,
	       .u.len_of = { .buf_field = "buf" }),
	FIELD(struct kexec_segment, mem),
	FIELD(struct kexec_segment, memsz),
};
