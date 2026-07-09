/*
 * struct_catalog/lsm.c -- lsm_set_self_attr struct field table.
 *
 * Tables are `const` (not `static const`) so the spine's `.fields =`
 * references resolve via the externs in struct_catalog-internal.h.
 * struct_catalog.h and arch.h are #included unconditionally so this TU
 * is never empty when USE_<X> is off.
 *
 * The struct lsm_ctx fallback below mirrors the trinity-local shim
 * that struct_catalog.c keeps under the same #ifndef _LINUX_LSM_H
 * guard: the spine references sizeof(struct lsm_ctx) on its catalog
 * entry, so the type must stay visible in both TUs.  Both copies must
 * land on a layout-identical definition; a future uapi bump that
 * grows the fixed head needs both updated.
 */

#include <stddef.h>
#include <linux/types.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

/* ------------------------------------------------------------------ */
/* struct lsm_ctx (lsm_set_self_attr)                                  */
/* ------------------------------------------------------------------ */

/*
 * struct lsm_ctx from include/uapi/linux/lsm.h.  Defined locally under
 * the header's include-guard probe so the translation unit builds
 * against older kernel headers that predate the lsm.h UAPI.  The shape
 * MUST match the kernel header -- a future bump that grows the fixed
 * head needs both copies updated.  The flexible ctx[] tail is
 * intentionally omitted: only the fixed 4-u64 head is cataloged; the
 * variable payload stays owned by the bespoke sanitiser.
 */
#ifndef _LINUX_LSM_H
struct lsm_ctx {
	__u64 id;
	__u64 flags;
	__u64 len;
	__u64 ctx_len;
};
#else
/*
 * Host <linux/lsm.h> supplied the struct.  Assert the fixed head is
 * the 4-u64 layout the fallback declares so a future uapi bump that
 * grows the head trips at compile time rather than silently diverging
 * from the shim in struct_catalog/catalog.c.  Only the fixed head is
 * cataloged; the flexible ctx[] tail is intentionally not covered.
 */
_Static_assert(sizeof(struct lsm_ctx) == 4 * sizeof(__u64),
	       "struct lsm_ctx head drifted from trinity fallback; update both fallback copies");
#endif

/*
 * lsm_set_self_attr(unsigned int attr, struct lsm_ctx __user *ctx,
 *                   u32 size, u32 flags) hands the kernel an LSM
 * context descriptor at a2.  argtype[1] is ARG_ADDRESS (not
 * ARG_STRUCT_PTR_*), so sanitise_lsm_set_self_attr() keeps owning the
 * live fill: a page_size + 64 buffer with id drawn from a small LSM
 * pool and size bucketed across the kernel's security_setselfattr()
 * size-validation arms (zero / undersized / oversized / variable
 * payload / current).  The variable ctx[] tail is owned by that
 * sanitiser and intentionally not modelled here.
 *
 * Registration is attribution-only, mirroring the in-tree msgbuf /
 * sigset_t entries: the bespoke sanitiser keeps owning the live fill
 * -- this only feeds the CMP-attribution path.  All four head fields
 * stay FT_RAW so the bespoke fill is preserved verbatim; the win is
 * letting struct_field_for_cmp() steer KCOV CMP-learned constants at
 * the named id / flags / len / ctx_len slots rather than at
 * coincidentally-same-width neighbours.
 */
const struct struct_field lsm_ctx_fields[LSM_CTX_FIELDS_N] = {
	FIELD(struct lsm_ctx, id),
	FIELD(struct lsm_ctx, flags),
	FIELD(struct lsm_ctx, len),
	FIELD(struct lsm_ctx, ctx_len),
};
