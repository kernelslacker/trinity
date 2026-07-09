/*
 * struct_catalog/crypto.c -- crypto / AF_ALG argument struct field
 * tables.
 *
 * struct af_alg_iv is the sendmsg(SOL_ALG, ALG_SET_IV) ancillary
 * control-message payload carried by AF_ALG cipher / aead / skcipher
 * sockets to pin the per-request IV.  The bespoke walkers in
 * childops/net/af-alg-*.c and the setsockopt/sendmsg wiring in
 * net/socket-family-grammar.c own every live fill; this table exists
 * so struct_field_for_cmp() can attribute a KCOV-CMP-learned constant
 * (typical IV lengths: 8, 12, 16, 32) to the ivlen slot by name rather
 * than guessing off a coincidentally-same-width field.
 *
 * Tables are `const` (not `static const`) so the spine's designated-
 * init `.fields =` reference resolves via the extern in
 * struct_catalog-internal.h.  struct_catalog.h and arch.h are
 * #included unconditionally so this TU is never empty when USE_IF_ALG
 * is off.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"

#ifdef USE_IF_ALG
#include <linux/if_alg.h>

/*
 * struct af_alg_iv: __u32 ivlen followed by a __u8 iv[] flexible tail.
 * Only ivlen is cataloged -- the flexible iv[] payload has size 0
 * under sizeof/offsetof and would confuse struct_field_for_cmp()'s
 * width-based candidate walk (same shape as file_handle's opaque
 * f_handle[] tail).  ivlen is left FT_RAW: the bespoke AF_ALG walkers
 * pin it against the live cipher's ivsize before every dispatch, so
 * a schema fill mask here would either duplicate that pinning or
 * over-widen it into ranges the kernel immediately rejects.  Naming
 * the field is enough for CMP attribution to steer learned constants
 * at ivlen rather than at a coincidentally-4-byte slot.
 */
const struct struct_field af_alg_iv_fields[AF_ALG_IV_FIELDS_N] = {
	FIELD(struct af_alg_iv, ivlen),
};
#endif /* USE_IF_ALG */
