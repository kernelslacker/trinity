/*
 * struct_catalog/keyctl.c -- keyctl payload per-cmd field tables.
 *
 * The keyctl multiplex points a2 at a different struct depending on
 * the cmd in a1, so this TU mirrors the union bpf_attr tagged-union
 * layout in bpf.c: one variant per cmd that dereferences a2 as a
 * kernel struct, dispatched off rec->a1.  Bespoke sanitise_keyctl()
 * still owns every live fill (argtype[] leaves the payload slot at
 * ARG_UNDEFINED so the schema-aware path never runs against rec->a2);
 * the catalog registration is attribution-only, letting
 * struct_field_for_cmp() name the specific field a KCOV-CMP-learned
 * constant fell out of instead of guessing off width alone.
 *
 * Tables are `const` (not `static const`) so the spine's designated-
 * init `.variants =` / `.fields =` references resolve via the externs
 * in struct_catalog-internal.h.
 */

#include <stddef.h>

#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#include "kernel/keyctl.h"

/*
 * struct keyctl_dh_params and struct keyctl_pkey_params (plus the
 * KEYCTL_SUPPORTS_* mask constants) landed in the uapi header in the
 * same batch as KEYCTL_SUPPORTS_ENCRYPT.  Older /usr/include/linux/
 * keyctl.h vintages ship the KEYCTL_PKEY_* / KEYCTL_DH_COMPUTE cmd
 * numbers via kernel/keyctl.h's fallback #defines but not the struct
 * definitions themselves, so shim them here under the same guard the
 * matching sizeof() reference in struct_catalog.c uses.  Layouts are
 * pinned to the upstream uapi; a future header bump that grows either
 * struct needs both copies updated.
 */
#ifndef KEYCTL_SUPPORTS_ENCRYPT
struct keyctl_dh_params {
	__s32 priv;
	__s32 prime;
	__s32 base;
};

struct keyctl_pkey_params {
	__s32 key_id;
	__u32 in_len;
	__u32 out_len;		/* union { out_len; in2_len; } -- same offset */
	__u32 __spare[7];
};
#else
/*
 * Host <linux/keyctl.h> supplied the structs.  Assert their sizes match
 * the fallback layouts above so a future uapi bump that grows either
 * struct trips at compile time rather than silently diverging from the
 * shim in struct_catalog/catalog.c.
 */
_Static_assert(sizeof(struct keyctl_dh_params) == 3 * sizeof(__s32),
	       "struct keyctl_dh_params head drifted from trinity fallback; update both fallback copies");
_Static_assert(sizeof(struct keyctl_pkey_params) == sizeof(__s32) + 9 * sizeof(__u32),
	       "struct keyctl_pkey_params head drifted from trinity fallback; update both fallback copies");
#endif

/*
 * KEYCTL_DH_COMPUTE variant: a2 points at struct keyctl_dh_params,
 * three key_serial_t fields (priv/prime/base).  key_serial_t values
 * come out of add_key/request_key and the keyctl mint arms, so
 * FT_FD-tagged CMP attribution puts learned constants against the
 * live serial vocabulary rather than a coincidentally-same-width u32.
 * The struct's anonymous `union { __s32 private; __s32 priv; }` share
 * one 4-byte slot at offset 0; the `priv` name is portable across C
 * and C++ header vintages while `private` is a C++ keyword, so name
 * the offset off `priv`.
 */
const struct struct_field keyctl_dh_params_fields[KEYCTL_DH_PARAMS_FIELDS_N] = {
	FIELDX(struct keyctl_dh_params, priv, FT_FD),
	FIELDX(struct keyctl_dh_params, prime, FT_FD),
	FIELDX(struct keyctl_dh_params, base, FT_FD),
};

/*
 * KEYCTL_PKEY_{ENCRYPT,DECRYPT,SIGN,VERIFY} variant: a2 points at
 * struct keyctl_pkey_params.  key_id is a key_serial_t (FT_FD).
 * in_len / out_len are u32 sizes the kernel bounds against the
 * key's max_data_size / max_sig_size / max_enc_size / max_dec_size
 * from KEYCTL_PKEY_QUERY -- FT_RANGE {0, 4096} keeps them plausible
 * while still exercising the size validators.  __spare[7] must be
 * zero on entry (the kernel rejects non-zero pad); leaving it FT_RAW
 * lets the mutator explore that error path too.
 *
 * The out_len / in2_len anonymous union shares one 4-byte slot at
 * the same offset; naming out_len is enough for CMP attribution
 * since the kernel reads the same bytes either way.
 */
const struct struct_field keyctl_pkey_params_fields[KEYCTL_PKEY_PARAMS_FIELDS_N] = {
	FIELDX(struct keyctl_pkey_params, key_id, FT_FD,
	       .mutate_weight = 120),
	FIELDX(struct keyctl_pkey_params, in_len, FT_RANGE,
	       .u.range = { 0, 4096 }),
	FIELDX(struct keyctl_pkey_params, out_len, FT_RANGE,
	       .u.range = { 0, 4096 }),
};

/*
 * PKEY_{ENCRYPT,DECRYPT,SIGN,VERIFY} share the keyctl_pkey_params
 * shape at a2; one variant claims all four cmds via discrim_values[]
 * so the resolver hits it without cloning the entry.  PKEY_QUERY
 * uses keyctl_pkey_query at a5 instead and stays unregistered here
 * (it belongs on a different (nr, arg) row if ever added).
 */
const unsigned long keyctl_pkey_op_cmds[KEYCTL_PKEY_OP_CMDS_N] = {
	KEYCTL_PKEY_ENCRYPT, KEYCTL_PKEY_DECRYPT,
	KEYCTL_PKEY_SIGN, KEYCTL_PKEY_VERIFY,
};

/*
 * Tagged-union variant table.  rec->a1 carries the keyctl cmd; the
 * discriminator scan picks the matching variant, and cmds without an
 * entry fall through to the empty shared prefix (a2 is a scalar
 * key_serial_t / opaque flag for most cmds and doesn't need a
 * struct-shaped attribution row).
 */
const struct union_variant keyctl_payload_variants[KEYCTL_PAYLOAD_VARIANTS_N] = {
	{
		.discrim_value	= KEYCTL_DH_COMPUTE,
		.name		= "DH_COMPUTE",
		.fields		= keyctl_dh_params_fields,
		.num_fields	= ARRAY_SIZE(keyctl_dh_params_fields),
		.effective_size	= sizeof(struct keyctl_dh_params),
	},
	{
		.discrim_values	    = keyctl_pkey_op_cmds,
		.num_discrim_values = ARRAY_SIZE(keyctl_pkey_op_cmds),
		.name		    = "PKEY_OP",
		.fields		    = keyctl_pkey_params_fields,
		.num_fields	    = ARRAY_SIZE(keyctl_pkey_params_fields),
		.effective_size	    = sizeof(struct keyctl_pkey_params),
	},
};
