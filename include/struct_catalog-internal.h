/*
 * Internal scaffolding shared between the struct_catalog spine
 * (struct_catalog.c) and the per-family leaf TUs under struct_catalog/.
 *
 * - FIELD / FIELDX initialiser macros used by every cataloged field
 *   table.
 * - extern declarations for every leaf array the spine references via
 *   designated initialisers (.fields = leaf_fields, .num_fields =
 *   ARRAY_SIZE(leaf_fields)).  Array bounds are stated explicitly so
 *   the spine's sizeof() / ARRAY_SIZE() at the reference site keep
 *   resolving against a complete type; the leaf TU's definition uses
 *   the same _N constant so any mismatch is a compile-time error.
 *
 * Kept out of struct_catalog.h: consumers outside the catalog only
 * need the data types and the lookup API, so the leaf-extern surface
 * stays scoped to the TUs that actually need it.
 */

#pragma once

#include <stddef.h>

#include "struct_catalog.h"

/*
 * FIELD(S, m): the FT_RAW shortcut.  Tag, weight, and the .u payload
 * stay zero-initialised, so the field falls through to the historical
 * per-field random splat.  Existing entries keep this form.
 */
#define FIELD(S, m) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m) }

/*
 * FIELDX(S, m, TAG, ...): the semantic form.  Trailing __VA_ARGS__
 * carries the tag-specific designated initialisers, typically
 * .u.<arm> = { ... } and/or .mutate_weight = N.
 */
#define FIELDX(S, m, TAG, ...) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m), \
	  .tag = (TAG), \
	  __VA_ARGS__ }

#ifdef USE_SCTP
/*
 * SCTP leaf tables defined in struct_catalog/sctp.c.  Each _N constant
 * names the array's element count so both the extern declaration here
 * and the definition over there compile against a complete array
 * type -- a mismatched initialiser fails as "excess elements" or
 * "too few" at the leaf TU, and the spine's ARRAY_SIZE() still folds
 * to the same constant it did before the carve.
 */
enum {
	SCTP_INITMSG_FIELDS_N			= 4,
	SCTP_RTOINFO_FIELDS_N			= 4,
	SCTP_ASSOCPARAMS_FIELDS_N		= 6,
	SCTP_SETADAPTATION_FIELDS_N		= 1,
	SCTP_ASSOC_VALUE_FIELDS_N		= 2,
	SCTP_SNDINFO_FIELDS_N			= 5,
	SCTP_SNDRCVINFO_FIELDS_N		= 9,
	SCTP_EVENT_SUBSCRIBE_FIELDS_N		= 14,
	SCTP_AUTHCHUNK_FIELDS_N			= 1,
	SCTP_SACK_INFO_FIELDS_N			= 3,
	SCTP_AUTHKEYID_FIELDS_N			= 2,
	SCTP_DEFAULT_PRINFO_POLICY_VALUES_N	= 4,
	SCTP_DEFAULT_PRINFO_FIELDS_N		= 3,
	SCTP_ADD_STREAMS_FIELDS_N		= 3,
	SCTP_STREAM_VALUE_FIELDS_N		= 3,
	SCTP_EVENT_FIELDS_N			= 3,
	SCTP_PADDRTHLDS_FIELDS_N		= 4,
	SCTP_PADDRTHLDS_V2_FIELDS_N		= 5,
	SCTP_UDPENCAPS_FIELDS_N			= 3,
	SCTP_PADDRPARAMS_FIELDS_N		= 9,
	SCTP_PROBEINTERVAL_FIELDS_N		= 3,
	SCTP_PRIM_FIELDS_N			= 2,
};

extern const struct struct_field sctp_initmsg_fields[SCTP_INITMSG_FIELDS_N];
extern const struct struct_field sctp_rtoinfo_fields[SCTP_RTOINFO_FIELDS_N];
extern const struct struct_field sctp_assocparams_fields[SCTP_ASSOCPARAMS_FIELDS_N];
extern const struct struct_field sctp_setadaptation_fields[SCTP_SETADAPTATION_FIELDS_N];
extern const struct struct_field sctp_assoc_value_fields[SCTP_ASSOC_VALUE_FIELDS_N];
extern const struct struct_field sctp_sndinfo_fields[SCTP_SNDINFO_FIELDS_N];
extern const struct struct_field sctp_sndrcvinfo_fields[SCTP_SNDRCVINFO_FIELDS_N];
extern const struct struct_field sctp_event_subscribe_fields[SCTP_EVENT_SUBSCRIBE_FIELDS_N];
extern const struct struct_field sctp_authchunk_fields[SCTP_AUTHCHUNK_FIELDS_N];
extern const struct struct_field sctp_sack_info_fields[SCTP_SACK_INFO_FIELDS_N];
extern const struct struct_field sctp_authkeyid_fields[SCTP_AUTHKEYID_FIELDS_N];
extern const unsigned long sctp_default_prinfo_policy_values[SCTP_DEFAULT_PRINFO_POLICY_VALUES_N];
extern const struct struct_field sctp_default_prinfo_fields[SCTP_DEFAULT_PRINFO_FIELDS_N];
extern const struct struct_field sctp_add_streams_fields[SCTP_ADD_STREAMS_FIELDS_N];
extern const struct struct_field sctp_stream_value_fields[SCTP_STREAM_VALUE_FIELDS_N];
extern const struct struct_field sctp_event_fields[SCTP_EVENT_FIELDS_N];
extern const struct struct_field sctp_paddrthlds_fields[SCTP_PADDRTHLDS_FIELDS_N];
extern const struct struct_field sctp_paddrthlds_v2_fields[SCTP_PADDRTHLDS_V2_FIELDS_N];
extern const struct struct_field sctp_udpencaps_fields[SCTP_UDPENCAPS_FIELDS_N];
extern const struct struct_field sctp_paddrparams_fields[SCTP_PADDRPARAMS_FIELDS_N];
extern const struct struct_field sctp_probeinterval_fields[SCTP_PROBEINTERVAL_FIELDS_N];
extern const struct struct_field sctp_prim_fields[SCTP_PRIM_FIELDS_N];
#endif /* USE_SCTP */
