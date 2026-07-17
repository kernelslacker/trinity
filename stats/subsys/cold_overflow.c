#include <stddef.h>
#include "stats-internal.h"

/* cold_overflow: SHADOW measurement of would-save events that fall on the
 * cold-or-corpus-absent tail under a CMP_RISING_PC_FLAT plateau (no
 * fuzzer-behaviour change -- see stats/subsys/cold_overflow.h for the
 * predicate and the SHADOW contract).  Aggregate scalars only.  Text
 * render gates on would_save so a run that never observed a qualifying
 * event emits nothing in the text dump; JSON renders unconditionally
 * for schema stability. */
static const struct stat_field cold_overflow_fields[] = {
	STAT_FIELD_SUB(cold_overflow, would_save),
	STAT_FIELD_SUB(cold_overflow, would_save_cold),
	STAT_FIELD_SUB(cold_overflow, would_save_absent),
};

const struct stat_category cold_overflow_category =
	STAT_CATEGORY("cold_overflow",
	              cold_overflow.would_save,
	              cold_overflow_fields);
