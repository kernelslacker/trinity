#include <stddef.h>
#include "stats-internal.h"

/* thp_split_ref_race oracle and race-landing counters.
 * split_trigger_rounds: total rounds executed (denominator).
 * thp_split_while_ref_held: rounds where process_vm_readv returned > 0
 *   confirming the reference walker reached folio_try_get() during the
 *   split window (race landed successfully).
 * thp_no_race: rounds where both walkers observed nothing useful (pages
 *   absent, no concurrency this round).
 * content_mismatch: rounds where process_vm_readv succeeded but the
 *   returned bytes didn't match the pre-split arena cookie (bug signal). */
static const struct stat_field thp_split_ref_race_fields[] = {
	STAT_FIELD_SUB(thp_split_ref_race, split_trigger_rounds),
	STAT_FIELD_SUB(thp_split_ref_race, thp_split_while_ref_held),
	STAT_FIELD_SUB(thp_split_ref_race, thp_no_race),
	STAT_FIELD_SUB(thp_split_ref_race, content_mismatch),
};

const struct stat_category thp_split_ref_race_category =
	STAT_CATEGORY("thp_split_ref_race",
	              thp_split_ref_race.split_trigger_rounds,
	              thp_split_ref_race_fields);
