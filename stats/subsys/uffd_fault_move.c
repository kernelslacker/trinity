#include <stddef.h>
#include "stats-internal.h"

/*
 * uffd_fault_move: stateful UFFD fault + UFFDIO_MOVE/swap-cache race counters.
 *
 * oracle_checks_run is the gate field: a healthy zero in oracle_mismatch
 * is only meaningful when checks_run is non-zero.
 */
static const struct stat_field uffd_fault_move_fields[] = {
	STAT_FIELD_SUB(uffd_fault_move, v1_resolve_ok),
	STAT_FIELD_SUB(uffd_fault_move, v1_resolve_fail),
	STAT_FIELD_SUB(uffd_fault_move, v1_wp_faults_resolved),
	STAT_FIELD_SUB(uffd_fault_move, v1_poison_faults_resolved),
	STAT_FIELD_SUB(uffd_fault_move, v1_dontwake_still_blocked),
	STAT_FIELD_SUB(uffd_fault_move, v1_dontwake_woke_early),
	STAT_FIELD_SUB(uffd_fault_move, v2_move_ok),
	STAT_FIELD_SUB(uffd_fault_move, v2_move_fail),
	STAT_FIELD_SUB(uffd_fault_move, v2_move_einval),
	STAT_FIELD_SUB(uffd_fault_move, v2_move_skipped),
	STAT_FIELD_SUB(uffd_fault_move, v3_teardown_ok),
	STAT_FIELD_SUB(uffd_fault_move, v3_teardown_fail),
	STAT_FIELD_SUB(uffd_fault_move, oracle_checks_run),
	STAT_FIELD_SUB(uffd_fault_move, oracle_mismatch),
};

const struct stat_category uffd_fault_move_category =
	STAT_CATEGORY("uffd_fault_move",
	              uffd_fault_move.oracle_checks_run,
	              uffd_fault_move_fields);
