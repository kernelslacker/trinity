#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field inet_listener_rehash_race_fields[] = {
	STAT_FIELD_SUB(inet_listener_rehash_race, runs),
	STAT_FIELD_SUB(inet_listener_rehash_race, setup_failed),
	STAT_FIELD_SUB(inet_listener_rehash_race, iter),
	STAT_FIELD_SUB(inet_listener_rehash_race, fork_failed),
	STAT_FIELD_SUB(inet_listener_rehash_race, spawn_quad_ok),
	STAT_FIELD_SUB(inet_listener_rehash_race, twseed_listener_ok),
	STAT_FIELD_SUB(inet_listener_rehash_race, twseed_ok),
	STAT_FIELD_SUB(inet_listener_rehash_race, churn_v4_cycles),
	STAT_FIELD_SUB(inet_listener_rehash_race, churn_v6_cycles),
	STAT_FIELD_SUB(inet_listener_rehash_race, syn_sent),
	STAT_FIELD_SUB(inet_listener_rehash_race, rehash_cycles),
	STAT_FIELD_SUB(inet_listener_rehash_race, sibling_crashed),
	STAT_FIELD_SUB(inet_listener_rehash_race, sibling_reaped_ok),
	STAT_FIELD_SUB(inet_listener_rehash_race, completed_ok),
	STAT_FIELD_SUB(inet_listener_rehash_race, addrform_returned_zero),
	STAT_FIELD_SUB(inet_listener_rehash_race, addrform_child_accepted),
	STAT_FIELD_SUB(inet_listener_rehash_race, addrform_setup_failed),
	STAT_FIELD_SUB(inet_listener_rehash_race, addrform_grace_forced),
	STAT_FIELD_SUB(inet_listener_rehash_race, addrform_listener_returned_zero),
};

const struct stat_category inet_listener_rehash_race_category =
	STAT_CATEGORY("inet_listener_rehash_race",
	              inet_listener_rehash_race.runs,
	              inet_listener_rehash_race_fields);
