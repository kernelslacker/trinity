/*
 * Tail-of-schema JSON emitter for --stats-json.  Carries its own
 * JSON-local descriptor table for vsock_transport_churn.
 */

#include <stdbool.h>
#include <stdio.h>
#include "shm.h"
#include "stats-internal.h"
#include "stats/json/internal.h"
#include "stats/arm-verdict.h"

void dump_stats_json_vsock_tail(void)
{
	json_stats_sep();
	stat_category_emit_json(&vsock_transport_churn_category);
}
