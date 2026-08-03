/*
 * JSON emission for the resource type-graph observer.
 *
 * The observer itself (publish ring + edge pool + EMA update) lives
 * in objects/type-graph.c; this file owns only the JSON shape so
 * the stats-json-schema check can find the printf format literals
 * inside stats/json/ where the extractor walks.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "stats-internal.h"
#include "stats/json/internal.h"
#include "type-graph.h"

void type_graph_json_emit_top_handoffs(void)
{
	struct type_graph_top_entry top[TYPE_GRAPH_TOP_N];
	unsigned int count;
	unsigned int i;
	uint64_t publish_obs = 0;
	uint64_t consume_obs = 0;
	uint64_t consume_hits = 0;
	uint64_t consume_misses = 0;
	uint64_t edge_inserts = 0;
	uint64_t edge_updates = 0;
	uint64_t exhausted = 0;

	if (type_graph_shm == NULL) {
		fputs(",\"type_graph\":null", stdout);
		return;
	}

	publish_obs = __atomic_load_n(&type_graph_shm->publish_observations,
				      __ATOMIC_RELAXED);
	consume_obs = __atomic_load_n(&type_graph_shm->consume_observations,
				      __ATOMIC_RELAXED);
	consume_hits = __atomic_load_n(&type_graph_shm->consume_hits,
				       __ATOMIC_RELAXED);
	consume_misses = __atomic_load_n(&type_graph_shm->consume_misses,
					 __ATOMIC_RELAXED);
	edge_inserts = __atomic_load_n(&type_graph_shm->edge_inserts,
				       __ATOMIC_RELAXED);
	edge_updates = __atomic_load_n(&type_graph_shm->edge_updates,
				       __ATOMIC_RELAXED);
	exhausted = __atomic_load_n(&type_graph_shm->edge_pool_exhausted,
				    __ATOMIC_RELAXED);

	printf(",\"type_graph\":{\"publish_observations\":%lu,"
	       "\"consume_observations\":%lu,\"consume_hits\":%lu,"
	       "\"consume_misses\":%lu,\"edge_inserts\":%lu,"
	       "\"edge_updates\":%lu,\"edge_pool_exhausted\":%lu,"
	       "\"top_handoffs\":[",
	       publish_obs, consume_obs, consume_hits, consume_misses,
	       edge_inserts, edge_updates, exhausted);

	count = type_graph_get_top_handoffs(top);
	for (i = 0; i < count; i++) {
		const char *tname = type_graph_obj_type_name(top[i].obj_type);
		const char *pname = type_graph_syscall_name(top[i].producer_nr,
							    top[i].producer_do32);
		const char *cname = type_graph_syscall_name(top[i].consumer_nr,
							    top[i].consumer_do32);

		printf("%s{\"producer\":\"%s\",\"consumer\":\"%s\","
		       "\"arg\":%u,\"type\":\"%s\","
		       "\"observations\":%lu,\"total_ema\":%u,"
		       "\"success_ema\":%u,\"novel_ema\":%u}",
		       i ? "," : "",
		       pname ? pname : "?", cname ? cname : "?",
		       top[i].consumer_arg, tname ? tname : "OBJ_?",
		       top[i].observations, top[i].total_ema,
		       top[i].success_ema, top[i].novel_ema);
	}
	fputs("]}", stdout);
}
