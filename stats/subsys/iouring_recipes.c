#include <stddef.h>
#include "stats-internal.h"

/*
 * Descriptors for the remaining categories in
 * dump_stats_json_iouring_and_zombies().  The text-side dump for these stays
 * hand-coded for now, and the JSON walker ignores gate_offset, so the gate
 * field choices below only matter if a future change wires
 * stat_category_emit_text() onto these tables.
 */
static const struct stat_field iouring_recipes_fields[] = {
	STAT_FIELD_SUB(iouring_recipes, runs),
	STAT_FIELD_SUB(iouring_recipes, completed),
	STAT_FIELD_SUB(iouring_recipes, partial),
	STAT_FIELD_SUB(iouring_recipes, enosys),
};

const struct stat_category iouring_recipes_category =
	STAT_CATEGORY("iouring_recipes",
	              iouring_recipes.runs,
	              iouring_recipes_fields);
