#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field recipe_runner_fields[] = {
	STAT_FIELD_SUB(recipe, runs),
	STAT_FIELD_SUB(recipe, completed),
	STAT_FIELD_SUB(recipe, partial),
	STAT_FIELD_SUB(recipe, unsupported),
};

const struct stat_category recipe_runner_category =
	STAT_CATEGORY("recipe_runner",
	              recipe.runs,
	              recipe_runner_fields);
