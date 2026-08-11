#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iouring_cmd_passthrough_fields[] = {
	STAT_FIELD_SUB(iouring_cmd_passthrough, mshot_cmd_no_cqe),
};

const struct stat_category iouring_cmd_passthrough_category =
	STAT_CATEGORY("iouring_cmd_passthrough",
	              iouring_cmd_passthrough.mshot_cmd_no_cqe,
	              iouring_cmd_passthrough_fields);
