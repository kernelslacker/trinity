#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iouring_cmd_passthrough_fields[] = {
	STAT_FIELD_SUB(iouring_cmd_passthrough, nulldev_mshot_attempts),
	STAT_FIELD_SUB(iouring_cmd_passthrough, mshot_cmd_no_cqe),
	STAT_FIELD_SUB(iouring_cmd_passthrough, cqe_rejected),
	STAT_FIELD_SUB(iouring_cmd_passthrough, nulldev_cmd_rejected),
	STAT_FIELD_SUB(iouring_cmd_passthrough, fixed_multishot_prep_rejected),
};

const struct stat_category iouring_cmd_passthrough_category =
	STAT_CATEGORY("iouring_cmd_passthrough",
	              iouring_cmd_passthrough_fields);
