#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field hfs_mount_fuzz_fields[] = {
	STAT_FIELD_SUB(hfs_mount_fuzz, runs),
	STAT_FIELD_SUB(hfs_mount_fuzz, setup_failed),
	STAT_FIELD_SUB(hfs_mount_fuzz, set_fd_ok),
	STAT_FIELD_SUB(hfs_mount_fuzz, set_fd_busy),
	STAT_FIELD_SUB(hfs_mount_fuzz, mount_ok),
	STAT_FIELD_SUB(hfs_mount_fuzz, mount_failed),
	STAT_FIELD_SUB(hfs_mount_fuzz, ns_unsupported),
	STAT_FIELD_SUB(hfs_mount_fuzz, hfs_unsupported),
};

const struct stat_category hfs_mount_fuzz_category =
	STAT_CATEGORY("hfs_mount_fuzz",
		      hfs_mount_fuzz.runs,
		      hfs_mount_fuzz_fields);
