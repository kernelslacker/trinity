#include <stddef.h>
#include "stats-internal.h"

/* fd_runtime_skipped: handle_retval_obj_fd's post-success classify of an
 * fd retval against the per-child local-object table.  The two paths are
 * mutually exclusive per call and both increment from the same site, so a
 * run where neither bumped means no syscall ever produced a registerable
 * fd; gating on _stdio (the dominant arm — retvals 0/1/2 from any
 * fd-returning syscall) keeps a quiet window terse in the text dump.
 * JSON renders unconditionally alongside aio for schema stability.
 *
 * The fd_runtime.registered counter lives in the same struct but is
 * emitted under fd_lifecycle.runtime_registered by the hand-coded printf
 * in stats/json/core.c; it is intentionally NOT wired into this table so
 * the top-level JSON key set stays byte-identical across the flat→struct
 * migration. */
static const struct stat_field fd_runtime_skipped_fields[] = {
	STAT_FIELD_SUB(fd_runtime, stdio),
	STAT_FIELD_SUB(fd_runtime, already_registered),
};

const struct stat_category fd_runtime_skipped_category =
	STAT_CATEGORY("fd_runtime_skipped",
	              fd_runtime.stdio,
	              fd_runtime_skipped_fields);
