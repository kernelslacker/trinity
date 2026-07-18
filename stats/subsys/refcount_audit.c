#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field refcount_audit_fields[] = {
	STAT_FIELD_SUB(refcount_audit, runs),
	STAT_FIELD_SUB(refcount_audit, fd_anomalies),
	STAT_FIELD_SUB(refcount_audit, mmap_anomalies),
	STAT_FIELD_SUB(refcount_audit, sock_anomalies),
};

const struct stat_category refcount_audit_category =
	STAT_CATEGORY("refcount_audit",
	              refcount_audit.runs,
	              refcount_audit_fields);
