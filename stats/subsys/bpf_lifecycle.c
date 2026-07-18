#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bpf_lifecycle_fields[] = {
	STAT_FIELD_SUB(bpf_lifecycle, runs),
	STAT_FIELD_SUB(bpf_lifecycle, progs_loaded),
	STAT_FIELD_SUB(bpf_lifecycle, attached),
	STAT_FIELD_SUB(bpf_lifecycle, triggered),
	STAT_FIELD_SUB(bpf_lifecycle, verifier_rejects),
	STAT_FIELD_SUB(bpf_lifecycle, attach_failed),
	STAT_FIELD_SUB(bpf_lifecycle, eperm),
};

const struct stat_category bpf_lifecycle_category =
	STAT_CATEGORY("bpf_lifecycle",
	              bpf_lifecycle.runs,
	              bpf_lifecycle_fields);
