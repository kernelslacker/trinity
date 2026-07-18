#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field bpf_cgroup_attach_fields[] = {
	STAT_FIELD_SUB(bpf_cgroup_attach, runs),
	STAT_FIELD_SUB(bpf_cgroup_attach, setup_failed),
	STAT_FIELD_SUB(bpf_cgroup_attach, prog_loaded),
	STAT_FIELD_SUB(bpf_cgroup_attach, attached),
	STAT_FIELD_SUB(bpf_cgroup_attach, attach_rejected),
	STAT_FIELD_SUB(bpf_cgroup_attach, packets_sent),
	STAT_FIELD_SUB(bpf_cgroup_attach, detached),
	STAT_FIELD_SUB(bpf_cgroup_attach, post_detach_sent),
};

const struct stat_category bpf_cgroup_attach_category =
	STAT_CATEGORY("bpf_cgroup_attach",
	              bpf_cgroup_attach.runs,
	              bpf_cgroup_attach_fields);
