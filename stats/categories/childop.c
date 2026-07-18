#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field userns_fuzzer_fields[] = {
	STAT_FIELD(userns, runs),
	STAT_FIELD(userns, inner_crashed),
	STAT_FIELD(userns, unsupported),
	STAT_FIELD(userns, root_private_failed),
};

const struct stat_category userns_fuzzer_category =
	STAT_CATEGORY("userns_fuzzer",
	              userns_runs,
	              userns_fuzzer_fields);

static const struct stat_field userns_bootstrap_fields[] = {
	STAT_FIELD(userns_bootstrap, runs),
	STAT_FIELD(userns_bootstrap, ran),
	STAT_FIELD(userns_bootstrap, eperm),
	STAT_FIELD(userns_bootstrap, userns_other),
	STAT_FIELD(userns_bootstrap, map_write_fail),
	STAT_FIELD(userns_bootstrap, map_write_fail_eperm),
	STAT_FIELD(userns_bootstrap, map_write_fail_einval),
	STAT_FIELD(userns_bootstrap, map_write_fail_other),
	STAT_FIELD(userns_bootstrap, target_unshare),
	STAT_FIELD(userns_bootstrap, fork_fail),
	STAT_FIELD(userns_bootstrap, signalled),
};

const struct stat_category userns_bootstrap_category =
	STAT_CATEGORY("userns_bootstrap",
	              userns_bootstrap_runs,
	              userns_bootstrap_fields);

static const struct stat_field cpu_hotplug_rider_fields[] = {
	STAT_FIELD(cpu_hotplug, runs),
	STAT_FIELD(cpu_hotplug, affinity_calls),
	STAT_FIELD(cpu_hotplug, sysfs_writes),
	STAT_FIELD(cpu_hotplug, open_eperm),
	STAT_FIELD(cpu_hotplug, write_eperm),
	STAT_FIELD(cpu_hotplug, write_ok),
	STAT_FIELD(cpu_hotplug, actual_offlines),
};

const struct stat_category cpu_hotplug_rider_category =
	STAT_CATEGORY("cpu_hotplug_rider",
	              cpu_hotplug_runs,
	              cpu_hotplug_rider_fields);

static const struct stat_field pidfd_storm_fields[] = {
	STAT_FIELD(pidfd_storm, runs),
	STAT_FIELD(pidfd_storm, signals),
	STAT_FIELD(pidfd_storm, getfds),
	STAT_FIELD(pidfd_storm, failed),
	STAT_FIELD(pidfd_storm, iters),
	STAT_FIELD(pidfd_storm, reap_slow),
	STAT_FIELD(pidfd_storm, reap_zombies),
};

const struct stat_category pidfd_storm_category =
	STAT_CATEGORY("pidfd_storm",
	              pidfd_storm_runs,
	              pidfd_storm_fields);

static const struct stat_field cgroup_churn_fields[] = {
	STAT_FIELD(cgroup_churn, runs),
	STAT_FIELD(cgroup, mkdirs),
	STAT_FIELD(cgroup, rmdirs),
	STAT_FIELD(cgroup, failed),
	STAT_FIELD(cgroup, psi_race_runs),
	STAT_FIELD(cgroup, psi_race_writes),
	STAT_FIELD(cgroup, psi_race_failed),
};

const struct stat_category cgroup_churn_category =
	STAT_CATEGORY("cgroup_churn",
	              cgroup_churn_runs,
	              cgroup_churn_fields);

static const struct stat_field umount_race_fields[] = {
	STAT_FIELD(umount_race, runs),
	STAT_FIELD(umount_race, picks),
	STAT_FIELD(umount_race, forks),
	STAT_FIELD(umount_race, umounts),
	STAT_FIELD(umount_race, umount_failed),
	STAT_FIELD(umount_race, setup_failed),
};

const struct stat_category umount_race_category =
	STAT_CATEGORY("umount_race",
	              umount_race_runs,
	              umount_race_fields);

static const struct stat_field statmount_idmap_fields[] = {
	STAT_FIELD(statmount_idmap, runs),
	STAT_FIELD(statmount_idmap, setup_failed),
	STAT_FIELD(statmount_idmap, iter),
	STAT_FIELD(statmount_idmap, fork_failed),
	STAT_FIELD(statmount_idmap, carrier_ok),
	STAT_FIELD(statmount_idmap, carrier_fail),
	STAT_FIELD(statmount_idmap, setattr_ok),
	STAT_FIELD(statmount_idmap, setattr_fail),
	STAT_FIELD(statmount_idmap, statmount_call),
	STAT_FIELD(statmount_idmap, statmount_ok),
	STAT_FIELD(statmount_idmap, statmount_overflow),
};

const struct stat_category statmount_idmap_category =
	STAT_CATEGORY("statmount_idmap",
	              statmount_idmap_runs,
	              statmount_idmap_fields);

static const struct stat_field iouring_send_zc_churn_fields[] = {
	STAT_FIELD(iouring_send_zc_churn, runs),
	STAT_FIELD(iouring_send_zc_churn, setup_failed),
	STAT_FIELD(iouring_send_zc_churn, register_bufs_ok),
	STAT_FIELD(iouring_send_zc_churn, send_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, sendmsg_zc_ok),
	STAT_FIELD(iouring_send_zc_churn, unregister_race_ok),
	STAT_FIELD(iouring_send_zc_churn, update_race_ok),
	STAT_FIELD(iouring_send_zc_churn, cqe_drained),
};

const struct stat_category iouring_send_zc_churn_category =
	STAT_CATEGORY("iouring_send_zc_churn",
	              iouring_send_zc_churn_runs,
	              iouring_send_zc_churn_fields);

/*
 * Descriptors for dump_stats_json_lifecycle_and_storms().  The JSON walker
 * ignores gate_offset (it emits every category unconditionally) so the gate
 * field here only matters if a future change wires stat_category_emit_text()
 * onto these tables; the current text dump for these two categories stays
 * hand-coded in dump_stats_childop_runs_local().
 */
static const struct stat_field fs_lifecycle_fields[] = {
	STAT_FIELD(fs_lifecycle, tmpfs),
	STAT_FIELD(fs_lifecycle, ramfs),
	STAT_FIELD(fs_lifecycle, rdonly),
	STAT_FIELD(fs_lifecycle, overlay),
	STAT_FIELD(fs_lifecycle, quota),
	STAT_FIELD(fs_lifecycle, bind),
	STAT_FIELD(fs_lifecycle, unsupported),
};

const struct stat_category fs_lifecycle_category =
	STAT_CATEGORY("fs_lifecycle",
	              fs_lifecycle_tmpfs,
	              fs_lifecycle_fields);

