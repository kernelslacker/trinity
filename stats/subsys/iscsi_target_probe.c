#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field iscsi_target_probe_fields[] = {
	STAT_FIELD_SUB(iscsi_target_probe, runs),
	STAT_FIELD_SUB(iscsi_target_probe, setup_failed),
	STAT_FIELD_SUB(iscsi_target_probe, no_target),
	STAT_FIELD_SUB(iscsi_target_probe, connected),
	STAT_FIELD_SUB(iscsi_target_probe, login_sent),
	STAT_FIELD_SUB(iscsi_target_probe, login_replies),
	STAT_FIELD_SUB(iscsi_target_probe, scsi_cmd_sent),
	STAT_FIELD_SUB(iscsi_target_probe, bytes_out),
	STAT_FIELD_SUB(iscsi_target_probe, bytes_in),
	STAT_FIELD_SUB(iscsi_target_probe, length_decoupled),
};

const struct stat_category iscsi_target_probe_category =
	STAT_CATEGORY("iscsi_target_probe",
	              iscsi_target_probe.runs,
	              iscsi_target_probe_fields);
