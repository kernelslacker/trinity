#include <stddef.h>
#include "stats-internal.h"

static const struct stat_field tcp_ao_rotate_fields[] = {
	STAT_FIELD_SUB(tcp_ao_rotate, runs),
	STAT_FIELD_SUB(tcp_ao_rotate, setup_failed),
	STAT_FIELD_SUB(tcp_ao_rotate, addkey_rejected),
	STAT_FIELD_SUB(tcp_ao_rotate, keys_added),
	STAT_FIELD_SUB(tcp_ao_rotate, connect_failed),
	STAT_FIELD_SUB(tcp_ao_rotate, connected),
	STAT_FIELD_SUB(tcp_ao_rotate, packets_sent),
	STAT_FIELD_SUB(tcp_ao_rotate, key_rotations),
	STAT_FIELD_SUB(tcp_ao_rotate, info_rejected),
	STAT_FIELD_SUB(tcp_ao_rotate, key_dels),
	STAT_FIELD_SUB(tcp_ao_rotate, delkey_rejected),
	STAT_FIELD_SUB(tcp_ao_rotate, cycles),
};

const struct stat_category tcp_ao_rotate_category =
	STAT_CATEGORY("tcp_ao_rotate",
	              tcp_ao_rotate.runs,
	              tcp_ao_rotate_fields);
