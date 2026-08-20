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
	STAT_FIELD_SUB(tcp_ao_rotate, reconnect_attempted),
	STAT_FIELD_SUB(tcp_ao_rotate, reconnect_setup_failed),
	STAT_FIELD_SUB(tcp_ao_rotate, reconnect_failed),
	STAT_FIELD_SUB(tcp_ao_rotate, reconnect_ok),
	STAT_FIELD_SUB(tcp_ao_rotate, reconnect_probed),
	STAT_FIELD_SUB(tcp_ao_rotate, stale_key_probed),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_enslave_attempted),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_enslave_setup_failed),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_detach_raced),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_connect_issued),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_connect_ok),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_accept_timeout),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_ao_unavailable),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_detach_landed),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_detach_before_connect),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_detach_after_connect),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_detach_tied),
	STAT_FIELD_SUB(tcp_ao_rotate, vrf_pipe_unavailable),
};

const struct stat_category tcp_ao_rotate_category =
	STAT_CATEGORY("tcp_ao_rotate",
	              tcp_ao_rotate_fields);
