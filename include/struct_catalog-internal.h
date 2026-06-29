/*
 * Internal scaffolding shared between the struct_catalog spine
 * (struct_catalog.c) and the per-family leaf TUs under struct_catalog/.
 *
 * - FIELD / FIELDX initialiser macros used by every cataloged field
 *   table.
 * - extern declarations for every leaf array the spine references via
 *   designated initialisers (.fields = leaf_fields, .num_fields =
 *   ARRAY_SIZE(leaf_fields)).  Array bounds are stated explicitly so
 *   the spine's sizeof() / ARRAY_SIZE() at the reference site keep
 *   resolving against a complete type; the leaf TU's definition uses
 *   the same _N constant so any mismatch is a compile-time error.
 *
 * Kept out of struct_catalog.h: consumers outside the catalog only
 * need the data types and the lookup API, so the leaf-extern surface
 * stays scoped to the TUs that actually need it.
 */

#pragma once

#include <stddef.h>

#include "struct_catalog.h"

/*
 * FIELD(S, m): the FT_RAW shortcut.  Tag, weight, and the .u payload
 * stay zero-initialised, so the field falls through to the historical
 * per-field random splat.  Existing entries keep this form.
 */
#define FIELD(S, m) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m) }

/*
 * FIELDX(S, m, TAG, ...): the semantic form.  Trailing __VA_ARGS__
 * carries the tag-specific designated initialisers, typically
 * .u.<arm> = { ... } and/or .mutate_weight = N.
 */
#define FIELDX(S, m, TAG, ...) \
	{ .name = #m, \
	  .offset = offsetof(S, m), \
	  .size = sizeof(((S *)NULL)->m), \
	  .tag = (TAG), \
	  __VA_ARGS__ }

#ifdef USE_SCTP
/*
 * SCTP leaf tables defined in struct_catalog/sctp.c.  Each _N constant
 * names the array's element count so both the extern declaration here
 * and the definition over there compile against a complete array
 * type -- a mismatched initialiser fails as "excess elements" or
 * "too few" at the leaf TU, and the spine's ARRAY_SIZE() still folds
 * to the same constant it did before the carve.
 */
enum {
	SCTP_INITMSG_FIELDS_N			= 4,
	SCTP_RTOINFO_FIELDS_N			= 4,
	SCTP_ASSOCPARAMS_FIELDS_N		= 6,
	SCTP_SETADAPTATION_FIELDS_N		= 1,
	SCTP_ASSOC_VALUE_FIELDS_N		= 2,
	SCTP_SNDINFO_FIELDS_N			= 5,
	SCTP_SNDRCVINFO_FIELDS_N		= 9,
	SCTP_EVENT_SUBSCRIBE_FIELDS_N		= 14,
	SCTP_AUTHCHUNK_FIELDS_N			= 1,
	SCTP_SACK_INFO_FIELDS_N			= 3,
	SCTP_AUTHKEYID_FIELDS_N			= 2,
	SCTP_DEFAULT_PRINFO_POLICY_VALUES_N	= 4,
	SCTP_DEFAULT_PRINFO_FIELDS_N		= 3,
	SCTP_ADD_STREAMS_FIELDS_N		= 3,
	SCTP_STREAM_VALUE_FIELDS_N		= 3,
	SCTP_EVENT_FIELDS_N			= 3,
	SCTP_PADDRTHLDS_FIELDS_N		= 4,
	SCTP_PADDRTHLDS_V2_FIELDS_N		= 5,
	SCTP_UDPENCAPS_FIELDS_N			= 3,
	SCTP_PADDRPARAMS_FIELDS_N		= 9,
	SCTP_PROBEINTERVAL_FIELDS_N		= 3,
	SCTP_PRIM_FIELDS_N			= 2,
};

extern const struct struct_field sctp_initmsg_fields[SCTP_INITMSG_FIELDS_N];
extern const struct struct_field sctp_rtoinfo_fields[SCTP_RTOINFO_FIELDS_N];
extern const struct struct_field sctp_assocparams_fields[SCTP_ASSOCPARAMS_FIELDS_N];
extern const struct struct_field sctp_setadaptation_fields[SCTP_SETADAPTATION_FIELDS_N];
extern const struct struct_field sctp_assoc_value_fields[SCTP_ASSOC_VALUE_FIELDS_N];
extern const struct struct_field sctp_sndinfo_fields[SCTP_SNDINFO_FIELDS_N];
extern const struct struct_field sctp_sndrcvinfo_fields[SCTP_SNDRCVINFO_FIELDS_N];
extern const struct struct_field sctp_event_subscribe_fields[SCTP_EVENT_SUBSCRIBE_FIELDS_N];
extern const struct struct_field sctp_authchunk_fields[SCTP_AUTHCHUNK_FIELDS_N];
extern const struct struct_field sctp_sack_info_fields[SCTP_SACK_INFO_FIELDS_N];
extern const struct struct_field sctp_authkeyid_fields[SCTP_AUTHKEYID_FIELDS_N];
extern const unsigned long sctp_default_prinfo_policy_values[SCTP_DEFAULT_PRINFO_POLICY_VALUES_N];
extern const struct struct_field sctp_default_prinfo_fields[SCTP_DEFAULT_PRINFO_FIELDS_N];
extern const struct struct_field sctp_add_streams_fields[SCTP_ADD_STREAMS_FIELDS_N];
extern const struct struct_field sctp_stream_value_fields[SCTP_STREAM_VALUE_FIELDS_N];
extern const struct struct_field sctp_event_fields[SCTP_EVENT_FIELDS_N];
extern const struct struct_field sctp_paddrthlds_fields[SCTP_PADDRTHLDS_FIELDS_N];
extern const struct struct_field sctp_paddrthlds_v2_fields[SCTP_PADDRTHLDS_V2_FIELDS_N];
extern const struct struct_field sctp_udpencaps_fields[SCTP_UDPENCAPS_FIELDS_N];
extern const struct struct_field sctp_paddrparams_fields[SCTP_PADDRPARAMS_FIELDS_N];
extern const struct struct_field sctp_probeinterval_fields[SCTP_PROBEINTERVAL_FIELDS_N];
extern const struct struct_field sctp_prim_fields[SCTP_PRIM_FIELDS_N];
#endif /* USE_SCTP */

#ifdef USE_BPF
/*
 * BPF leaf tables defined in struct_catalog/bpf.c.  The spine in
 * struct_catalog.c references bpf_attr_variants and bpf_insn_fields
 * by name with ARRAY_SIZE() at the use site, so those two carry
 * explicit array bounds via _N constants -- a count mismatch fails
 * at the leaf TU as "excess elements" / "too few".  The remaining
 * tables are referenced only from within bpf.c (per-cmd field
 * arrays threaded into bpf_attr_variants, nested-variant tails
 * threaded into bpf_attr_LINK_CREATE_nested, and the attach-type
 * value pools they pin), so their extern decls land here without
 * sizes -- bpf.c sees the complete definition at every use site.
 *
 * bpf_map_types / bpf_prog_types / bpf_attach_types and their
 * _count companions are declared in include/bpf.h (shared with
 * syscalls/bpf.c) and intentionally not duplicated here.
 */
enum {
	BPF_ATTR_VARIANTS_N	= 38,
	BPF_INSN_FIELDS_N	= 3,
};

extern const struct struct_field bpf_attr_MAP_CREATE_fields[];
extern const struct struct_field bpf_attr_PROG_LOAD_fields[];
extern const struct struct_field bpf_attr_PROG_ATTACH_fields[];
extern const struct struct_field bpf_attr_OBJ_fields[];
extern const struct struct_field bpf_attr_MAP_ELEM_fields[];
extern const struct struct_field bpf_attr_GET_ID_fields[];
extern const struct struct_field bpf_attr_LINK_UPDATE_fields[];
extern const struct struct_field bpf_attr_LINK_DETACH_fields[];
extern const struct struct_field bpf_attr_ENABLE_STATS_fields[];
extern const struct struct_field bpf_attr_ITER_CREATE_fields[];
extern const struct struct_field bpf_attr_PROG_BIND_MAP_fields[];
extern const struct struct_field bpf_attr_TOKEN_CREATE_fields[];
extern const char *const bpf_attr_query_arrays[];
extern const struct struct_field bpf_attr_QUERY_fields[];
extern const struct struct_field bpf_attr_TASK_FD_QUERY_fields[];
extern const struct struct_field bpf_attr_BTF_LOAD_fields[];
extern const char *const bpf_attr_batch_arrays[];
extern const struct struct_field bpf_attr_BATCH_fields[];
extern const struct struct_field bpf_attr_TEST_fields[];
extern const struct struct_field bpf_attr_INFO_fields[];
extern const struct struct_field bpf_attr_RAW_TRACEPOINT_fields[];
extern const struct struct_field bpf_attr_PROG_STREAM_READ_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_BASE_fields[];
extern const struct union_variant bpf_attr_LINK_CREATE_base;
extern const unsigned long bpf_attach_types_tracing[];
extern const struct struct_field bpf_attr_LINK_CREATE_ITER_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_PERF_EVENT_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_TRACING_fields[];
extern const unsigned long netfilter_pfs[];
extern const struct struct_field bpf_attr_LINK_CREATE_NETFILTER_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_TCX_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_NETKIT_fields[];
extern const struct struct_field bpf_attr_LINK_CREATE_CGROUP_fields[];
extern const unsigned long bpf_attach_types_tcx[];
extern const unsigned long bpf_attach_types_netkit[];
extern const unsigned long bpf_attach_types_cgroup[];
extern const unsigned long bpf_attach_types_kprobe_multi[];
extern const char *const bpf_attr_link_create_kprobe_multi_arrays[];
extern const struct struct_field bpf_attr_LINK_CREATE_KPROBE_MULTI_fields[];
extern const unsigned long bpf_attach_types_uprobe_multi[];
extern const char *const bpf_attr_link_create_uprobe_multi_arrays[];
extern const struct struct_field bpf_attr_LINK_CREATE_UPROBE_MULTI_fields[];
extern const struct union_variant bpf_attr_LINK_CREATE_nested[];
extern const struct struct_field bpf_insn_fields[BPF_INSN_FIELDS_N];
extern const struct union_variant bpf_attr_variants[BPF_ATTR_VARIANTS_N];
#endif /* USE_BPF */

/*
 * Sockaddr / setsockopt leaf tables defined in struct_catalog/sockaddr.c.
 * The sockaddr_storage envelope itself is always built, so the
 * sockaddr_storage_fields and sockaddr_storage_variants externs (plus
 * the always-on AF arms) live outside any USE_* guard.  Per-AF
 * variants and their pools are gated by the same USE_<AF> macros the
 * definitions use so the extern surface tracks the live build.
 *
 * sockaddr_storage_variants is the tagged-union dispatch table whose
 * entry count is configuration-dependent (one entry per #ifdef
 * USE_<AF> arm; USE_AX25 contributes two for AF_AX25/AF_NETROM).
 * SOCKADDR_STORAGE_VARIANTS_N mirrors that arithmetic so the spine's
 * ARRAY_SIZE(sockaddr_storage_variants) still folds to the same
 * constant the static-table form did.  USE_* macros come from
 * config.h, which struct_catalog.c and struct_catalog/sockaddr.c
 * include before this header.
 */
enum {
	SOCKADDR_STORAGE_FIELDS_N	= 1,
	LINGER_FIELDS_N			= 2,
	IP_MREQN_FIELDS_N		= 3,
	IP_MREQ_SOURCE_FIELDS_N		= 3,
	IPV6_MREQ_FIELDS_N		= 2,
	PACKET_MREQ_FIELDS_N		= 4,
	GROUP_REQ_FIELDS_N		= 2,
	GROUP_SOURCE_REQ_FIELDS_N	= 3,

	SOCKADDR_STORAGE_VARIANTS_N	= 8 /* UNIX,INET,INET6,NETLINK,PACKET,TIPC,QIPCRTR,NFC */
#ifdef USE_VSOCK
		+ 1
#endif
#ifdef USE_PPPOX
		+ 1
#endif
#ifdef USE_CAIF
		+ 1
#endif
#ifdef USE_CAN
		+ 1
#endif
#ifdef USE_RXRPC
		+ 1
#endif
#ifdef USE_X25
		+ 1
#endif
#ifdef USE_PHONET
		+ 1
#endif
#ifdef USE_AX25
		+ 2 /* AF_AX25 + AF_NETROM */
#endif
#ifdef USE_ROSE
		+ 1
#endif
#ifdef USE_ATM
		+ 1 /* AF_ATMPVC */
#endif
#ifdef USE_LLC
		+ 1
#endif
#ifdef USE_MCTP
		+ 1
#endif
#ifdef USE_IF_ALG
		+ 1
#endif
#ifdef USE_XDP
		+ 1
#endif
		,
};

extern const unsigned long sockaddr_storage_af_vocab[];
extern const unsigned long packet_eth_p_vocab[];
extern const unsigned long packet_arphrd_vocab[];
extern const unsigned long packet_pkttype_vocab[];
extern const struct struct_field sockaddr_un_variant_fields[];
extern const struct struct_field sockaddr_in_variant_fields[];
extern const struct struct_field sockaddr_in6_variant_fields[];
extern const struct struct_field sockaddr_nl_variant_fields[];
extern const struct struct_field sockaddr_ll_variant_fields[];
#ifdef USE_VSOCK
extern const unsigned long vsock_cid_vocab[];
extern const struct struct_field sockaddr_vm_variant_fields[];
#endif
#ifdef USE_PPPOX
extern const struct struct_field sockaddr_pppox_variant_fields[];
#endif
#ifdef USE_CAIF
extern const struct struct_field sockaddr_caif_variant_fields[];
#endif
#ifdef USE_CAN
extern const struct struct_field sockaddr_can_variant_fields[];
#endif
#ifdef USE_RXRPC
extern const struct struct_field sockaddr_rxrpc_variant_fields[];
#endif
#ifdef USE_X25
extern const struct struct_field sockaddr_x25_variant_fields[];
#endif
#ifdef USE_PHONET
extern const struct struct_field sockaddr_pn_variant_fields[];
#endif
#ifdef USE_AX25
extern const struct struct_field sockaddr_ax25_variant_fields[];
#endif
#ifdef USE_ROSE
extern const struct struct_field sockaddr_rose_variant_fields[];
#endif
#ifdef USE_ATM
extern const struct struct_field sockaddr_atmpvc_variant_fields[];
#endif
#ifdef USE_LLC
extern const struct struct_field sockaddr_llc_variant_fields[];
#endif
#ifdef USE_MCTP
extern const struct struct_field sockaddr_mctp_variant_fields[];
#endif
#ifdef USE_IF_ALG
extern const char *const salg_type_vocab[];
extern const char *const salg_name_vocab[];
extern const struct struct_field sockaddr_alg_variant_fields[];
#endif
extern const unsigned long tipc_addrtype_vocab[];
extern const unsigned long tipc_scope_vocab[];
extern const struct struct_field sockaddr_tipc_variant_fields[];
extern const struct struct_field sockaddr_tipc_id_fields[];
extern const struct struct_field sockaddr_tipc_nameseq_fields[];
extern const struct struct_field sockaddr_tipc_name_fields[];
extern const struct union_variant sockaddr_tipc_addr_nested[];
extern const unsigned long qrtr_node_vocab[];
extern const unsigned long qrtr_port_vocab[];
extern const struct struct_field sockaddr_qrtr_variant_fields[];
extern const unsigned long nfc_proto_vocab[];
extern const struct struct_field sockaddr_nfc_variant_fields[];
#ifdef USE_XDP
extern const struct struct_field sockaddr_xdp_variant_fields[];
#endif
extern const struct union_variant sockaddr_storage_variants[SOCKADDR_STORAGE_VARIANTS_N];
extern const struct struct_field sockaddr_storage_fields[SOCKADDR_STORAGE_FIELDS_N];

extern const struct struct_field linger_fields[LINGER_FIELDS_N];
extern const unsigned char ipv4_mcast_all_hosts[4];
extern const unsigned char ipv4_mcast_all_routers[4];
extern const unsigned char ipv4_mcast_igmpv3[4];
extern const unsigned char ipv4_mcast_mdns[4];
extern const unsigned char ipv4_mcast_ntp[4];
extern const unsigned char ipv4_mcast_ssm[4];
extern const unsigned char ipv4_mcast_ssdp[4];
extern const unsigned char *const ipv4_mcast_vocab[];
extern const struct struct_field ip_mreqn_fields[IP_MREQN_FIELDS_N];
extern const struct struct_field ip_mreq_source_fields[IP_MREQ_SOURCE_FIELDS_N];
extern const unsigned char ipv6_mcast_all_nodes[16];
extern const unsigned char ipv6_mcast_all_routers[16];
extern const unsigned char ipv6_mcast_mldv2_reports[16];
extern const unsigned char ipv6_mcast_solicited_node[16];
extern const unsigned char ipv6_mcast_site_routers[16];
extern const unsigned char *const ipv6_mreq_multiaddr_vocab[];
extern const struct struct_field ipv6_mreq_fields[IPV6_MREQ_FIELDS_N];
extern const unsigned long packet_mreq_type_values[];
extern const struct struct_field packet_mreq_fields[PACKET_MREQ_FIELDS_N];
extern const struct struct_field group_req_fields[GROUP_REQ_FIELDS_N];
extern const struct struct_field group_source_req_fields[GROUP_SOURCE_REQ_FIELDS_N];

/*
 * socket-family leaf tables defined in struct_catalog/socket.c.
 * Covers struct iovec (msg_iov array element, also referenced from
 * the io_uring_register variant table below), struct msghdr (sendmsg /
 * recvmsg), and struct mmsghdr (sendmmsg / recvmmsg).  Each _N constant
 * gives the extern decl a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same constant
 * it did before the carve.  iovec_fields is shared with
 * struct_catalog/io_uring_register.c (via its IOVEC_FIELDS_N extern
 * below), so the count constant stays in the io_uring block to preserve
 * the existing declaration order.
 */
enum {
	MSGHDR_FIELDS_N			= 7,
	MMSGHDR_FIELDS_N		= 1,
};

extern const struct struct_field msghdr_fields[MSGHDR_FIELDS_N];
extern const struct struct_field mmsghdr_fields[MMSGHDR_FIELDS_N];

/*
 * io_uring_setup / io_uring_register leaf tables defined in
 * struct_catalog/io_uring_register.c.  The _N constants give the
 * extern decls a complete array type so the spine's ARRAY_SIZE() at
 * the reference site keeps folding to the same constant it did before
 * the carve.  iovec_fields lives in struct_catalog/socket.c (referenced
 * by several non-io_uring spine entries too); the io_uring_register
 * variant table here references it via the same extern, so promoting
 * iovec_fields to external linkage is enough to keep the variant
 * .fields = iovec_fields initialiser resolving.
 */
enum {
	IOVEC_FIELDS_N					= 2,
	IO_URING_PARAMS_FIELDS_N			= 7,
	IO_URING_REGISTER_EVENTFD_FIELDS_N		= 1,
	IO_URING_REGISTER_FILES_UPDATE_FIELDS_N		= 3,
	IO_URING_REGISTER_FILE_ALLOC_RANGE_FIELDS_N	= 3,
	IO_URING_REGISTER_PBUF_RING_FIELDS_N		= 5,
	IO_URING_REGISTER_SYNC_CANCEL_FIELDS_N		= 4,
	IO_URING_RESTRICTION_OPCODES_N			= 4,
	IO_URING_REGISTER_RESTRICTION_FIELDS_N		= 4,
	IO_URING_NAPI_OPCODES_N				= 3,
	IO_URING_NAPI_TRACKING_STRATEGIES_N		= 3,
	IO_URING_REGISTER_NAPI_FIELDS_N			= 6,
	IO_URING_CLOCK_IDS_N				= 2,
	IO_URING_REGISTER_CLOCK_FIELDS_N		= 2,
	IO_URING_REGISTER_CLONE_BUFFERS_FIELDS_N	= 6,
	IO_URING_REGISTER_PBUF_STATUS_FIELDS_N		= 3,
	IO_URING_REGISTER_RSRC_REGISTER_FIELDS_N	= 5,
	IO_URING_REGISTER_RSRC_UPDATE2_FIELDS_N		= 6,
	IO_URING_REGISTER_PROBE_FIELDS_N		= 4,
	IO_URING_REGISTER_VARIANTS_N			= 24,
};

extern const struct struct_field iovec_fields[IOVEC_FIELDS_N];
extern const struct struct_field io_uring_params_fields[IO_URING_PARAMS_FIELDS_N];
extern const struct struct_field io_uring_register_eventfd_fields[IO_URING_REGISTER_EVENTFD_FIELDS_N];
extern const struct struct_field io_uring_register_files_update_fields[IO_URING_REGISTER_FILES_UPDATE_FIELDS_N];
extern const struct struct_field io_uring_register_file_alloc_range_fields[IO_URING_REGISTER_FILE_ALLOC_RANGE_FIELDS_N];
extern const struct struct_field io_uring_register_pbuf_ring_fields[IO_URING_REGISTER_PBUF_RING_FIELDS_N];
extern const struct struct_field io_uring_register_sync_cancel_fields[IO_URING_REGISTER_SYNC_CANCEL_FIELDS_N];
extern const unsigned long io_uring_restriction_opcodes[IO_URING_RESTRICTION_OPCODES_N];
extern const struct struct_field io_uring_register_restriction_fields[IO_URING_REGISTER_RESTRICTION_FIELDS_N];
extern const unsigned long io_uring_napi_opcodes[IO_URING_NAPI_OPCODES_N];
extern const unsigned long io_uring_napi_tracking_strategies[IO_URING_NAPI_TRACKING_STRATEGIES_N];
extern const struct struct_field io_uring_register_napi_fields[IO_URING_REGISTER_NAPI_FIELDS_N];
extern const unsigned long io_uring_clock_ids[IO_URING_CLOCK_IDS_N];
extern const struct struct_field io_uring_register_clock_fields[IO_URING_REGISTER_CLOCK_FIELDS_N];
extern const struct struct_field io_uring_register_clone_buffers_fields[IO_URING_REGISTER_CLONE_BUFFERS_FIELDS_N];
extern const struct struct_field io_uring_register_pbuf_status_fields[IO_URING_REGISTER_PBUF_STATUS_FIELDS_N];
extern const struct struct_field io_uring_register_rsrc_register_fields[IO_URING_REGISTER_RSRC_REGISTER_FIELDS_N];
extern const struct struct_field io_uring_register_rsrc_update2_fields[IO_URING_REGISTER_RSRC_UPDATE2_FIELDS_N];
extern const struct struct_field io_uring_register_probe_fields[IO_URING_REGISTER_PROBE_FIELDS_N];
extern const struct union_variant io_uring_register_variants[IO_URING_REGISTER_VARIANTS_N];

/*
 * quotactl / quotactl_fd leaf tables defined in struct_catalog/quota.c.
 * The _N constants give the extern decls a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.
 */
enum {
	IF_DQBLK_FIELDS_N	= 9,
	IF_DQINFO_FIELDS_N	= 4,
	FS_DISK_QUOTA_FIELDS_N	= 22,
};

extern const struct struct_field if_dqblk_fields[IF_DQBLK_FIELDS_N];
extern const struct struct_field if_dqinfo_fields[IF_DQINFO_FIELDS_N];
extern const struct struct_field fs_disk_quota_fields[FS_DISK_QUOTA_FIELDS_N];

/*
 * time-shaped leaf tables defined in struct_catalog/time.c.  The _N
 * constants give the extern decls a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same constant
 * it did before the carve.
 */
enum {
	TIMEX_FIELDS_N		= 18,
	ITIMERSPEC_FIELDS_N	= 4,
	TIMESPEC_FIELDS_N	= 2,
	ITIMERVAL_FIELDS_N	= 4,
	UTIMBUF_FIELDS_N	= 2,
	TIMEVAL_FIELDS_N	= 2,
	TIMEZONE_FIELDS_N	= 2,
};

extern const struct struct_field timex_fields[TIMEX_FIELDS_N];
extern const struct struct_field itimerspec_fields[ITIMERSPEC_FIELDS_N];
extern const struct struct_field timespec_fields[TIMESPEC_FIELDS_N];
extern const struct struct_field itimerval_fields[ITIMERVAL_FIELDS_N];
extern const struct struct_field utimbuf_fields[UTIMBUF_FIELDS_N];
extern const struct struct_field timeval_fields[TIMEVAL_FIELDS_N];
extern const struct struct_field timezone_fields[TIMEZONE_FIELDS_N];

/*
 * perf_event_attr leaf tables defined in struct_catalog/perf.c.  The
 * _N constants give the extern decls a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.  Only the shared field table and
 * the variant array are referenced from the spine; the per-PERF_TYPE_*
 * variant field arrays and their value/vocab pools are file-private to
 * struct_catalog/perf.c and stay static const.
 */
enum {
	PERF_EVENT_ATTR_FIELDS_N	= 22,
	PERF_EVENT_ATTR_VARIANTS_N	= 6,
};

extern const struct struct_field perf_event_attr_fields[PERF_EVENT_ATTR_FIELDS_N];
extern const struct union_variant perf_event_attr_variants[PERF_EVENT_ATTR_VARIANTS_N];

/*
 * landlock attr leaf tables defined in struct_catalog/landlock.c.
 * Three FT_FLAGS / FT_RANGE-tagged field arrays cataloging the attr
 * structs passed to landlock_create_ruleset and the two rule_type
 * arms of landlock_add_rule.  Only these arrays are referenced from
 * the spine; the LANDLOCK_ACCESS_FS_MASK / LANDLOCK_ACCESS_NET_MASK
 * / LANDLOCK_SCOPE_MASK helper macros they consume stay file-private
 * to struct_catalog/landlock.c.
 */
enum {
	LANDLOCK_RULESET_ATTR_FIELDS_N		= 3,
	LANDLOCK_PATH_BENEATH_ATTR_FIELDS_N	= 2,
	LANDLOCK_NET_PORT_ATTR_FIELDS_N		= 2,
};

extern const struct struct_field landlock_ruleset_attr_fields[LANDLOCK_RULESET_ATTR_FIELDS_N];
extern const struct struct_field landlock_path_beneath_attr_fields[LANDLOCK_PATH_BENEATH_ATTR_FIELDS_N];
extern const struct struct_field landlock_net_port_attr_fields[LANDLOCK_NET_PORT_ATTR_FIELDS_N];

/*
 * LSM leaf table defined in struct_catalog/lsm.c.  Covers struct
 * lsm_ctx (lsm_set_self_attr a2 head).  The _N constant gives the
 * extern decl a complete array type so the spine's ARRAY_SIZE() at
 * the reference site keeps folding to the same constant it did before
 * the carve.  The struct lsm_ctx fallback shim lives in both
 * struct_catalog.c and struct_catalog/lsm.c under the same
 * #ifndef _LINUX_LSM_H guard -- the spine needs the type visible for
 * sizeof(struct lsm_ctx) on its catalog entry, the leaf TU needs it
 * for the FIELD() offsetof / sizeof initialisers.
 */
enum {
	LSM_CTX_FIELDS_N	= 4,
};

extern const struct struct_field lsm_ctx_fields[LSM_CTX_FIELDS_N];

/*
 * signal-shaped leaf tables defined in struct_catalog/signal.c.
 * Covers struct sigevent (timer_create), struct sigaction (rt_sigaction),
 * stack_t (sigaltstack), the siginfo_t header + its _rt / _kill variant
 * arms (rt_sigqueueinfo / rt_tgsigqueueinfo / pidfd_send_signal), and
 * sigset_t (signalfd / signalfd4).  Each _N constant gives the extern
 * decl a complete array type so the spine's ARRAY_SIZE() at the
 * reference site keeps folding to the same constant it did before the
 * carve.  sigevent_notify_values / siginfo_t_si_code_vocab /
 * siginfo_t_kill_discrim_values are private vocab pools referenced
 * only by their own signal field arrays / variant entries and stay
 * scoped to signal.c through this extern surface.
 */
enum {
	SIGEVENT_NOTIFY_VALUES_N		= 4,
	SIGEVENT_FIELDS_N			= 4,
	SIGACTION_FIELDS_N			= 1,
	STACK_T_FIELDS_N			= 3,
	SIGINFO_T_SI_CODE_VOCAB_N		= 6,
	SIGINFO_T_FIELDS_N			= 3,
	SIGINFO_T_RT_VARIANT_FIELDS_N		= 3,
	SIGINFO_T_KILL_VARIANT_FIELDS_N		= 2,
	SIGINFO_T_KILL_DISCRIM_VALUES_N		= 2,
	SIGINFO_T_VARIANTS_N			= 2,
	SIGSET_T_FIELDS_N			= 1,
};

extern const unsigned long sigevent_notify_values[SIGEVENT_NOTIFY_VALUES_N];
extern const struct struct_field sigevent_fields[SIGEVENT_FIELDS_N];
extern const struct struct_field sigaction_fields[SIGACTION_FIELDS_N];
extern const struct struct_field stack_t_fields[STACK_T_FIELDS_N];
extern const unsigned long siginfo_t_si_code_vocab[SIGINFO_T_SI_CODE_VOCAB_N];
extern const struct struct_field siginfo_t_fields[SIGINFO_T_FIELDS_N];
extern const struct struct_field siginfo_t_rt_variant_fields[SIGINFO_T_RT_VARIANT_FIELDS_N];
extern const struct struct_field siginfo_t_kill_variant_fields[SIGINFO_T_KILL_VARIANT_FIELDS_N];
extern const unsigned long siginfo_t_kill_discrim_values[SIGINFO_T_KILL_DISCRIM_VALUES_N];
extern const struct union_variant siginfo_t_variants[SIGINFO_T_VARIANTS_N];
extern const struct struct_field sigset_t_fields[SIGSET_T_FIELDS_N];

/*
 * SysV / POSIX IPC leaf tables defined in struct_catalog/ipc.c.
 * Covers struct sembuf (semop / semtimedop), struct mq_attr
 * (mq_open / mq_getsetattr), struct msqid_ds (msgctl IPC_SET),
 * struct shmid_ds (shmctl IPC_SET), and struct msgbuf (msgsnd).
 * Each _N constant gives the extern decl a complete array type so
 * the spine's ARRAY_SIZE() at the reference site keeps folding to
 * the same constant it did before the carve.
 */
enum {
	SEMBUF_FIELDS_N		= 3,
	MQ_ATTR_FIELDS_N	= 4,
	MSQID_DS_FIELDS_N	= 2,
	SHMID_DS_FIELDS_N	= 3,
	MSGBUF_FIELDS_N		= 1,
};

extern const struct struct_field sembuf_fields[SEMBUF_FIELDS_N];
extern const struct struct_field mq_attr_fields[MQ_ATTR_FIELDS_N];
extern const struct struct_field msqid_ds_fields[MSQID_DS_FIELDS_N];
extern const struct struct_field shmid_ds_fields[SHMID_DS_FIELDS_N];
extern const struct struct_field msgbuf_fields[MSGBUF_FIELDS_N];

/*
 * fcntl-family leaf tables defined in struct_catalog/fcntl.c.
 * Covers struct flock (fcntl F_*LK / F_OFD_*LK / F_CANCELLK), struct
 * f_owner_ex (fcntl F_GETOWN_EX / F_SETOWN_EX), struct open_how
 * (openat2), and struct file_handle (open_by_handle_at).  Each _N
 * constant gives the extern decl a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the
 * same constant it did before the carve.  flock_l_type_values /
 * flock_l_whence_values / f_owner_ex_type_values are private vocab
 * pools referenced only by their own fcntl field arrays and stay
 * scoped to fcntl.c through this extern surface.
 */
enum {
	FLOCK_L_TYPE_VALUES_N		= 3,
	FLOCK_L_WHENCE_VALUES_N		= 3,
	FLOCK_FIELDS_N			= 5,
	F_OWNER_EX_TYPE_VALUES_N	= 3,
	F_OWNER_EX_FIELDS_N		= 2,
	OPEN_HOW_FIELDS_N		= 3,
	FILE_HANDLE_FIELDS_N		= 2,
};

extern const unsigned long flock_l_type_values[FLOCK_L_TYPE_VALUES_N];
extern const unsigned long flock_l_whence_values[FLOCK_L_WHENCE_VALUES_N];
extern const struct struct_field flock_fields[FLOCK_FIELDS_N];
extern const unsigned long f_owner_ex_type_values[F_OWNER_EX_TYPE_VALUES_N];
extern const struct struct_field f_owner_ex_fields[F_OWNER_EX_FIELDS_N];
extern const struct struct_field open_how_fields[OPEN_HOW_FIELDS_N];
extern const struct struct_field file_handle_fields[FILE_HANDLE_FIELDS_N];

/*
 * sched-shaped leaf tables defined in struct_catalog/sched.c.  Covers
 * struct sched_attr (sched_setattr / sched_getattr), struct clone_args
 * (clone3), and struct sched_param (sched_setparam / sched_setscheduler).
 * Each _N constant gives the extern decl a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.
 */
enum {
	SCHED_ATTR_FIELDS_N	= 10,
	CLONE_ARGS_FIELDS_N	= 11,
	SCHED_PARAM_FIELDS_N	= 1,
};

extern const struct struct_field sched_attr_fields[SCHED_ATTR_FIELDS_N];
extern const struct struct_field clone_args_fields[CLONE_ARGS_FIELDS_N];
extern const struct struct_field sched_param_fields[SCHED_PARAM_FIELDS_N];

/*
 * aio-shaped leaf tables defined in struct_catalog/aio.c.  Covers
 * struct iocb (io_cancel) with its IOCB_CMD_* opcode vocab.  Each _N
 * constant gives the extern decl a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.  iocb_opcode_values is referenced
 * only by iocb_fields itself but lives at file scope in aio.c so its
 * ARRAY_SIZE() inside the FIELDX initialiser keeps folding -- the
 * extern surface lets the spine's struct_catalog[SC_IOCB].fields
 * reference resolve while iocb_opcode_values stays scoped to aio.c
 * through this extern.  IOCB_FLAGS_MASK / IOCB_RWF_MASK helper
 * macros are private to aio.c.
 */
enum {
	IOCB_OPCODE_VALUES_N	= 8,
	IOCB_FIELDS_N		= 12,
};

extern const unsigned long iocb_opcode_values[IOCB_OPCODE_VALUES_N];
extern const struct struct_field iocb_fields[IOCB_FIELDS_N];

/*
 * futex-shaped leaf tables defined in struct_catalog/futex.c.  Covers
 * struct robust_list_head (set_robust_list), struct rseq (rseq), and
 * struct futex_waitv (futex_waitv).  Each _N constant gives the extern
 * decl a complete array type so the spine's ARRAY_SIZE() at the
 * reference site keeps folding to the same constant it did before the
 * carve.
 */
enum {
	ROBUST_LIST_HEAD_FIELDS_N	= 3,
	RSEQ_FIELDS_N			= 6,
	FUTEX_WAITV_FIELDS_N		= 3,
};

extern const struct struct_field robust_list_head_fields[ROBUST_LIST_HEAD_FIELDS_N];
extern const struct struct_field rseq_fields[RSEQ_FIELDS_N];
extern const struct struct_field futex_waitv_fields[FUTEX_WAITV_FIELDS_N];

/*
 * capability leaf tables defined in struct_catalog/cap.c.  Covers
 * struct __user_cap_header_struct and struct __user_cap_data_struct
 * (capset / capget).  Each _N constant gives the extern decl a complete
 * array type so the spine's ARRAY_SIZE() at the reference site keeps
 * folding to the same constant it did before the carve.
 */
enum {
	USER_CAP_HEADER_FIELDS_N	= 2,
	USER_CAP_DATA_FIELDS_N		= 3,
};

extern const struct struct_field user_cap_header_fields[USER_CAP_HEADER_FIELDS_N];
extern const struct struct_field user_cap_data_fields[USER_CAP_DATA_FIELDS_N];

/*
 * Classic-BPF leaf tables defined in struct_catalog/bpf_classic.c.
 * Covers struct sock_filter (the cBPF instruction word, referenced by
 * sock_fprog.filter via FT_PTR_ARRAY.elem_struct) and struct sock_fprog
 * (seccomp SET_MODE_FILTER, setsockopt(SO_ATTACH_FILTER), prctl(PR_SET_
 * SECCOMP)).  The two ship in the same TU because sock_fprog names
 * sock_filter as its element-struct: the pointer-fill pass dereferences
 * that name through the catalog to size the sub-array, so the element
 * descriptor has to be co-located with the container.  Each _N constant
 * gives the extern decl a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same constant
 * it did before the carve.
 */
enum {
	SOCK_FILTER_FIELDS_N	= 4,
	SOCK_FPROG_FIELDS_N	= 2,
};

extern const struct struct_field sock_filter_fields[SOCK_FILTER_FIELDS_N];
extern const struct struct_field sock_fprog_fields[SOCK_FPROG_FIELDS_N];

/*
 * kexec leaf tables defined in struct_catalog/kexec.c.  Covers struct
 * kexec_segment (the kexec_load segments array element).  The _N
 * constant gives the extern decl a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.
 */
enum {
	KEXEC_SEGMENT_FIELDS_N	= 4,
};

extern const struct struct_field kexec_segment_fields[KEXEC_SEGMENT_FIELDS_N];

/*
 * mount / namespace leaf tables defined in struct_catalog/mount.c.
 * Covers struct mount_attr (mount_setattr / open_tree_attr), struct
 * mnt_id_req (statmount / listmount), and struct ns_id_req (listns).
 * Each _N constant gives the extern decl a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.  The struct ns_id_req fallback
 * shim lives in both struct_catalog.c and struct_catalog/mount.c under
 * the same #ifndef NS_ID_REQ_SIZE_VER0 guard -- the spine needs the
 * type visible for sizeof(struct ns_id_req) on its catalog entry, the
 * leaf TU needs it for the FIELD() offsetof / sizeof initialisers.
 */
enum {
	MOUNT_ATTR_FIELDS_N	= 4,
	MNT_ID_REQ_FIELDS_N	= 3,
	NS_ID_REQ_FIELDS_N	= 4,
};

extern const struct struct_field mount_attr_fields[MOUNT_ATTR_FIELDS_N];
extern const struct struct_field mnt_id_req_fields[MNT_ID_REQ_FIELDS_N];
extern const struct struct_field ns_id_req_fields[NS_ID_REQ_FIELDS_N];

/*
 * TCP leaf tables defined in struct_catalog/tcp.c.  Covers struct
 * tcp_repair_opt (IPPROTO_TCP / TCP_REPAIR_OPTIONS setsockopt optval
 * array element).  The _N constant gives the extern decl a complete
 * array type so the spine's ARRAY_SIZE() at the reference site keeps
 * folding to the same constant it did before the carve.  Gated by
 * USE_TCP_REPAIR_OPT to mirror the existing guard on the spine
 * reference and the struct's header availability.
 */
#ifdef USE_TCP_REPAIR_OPT
enum {
	TCP_REPAIR_OPT_FIELDS_N	= 2,
};

extern const struct struct_field tcp_repair_opt_fields[TCP_REPAIR_OPT_FIELDS_N];
#endif /* USE_TCP_REPAIR_OPT */

/*
 * resource-shaped leaf tables defined in struct_catalog/resource.c.
 * Covers struct rlimit (setrlimit / getrlimit / prlimit64) and struct
 * cachestat_range (cachestat).  Each _N constant gives the extern decl
 * a complete array type so the spine's ARRAY_SIZE() at the reference
 * site keeps folding to the same constant it did before the carve.
 * Neither table is config-gated -- both structs come from headers
 * trinity already requires.
 */
enum {
	RLIMIT_FIELDS_N			= 2,
	CACHESTAT_RANGE_FIELDS_N	= 2,
};

extern const struct struct_field rlimit_fields[RLIMIT_FIELDS_N];
extern const struct struct_field cachestat_range_fields[CACHESTAT_RANGE_FIELDS_N];

/*
 * poll-family leaf tables defined in struct_catalog/poll.c.  Covers
 * struct pollfd (poll / ppoll) and struct epoll_event (epoll_ctl).
 * Each _N constant gives the extern decl a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the
 * same constant it did before the carve.  Neither table is
 * config-gated -- both structs come from headers trinity already
 * requires.
 */
enum {
	POLLFD_FIELDS_N		= 3,
	EPOLL_EVENT_FIELDS_N	= 1,
};

extern const struct struct_field pollfd_fields[POLLFD_FIELDS_N];
extern const struct struct_field epoll_event_fields[EPOLL_EVENT_FIELDS_N];

/*
 * xattr / file_attr leaf tables defined in struct_catalog/xattr.c.
 * struct xattr_args is gated on USE_XATTR_ARGS to track the build
 * host's uapi vintage (mirroring the spine reference and the
 * syscalls/{set,get}xattrat.c guards); struct file_attr is always
 * available via the compat.h fallback so its extern stays unguarded.
 * Each _N constant gives the extern decl a complete array type so
 * the spine's ARRAY_SIZE() at the reference site keeps folding to
 * the same constant it did before the carve.
 */
#ifdef USE_XATTR_ARGS
enum {
	XATTR_ARGS_FIELDS_N	= 3,
};

extern const struct struct_field xattr_args_fields[XATTR_ARGS_FIELDS_N];
#endif /* USE_XATTR_ARGS */

enum {
	FILE_ATTR_FIELDS_N	= 5,
};

extern const struct struct_field file_attr_fields[FILE_ATTR_FIELDS_N];

/*
 * LDT leaf table defined in struct_catalog/ldt.c.  Covers struct
 * user_desc (modify_ldt write_ldt arm, func == 1).  The _N constant
 * gives the extern decl a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.  Gated by X86 to mirror the
 * existing guard on the spine reference and the struct's header
 * availability -- struct user_desc lives in <asm/ldt.h> and the
 * modify_ldt syscall it parameterises is x86-only.
 */
#ifdef X86
enum {
	USER_DESC_FIELDS_N	= 3,
};

extern const struct struct_field user_desc_fields[USER_DESC_FIELDS_N];
#endif /* X86 */
