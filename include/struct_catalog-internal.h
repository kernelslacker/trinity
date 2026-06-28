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
 * USE_<AF> arm; USE_AX25 contributes two for AF_AX25/AF_NETROM and
 * USE_ATM contributes two for AF_ATMSVC/AF_ATMPVC).
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
#ifdef USE_ATALK
		+ 1
#endif
#ifdef USE_ATM
		+ 2 /* AF_ATMSVC + AF_ATMPVC */
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
#ifdef USE_ATALK
extern const struct struct_field sockaddr_at_variant_fields[];
#endif
#ifdef USE_ATM
extern const struct struct_field sockaddr_atmsvc_variant_fields[];
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
 * io_uring_setup / io_uring_register leaf tables defined in
 * struct_catalog/io_uring_register.c.  The _N constants give the
 * extern decls a complete array type so the spine's ARRAY_SIZE() at
 * the reference site keeps folding to the same constant it did before
 * the carve.  iovec_fields lives in struct_catalog.c (referenced by
 * several non-io_uring spine entries too); the io_uring_register
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
