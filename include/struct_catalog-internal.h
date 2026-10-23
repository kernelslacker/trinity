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

#include <stdbool.h>
#include <stddef.h>

#include "struct_catalog.h"

#include "kernel/fcntl.h"
#include "kernel/sctp.h"
#include "kernel/sched.h"
#include "kernel/mount.h"
struct syscallrecord;

/* ------------------------------------------------------------------ */
/* Spine internals shared across struct_catalog/ TUs.                   */
/* ------------------------------------------------------------------ */

/*
 * Variant / discriminator resolution helpers defined in
 * struct_catalog/variant.c.  Shared with the (nr, arg) registry
 * lookup in struct_catalog/catalog.c so both callers of "match a
 * discriminated syscall_struct_args[] row against a live rec" run
 * the same value/values match.
 */
bool read_rec_arg(const struct syscallrecord *rec,
		  unsigned int arg_idx, unsigned long *out);
bool discrim_key_matches(unsigned long raw,
			 unsigned long value,
			 const unsigned long *values,
			 unsigned int num_values);
bool discrim_key2_matches(const struct syscall_struct_arg *sa,
			  const struct syscallrecord *rec);

/*
 * Init-only validation of syscall_struct_args[] slot shapes.  Called
 * by struct_catalog_init() in struct_catalog/registry.c; defined in
 * struct_catalog/validate.c.
 */
void validate_syscall_struct_args(void);

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
 * BPF leaf tables.  bpf_attr_variants lives in the facade
 * struct_catalog/bpf.c and is consumed from the spine in
 * struct_catalog.c via ARRAY_SIZE() at the use site; every other
 * table listed below lives in a per-family leaf TU
 * (struct_catalog/bpf-map.c, bpf-prog.c, bpf-link.c, bpf-btf.c,
 * bpf-task-storage.c) and is threaded into the facade's
 * bpf_attr_variants aggregator by extern reference.  Every table
 * carries an explicit _N constant so the extern decl compiles against
 * a complete array type -- a count mismatch fails at the leaf TU as
 * "excess elements" / "too few", and the facade's ARRAY_SIZE() at
 * the reference site keeps folding.
 *
 * bpf_map_types / bpf_prog_types / bpf_attach_types and their
 * _count companions are declared in include/bpf.h (shared with
 * syscalls/bpf.c) and intentionally not duplicated here.
 */
enum {
	/*
	 * The BPF_PROG_STREAM_READ_BY_FD variant is gated on
	 * USE_BPF_PROG_STREAM_READ (the prog_stream_read member is absent
	 * from older uapi headers), so the variant count tracks it.
	 */
#ifdef USE_BPF_PROG_STREAM_READ
	BPF_ATTR_VARIANTS_N	= 38,
#else
	BPF_ATTR_VARIANTS_N	= 37,
#endif

	BPF_ATTR_MAP_CREATE_FIELDS_N	= 16,
	BPF_ATTR_MAP_ELEM_FIELDS_N	= 4,
	BPF_ATTR_BATCH_ARRAYS_N		= 2,
	BPF_ATTR_BATCH_FIELDS_N		= 8,

	BPF_ATTR_PROG_LOAD_FIELDS_N	= 26,
	BPF_ATTR_PROG_ATTACH_FIELDS_N	= 7,
	BPF_ATTR_PROG_BIND_MAP_FIELDS_N	= 3,
	BPF_ATTR_QUERY_ARRAYS_N		= 4,
	BPF_ATTR_QUERY_FIELDS_N		= 10,
	BPF_ATTR_TEST_FIELDS_N		= 15,
	BPF_ATTR_PROG_STREAM_READ_FIELDS_N	= 4,

	BPF_ATTR_LINK_UPDATE_FIELDS_N	= 4,
	BPF_ATTR_LINK_DETACH_FIELDS_N	= 1,
	BPF_ATTR_LINK_CREATE_FIELDS_N	= 4,
	/*
	 * bpf_attr_LINK_CREATE_nested[] fan-out: 8 always-on sub-variants
	 * (ITER, PERF_EVENT, TRACING, KPROBE_MULTI, UPROBE_MULTI,
	 * NETFILTER, TCX, NETKIT) + optional TRACING_MULTI and CGROUP
	 * arms gated on the same USE_* macros as their inner-union member
	 * definitions.
	 */
	BPF_ATTR_LINK_CREATE_NESTED_N	= 8
#ifdef USE_BPF_LINK_CREATE_TRACING_MULTI
		+ 1
#endif
#ifdef USE_BPF_LINK_CREATE_CGROUP
		+ 1
#endif
		,

	BPF_ATTR_BTF_LOAD_FIELDS_N	= 8,
	BPF_ATTR_INFO_FIELDS_N		= 3,

	BPF_ATTR_ENABLE_STATS_FIELDS_N	= 1,
	BPF_ATTR_ITER_CREATE_FIELDS_N	= 2,
	BPF_ATTR_TOKEN_CREATE_FIELDS_N	= 2,
	BPF_ATTR_TASK_FD_QUERY_FIELDS_N	= 9,
	BPF_ATTR_RAW_TRACEPOINT_FIELDS_N	= 3,
};

extern const struct struct_field bpf_attr_MAP_CREATE_fields[BPF_ATTR_MAP_CREATE_FIELDS_N];
extern const struct struct_field bpf_attr_PROG_LOAD_fields[BPF_ATTR_PROG_LOAD_FIELDS_N];
extern const struct struct_field bpf_attr_PROG_ATTACH_fields[BPF_ATTR_PROG_ATTACH_FIELDS_N];
extern const struct struct_field bpf_attr_OBJ_fields[];
extern const struct struct_field bpf_attr_MAP_ELEM_fields[BPF_ATTR_MAP_ELEM_FIELDS_N];
extern const struct struct_field bpf_attr_GET_ID_fields[];
extern const struct struct_field bpf_attr_LINK_UPDATE_fields[BPF_ATTR_LINK_UPDATE_FIELDS_N];
extern const struct struct_field bpf_attr_LINK_DETACH_fields[BPF_ATTR_LINK_DETACH_FIELDS_N];
extern const struct struct_field bpf_attr_ENABLE_STATS_fields[BPF_ATTR_ENABLE_STATS_FIELDS_N];
extern const struct struct_field bpf_attr_ITER_CREATE_fields[BPF_ATTR_ITER_CREATE_FIELDS_N];
extern const struct struct_field bpf_attr_PROG_BIND_MAP_fields[BPF_ATTR_PROG_BIND_MAP_FIELDS_N];
extern const struct struct_field bpf_attr_TOKEN_CREATE_fields[BPF_ATTR_TOKEN_CREATE_FIELDS_N];
extern const char *const bpf_attr_query_arrays[BPF_ATTR_QUERY_ARRAYS_N];
extern const struct struct_field bpf_attr_QUERY_fields[BPF_ATTR_QUERY_FIELDS_N];
extern const struct struct_field bpf_attr_TASK_FD_QUERY_fields[BPF_ATTR_TASK_FD_QUERY_FIELDS_N];
extern const struct struct_field bpf_attr_BTF_LOAD_fields[BPF_ATTR_BTF_LOAD_FIELDS_N];
extern const char *const bpf_attr_batch_arrays[BPF_ATTR_BATCH_ARRAYS_N];
extern const struct struct_field bpf_attr_BATCH_fields[BPF_ATTR_BATCH_FIELDS_N];
extern const struct struct_field bpf_attr_TEST_fields[BPF_ATTR_TEST_FIELDS_N];
extern const struct struct_field bpf_attr_INFO_fields[BPF_ATTR_INFO_FIELDS_N];
extern const struct struct_field bpf_attr_RAW_TRACEPOINT_fields[BPF_ATTR_RAW_TRACEPOINT_FIELDS_N];
#ifdef USE_BPF_PROG_STREAM_READ
extern const struct struct_field bpf_attr_PROG_STREAM_READ_fields[BPF_ATTR_PROG_STREAM_READ_FIELDS_N];
#endif
extern const struct struct_field bpf_attr_LINK_CREATE_fields[BPF_ATTR_LINK_CREATE_FIELDS_N];
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
#ifdef USE_BPF_LINK_CREATE_CGROUP
extern const struct struct_field bpf_attr_LINK_CREATE_CGROUP_fields[];
#endif
extern const unsigned long bpf_attach_types_tcx[];
extern const unsigned long bpf_attach_types_netkit[];
extern const unsigned long bpf_attach_types_cgroup[];
extern const unsigned long bpf_attach_types_kprobe_multi[];
extern const char *const bpf_attr_link_create_kprobe_multi_arrays[];
extern const struct struct_field bpf_attr_LINK_CREATE_KPROBE_MULTI_fields[];
extern const unsigned long bpf_attach_types_uprobe_multi[];
extern const char *const bpf_attr_link_create_uprobe_multi_arrays[];
extern const struct struct_field bpf_attr_LINK_CREATE_UPROBE_MULTI_fields[];
extern const struct union_variant bpf_attr_LINK_CREATE_nested[BPF_ATTR_LINK_CREATE_NESTED_N];
extern const struct union_variant bpf_attr_variants[BPF_ATTR_VARIANTS_N];
#endif /* USE_BPF */

/*
 * Sockaddr / setsockopt leaf tables defined in the struct_catalog/
 * sockaddr-* TUs: sockaddr_storage variants and per-AF field arrays
 * live in struct_catalog/sockaddr-af.c, the IPv4/IPv6 multicast
 * optval tables (ip_mreqn / ip_mreq_source / ipv6_mreq) in
 * struct_catalog/sockaddr-mcast.c, and the non-multicast optval
 * tables (linger / packet_mreq / group_req / group_source_req) in
 * struct_catalog/sockaddr-sockopt.c.  The sockaddr_storage envelope
 * itself is always built, so the sockaddr_storage_fields and
 * sockaddr_storage_variants externs (plus the always-on AF arms)
 * live outside any USE_* guard.  Per-AF variants and their pools are
 * gated by the same USE_<AF> macros the definitions use so the
 * extern surface tracks the live build.
 *
 * sockaddr_storage_variants is the tagged-union dispatch table whose
 * entry count is configuration-dependent (one entry per #ifdef
 * USE_<AF> arm).
 * SOCKADDR_STORAGE_VARIANTS_N mirrors that arithmetic so the spine's
 * ARRAY_SIZE(sockaddr_storage_variants) still folds to the same
 * constant the static-table form did.  USE_* macros come from
 * config.h, which struct_catalog.c and the sockaddr-* TUs include
 * before this header.
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
 * time-shaped leaf tables defined in struct_catalog/time.c.  The _N
 * constants give the extern decls a complete array type so the spine's
 * ARRAY_SIZE() at the reference site keeps folding to the same constant
 * it did before the carve.
 */
enum {
	UTIMBUF_FIELDS_N	= 2,
	TIMEVAL_FIELDS_N	= 2,
};

extern const struct struct_field utimbuf_fields[UTIMBUF_FIELDS_N];
extern const struct struct_field timeval_fields[TIMEVAL_FIELDS_N];

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
 * fcntl-family leaf tables defined in struct_catalog/fcntl.c.
 * Covers struct flock (fcntl F_*LK / F_OFD_*LK / F_CANCELLK), struct
 * f_owner_ex (fcntl F_GETOWN_EX / F_SETOWN_EX), and struct file_handle
 * (open_by_handle_at).  Each _N constant gives the extern decl a
 * complete array type so the spine's ARRAY_SIZE() at the reference
 * site keeps folding to the same constant it did before the carve.
 * flock_l_type_values / flock_l_whence_values /
 * f_owner_ex_type_values are private vocab pools referenced only by
 * their own fcntl field arrays and stay scoped to fcntl.c through this
 * extern surface.
 */
enum {
	FLOCK_L_TYPE_VALUES_N		= 3,
	FLOCK_L_WHENCE_VALUES_N		= 3,
	FLOCK_FIELDS_N			= 5,
	F_OWNER_EX_TYPE_VALUES_N	= 3,
	F_OWNER_EX_FIELDS_N		= 2,
	FILE_HANDLE_FIELDS_N		= 2,
};

extern const unsigned long flock_l_type_values[FLOCK_L_TYPE_VALUES_N];
extern const unsigned long flock_l_whence_values[FLOCK_L_WHENCE_VALUES_N];
extern const struct struct_field flock_fields[FLOCK_FIELDS_N];
extern const unsigned long f_owner_ex_type_values[F_OWNER_EX_TYPE_VALUES_N];
extern const struct struct_field f_owner_ex_fields[F_OWNER_EX_FIELDS_N];
extern const struct struct_field file_handle_fields[FILE_HANDLE_FIELDS_N];

/*
 * sched-shaped leaf tables defined in struct_catalog/sched.c.  Covers
 * struct sched_attr (sched_getattr) and struct clone_args (clone3).
 * Each _N constant gives the extern decl a complete array type so the
 * spine's ARRAY_SIZE() at the reference site keeps folding to the same
 * constant it did before the carve.
 */
enum {
	SCHED_ATTR_FIELDS_N	= 10,
	CLONE_ARGS_FIELDS_N	= 11,
};

extern const struct struct_field sched_attr_fields[SCHED_ATTR_FIELDS_N];
extern const struct struct_field clone_args_fields[CLONE_ARGS_FIELDS_N];

/*
 * mount leaf table defined in struct_catalog/mount.c: struct mount_attr
 * (mount_setattr / open_tree_attr).  The _N constant gives the extern
 * decl a complete array type so the spine's ARRAY_SIZE() at the
 * reference site keeps folding to the same constant it did before the
 * carve.
 */
enum {
	MOUNT_ATTR_FIELDS_N	= 4,
};

extern const struct struct_field mount_attr_fields[MOUNT_ATTR_FIELDS_N];

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
 * resource leaf table defined in struct_catalog/resource.c: struct
 * rlimit (getrlimit).  The _N constant gives the extern decl a complete
 * array type so the spine's ARRAY_SIZE() at the reference site keeps
 * folding to the same constant it did before the carve.  The table is
 * not config-gated -- the struct comes from headers trinity already
 * requires.
 */
enum {
	RLIMIT_FIELDS_N			= 2,
};

extern const struct struct_field rlimit_fields[RLIMIT_FIELDS_N];

/*
 * poll leaf table defined in struct_catalog/poll.c: struct epoll_event
 * (epoll_ctl).  The _N constant gives the extern decl a complete array
 * type so the spine's ARRAY_SIZE() at the reference site keeps folding
 * to the same constant it did before the carve.  The table is not
 * config-gated -- the struct comes from headers trinity already
 * requires.
 */
enum {
	EPOLL_EVENT_FIELDS_N	= 1,
};

extern const struct struct_field epoll_event_fields[EPOLL_EVENT_FIELDS_N];
