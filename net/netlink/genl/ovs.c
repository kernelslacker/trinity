/*
 * Genetlink family grammar: openvswitch, six families (ovs_datapath,
 * ovs_vport, ovs_flow, ovs_packet, ovs_meter, ovs_ct_limit), targeting
 * net/openvswitch/.  All six set hdrsize to sizeof(struct ovs_header),
 * which the generator emits before the attributes.
 */

#if __has_include(<linux/openvswitch.h>)

#include <linux/erspan.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>

#include "netlink-genl-families.h"
#include "utils.h"

#include "kernel/openvswitch.h"
/* struct ovs_header is a single int dp_ifindex; kernel-side family
 * registrations all set hdrsize = sizeof(struct ovs_header). */
#define OVS_FAM_HDRSIZE sizeof(struct ovs_header)

/* ---- ovs_datapath ---- */

/*
 * Datapath policy lives in net/openvswitch/datapath.c::datapath_policy.
 * NAME is an NLA_NUL_STRING (IFNAMSIZ - 1), so a byte at least, for the
 * terminator.  UPCALL_PID and USER_FEATURES are u32.  PER_CPU_PIDS is a
 * per-cpu array of u32 PIDs (cap at a small multiple to keep payloads
 * bounded).  STATS / MEGAFLOW_STATS are pure response payloads but we
 * list them so SET paths exercise the validator's "ignore on input"
 * branch.  MASKS_CACHE_SIZE is held to PCPU_MIN_UNIT_SIZE over the size of
 * a mask_cache_entry, 4096 with 4 KiB pages (more with larger ones), and
 * IFINDEX is an s32 of 0 or more, as is a vport's.
 */
static const struct nla_attr_spec ovs_dp_attrs[] = {
	{ OVS_DP_ATTR_NAME,		NLA_KIND_STRING, 15, 1 },
	{ OVS_DP_ATTR_UPCALL_PID,	NLA_KIND_U32,    4 },
	{ OVS_DP_ATTR_STATS,		NLA_KIND_BINARY, sizeof(struct ovs_dp_stats) },
	{ OVS_DP_ATTR_MEGAFLOW_STATS,	NLA_KIND_BINARY, sizeof(struct ovs_dp_megaflow_stats) },
	{ OVS_DP_ATTR_USER_FEATURES,	NLA_KIND_U32,    4 },
	{ OVS_DP_ATTR_MASKS_CACHE_SIZE,	NLA_KIND_U32_RANGE, 4096, 0 },
	{ OVS_DP_ATTR_PER_CPU_PIDS,	NLA_KIND_BINARY, 64 },
	{ OVS_DP_ATTR_IFINDEX,		NLA_KIND_U32_RANGE, INT32_MAX, 0 },
};

/*
 * What ovs_dp_cmd_new() and the ovs_dp_change() it calls read; it answers
 * -EINVAL to a request without NAME or UPCALL_PID.
 */
static const struct nla_attr_spec ovs_dp_new_attrs[] = {
	{ OVS_DP_ATTR_NAME,		NLA_KIND_STRING, 15, 1,
	  .required = true },
	{ OVS_DP_ATTR_UPCALL_PID,	NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_DP_ATTR_USER_FEATURES,	NLA_KIND_U32,    4 },
	{ OVS_DP_ATTR_MASKS_CACHE_SIZE,	NLA_KIND_U32_RANGE, 4096, 0 },
	{ OVS_DP_ATTR_PER_CPU_PIDS,	NLA_KIND_BINARY, 64 },
	{ OVS_DP_ATTR_IFINDEX,		NLA_KIND_U32_RANGE, INT32_MAX, 0 },
};

static const struct genl_cmd_grammar ovs_dp_cmds[] = {
	{ OVS_DP_CMD_NEW, "OVS_DP_CMD_NEW",
	  ovs_dp_new_attrs, ARRAY_SIZE(ovs_dp_new_attrs) },
	{ OVS_DP_CMD_DEL, "OVS_DP_CMD_DEL" },
	{ OVS_DP_CMD_GET, "OVS_DP_CMD_GET" },
	{ OVS_DP_CMD_SET, "OVS_DP_CMD_SET" },
};

struct genl_family_grammar fam_ovs_datapath = {
	.name = OVS_DATAPATH_FAMILY,
	.cmds = ovs_dp_cmds,
	.n_cmds = ARRAY_SIZE(ovs_dp_cmds),
	.attrs = ovs_dp_attrs,
	.n_attrs = ARRAY_SIZE(ovs_dp_attrs),
	.default_version = OVS_DATAPATH_VERSION,
	.hdrsize = OVS_FAM_HDRSIZE,
};

/* ---- ovs_vport ---- */

/*
 * The legacy tunnel options OPTIONS holds, a destination port and an
 * extension wrapping OVS_VXLAN_EXT_GBP, and the two u64 counters
 * UPCALL_STATS nests.  The nests have no policy of their own.
 */
static const struct nla_attr_spec ovs_vport_vxlan_ext_attrs[] = {
	{ OVS_VXLAN_EXT_GBP,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec ovs_vport_tunnel_attrs[] = {
	{ OVS_TUNNEL_ATTR_DST_PORT,	NLA_KIND_U16,    2 },
	{ OVS_TUNNEL_ATTR_EXTENSION,	NLA_KIND_NESTED, 0, 0,
	  ovs_vport_vxlan_ext_attrs, ARRAY_SIZE(ovs_vport_vxlan_ext_attrs) },
};

static const struct nla_attr_spec ovs_vport_upcall_attrs[] = {
	{ OVS_VPORT_UPCALL_ATTR_SUCCESS, NLA_KIND_U64,   8 },
	{ OVS_VPORT_UPCALL_ATTR_FAIL,	NLA_KIND_U64,    8 },
};

/*
 * vport_policy in net/openvswitch/datapath.c, which the ops share and
 * validate liberally.  TYPE is u32 OVS_VPORT_TYPE_* (NETDEV / INTERNAL /
 * GRE / VXLAN / GENEVE).  NAME is an NLA_NUL_STRING (IFNAMSIZ - 1), so a
 * byte at least, for the terminator.  STATS is a slot with a length, so
 * exactly struct ovs_vport_stats: any shorter payload is refused.
 * UPCALL_PID is an array of u32 PIDs, which the policy takes at any
 * length.  OPTIONS is a NESTED carrying tunnel-type specific attrs, which
 * ovs_vport_cmd_set() answers with -EOPNOTSUPP, as no vport type takes
 * them now.  UPCALL_STATS is a reply's nest of counters.  The ids of the
 * nests sit in tables of their own: at the top level they met PORT_NO,
 * where a u16 DST_PORT is too short for an NLA_U32.
 */
static const struct nla_attr_spec ovs_vport_attrs[] = {
	{ OVS_VPORT_ATTR_PORT_NO,		NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_TYPE,			NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_NAME,			NLA_KIND_STRING, 15, 1 },
	{ OVS_VPORT_ATTR_OPTIONS,		NLA_KIND_NESTED, 0, 0,
	  ovs_vport_tunnel_attrs, ARRAY_SIZE(ovs_vport_tunnel_attrs) },
	{ OVS_VPORT_ATTR_UPCALL_PID,		NLA_KIND_BINARY, 64 },
	{ OVS_VPORT_ATTR_STATS,			NLA_KIND_BINARY_FIXED2,
	  sizeof(struct ovs_vport_stats), sizeof(struct ovs_vport_stats) },
	{ OVS_VPORT_ATTR_IFINDEX,		NLA_KIND_U32_RANGE, INT32_MAX, 0 },
	{ OVS_VPORT_ATTR_NETNSID,		NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_UPCALL_STATS,		NLA_KIND_NESTED, 0, 0,
	  ovs_vport_upcall_attrs, ARRAY_SIZE(ovs_vport_upcall_attrs) },
};

/*
 * What ovs_vport_cmd_new() reads; it answers -EINVAL to a request without
 * NAME, TYPE or UPCALL_PID.  IFINDEX counts for an internal port alone.
 */
static const struct nla_attr_spec ovs_vport_new_attrs[] = {
	{ OVS_VPORT_ATTR_PORT_NO,		NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_TYPE,			NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_VPORT_ATTR_NAME,			NLA_KIND_STRING, 15, 1,
	  .required = true },
	{ OVS_VPORT_ATTR_UPCALL_PID,		NLA_KIND_BINARY, 64,
	  .required = true },
	{ OVS_VPORT_ATTR_IFINDEX,		NLA_KIND_U32_RANGE, INT32_MAX, 0 },
};

static const struct genl_cmd_grammar ovs_vport_cmds[] = {
	{ OVS_VPORT_CMD_NEW, "OVS_VPORT_CMD_NEW",
	  ovs_vport_new_attrs, ARRAY_SIZE(ovs_vport_new_attrs) },
	{ OVS_VPORT_CMD_DEL, "OVS_VPORT_CMD_DEL" },
	{ OVS_VPORT_CMD_GET, "OVS_VPORT_CMD_GET" },
	{ OVS_VPORT_CMD_SET, "OVS_VPORT_CMD_SET" },
};

struct genl_family_grammar fam_ovs_vport = {
	.name = OVS_VPORT_FAMILY,
	.cmds = ovs_vport_cmds,
	.n_cmds = ARRAY_SIZE(ovs_vport_cmds),
	.attrs = ovs_vport_attrs,
	.n_attrs = ARRAY_SIZE(ovs_vport_attrs),
	.default_version = OVS_VPORT_VERSION,
	.hdrsize = OVS_FAM_HDRSIZE,
};

/* ---- ovs_flow ---- */

/*
 * Each nest of a flow request is parsed in a namespace of its own by
 * net/openvswitch/flow_netlink.c: a key or a mask (ovs_key_lens), a tunnel
 * key (ovs_tunnel_key_lens), an NSH key, an action list (the action_lens
 * of __ovs_nla_copy_actions()) and the nests some actions open.  So each
 * has a table of its own, with each attribute exactly as long as its
 * namespace gives it, and the parsers refuse an id past the namespace's
 * last, any other length, and a key attribute twice.
 */
static const struct nla_attr_spec ovs_vxlan_ext_attrs[] = {
	{ OVS_VXLAN_EXT_GBP,			NLA_KIND_U32,    4 },
};

/*
 * ip_tun_from_nlattr() refuses a tunnel key without a destination address,
 * one of the two families', or without a TTL outside the IPv4 info bridge
 * mode, and more than one option block: a GENEVE block a multiple of 4
 * bytes, an ERSPAN one a struct erspan_metadata.
 */
static const struct nla_attr_spec ovs_tunnel_key_attrs[] = {
	{ OVS_TUNNEL_KEY_ATTR_ID,		NLA_KIND_U64,    8 },
	{ OVS_TUNNEL_KEY_ATTR_IPV4_SRC,		NLA_KIND_U32,    4 },
	{ OVS_TUNNEL_KEY_ATTR_IPV4_DST,		NLA_KIND_U32,    4 },
	{ OVS_TUNNEL_KEY_ATTR_TOS,		NLA_KIND_U8,     1 },
	{ OVS_TUNNEL_KEY_ATTR_TTL,		NLA_KIND_U8,     1,
	  .required = true },
	{ OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,	NLA_KIND_FLAG,   0 },
	{ OVS_TUNNEL_KEY_ATTR_CSUM,		NLA_KIND_FLAG,   0 },
	{ OVS_TUNNEL_KEY_ATTR_TP_SRC,		NLA_KIND_U16,    2 },
	{ OVS_TUNNEL_KEY_ATTR_TP_DST,		NLA_KIND_U16,    2 },
	{ OVS_TUNNEL_KEY_ATTR_OAM,		NLA_KIND_FLAG,   0 },
	{ OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,	NLA_KIND_BINARY_FIXED2, 16, 8 },
	{ OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS,	NLA_KIND_NESTED, 0, 0,
	  ovs_vxlan_ext_attrs, ARRAY_SIZE(ovs_vxlan_ext_attrs) },
	{ OVS_TUNNEL_KEY_ATTR_IPV6_SRC,		NLA_KIND_BINARY_FIXED2, 16, 16 },
	{ OVS_TUNNEL_KEY_ATTR_IPV6_DST,		NLA_KIND_BINARY_FIXED2, 16, 16 },
	{ OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS,	NLA_KIND_BINARY_FIXED2,
	  sizeof(struct erspan_metadata), sizeof(struct erspan_metadata) },
	{ OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE,	NLA_KIND_FLAG,   0 },
};

/* nsh_key_put_from_nlattr(): MD2, from 1 to NSH_CTX_HDRS_MAX_LEN (244)
 * bytes, is a push_nsh action's alone. */
static const struct nla_attr_spec ovs_nsh_key_attrs[] = {
	{ OVS_NSH_KEY_ATTR_BASE,		NLA_KIND_BINARY_FIXED2,
	  sizeof(struct ovs_nsh_key_base), sizeof(struct ovs_nsh_key_base) },
	{ OVS_NSH_KEY_ATTR_MD1,			NLA_KIND_BINARY_FIXED2,
	  sizeof(struct ovs_nsh_key_md1), sizeof(struct ovs_nsh_key_md1) },
	{ OVS_NSH_KEY_ATTR_MD2,			NLA_KIND_BINARY, 244, 1 },
};

#define OVS_FIXED(type, s) \
	{ type, NLA_KIND_BINARY_FIXED2, sizeof(struct s), sizeof(struct s) }

/*
 * ovs_key_lens, less PACKET_TYPE, ND_EXTENSIONS and TUNNEL_INFO, which
 * __parse_flow_nlattrs() refuses, and ENCAP, the key of a VLAN's payload in
 * the same namespace.  MPLS is one label or two of the three it holds.
 */
static const struct nla_attr_spec ovs_key_attrs[] = {
	{ OVS_KEY_ATTR_PRIORITY,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_IN_PORT,			NLA_KIND_U32,    4 },
	OVS_FIXED(OVS_KEY_ATTR_ETHERNET, ovs_key_ethernet),
	{ OVS_KEY_ATTR_VLAN,			NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_ETHERTYPE,		NLA_KIND_U16,    2 },
	OVS_FIXED(OVS_KEY_ATTR_IPV4, ovs_key_ipv4),
	OVS_FIXED(OVS_KEY_ATTR_IPV6, ovs_key_ipv6),
	OVS_FIXED(OVS_KEY_ATTR_TCP, ovs_key_tcp),
	OVS_FIXED(OVS_KEY_ATTR_UDP, ovs_key_udp),
	OVS_FIXED(OVS_KEY_ATTR_ICMP, ovs_key_icmp),
	OVS_FIXED(OVS_KEY_ATTR_ICMPV6, ovs_key_icmpv6),
	OVS_FIXED(OVS_KEY_ATTR_ARP, ovs_key_arp),
	OVS_FIXED(OVS_KEY_ATTR_ND, ovs_key_nd),
	{ OVS_KEY_ATTR_SKB_MARK,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_TUNNEL,			NLA_KIND_NESTED, 0, 0,
	  ovs_tunnel_key_attrs, ARRAY_SIZE(ovs_tunnel_key_attrs) },
	OVS_FIXED(OVS_KEY_ATTR_SCTP, ovs_key_sctp),
	{ OVS_KEY_ATTR_TCP_FLAGS,		NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_DP_HASH,			NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_RECIRC_ID,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_MPLS,			NLA_KIND_BINARY_FIXED2,
	  2 * sizeof(struct ovs_key_mpls), sizeof(struct ovs_key_mpls) },
	{ OVS_KEY_ATTR_CT_STATE,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_CT_ZONE,			NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_CT_MARK,			NLA_KIND_U32,    4 },
	OVS_FIXED(OVS_KEY_ATTR_CT_LABELS, ovs_key_ct_labels),
	OVS_FIXED(OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4, ovs_key_ct_tuple_ipv4),
	OVS_FIXED(OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6, ovs_key_ct_tuple_ipv6),
	{ OVS_KEY_ATTR_NSH,			NLA_KIND_NESTED, 0, 0,
	  ovs_nsh_key_attrs, ARRAY_SIZE(ovs_nsh_key_attrs) },
	OVS_FIXED(OVS_KEY_ATTR_IPV6_EXTHDRS, ovs_key_ipv6_exthdrs),
};

/*
 * The keys validate_set() lets a SET action write, one key to an action,
 * which it then holds to the flow's: an IPv4 key wants an IPv4 flow, and
 * so on.  MPLS is exactly one label.  A SET_MASKED key is the value and a
 * mask of the same length, and no tunnel.
 */
static const struct nla_attr_spec ovs_set_key_attrs[] = {
	{ OVS_KEY_ATTR_PRIORITY,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_SKB_MARK,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_CT_MARK,			NLA_KIND_U32,    4 },
	OVS_FIXED(OVS_KEY_ATTR_CT_LABELS, ovs_key_ct_labels),
	OVS_FIXED(OVS_KEY_ATTR_ETHERNET, ovs_key_ethernet),
	{ OVS_KEY_ATTR_TUNNEL,			NLA_KIND_NESTED, 0, 0,
	  ovs_tunnel_key_attrs, ARRAY_SIZE(ovs_tunnel_key_attrs) },
	OVS_FIXED(OVS_KEY_ATTR_IPV4, ovs_key_ipv4),
	OVS_FIXED(OVS_KEY_ATTR_IPV6, ovs_key_ipv6),
	OVS_FIXED(OVS_KEY_ATTR_TCP, ovs_key_tcp),
	OVS_FIXED(OVS_KEY_ATTR_UDP, ovs_key_udp),
	OVS_FIXED(OVS_KEY_ATTR_MPLS, ovs_key_mpls),
	OVS_FIXED(OVS_KEY_ATTR_SCTP, ovs_key_sctp),
};

#define OVS_MASKED(type, s) \
	{ type, NLA_KIND_BINARY_FIXED2, 2 * sizeof(s), 2 * sizeof(s) }

static const struct nla_attr_spec ovs_set_masked_key_attrs[] = {
	OVS_MASKED(OVS_KEY_ATTR_PRIORITY, uint32_t),
	OVS_MASKED(OVS_KEY_ATTR_SKB_MARK, uint32_t),
	OVS_MASKED(OVS_KEY_ATTR_CT_MARK, uint32_t),
	OVS_MASKED(OVS_KEY_ATTR_CT_LABELS, struct ovs_key_ct_labels),
	OVS_MASKED(OVS_KEY_ATTR_ETHERNET, struct ovs_key_ethernet),
	OVS_MASKED(OVS_KEY_ATTR_IPV4, struct ovs_key_ipv4),
	OVS_MASKED(OVS_KEY_ATTR_IPV6, struct ovs_key_ipv6),
	OVS_MASKED(OVS_KEY_ATTR_TCP, struct ovs_key_tcp),
	OVS_MASKED(OVS_KEY_ATTR_UDP, struct ovs_key_udp),
	OVS_MASKED(OVS_KEY_ATTR_MPLS, struct ovs_key_mpls),
	OVS_MASKED(OVS_KEY_ATTR_SCTP, struct ovs_key_sctp),
};

/*
 * The nests the actions open.  validate_userspace() parses USERSPACE
 * strictly and wants a PID that is not 0.  A SAMPLE wants a PROBABILITY
 * and its ACTIONS, a CHECK_PKT_LEN a PKT_LEN that is not 0 and both
 * branches, a DEC_TTL its ACTION and a PSAMPLE its GROUP.  The CT nest
 * (ovs_ct_attr_lens in conntrack.c) takes the name of a conntrack helper,
 * a module request away when it is not loaded, and of a timeout policy,
 * which the cttimeout grammar names "trinity"; its NAT nest a range of
 * IPv4 or IPv6 addresses and ports.
 */
static const struct nla_attr_spec ovs_userspace_attrs[] = {
	{ OVS_USERSPACE_ATTR_PID,		NLA_KIND_U32_RANGE, UINT32_MAX, 1,
	  .required = true },
	{ OVS_USERSPACE_ATTR_USERDATA,		NLA_KIND_BINARY, 32 },
	{ OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,	NLA_KIND_U32,    4 },
	{ OVS_USERSPACE_ATTR_ACTIONS,		NLA_KIND_FLAG,   0 },
};

static const struct nla_attr_spec ovs_nat_attrs[] = {
	{ OVS_NAT_ATTR_SRC,			NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_DST,			NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_IP_MIN,			NLA_KIND_BINARY_FIXED2, 16, 4 },
	{ OVS_NAT_ATTR_IP_MAX,			NLA_KIND_BINARY_FIXED2, 16, 4 },
	{ OVS_NAT_ATTR_PROTO_MIN,		NLA_KIND_U16,    2 },
	{ OVS_NAT_ATTR_PROTO_MAX,		NLA_KIND_U16,    2 },
	{ OVS_NAT_ATTR_PERSISTENT,		NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_PROTO_HASH,		NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_PROTO_RANDOM,		NLA_KIND_FLAG,   0 },
};

static const char *const ovs_ct_helpers[] = {
	"amanda", "ftp", "H.245", "irc", "netbios-ns", "pptp", "Q.931",
	"RAS", "sane", "sip", "snmp", "tftp",
};

static const struct nla_attr_spec ovs_ct_attrs[] = {
	{ OVS_CT_ATTR_COMMIT,			NLA_KIND_FLAG,   0 },
	{ OVS_CT_ATTR_ZONE,			NLA_KIND_U16,    2 },
	{ OVS_CT_ATTR_MARK,			NLA_KIND_BINARY_FIXED2, 8, 8 },
	{ OVS_CT_ATTR_LABELS,			NLA_KIND_BINARY_FIXED2,
	  2 * OVS_CT_LABELS_LEN, 2 * OVS_CT_LABELS_LEN },
	{ OVS_CT_ATTR_HELPER,			NLA_KIND_STRING_ONEOF, 0, 0,
	  .words = ovs_ct_helpers, .n_words = ARRAY_SIZE(ovs_ct_helpers) },
	{ OVS_CT_ATTR_NAT,			NLA_KIND_NESTED, 0, 0,
	  ovs_nat_attrs, ARRAY_SIZE(ovs_nat_attrs) },
	{ OVS_CT_ATTR_FORCE_COMMIT,		NLA_KIND_FLAG,   0 },
	{ OVS_CT_ATTR_EVENTMASK,		NLA_KIND_U32,    4 },
	{ OVS_CT_ATTR_TIMEOUT,			NLA_KIND_STRING_WORD, 0, 0,
	  .word = "trinity" },
};

static const struct nla_attr_spec ovs_psample_attrs[] = {
	{ OVS_PSAMPLE_ATTR_GROUP,		NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_PSAMPLE_ATTR_COOKIE,		NLA_KIND_BINARY,
	  OVS_PSAMPLE_COOKIE_MAX_SIZE },
};

/*
 * The actions, by action_lens.  OUTPUT names a port below DP_MAX_PORTS,
 * USHRT_MAX, and TRUNC keeps ETH_HLEN bytes at least; SET and SET_MASKED
 * hold one key apiece.  The lists nested in an action draw from the leaf
 * actions, those that nest no list, which ends the recursion the kernel
 * bounds at SAMPLE_ACTION_DEPTH.
 */
#define OVS_LEAF_ACTIONS \
	{ OVS_ACTION_ATTR_OUTPUT,		NLA_KIND_U32_RANGE, 65534, 0 }, \
	{ OVS_ACTION_ATTR_USERSPACE,		NLA_KIND_NESTED, 0, 0, \
	  ovs_userspace_attrs, ARRAY_SIZE(ovs_userspace_attrs) }, \
	{ OVS_ACTION_ATTR_SET,			NLA_KIND_NESTED, 1, 0, \
	  ovs_set_key_attrs, ARRAY_SIZE(ovs_set_key_attrs) }, \
	OVS_FIXED(OVS_ACTION_ATTR_PUSH_VLAN, ovs_action_push_vlan), \
	{ OVS_ACTION_ATTR_POP_VLAN,		NLA_KIND_FLAG,   0 }, \
	{ OVS_ACTION_ATTR_RECIRC,		NLA_KIND_U32,    4 }, \
	OVS_FIXED(OVS_ACTION_ATTR_HASH, ovs_action_hash), \
	OVS_FIXED(OVS_ACTION_ATTR_PUSH_MPLS, ovs_action_push_mpls), \
	{ OVS_ACTION_ATTR_POP_MPLS,		NLA_KIND_U16,    2 }, \
	{ OVS_ACTION_ATTR_SET_MASKED,		NLA_KIND_NESTED, 1, 0, \
	  ovs_set_masked_key_attrs, ARRAY_SIZE(ovs_set_masked_key_attrs) }, \
	{ OVS_ACTION_ATTR_CT,			NLA_KIND_NESTED, 0, 0, \
	  ovs_ct_attrs, ARRAY_SIZE(ovs_ct_attrs) }, \
	{ OVS_ACTION_ATTR_TRUNC,		NLA_KIND_U32_RANGE, UINT32_MAX, 14 }, \
	OVS_FIXED(OVS_ACTION_ATTR_PUSH_ETH, ovs_action_push_eth), \
	{ OVS_ACTION_ATTR_POP_ETH,		NLA_KIND_FLAG,   0 }, \
	{ OVS_ACTION_ATTR_CT_CLEAR,		NLA_KIND_FLAG,   0 }, \
	{ OVS_ACTION_ATTR_PUSH_NSH,		NLA_KIND_NESTED, 0, 0, \
	  ovs_nsh_key_attrs, ARRAY_SIZE(ovs_nsh_key_attrs) }, \
	{ OVS_ACTION_ATTR_POP_NSH,		NLA_KIND_FLAG,   0 }, \
	{ OVS_ACTION_ATTR_METER,		NLA_KIND_U32,    4 }, \
	OVS_FIXED(OVS_ACTION_ATTR_ADD_MPLS, ovs_action_add_mpls), \
	{ OVS_ACTION_ATTR_DROP,			NLA_KIND_U32,    4 }, \
	{ OVS_ACTION_ATTR_PSAMPLE,		NLA_KIND_NESTED, 0, 0, \
	  ovs_psample_attrs, ARRAY_SIZE(ovs_psample_attrs) }

static const struct nla_attr_spec ovs_leaf_action_attrs[] = {
	OVS_LEAF_ACTIONS,
};

static const struct nla_attr_spec ovs_sample_attrs[] = {
	{ OVS_SAMPLE_ATTR_PROBABILITY,		NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_SAMPLE_ATTR_ACTIONS,		NLA_KIND_NESTED, 0, 0,
	  ovs_leaf_action_attrs, ARRAY_SIZE(ovs_leaf_action_attrs),
	  .required = true },
};

static const struct nla_attr_spec ovs_check_pkt_len_attrs[] = {
	{ OVS_CHECK_PKT_LEN_ATTR_PKT_LEN,	NLA_KIND_U16,    2,
	  .required = true },
	{ OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER, NLA_KIND_NESTED, 0, 0,
	  ovs_leaf_action_attrs, ARRAY_SIZE(ovs_leaf_action_attrs),
	  .required = true },
	{ OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL, NLA_KIND_NESTED, 0, 0,
	  ovs_leaf_action_attrs, ARRAY_SIZE(ovs_leaf_action_attrs),
	  .required = true },
};

static const struct nla_attr_spec ovs_dec_ttl_attrs[] = {
	{ OVS_DEC_TTL_ATTR_ACTION,		NLA_KIND_NESTED, 0, 0,
	  ovs_leaf_action_attrs, ARRAY_SIZE(ovs_leaf_action_attrs) },
};

static const struct nla_attr_spec ovs_action_attrs[] = {
	OVS_LEAF_ACTIONS,
	{ OVS_ACTION_ATTR_SAMPLE,		NLA_KIND_NESTED, 0, 0,
	  ovs_sample_attrs, ARRAY_SIZE(ovs_sample_attrs) },
	{ OVS_ACTION_ATTR_CLONE,		NLA_KIND_NESTED, 0, 0,
	  ovs_leaf_action_attrs, ARRAY_SIZE(ovs_leaf_action_attrs) },
	{ OVS_ACTION_ATTR_CHECK_PKT_LEN,	NLA_KIND_NESTED, 0, 0,
	  ovs_check_pkt_len_attrs, ARRAY_SIZE(ovs_check_pkt_len_attrs) },
	{ OVS_ACTION_ATTR_DEC_TTL,		NLA_KIND_NESTED, 0, 0,
	  ovs_dec_ttl_attrs, ARRAY_SIZE(ovs_dec_ttl_attrs) },
};

/*
 * flow_policy, which the ops validate liberally.  NEW answers -EINVAL
 * without a KEY or ACTIONS; SET, GET and DEL find a flow by its KEY or its
 * UFID, which a mark cannot say, and a DEL with neither flushes the table.
 * A UFID is 1 to MAX_UFID_LENGTH, 16, bytes.  The dumpit reads UFID_FLAGS
 * alone.  STATS, TCP_FLAGS and USED are only replies'.
 */
#define OVS_FLOW_KEY_SPEC(...) \
	{ OVS_FLOW_ATTR_KEY,		NLA_KIND_NESTED, 0, 0, \
	  ovs_key_attrs, ARRAY_SIZE(ovs_key_attrs), ##__VA_ARGS__ }
#define OVS_FLOW_MASK_SPEC \
	{ OVS_FLOW_ATTR_MASK,		NLA_KIND_NESTED, 0, 0, \
	  ovs_key_attrs, ARRAY_SIZE(ovs_key_attrs) }
#define OVS_FLOW_ACTIONS_SPEC(...) \
	{ OVS_FLOW_ATTR_ACTIONS,	NLA_KIND_NESTED, 0, 0, \
	  ovs_action_attrs, ARRAY_SIZE(ovs_action_attrs), ##__VA_ARGS__ }
#define OVS_FLOW_ID_SPECS \
	{ OVS_FLOW_ATTR_PROBE,		NLA_KIND_FLAG,   0 }, \
	{ OVS_FLOW_ATTR_UFID,		NLA_KIND_BINARY, 16, 1 }, \
	{ OVS_FLOW_ATTR_UFID_FLAGS,	NLA_KIND_U32,    4 }

static const struct nla_attr_spec ovs_flow_new_attrs[] = {
	OVS_FLOW_KEY_SPEC(.required = true),
	OVS_FLOW_MASK_SPEC,
	OVS_FLOW_ACTIONS_SPEC(.required = true),
	OVS_FLOW_ID_SPECS,
};

static const struct nla_attr_spec ovs_flow_set_attrs[] = {
	OVS_FLOW_KEY_SPEC(),
	OVS_FLOW_MASK_SPEC,
	OVS_FLOW_ACTIONS_SPEC(),
	{ OVS_FLOW_ATTR_CLEAR,		NLA_KIND_FLAG,   0 },
	OVS_FLOW_ID_SPECS,
};

static const struct nla_attr_spec ovs_flow_get_attrs[] = {
	OVS_FLOW_KEY_SPEC(),
	OVS_FLOW_ID_SPECS,
};

static const struct nla_attr_spec ovs_flow_dump_attrs[] = {
	{ OVS_FLOW_ATTR_UFID_FLAGS,	NLA_KIND_U32,    4 },
};

static const struct genl_cmd_grammar ovs_flow_cmds[] = {
	{ OVS_FLOW_CMD_NEW, "OVS_FLOW_CMD_NEW",
	  ovs_flow_new_attrs, ARRAY_SIZE(ovs_flow_new_attrs) },
	{ OVS_FLOW_CMD_DEL, "OVS_FLOW_CMD_DEL",
	  ovs_flow_get_attrs, ARRAY_SIZE(ovs_flow_get_attrs) },
	{ OVS_FLOW_CMD_GET, "OVS_FLOW_CMD_GET",
	  ovs_flow_get_attrs, ARRAY_SIZE(ovs_flow_get_attrs),
	  ovs_flow_dump_attrs, ARRAY_SIZE(ovs_flow_dump_attrs) },
	{ OVS_FLOW_CMD_SET, "OVS_FLOW_CMD_SET",
	  ovs_flow_set_attrs, ARRAY_SIZE(ovs_flow_set_attrs) },
};

struct genl_family_grammar fam_ovs_flow = {
	.name = OVS_FLOW_FAMILY,
	.cmds = ovs_flow_cmds,
	.n_cmds = ARRAY_SIZE(ovs_flow_cmds),
	.default_version = OVS_FLOW_VERSION,
	.hdrsize = OVS_FAM_HDRSIZE,
};

/* ---- ovs_packet ---- */

static const struct genl_cmd_grammar ovs_packet_cmds[] = {
	{ OVS_PACKET_CMD_EXECUTE, "OVS_PACKET_CMD_EXECUTE" },
};

/*
 * Packet inject path.  Userspace sends OVS_PACKET_CMD_EXECUTE with a
 * packet blob, the flow key the kernel should treat the packet as
 * having, and an action list to execute.  KEY and ACTIONS reuse the
 * OVS_KEY_ATTR_* / OVS_ACTION_ATTR_* sub-namespaces — the same
 * machinery the flow family parses, but reached via a separate per-cmd
 * policy in net/openvswitch/datapath.c::packet_policy.  Listing only
 * the outer OVS_PACKET_ATTR_* here keeps this table small: KEY and
 * ACTIONS are bare NLA_NESTED in packet_policy, and the generator
 * fills them with children drawn from this table, not with
 * OVS_KEY_ATTR_* / OVS_ACTION_ATTR_* ones.
 */
static const struct nla_attr_spec ovs_packet_attrs[] = {
	{ OVS_PACKET_ATTR_PACKET,		NLA_KIND_BINARY, 256 },
	{ OVS_PACKET_ATTR_KEY,			NLA_KIND_NESTED, 0 },
	{ OVS_PACKET_ATTR_ACTIONS,		NLA_KIND_NESTED, 0 },
	{ OVS_PACKET_ATTR_USERDATA,		NLA_KIND_BINARY, 32 },
	{ OVS_PACKET_ATTR_EGRESS_TUN_KEY,	NLA_KIND_NESTED, 0 },
	{ OVS_PACKET_ATTR_PROBE,		NLA_KIND_FLAG,   0 },
	{ OVS_PACKET_ATTR_MRU,			NLA_KIND_U16,    2 },
	{ OVS_PACKET_ATTR_LEN,			NLA_KIND_U32,    4 },
	{ OVS_PACKET_ATTR_HASH,			NLA_KIND_U64,    8 },
	{ OVS_PACKET_ATTR_UPCALL_PID,		NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_ovs_packet = {
	.name = OVS_PACKET_FAMILY,
	.cmds = ovs_packet_cmds,
	.n_cmds = ARRAY_SIZE(ovs_packet_cmds),
	.attrs = ovs_packet_attrs,
	.n_attrs = ARRAY_SIZE(ovs_packet_attrs),
	.default_version = OVS_PACKET_VERSION,
	.hdrsize = OVS_FAM_HDRSIZE,
};

/* ---- ovs_meter ---- */

/*
 * band_policy in net/openvswitch/meter.c, the policy of one band.  STATS is
 * a slot with a length and no type, so exactly struct ovs_flow_stats: a
 * shorter payload is refused.  dp_meter_create() answers -EINVAL to a band
 * without TYPE, RATE or BURST.
 */
static const struct nla_attr_spec ovs_meter_band_attrs[] = {
	{ OVS_BAND_ATTR_TYPE,		NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_BAND_ATTR_RATE,		NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_BAND_ATTR_BURST,		NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_BAND_ATTR_STATS,		NLA_KIND_BINARY_FIXED2,
	  sizeof(struct ovs_flow_stats), sizeof(struct ovs_flow_stats) },
};

/*
 * Meter policy lives in net/openvswitch/meter.c::meter_policy.  ID is the
 * per-datapath meter slot.  KBPS is a flag switching units between
 * packets/sec and kbits/sec.  BANDS is a nest of band nests, each a
 * band_policy stream under any attribute type, which dp_meter_create()
 * walks and counts against DP_MAX_BANDS, which is 1, so it refuses a second
 * element: the array is capped there.  The band attributes sit in the table
 * of the nest: on the top level they met KBPS, a flag, and STATS, which
 * wants 16 bytes.
 */
static const struct nla_attr_spec ovs_meter_attrs[] = {
	{ OVS_METER_ATTR_ID,		NLA_KIND_U32,    4 },
	{ OVS_METER_ATTR_KBPS,		NLA_KIND_FLAG,   0 },
	{ OVS_METER_ATTR_STATS,		NLA_KIND_BINARY_FIXED2,
	  sizeof(struct ovs_flow_stats), sizeof(struct ovs_flow_stats) },
	{ OVS_METER_ATTR_BANDS,		NLA_KIND_NESTED_ARRAY, 1, 0,
	  ovs_meter_band_attrs, ARRAY_SIZE(ovs_meter_band_attrs) },
	{ OVS_METER_ATTR_USED,		NLA_KIND_U64,    8 },
	{ OVS_METER_ATTR_CLEAR,		NLA_KIND_FLAG,   0 },
	{ OVS_METER_ATTR_MAX_METERS,	NLA_KIND_U32,    4 },
	{ OVS_METER_ATTR_MAX_BANDS,	NLA_KIND_U32,    4 },
};

/*
 * What ovs_meter_cmd_set() and the dp_meter_create() it calls read; they
 * answer -EINVAL to a request without ID or BANDS.  GET and DEL read ID
 * alone.
 */
static const struct nla_attr_spec ovs_meter_set_attrs[] = {
	{ OVS_METER_ATTR_ID,		NLA_KIND_U32,    4,
	  .required = true },
	{ OVS_METER_ATTR_KBPS,		NLA_KIND_FLAG,   0 },
	{ OVS_METER_ATTR_STATS,		NLA_KIND_BINARY_FIXED2,
	  sizeof(struct ovs_flow_stats), sizeof(struct ovs_flow_stats) },
	{ OVS_METER_ATTR_BANDS,		NLA_KIND_NESTED_ARRAY, 1, 0,
	  ovs_meter_band_attrs, ARRAY_SIZE(ovs_meter_band_attrs),
	  .required = true },
	{ OVS_METER_ATTR_CLEAR,		NLA_KIND_FLAG,   0 },
};

static const struct nla_attr_spec ovs_meter_id_attrs[] = {
	{ OVS_METER_ATTR_ID,		NLA_KIND_U32,    4 },
};

static const struct genl_cmd_grammar ovs_meter_cmds[] = {
	{ OVS_METER_CMD_FEATURES, "OVS_METER_CMD_FEATURES" },
	{ OVS_METER_CMD_SET,	  "OVS_METER_CMD_SET",
	  ovs_meter_set_attrs, ARRAY_SIZE(ovs_meter_set_attrs) },
	{ OVS_METER_CMD_DEL,	  "OVS_METER_CMD_DEL",
	  ovs_meter_id_attrs, ARRAY_SIZE(ovs_meter_id_attrs) },
	{ OVS_METER_CMD_GET,	  "OVS_METER_CMD_GET",
	  ovs_meter_id_attrs, ARRAY_SIZE(ovs_meter_id_attrs) },
};

struct genl_family_grammar fam_ovs_meter = {
	.name = OVS_METER_FAMILY,
	.cmds = ovs_meter_cmds,
	.n_cmds = ARRAY_SIZE(ovs_meter_cmds),
	.attrs = ovs_meter_attrs,
	.n_attrs = ARRAY_SIZE(ovs_meter_attrs),
	.default_version = OVS_METER_VERSION,
	.hdrsize = OVS_FAM_HDRSIZE,
};

/* ---- ovs_ct_limit ---- */

static const struct genl_cmd_grammar ovs_ct_limit_cmds[] = {
	{ OVS_CT_LIMIT_CMD_SET, "OVS_CT_LIMIT_CMD_SET" },
	{ OVS_CT_LIMIT_CMD_DEL, "OVS_CT_LIMIT_CMD_DEL" },
	{ OVS_CT_LIMIT_CMD_GET, "OVS_CT_LIMIT_CMD_GET" },
};

/*
 * Conntrack zone limits.  Single outer attr OVS_CT_LIMIT_ATTR_ZONE_LIMIT
 * carries an array of struct ovs_zone_limit (12 bytes each: zone_id +
 * limit + count).  The kernel-side parser in net/openvswitch/conntrack.c
 * walks the payload as a packed array, so a binary payload sized to a
 * small multiple of the struct size is what we want to emit.  The policy
 * types ZONE_LIMIT a nest, which takes no bytes or NLA_HDRLEN at least,
 * so a payload of one to three bytes is refused.
 */
static const struct nla_attr_spec ovs_ct_limit_attrs[] = {
	{ OVS_CT_LIMIT_ATTR_ZONE_LIMIT,	NLA_KIND_BINARY, sizeof(struct ovs_zone_limit) * 4, NLA_HDRLEN },
};

struct genl_family_grammar fam_ovs_ct_limit = {
	.name = OVS_CT_LIMIT_FAMILY,
	.cmds = ovs_ct_limit_cmds,
	.n_cmds = ARRAY_SIZE(ovs_ct_limit_cmds),
	.attrs = ovs_ct_limit_attrs,
	.n_attrs = ARRAY_SIZE(ovs_ct_limit_attrs),
	.default_version = OVS_CT_LIMIT_VERSION,
	.hdrsize = OVS_FAM_HDRSIZE,
};

#endif /* __has_include(<linux/openvswitch.h>) */
