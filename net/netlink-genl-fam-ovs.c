/*
 * Genetlink family grammar: openvswitch (six families).
 *
 * The kernel openvswitch datapath exposes its userspace control plane
 * across six generic-netlink families ("ovs_datapath", "ovs_vport",
 * "ovs_flow", "ovs_packet", "ovs_meter", "ovs_ct_limit").  All six
 * share a 4-byte fixed family header (struct ovs_header — a single
 * dp_ifindex slot) that the kernel consumes via family->hdrsize before
 * walking attributes; the message generator emits that prefix when the
 * family grammar declares hdrsize so the per-cmd nla_policy parsers see
 * TLVs at the offset they expect.
 *
 * The flow family's parser is the densest hand-written nla_validate in
 * the kernel: net/openvswitch/flow_netlink.c::ovs_nla_get_match recursively
 * walks OVS_KEY_ATTR_* (~30 packet-header types, several with nested
 * sub-namespaces of their own — OVS_TUNNEL_KEY_ATTR_*, OVS_NSH_KEY_ATTR_*,
 * OVS_VXLAN_EXT_*) and ovs_nla_get_flow_actions walks OVS_ACTION_ATTR_*
 * (~25 action types, each with its own optional sub-namespace —
 * OVS_USERSPACE_ATTR_*, OVS_SAMPLE_ATTR_*, OVS_CT_ATTR_* / OVS_NAT_ATTR_*,
 * OVS_CHECK_PKT_LEN_ATTR_*, OVS_DEC_TTL_ATTR_*, OVS_PSAMPLE_ATTR_*).
 * Random nlmsg_type IDs essentially never matched ovs_flow's runtime-
 * assigned family_id, so this validator has been routinely cold under
 * generic netlink fuzzing; controller-resolved family_ids change that.
 *
 * Per the wireguard / tipc model, each family's flat nla_attr_spec table
 * lists every attribute id used by any nest reachable from that family's
 * commands, with collisions across nested namespaces left intentional
 * (the kernel only validates each child against the policy of whichever
 * nest is currently being walked, so id 1 meaning OVS_FLOW_ATTR_KEY at
 * the outer level and OVS_KEY_ATTR_ENCAP one nest deeper is fine).
 *
 * Header gating mirrors mptcp_pm: <linux/openvswitch.h> ships in the
 * upstream UAPI tree; build hosts whose sysroot lacks it silently drop
 * all six families from the registry instead of failing the build.
 */

#if __has_include(<linux/openvswitch.h>)

#include <linux/openvswitch.h>

#include "netlink-genl-families.h"
#include "utils.h"

/* struct ovs_header is a single int dp_ifindex; kernel-side family
 * registrations all set hdrsize = sizeof(struct ovs_header). */
#define OVS_FAM_HDRSIZE sizeof(struct ovs_header)

/* ---- ovs_datapath ---- */

static const struct genl_cmd_grammar ovs_dp_cmds[] = {
	{ OVS_DP_CMD_NEW, "OVS_DP_CMD_NEW" },
	{ OVS_DP_CMD_DEL, "OVS_DP_CMD_DEL" },
	{ OVS_DP_CMD_GET, "OVS_DP_CMD_GET" },
	{ OVS_DP_CMD_SET, "OVS_DP_CMD_SET" },
};

/*
 * Datapath policy lives in net/openvswitch/datapath.c::datapath_policy.
 * NAME is a NUL-terminated string (IFNAMSIZ - 1).  UPCALL_PID and
 * USER_FEATURES are u32.  PER_CPU_PIDS is a per-cpu array of u32 PIDs
 * (cap at a small multiple to keep payloads bounded).  STATS /
 * MEGAFLOW_STATS are pure response payloads but we list them so SET
 * paths exercise the validator's "ignore on input" branch.
 */
static const struct nla_attr_spec ovs_dp_attrs[] = {
	{ OVS_DP_ATTR_NAME,		NLA_KIND_STRING, 15 },
	{ OVS_DP_ATTR_UPCALL_PID,	NLA_KIND_U32,    4 },
	{ OVS_DP_ATTR_STATS,		NLA_KIND_BINARY, sizeof(struct ovs_dp_stats) },
	{ OVS_DP_ATTR_MEGAFLOW_STATS,	NLA_KIND_BINARY, sizeof(struct ovs_dp_megaflow_stats) },
	{ OVS_DP_ATTR_USER_FEATURES,	NLA_KIND_U32,    4 },
	{ OVS_DP_ATTR_MASKS_CACHE_SIZE,	NLA_KIND_U32,    4 },
	{ OVS_DP_ATTR_PER_CPU_PIDS,	NLA_KIND_BINARY, 64 },
	{ OVS_DP_ATTR_IFINDEX,		NLA_KIND_U32,    4 },
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

static const struct genl_cmd_grammar ovs_vport_cmds[] = {
	{ OVS_VPORT_CMD_NEW, "OVS_VPORT_CMD_NEW" },
	{ OVS_VPORT_CMD_DEL, "OVS_VPORT_CMD_DEL" },
	{ OVS_VPORT_CMD_GET, "OVS_VPORT_CMD_GET" },
	{ OVS_VPORT_CMD_SET, "OVS_VPORT_CMD_SET" },
};

/*
 * Vport policy lives in net/openvswitch/vport-netdev.c et al via
 * vport_policy[].  TYPE is u32 OVS_VPORT_TYPE_* (NETDEV / INTERNAL /
 * GRE / VXLAN / GENEVE).  OPTIONS is a NESTED carrying tunnel-type
 * specific attrs — for VXLAN that's OVS_TUNNEL_ATTR_DST_PORT plus
 * OVS_TUNNEL_ATTR_EXTENSION wrapping OVS_VXLAN_EXT_GBP.  UPCALL_PID is
 * an array of u32 PIDs, STATS is struct ovs_vport_stats, UPCALL_STATS
 * is a NESTED of OVS_VPORT_UPCALL_ATTR_* u64 counters.
 */
static const struct nla_attr_spec ovs_vport_attrs[] = {
	{ OVS_VPORT_ATTR_PORT_NO,		NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_TYPE,			NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_NAME,			NLA_KIND_STRING, 15 },
	{ OVS_VPORT_ATTR_OPTIONS,		NLA_KIND_NESTED, 0 },
	{ OVS_VPORT_ATTR_UPCALL_PID,		NLA_KIND_BINARY, 64 },
	{ OVS_VPORT_ATTR_STATS,			NLA_KIND_BINARY, sizeof(struct ovs_vport_stats) },
	{ OVS_VPORT_ATTR_IFINDEX,		NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_NETNSID,		NLA_KIND_U32,    4 },
	{ OVS_VPORT_ATTR_UPCALL_STATS,		NLA_KIND_NESTED, 0 },

	/* OVS_TUNNEL_ATTR_* — nested under OVS_VPORT_ATTR_OPTIONS for
	 * tunnel-typed vports (VXLAN / GENEVE / GRE). */
	{ OVS_TUNNEL_ATTR_DST_PORT,		NLA_KIND_U16,    2 },
	{ OVS_TUNNEL_ATTR_EXTENSION,		NLA_KIND_NESTED, 0 },

	/* OVS_VXLAN_EXT_* — nested under OVS_TUNNEL_ATTR_EXTENSION for
	 * VXLAN vports. */
	{ OVS_VXLAN_EXT_GBP,			NLA_KIND_U32,    4 },

	/* OVS_VPORT_UPCALL_ATTR_* — nested under OVS_VPORT_ATTR_UPCALL_STATS. */
	{ OVS_VPORT_UPCALL_ATTR_SUCCESS,	NLA_KIND_U64,    8 },
	{ OVS_VPORT_UPCALL_ATTR_FAIL,		NLA_KIND_U64,    8 },
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

static const struct genl_cmd_grammar ovs_flow_cmds[] = {
	{ OVS_FLOW_CMD_NEW, "OVS_FLOW_CMD_NEW" },
	{ OVS_FLOW_CMD_DEL, "OVS_FLOW_CMD_DEL" },
	{ OVS_FLOW_CMD_GET, "OVS_FLOW_CMD_GET" },
	{ OVS_FLOW_CMD_SET, "OVS_FLOW_CMD_SET" },
};

/*
 * Flow grammar.  This is the high-value target: ovs_nla_get_match walks
 * OVS_KEY_ATTR_* recursively (with OVS_KEY_ATTR_TUNNEL nesting
 * OVS_TUNNEL_KEY_ATTR_*, OVS_KEY_ATTR_NSH nesting OVS_NSH_KEY_ATTR_*,
 * OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS nesting OVS_VXLAN_EXT_*) and
 * ovs_nla_get_flow_actions walks OVS_ACTION_ATTR_* (with USERSPACE /
 * SAMPLE / CT (-> NAT) / CHECK_PKT_LEN / DEC_TTL / PSAMPLE / PUSH_NSH
 * each opening a sub-namespace, plus SET / SET_MASKED nesting one
 * OVS_KEY_ATTR_*).  Listing every id used by any of these nests in a
 * single flat table — the wireguard / tipc model — gives the spec
 * emitter a wide pool to draw plausible nested children from; the
 * kernel only validates each child against the policy of the currently-
 * walked nest, so id collisions across namespaces (OVS_FLOW_ATTR_KEY=1
 * vs OVS_KEY_ATTR_ENCAP=1 vs OVS_ACTION_ATTR_OUTPUT=1) are harmless.
 *
 * Binary sizes match the corresponding upstream payload structs exactly
 * so the per-cmd policy's NLA_POLICY_EXACT_LEN checks in flow_netlink.c
 * accept them: ovs_key_ethernet (12), ovs_key_ipv4 (12), ovs_key_ipv6
 * (40), ovs_key_arp (24), ovs_key_nd (28), ovs_key_ct_tuple_ipv4 (13),
 * ovs_key_ct_tuple_ipv6 (37), ovs_action_push_vlan (4),
 * ovs_action_push_mpls (6), ovs_action_add_mpls (8), ovs_action_hash
 * (8), ovs_action_trunc (4), ovs_action_push_eth (12), ovs_nsh_key_base
 * (8), ovs_nsh_key_md1 (16).
 */
static const struct nla_attr_spec ovs_flow_attrs[] = {
	/* OVS_FLOW_ATTR_* — outer */
	{ OVS_FLOW_ATTR_KEY,			NLA_KIND_NESTED, 0 },
	{ OVS_FLOW_ATTR_ACTIONS,		NLA_KIND_NESTED, 0 },
	{ OVS_FLOW_ATTR_STATS,			NLA_KIND_BINARY, sizeof(struct ovs_flow_stats) },
	{ OVS_FLOW_ATTR_TCP_FLAGS,		NLA_KIND_U8,     1 },
	{ OVS_FLOW_ATTR_USED,			NLA_KIND_U64,    8 },
	{ OVS_FLOW_ATTR_CLEAR,			NLA_KIND_FLAG,   0 },
	{ OVS_FLOW_ATTR_MASK,			NLA_KIND_NESTED, 0 },
	{ OVS_FLOW_ATTR_PROBE,			NLA_KIND_FLAG,   0 },
	{ OVS_FLOW_ATTR_UFID,			NLA_KIND_BINARY, 16 },
	{ OVS_FLOW_ATTR_UFID_FLAGS,		NLA_KIND_U32,    4 },

	/* OVS_KEY_ATTR_* — nested under OVS_FLOW_ATTR_KEY / MASK and
	 * under OVS_PACKET_ATTR_KEY / OVS_ACTION_ATTR_SET / SET_MASKED. */
	{ OVS_KEY_ATTR_ENCAP,			NLA_KIND_NESTED, 0 },
	{ OVS_KEY_ATTR_PRIORITY,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_IN_PORT,			NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_ETHERNET,		NLA_KIND_BINARY, sizeof(struct ovs_key_ethernet) },
	{ OVS_KEY_ATTR_VLAN,			NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_ETHERTYPE,		NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_IPV4,			NLA_KIND_BINARY, sizeof(struct ovs_key_ipv4) },
	{ OVS_KEY_ATTR_IPV6,			NLA_KIND_BINARY, sizeof(struct ovs_key_ipv6) },
	{ OVS_KEY_ATTR_TCP,			NLA_KIND_BINARY, sizeof(struct ovs_key_tcp) },
	{ OVS_KEY_ATTR_UDP,			NLA_KIND_BINARY, sizeof(struct ovs_key_udp) },
	{ OVS_KEY_ATTR_ICMP,			NLA_KIND_BINARY, sizeof(struct ovs_key_icmp) },
	{ OVS_KEY_ATTR_ICMPV6,			NLA_KIND_BINARY, sizeof(struct ovs_key_icmpv6) },
	{ OVS_KEY_ATTR_ARP,			NLA_KIND_BINARY, sizeof(struct ovs_key_arp) },
	{ OVS_KEY_ATTR_ND,			NLA_KIND_BINARY, sizeof(struct ovs_key_nd) },
	{ OVS_KEY_ATTR_SKB_MARK,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_TUNNEL,			NLA_KIND_NESTED, 0 },
	{ OVS_KEY_ATTR_SCTP,			NLA_KIND_BINARY, sizeof(struct ovs_key_sctp) },
	{ OVS_KEY_ATTR_TCP_FLAGS,		NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_DP_HASH,			NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_RECIRC_ID,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_MPLS,			NLA_KIND_BINARY, sizeof(struct ovs_key_mpls) },
	{ OVS_KEY_ATTR_CT_STATE,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_CT_ZONE,			NLA_KIND_U16,    2 },
	{ OVS_KEY_ATTR_CT_MARK,			NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_CT_LABELS,		NLA_KIND_BINARY, OVS_CT_LABELS_LEN },
	{ OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV4,	NLA_KIND_BINARY, sizeof(struct ovs_key_ct_tuple_ipv4) },
	{ OVS_KEY_ATTR_CT_ORIG_TUPLE_IPV6,	NLA_KIND_BINARY, sizeof(struct ovs_key_ct_tuple_ipv6) },
	{ OVS_KEY_ATTR_NSH,			NLA_KIND_NESTED, 0 },
	{ OVS_KEY_ATTR_PACKET_TYPE,		NLA_KIND_U32,    4 },
	{ OVS_KEY_ATTR_IPV6_EXTHDRS,		NLA_KIND_BINARY, sizeof(struct ovs_key_ipv6_exthdrs) },

	/* OVS_TUNNEL_KEY_ATTR_* — nested under OVS_KEY_ATTR_TUNNEL. */
	{ OVS_TUNNEL_KEY_ATTR_ID,		NLA_KIND_U64,    8 },
	{ OVS_TUNNEL_KEY_ATTR_IPV4_SRC,		NLA_KIND_BINARY, 4 },
	{ OVS_TUNNEL_KEY_ATTR_IPV4_DST,		NLA_KIND_BINARY, 4 },
	{ OVS_TUNNEL_KEY_ATTR_TOS,		NLA_KIND_U8,     1 },
	{ OVS_TUNNEL_KEY_ATTR_TTL,		NLA_KIND_U8,     1 },
	{ OVS_TUNNEL_KEY_ATTR_DONT_FRAGMENT,	NLA_KIND_FLAG,   0 },
	{ OVS_TUNNEL_KEY_ATTR_CSUM,		NLA_KIND_FLAG,   0 },
	{ OVS_TUNNEL_KEY_ATTR_OAM,		NLA_KIND_FLAG,   0 },
	{ OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS,	NLA_KIND_BINARY, 64 },
	{ OVS_TUNNEL_KEY_ATTR_TP_SRC,		NLA_KIND_U16,    2 },
	{ OVS_TUNNEL_KEY_ATTR_TP_DST,		NLA_KIND_U16,    2 },
	{ OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS,	NLA_KIND_NESTED, 0 },
	{ OVS_TUNNEL_KEY_ATTR_IPV6_SRC,		NLA_KIND_BINARY, 16 },
	{ OVS_TUNNEL_KEY_ATTR_IPV6_DST,		NLA_KIND_BINARY, 16 },
	{ OVS_TUNNEL_KEY_ATTR_ERSPAN_OPTS,	NLA_KIND_BINARY, 16 },
	{ OVS_TUNNEL_KEY_ATTR_IPV4_INFO_BRIDGE,	NLA_KIND_FLAG,   0 },

	/* OVS_NSH_KEY_ATTR_* — nested under OVS_KEY_ATTR_NSH. */
	{ OVS_NSH_KEY_ATTR_BASE,		NLA_KIND_BINARY, sizeof(struct ovs_nsh_key_base) },
	{ OVS_NSH_KEY_ATTR_MD1,			NLA_KIND_BINARY, sizeof(struct ovs_nsh_key_md1) },
	{ OVS_NSH_KEY_ATTR_MD2,			NLA_KIND_BINARY, 32 },

	/* OVS_ACTION_ATTR_* — nested under OVS_FLOW_ATTR_ACTIONS and
	 * under OVS_PACKET_ATTR_ACTIONS / OVS_SAMPLE_ATTR_ACTIONS /
	 * OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_* / OVS_DEC_TTL_ATTR_ACTION /
	 * OVS_USERSPACE_ATTR_ACTIONS / OVS_ACTION_ATTR_CLONE. */
	{ OVS_ACTION_ATTR_OUTPUT,		NLA_KIND_U32,    4 },
	{ OVS_ACTION_ATTR_USERSPACE,		NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_SET,			NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_PUSH_VLAN,		NLA_KIND_BINARY, sizeof(struct ovs_action_push_vlan) },
	{ OVS_ACTION_ATTR_POP_VLAN,		NLA_KIND_FLAG,   0 },
	{ OVS_ACTION_ATTR_SAMPLE,		NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_RECIRC,		NLA_KIND_U32,    4 },
	{ OVS_ACTION_ATTR_HASH,			NLA_KIND_BINARY, sizeof(struct ovs_action_hash) },
	{ OVS_ACTION_ATTR_PUSH_MPLS,		NLA_KIND_BINARY, sizeof(struct ovs_action_push_mpls) },
	{ OVS_ACTION_ATTR_POP_MPLS,		NLA_KIND_U16,    2 },
	{ OVS_ACTION_ATTR_SET_MASKED,		NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_CT,			NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_TRUNC,		NLA_KIND_BINARY, sizeof(struct ovs_action_trunc) },
	{ OVS_ACTION_ATTR_PUSH_ETH,		NLA_KIND_BINARY, sizeof(struct ovs_action_push_eth) },
	{ OVS_ACTION_ATTR_POP_ETH,		NLA_KIND_FLAG,   0 },
	{ OVS_ACTION_ATTR_CT_CLEAR,		NLA_KIND_FLAG,   0 },
	{ OVS_ACTION_ATTR_PUSH_NSH,		NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_POP_NSH,		NLA_KIND_FLAG,   0 },
	{ OVS_ACTION_ATTR_METER,		NLA_KIND_U32,    4 },
	{ OVS_ACTION_ATTR_CLONE,		NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_CHECK_PKT_LEN,	NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_ADD_MPLS,		NLA_KIND_BINARY, sizeof(struct ovs_action_add_mpls) },
	{ OVS_ACTION_ATTR_DEC_TTL,		NLA_KIND_NESTED, 0 },
	{ OVS_ACTION_ATTR_DROP,			NLA_KIND_U32,    4 },
	{ OVS_ACTION_ATTR_PSAMPLE,		NLA_KIND_NESTED, 0 },

	/* OVS_USERSPACE_ATTR_* — nested under OVS_ACTION_ATTR_USERSPACE. */
	{ OVS_USERSPACE_ATTR_PID,		NLA_KIND_U32,    4 },
	{ OVS_USERSPACE_ATTR_USERDATA,		NLA_KIND_BINARY, 32 },
	{ OVS_USERSPACE_ATTR_EGRESS_TUN_PORT,	NLA_KIND_U32,    4 },
	{ OVS_USERSPACE_ATTR_ACTIONS,		NLA_KIND_FLAG,   0 },

	/* OVS_SAMPLE_ATTR_* — nested under OVS_ACTION_ATTR_SAMPLE. */
	{ OVS_SAMPLE_ATTR_PROBABILITY,		NLA_KIND_U32,    4 },
	{ OVS_SAMPLE_ATTR_ACTIONS,		NLA_KIND_NESTED, 0 },

	/* OVS_CT_ATTR_* — nested under OVS_ACTION_ATTR_CT. */
	{ OVS_CT_ATTR_COMMIT,			NLA_KIND_FLAG,   0 },
	{ OVS_CT_ATTR_ZONE,			NLA_KIND_U16,    2 },
	{ OVS_CT_ATTR_MARK,			NLA_KIND_BINARY, 8 },
	{ OVS_CT_ATTR_LABELS,			NLA_KIND_BINARY, OVS_CT_LABELS_LEN * 2 },
	{ OVS_CT_ATTR_HELPER,			NLA_KIND_STRING, 16 },
	{ OVS_CT_ATTR_NAT,			NLA_KIND_NESTED, 0 },
	{ OVS_CT_ATTR_FORCE_COMMIT,		NLA_KIND_FLAG,   0 },
	{ OVS_CT_ATTR_EVENTMASK,		NLA_KIND_U32,    4 },
	{ OVS_CT_ATTR_TIMEOUT,			NLA_KIND_STRING, 32 },

	/* OVS_NAT_ATTR_* — nested under OVS_CT_ATTR_NAT. */
	{ OVS_NAT_ATTR_SRC,			NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_DST,			NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_IP_MIN,			NLA_KIND_BINARY, 16 },
	{ OVS_NAT_ATTR_IP_MAX,			NLA_KIND_BINARY, 16 },
	{ OVS_NAT_ATTR_PROTO_MIN,		NLA_KIND_U16,    2 },
	{ OVS_NAT_ATTR_PROTO_MAX,		NLA_KIND_U16,    2 },
	{ OVS_NAT_ATTR_PERSISTENT,		NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_PROTO_HASH,		NLA_KIND_FLAG,   0 },
	{ OVS_NAT_ATTR_PROTO_RANDOM,		NLA_KIND_FLAG,   0 },

	/* OVS_CHECK_PKT_LEN_ATTR_* — nested under OVS_ACTION_ATTR_CHECK_PKT_LEN. */
	{ OVS_CHECK_PKT_LEN_ATTR_PKT_LEN,		NLA_KIND_U16,    2 },
	{ OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_GREATER,	NLA_KIND_NESTED, 0 },
	{ OVS_CHECK_PKT_LEN_ATTR_ACTIONS_IF_LESS_EQUAL,	NLA_KIND_NESTED, 0 },

	/* OVS_DEC_TTL_ATTR_* — nested under OVS_ACTION_ATTR_DEC_TTL. */
	{ OVS_DEC_TTL_ATTR_ACTION,		NLA_KIND_NESTED, 0 },

	/* OVS_PSAMPLE_ATTR_* — nested under OVS_ACTION_ATTR_PSAMPLE. */
	{ OVS_PSAMPLE_ATTR_GROUP,		NLA_KIND_U32,    4 },
	{ OVS_PSAMPLE_ATTR_COOKIE,		NLA_KIND_BINARY, OVS_PSAMPLE_COOKIE_MAX_SIZE },

	/* OVS_VXLAN_EXT_* — nested under OVS_TUNNEL_KEY_ATTR_VXLAN_OPTS. */
	{ OVS_VXLAN_EXT_GBP,			NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_ovs_flow = {
	.name = OVS_FLOW_FAMILY,
	.cmds = ovs_flow_cmds,
	.n_cmds = ARRAY_SIZE(ovs_flow_cmds),
	.attrs = ovs_flow_attrs,
	.n_attrs = ARRAY_SIZE(ovs_flow_attrs),
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
 * the outer OVS_PACKET_ATTR_* here keeps this table small; the inner
 * KEY / ACTIONS payloads borrow their structure from random emit when
 * the spec emitter walks into a NESTED.
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

static const struct genl_cmd_grammar ovs_meter_cmds[] = {
	{ OVS_METER_CMD_FEATURES, "OVS_METER_CMD_FEATURES" },
	{ OVS_METER_CMD_SET,	  "OVS_METER_CMD_SET" },
	{ OVS_METER_CMD_DEL,	  "OVS_METER_CMD_DEL" },
	{ OVS_METER_CMD_GET,	  "OVS_METER_CMD_GET" },
};

/*
 * Meter policy lives in net/openvswitch/meter.c::meter_policy /
 * band_policy.  ID is the per-datapath meter slot.  KBPS is a flag
 * switching units between packets/sec and kbits/sec.  BANDS is a list
 * of nested OVS_BAND_ATTR_* describing rate / burst / type per band.
 */
static const struct nla_attr_spec ovs_meter_attrs[] = {
	{ OVS_METER_ATTR_ID,		NLA_KIND_U32,    4 },
	{ OVS_METER_ATTR_KBPS,		NLA_KIND_FLAG,   0 },
	{ OVS_METER_ATTR_STATS,		NLA_KIND_BINARY, sizeof(struct ovs_flow_stats) },
	{ OVS_METER_ATTR_BANDS,		NLA_KIND_NESTED, 0 },
	{ OVS_METER_ATTR_USED,		NLA_KIND_U64,    8 },
	{ OVS_METER_ATTR_CLEAR,		NLA_KIND_FLAG,   0 },
	{ OVS_METER_ATTR_MAX_METERS,	NLA_KIND_U32,    4 },
	{ OVS_METER_ATTR_MAX_BANDS,	NLA_KIND_U32,    4 },

	/* OVS_BAND_ATTR_* — nested under OVS_METER_ATTR_BANDS. */
	{ OVS_BAND_ATTR_TYPE,		NLA_KIND_U32,    4 },
	{ OVS_BAND_ATTR_RATE,		NLA_KIND_U32,    4 },
	{ OVS_BAND_ATTR_BURST,		NLA_KIND_U32,    4 },
	{ OVS_BAND_ATTR_STATS,		NLA_KIND_BINARY, sizeof(struct ovs_flow_stats) },
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
 * small multiple of the struct size is what we want to emit.
 */
static const struct nla_attr_spec ovs_ct_limit_attrs[] = {
	{ OVS_CT_LIMIT_ATTR_ZONE_LIMIT,	NLA_KIND_BINARY, sizeof(struct ovs_zone_limit) * 4 },
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
