/*
 * msg-tables.c
 *
 * Descriptor tables extracted from msg.c so the two halves of
 * the module can compile in parallel.  The tables here are pure data:
 * per-protocol message-type lists (NETLINK_ROUTE / NETLINK_XFRM /
 * NETLINK_AUDIT), per-rtnetlink-group nlattr-type lists, per-family
 * nla_attr_spec tables (genl-ctrl, XFRM, sock_diag) and the xfrm
 * family-field offset table consumed by xfrm_pin_family.
 *
 * Each table was file-static in the original TU; linkage is widened
 * to external here so the emitters in msg.c can index into
 * them across the TU split.  A companion `_n` size constant is
 * emitted for every table so the emitter side can scale a uniform
 * pick without needing the complete array type that ARRAY_SIZE()
 * requires across the TU boundary.
 *
 * Body contents — initializers, comments, ordering — are byte-
 * identical to the original.
 */

#include <stddef.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/netconf.h>
#include <linux/nexthop.h>
#include <linux/dcbnl.h>
#include <linux/genetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/inet_diag.h>
#include "msg-internal.h"
#include "utils.h"

#include "kernel/netlink.h"

/* Newer RTM_* types may be missing from older system headers. */
#ifndef RTM_DELLINKPROP
#define RTM_DELLINKPROP		109
#endif
#ifndef RTM_GETLINKPROP
#define RTM_GETLINKPROP		110
#endif

/* rtnetlink message types (NEW/DEL/GET variants picked at random) */
const unsigned short rtnl_types[] = {
	RTM_NEWLINK, RTM_DELLINK, RTM_GETLINK, RTM_SETLINK,
	RTM_NEWADDR, RTM_DELADDR, RTM_GETADDR,
	RTM_NEWROUTE, RTM_DELROUTE, RTM_GETROUTE,
	RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH,
	RTM_NEWRULE, RTM_DELRULE, RTM_GETRULE,
	RTM_NEWQDISC, RTM_DELQDISC, RTM_GETQDISC,
	RTM_NEWTCLASS, RTM_DELTCLASS, RTM_GETTCLASS,
	RTM_NEWTFILTER, RTM_DELTFILTER, RTM_GETTFILTER,
	RTM_NEWACTION, RTM_DELACTION, RTM_GETACTION,
	RTM_NEWPREFIX, RTM_GETMULTICAST, RTM_GETANYCAST,
	RTM_NEWNEIGHTBL, RTM_GETNEIGHTBL, RTM_SETNEIGHTBL,
	RTM_NEWNDUSEROPT,
	RTM_NEWADDRLABEL, RTM_GETADDRLABEL,
	RTM_GETDCB, RTM_SETDCB,
	RTM_NEWNETCONF, RTM_GETNETCONF,
	RTM_NEWMDB, RTM_DELMDB, RTM_GETMDB,
	RTM_NEWNSID, RTM_GETNSID,
	RTM_NEWSTATS, RTM_GETSTATS, RTM_SETSTATS,
	RTM_NEWCHAIN, RTM_DELCHAIN, RTM_GETCHAIN,
	RTM_NEWNEXTHOP, RTM_DELNEXTHOP, RTM_GETNEXTHOP,
	RTM_NEWLINKPROP, RTM_DELLINKPROP, RTM_GETLINKPROP,
	RTM_NEWVLAN, RTM_DELVLAN, RTM_GETVLAN,
	RTM_NEWNEXTHOPBUCKET, RTM_DELNEXTHOPBUCKET, RTM_GETNEXTHOPBUCKET,
	RTM_NEWTUNNEL, RTM_DELTUNNEL, RTM_GETTUNNEL,
};
const size_t rtnl_types_n = ARRAY_SIZE(rtnl_types);

const unsigned short xfrm_types[] = {
	XFRM_MSG_NEWSA, XFRM_MSG_DELSA, XFRM_MSG_GETSA,
	XFRM_MSG_NEWPOLICY, XFRM_MSG_DELPOLICY, XFRM_MSG_GETPOLICY,
	XFRM_MSG_ALLOCSPI, XFRM_MSG_ACQUIRE, XFRM_MSG_EXPIRE,
	XFRM_MSG_UPDPOLICY, XFRM_MSG_UPDSA,
	XFRM_MSG_POLEXPIRE, XFRM_MSG_FLUSHSA, XFRM_MSG_FLUSHPOLICY,
	XFRM_MSG_NEWAE, XFRM_MSG_GETAE,
	XFRM_MSG_GETSADINFO, XFRM_MSG_GETSPDINFO,
	XFRM_MSG_MIGRATE,
	XFRM_MSG_NEWSADINFO, XFRM_MSG_NEWSPDINFO,
	XFRM_MSG_MAPPING, XFRM_MSG_REPORT,
	XFRM_MSG_SETDEFAULT, XFRM_MSG_GETDEFAULT,
};
const size_t xfrm_types_n = ARRAY_SIZE(xfrm_types);

const unsigned short audit_types[] = {
	AUDIT_GET, AUDIT_SET, AUDIT_LIST_RULES, AUDIT_ADD_RULE,
	AUDIT_DEL_RULE, AUDIT_USER, AUDIT_LOGIN,
	AUDIT_WATCH_INS, AUDIT_WATCH_REM, AUDIT_WATCH_LIST,
	AUDIT_SIGNAL_INFO, AUDIT_TTY_GET, AUDIT_TTY_SET,
};
const size_t audit_types_n = ARRAY_SIZE(audit_types);

/* RTAX_* metrics sub-attributes for RTA_METRICS nested container */
const unsigned short rtax_attrs[] = {
	RTAX_MTU, RTAX_WINDOW, RTAX_RTT, RTAX_RTTVAR,
	RTAX_SSTHRESH, RTAX_CWND, RTAX_ADVMSS, RTAX_REORDERING,
	RTAX_HOPLIMIT, RTAX_INITCWND, RTAX_FEATURES, RTAX_RTO_MIN,
	RTAX_INITRWND, RTAX_QUICKACK,
};
const size_t rtax_attrs_n = ARRAY_SIZE(rtax_attrs);

/* Top-level DCB_ATTR_* types emitted alongside struct dcbmsg.  Without
 * at least DCB_ATTR_IFNAME the kernel's dcb_doit() short-circuits before
 * dispatching to any per-feature setter, so a netlink message with just
 * the dcbmsg header can never reach the IEEE / CEE / PFC code paths. */
const unsigned short dcb_attrs[] = {
	DCB_ATTR_IFNAME, DCB_ATTR_IEEE,
};
const size_t dcb_attrs_n = ARRAY_SIZE(dcb_attrs);

/* DCB_ATTR_IEEE_* children for the DCB_ATTR_IEEE nested container. */
const unsigned short dcb_ieee_attrs[] = {
	DCB_ATTR_IEEE_ETS, DCB_ATTR_IEEE_PFC, DCB_ATTR_IEEE_APP_TABLE,
};
const size_t dcb_ieee_attrs_n = ARRAY_SIZE(dcb_ieee_attrs);

/* Link type names for IFLA_INFO_KIND */
const char *link_kinds[] = {
	"veth", "bridge", "bond", "vlan", "macvlan",
	"vxlan", "ipvlan", "dummy", "ifb", "gre",
	"gretap", "sit", "ip6tnl", "ip6gre", "vti",
};
const size_t link_kinds_n = ARRAY_SIZE(link_kinds);

/* nlattr types for each rtnetlink message group.
 * Each call picks a random entry from the appropriate list. */

/* Newer IFLA_* attrs may be missing from older system headers. */
#ifndef IFLA_PROTO_DOWN_REASON
#define IFLA_PROTO_DOWN_REASON		55
#endif
#ifndef IFLA_PARENT_DEV_NAME
#define IFLA_PARENT_DEV_NAME		56
#endif
#ifndef IFLA_PARENT_DEV_BUS_NAME
#define IFLA_PARENT_DEV_BUS_NAME	57
#endif
#ifndef IFLA_GRO_MAX_SIZE
#define IFLA_GRO_MAX_SIZE		58
#endif
#ifndef IFLA_TSO_MAX_SIZE
#define IFLA_TSO_MAX_SIZE		59
#endif
#ifndef IFLA_TSO_MAX_SEGS
#define IFLA_TSO_MAX_SEGS		60
#endif
#ifndef IFLA_ALLMULTI
#define IFLA_ALLMULTI			61
#endif
#ifndef IFLA_DEVLINK_PORT
#define IFLA_DEVLINK_PORT		62
#endif
#ifndef IFLA_GSO_IPV4_MAX_SIZE
#define IFLA_GSO_IPV4_MAX_SIZE		63
#endif
#ifndef IFLA_GRO_IPV4_MAX_SIZE
#define IFLA_GRO_IPV4_MAX_SIZE		64
#endif
#ifndef IFLA_DPLL_PIN
#define IFLA_DPLL_PIN			65
#endif
#ifndef IFLA_MAX_PACING_OFFLOAD_HORIZON
#define IFLA_MAX_PACING_OFFLOAD_HORIZON	66
#endif
#ifndef IFLA_NETNS_IMMUTABLE
#define IFLA_NETNS_IMMUTABLE		67
#endif
#ifndef IFLA_HEADROOM
#define IFLA_HEADROOM			68
#endif
#ifndef IFLA_TAILROOM
#define IFLA_TAILROOM			69
#endif

const unsigned short ifla_attrs[] = {
	IFLA_ADDRESS, IFLA_BROADCAST, IFLA_IFNAME, IFLA_MTU, IFLA_LINK,
	IFLA_QDISC, IFLA_STATS, IFLA_COST, IFLA_PRIORITY, IFLA_MASTER,
	IFLA_PROTINFO, IFLA_TXQLEN, IFLA_MAP, IFLA_WEIGHT, IFLA_OPERSTATE,
	IFLA_LINKMODE, IFLA_LINKINFO, IFLA_NET_NS_PID, IFLA_IFALIAS,
	IFLA_NUM_VF, IFLA_STATS64, IFLA_AF_SPEC, IFLA_GROUP,
	IFLA_NET_NS_FD, IFLA_EXT_MASK, IFLA_PROMISCUITY,
	IFLA_NUM_TX_QUEUES, IFLA_NUM_RX_QUEUES, IFLA_CARRIER,
	IFLA_PHYS_PORT_ID, IFLA_LINK_NETNSID, IFLA_PROTO_DOWN,
	IFLA_GSO_MAX_SEGS, IFLA_GSO_MAX_SIZE, IFLA_XDP,
	IFLA_NEW_IFINDEX, IFLA_MIN_MTU, IFLA_MAX_MTU,
	IFLA_PROP_LIST, IFLA_ALT_IFNAME, IFLA_PERM_ADDRESS,
	IFLA_PROTO_DOWN_REASON, IFLA_PARENT_DEV_NAME,
	IFLA_PARENT_DEV_BUS_NAME, IFLA_GRO_MAX_SIZE,
	IFLA_TSO_MAX_SIZE, IFLA_TSO_MAX_SEGS, IFLA_ALLMULTI,
	IFLA_DEVLINK_PORT, IFLA_GSO_IPV4_MAX_SIZE,
	IFLA_GRO_IPV4_MAX_SIZE, IFLA_DPLL_PIN,
	IFLA_MAX_PACING_OFFLOAD_HORIZON, IFLA_NETNS_IMMUTABLE,
	IFLA_HEADROOM, IFLA_TAILROOM,
};
const size_t ifla_attrs_n = ARRAY_SIZE(ifla_attrs);

/* Newer IFA_* attrs may be missing from older system headers. */
#ifndef IFA_MULTICAST
#define IFA_MULTICAST			7
#endif
#ifndef IFA_TARGET_NETNSID
#define IFA_TARGET_NETNSID		10
#endif

const unsigned short ifa_attrs[] = {
	IFA_ADDRESS, IFA_LOCAL, IFA_LABEL, IFA_BROADCAST, IFA_ANYCAST,
	IFA_CACHEINFO, IFA_MULTICAST, IFA_FLAGS, IFA_RT_PRIORITY,
	IFA_TARGET_NETNSID, IFA_PROTO,
};
const size_t ifa_attrs_n = ARRAY_SIZE(ifa_attrs);

/* Newer RTA_* attrs may be missing from older system headers. */
#ifndef RTA_FLOWLABEL
#define RTA_FLOWLABEL			31
#endif

const unsigned short rta_attrs[] = {
	RTA_DST, RTA_SRC, RTA_IIF, RTA_OIF, RTA_GATEWAY, RTA_PRIORITY,
	RTA_PREFSRC, RTA_METRICS, RTA_MULTIPATH, RTA_FLOW, RTA_CACHEINFO,
	RTA_TABLE, RTA_MARK, RTA_MFC_STATS, RTA_VIA, RTA_NEWDST,
	RTA_PREF, RTA_ENCAP_TYPE, RTA_ENCAP, RTA_EXPIRES, RTA_UID,
	RTA_TTL_PROPAGATE, RTA_IP_PROTO, RTA_SPORT, RTA_DPORT, RTA_NH_ID,
	RTA_FLOWLABEL,
};
const size_t rta_attrs_n = ARRAY_SIZE(rta_attrs);

/* Newer NDA_* attrs may be missing from older system headers. */
#ifndef NDA_FDB_EXT_ATTRS
#define NDA_FDB_EXT_ATTRS		14
#endif

const unsigned short nda_attrs[] = {
	NDA_DST, NDA_LLADDR, NDA_CACHEINFO, NDA_PROBES, NDA_VLAN,
	NDA_PORT, NDA_VNI, NDA_IFINDEX, NDA_MASTER, NDA_LINK_NETNSID,
	NDA_SRC_VNI, NDA_PROTOCOL, NDA_NH_ID, NDA_FDB_EXT_ATTRS,
	NDA_FLAGS_EXT, NDA_NDM_STATE_MASK, NDA_NDM_FLAGS_MASK,
};
const size_t nda_attrs_n = ARRAY_SIZE(nda_attrs);

/* Newer FRA_* attrs may be missing from older system headers. */
#ifndef FRA_UID_RANGE
#define FRA_UID_RANGE			20
#endif
#ifndef FRA_PROTOCOL
#define FRA_PROTOCOL			21
#endif
#ifndef FRA_IP_PROTO
#define FRA_IP_PROTO			22
#endif
#ifndef FRA_SPORT_RANGE
#define FRA_SPORT_RANGE			23
#endif
#ifndef FRA_DPORT_RANGE
#define FRA_DPORT_RANGE			24
#endif
#ifndef FRA_DSCP
#define FRA_DSCP			25
#endif
#ifndef FRA_FLOWLABEL
#define FRA_FLOWLABEL			26
#endif
#ifndef FRA_FLOWLABEL_MASK
#define FRA_FLOWLABEL_MASK		27
#endif
#ifndef FRA_SPORT_MASK
#define FRA_SPORT_MASK			28
#endif
#ifndef FRA_DPORT_MASK
#define FRA_DPORT_MASK			29
#endif
#ifndef FRA_DSCP_MASK
#define FRA_DSCP_MASK			30
#endif

const unsigned short fra_attrs[] = {
	FRA_DST, FRA_SRC, FRA_IIFNAME, FRA_GOTO, FRA_PRIORITY,
	FRA_FWMARK, FRA_FLOW, FRA_TUN_ID, FRA_SUPPRESS_IFGROUP,
	FRA_SUPPRESS_PREFIXLEN, FRA_TABLE, FRA_FWMASK, FRA_OIFNAME,
	FRA_L3MDEV, FRA_UID_RANGE, FRA_PROTOCOL, FRA_IP_PROTO,
	FRA_SPORT_RANGE, FRA_DPORT_RANGE, FRA_DSCP, FRA_FLOWLABEL,
	FRA_FLOWLABEL_MASK, FRA_SPORT_MASK, FRA_DPORT_MASK,
	FRA_DSCP_MASK,
};
const size_t fra_attrs_n = ARRAY_SIZE(fra_attrs);

const unsigned short tca_attrs[] = {
	TCA_KIND, TCA_OPTIONS, TCA_STATS, TCA_XSTATS, TCA_RATE,
	TCA_FCNT, TCA_STATS2, TCA_STAB, TCA_CHAIN, TCA_HW_OFFLOAD,
	TCA_INGRESS_BLOCK, TCA_EXT_WARN_MSG,
};
const size_t tca_attrs_n = ARRAY_SIZE(tca_attrs);

/* Newer NHA_* attrs may be missing from older system headers. */
#ifndef NHA_GROUP_STATS
#define NHA_GROUP_STATS			15
#endif

const unsigned short nha_attrs[] = {
	NHA_GROUP, NHA_GROUP_TYPE, NHA_BLACKHOLE, NHA_OIF, NHA_GATEWAY,
	NHA_ENCAP_TYPE, NHA_ENCAP, NHA_GROUPS, NHA_MASTER, NHA_FDB,
	NHA_RES_GROUP, NHA_RES_BUCKET, NHA_OP_FLAGS, NHA_GROUP_STATS,
	NHA_HW_STATS_USED, NHA_HW_STATS_ENABLE,
};
const size_t nha_attrs_n = ARRAY_SIZE(nha_attrs);

/* Newer NETCONFA_* attrs may be missing from older system headers. */
#ifndef NETCONFA_FORCE_FORWARDING
#define NETCONFA_FORCE_FORWARDING	9
#endif

const unsigned short netconfa_attrs[] = {
	NETCONFA_IFINDEX, NETCONFA_FORWARDING, NETCONFA_RP_FILTER,
	NETCONFA_MC_FORWARDING, NETCONFA_PROXY_NEIGH,
	NETCONFA_IGNORE_ROUTES_WITH_LINKDOWN,
	NETCONFA_INPUT, NETCONFA_BC_FORWARDING,
	NETCONFA_FORCE_FORWARDING,
};
const size_t netconfa_attrs_n = ARRAY_SIZE(netconfa_attrs);

const unsigned short ifal_attrs[] = {
	IFAL_ADDRESS, IFAL_LABEL,
};
const size_t ifal_attrs_n = ARRAY_SIZE(ifal_attrs);

const unsigned short mdba_attrs[] = {
	MDBA_MDB, MDBA_ROUTER, MDBA_SET_ENTRY, MDBA_SET_ENTRY_ATTRS,
};
const size_t mdba_attrs_n = ARRAY_SIZE(mdba_attrs);

const unsigned short bridge_vlandb_attrs[] = {
	BRIDGE_VLANDB_ENTRY, BRIDGE_VLANDB_GLOBAL_OPTIONS,
};
const size_t bridge_vlandb_attrs_n = ARRAY_SIZE(bridge_vlandb_attrs);

/*
 * Per-family attribute spec tables.
 *
 * Each entry pairs an attribute type with its kernel-side kind (NLA_U8,
 * NLA_STRING, NLA_NESTED, etc.) and an upper bound on the payload
 * length.  This carries enough information for the generator to emit
 * an attribute that survives the family's nla_policy validation gate
 * (nla_parse_nested_deprecated, nla_validate) and reaches the deeper
 * command dispatch where bugs actually live.  Without this, most
 * generated attrs are length-rejected with -EINVAL before any code
 * the family cares about gets to run.
 */
/* genl controller (GENL_ID_CTRL) attributes */
const struct nla_attr_spec ctrl_specs[] = {
	{ CTRL_ATTR_FAMILY_ID,    NLA_KIND_U16,    2 },
	{ CTRL_ATTR_FAMILY_NAME,  NLA_KIND_STRING, GENL_NAMSIZ },
	{ CTRL_ATTR_VERSION,      NLA_KIND_U32,    4 },
	{ CTRL_ATTR_HDRSIZE,      NLA_KIND_U32,    4 },
	{ CTRL_ATTR_MAXATTR,      NLA_KIND_U32,    4 },
	{ CTRL_ATTR_OPS,          NLA_KIND_NESTED, 0 },
	{ CTRL_ATTR_MCAST_GROUPS, NLA_KIND_NESTED, 0 },
	{ CTRL_ATTR_POLICY,       NLA_KIND_NESTED, 0 },
	{ CTRL_ATTR_OP,           NLA_KIND_U32,    4 },
};
const size_t ctrl_specs_n = ARRAY_SIZE(ctrl_specs);

/* Newer XFRMA_* attrs may be missing from older system headers. */
#ifndef XFRMA_NAT_KEEPALIVE_INTERVAL
#define XFRMA_NAT_KEEPALIVE_INTERVAL	35
#endif
#ifndef XFRMA_SA_PCPU
#define XFRMA_SA_PCPU			36
#endif
#ifndef XFRMA_IPTFS_DROP_TIME
#define XFRMA_IPTFS_DROP_TIME		37
#endif
#ifndef XFRMA_IPTFS_REORDER_WINDOW
#define XFRMA_IPTFS_REORDER_WINDOW	38
#endif
#ifndef XFRMA_IPTFS_DONT_FRAG
#define XFRMA_IPTFS_DONT_FRAG		39
#endif
#ifndef XFRMA_IPTFS_INIT_DELAY
#define XFRMA_IPTFS_INIT_DELAY		40
#endif
#ifndef XFRMA_IPTFS_MAX_QSIZE
#define XFRMA_IPTFS_MAX_QSIZE		41
#endif
#ifndef XFRMA_IPTFS_PKT_SIZE
#define XFRMA_IPTFS_PKT_SIZE		42
#endif

/* XFRM attribute spec table (XFRMA_*) */
const struct nla_attr_spec xfrma_specs[] = {
	{ XFRMA_ALG_AUTH,        NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_CRYPT,       NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_COMP,        NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_AEAD,        NLA_KIND_BINARY, 128 },
	{ XFRMA_ALG_AUTH_TRUNC,  NLA_KIND_BINARY, 128 },
	{ XFRMA_ENCAP,           NLA_KIND_BINARY, 24 },
	{ XFRMA_TMPL,            NLA_KIND_BINARY, 64 },
	{ XFRMA_SA,              NLA_KIND_NESTED, 0 },
	{ XFRMA_POLICY,          NLA_KIND_NESTED, 0 },
	{ XFRMA_SEC_CTX,         NLA_KIND_BINARY, 32 },
	{ XFRMA_LTIME_VAL,       NLA_KIND_BINARY, 32 },
	{ XFRMA_REPLAY_VAL,      NLA_KIND_BINARY, 16 },
	{ XFRMA_REPLAY_THRESH,   NLA_KIND_U32,    4 },
	{ XFRMA_ETIMER_THRESH,   NLA_KIND_U32,    4 },
	{ XFRMA_SRCADDR,         NLA_KIND_BINARY, 16 },
	{ XFRMA_COADDR,          NLA_KIND_BINARY, 16 },
	{ XFRMA_LASTUSED,        NLA_KIND_U64,    8 },
	{ XFRMA_POLICY_TYPE,     NLA_KIND_BINARY, 4 },
	{ XFRMA_MIGRATE,         NLA_KIND_BINARY, 64 },
	{ XFRMA_KMADDRESS,       NLA_KIND_BINARY, 36 },
	{ XFRMA_MARK,            NLA_KIND_BINARY, 8 },
	{ XFRMA_TFCPAD,          NLA_KIND_U32,    4 },
	{ XFRMA_REPLAY_ESN_VAL,  NLA_KIND_BINARY, 32 },
	{ XFRMA_SA_EXTRA_FLAGS,  NLA_KIND_U32,    4 },
	{ XFRMA_PROTO,           NLA_KIND_U8,     1 },
	{ XFRMA_ADDRESS_FILTER,  NLA_KIND_BINARY, 36 },
	{ XFRMA_OFFLOAD_DEV,     NLA_KIND_BINARY, 8 },
	{ XFRMA_SET_MARK,        NLA_KIND_U32,    4 },
	{ XFRMA_SET_MARK_MASK,   NLA_KIND_U32,    4 },
	{ XFRMA_IF_ID,           NLA_KIND_U32,    4 },
	{ XFRMA_MTIMER_THRESH,   NLA_KIND_U32,    4 },
	{ XFRMA_SA_DIR,          NLA_KIND_U8,     1 },
	{ XFRMA_NAT_KEEPALIVE_INTERVAL, NLA_KIND_U32,  4 },
	{ XFRMA_SA_PCPU,                NLA_KIND_U32,  4 },
	{ XFRMA_IPTFS_DROP_TIME,        NLA_KIND_U32,  4 },
	{ XFRMA_IPTFS_REORDER_WINDOW,   NLA_KIND_U16,  2 },
	{ XFRMA_IPTFS_DONT_FRAG,        NLA_KIND_FLAG, 0 },
	{ XFRMA_IPTFS_INIT_DELAY,       NLA_KIND_U32,  4 },
	{ XFRMA_IPTFS_MAX_QSIZE,        NLA_KIND_U32,  4 },
	{ XFRMA_IPTFS_PKT_SIZE,         NLA_KIND_U32,  4 },
};
const size_t xfrma_specs_n = ARRAY_SIZE(xfrma_specs);

/*
 * Per-message-type family-field offsets within the xfrm body.
 * Most xfrm structs carry an AF_INET/AF_INET6 family value (sometimes
 * two — the SA family and the selector family). Random bytes set these
 * to garbage so the kernel rejects the message at family validation,
 * giving terrible coverage past the entry point. Writing a real family
 * value gets us into the deeper code paths.
 *
 * sel_family_offset == ~0u means the message has no separate selector
 * family to pin.
 */
const struct xfrm_family_offset xfrm_family_offsets[] = {
	{ XFRM_MSG_NEWSA,
	  offsetof(struct xfrm_usersa_info, family),
	  offsetof(struct xfrm_usersa_info, sel) +
		offsetof(struct xfrm_selector, family) },
	{ XFRM_MSG_UPDSA,
	  offsetof(struct xfrm_usersa_info, family),
	  offsetof(struct xfrm_usersa_info, sel) +
		offsetof(struct xfrm_selector, family) },
	{ XFRM_MSG_DELSA,
	  offsetof(struct xfrm_usersa_id, family), ~0u },
	{ XFRM_MSG_GETSA,
	  offsetof(struct xfrm_usersa_id, family), ~0u },
	{ XFRM_MSG_NEWPOLICY,
	  offsetof(struct xfrm_userpolicy_info, sel) +
		offsetof(struct xfrm_selector, family), ~0u },
	{ XFRM_MSG_UPDPOLICY,
	  offsetof(struct xfrm_userpolicy_info, sel) +
		offsetof(struct xfrm_selector, family), ~0u },
	{ XFRM_MSG_DELPOLICY,
	  offsetof(struct xfrm_userpolicy_id, sel) +
		offsetof(struct xfrm_selector, family), ~0u },
	{ XFRM_MSG_GETPOLICY,
	  offsetof(struct xfrm_userpolicy_id, sel) +
		offsetof(struct xfrm_selector, family), ~0u },
	{ XFRM_MSG_ALLOCSPI,
	  offsetof(struct xfrm_userspi_info, info) +
		offsetof(struct xfrm_usersa_info, family),
	  offsetof(struct xfrm_userspi_info, info) +
		offsetof(struct xfrm_usersa_info, sel) +
		offsetof(struct xfrm_selector, family) },
	{ XFRM_MSG_ACQUIRE,
	  offsetof(struct xfrm_user_acquire, policy) +
		offsetof(struct xfrm_userpolicy_info, sel) +
		offsetof(struct xfrm_selector, family),
	  offsetof(struct xfrm_user_acquire, sel) +
		offsetof(struct xfrm_selector, family) },
	{ XFRM_MSG_EXPIRE,
	  offsetof(struct xfrm_user_expire, state) +
		offsetof(struct xfrm_usersa_info, family),
	  offsetof(struct xfrm_user_expire, state) +
		offsetof(struct xfrm_usersa_info, sel) +
		offsetof(struct xfrm_selector, family) },
	{ XFRM_MSG_POLEXPIRE,
	  offsetof(struct xfrm_user_polexpire, pol) +
		offsetof(struct xfrm_userpolicy_info, sel) +
		offsetof(struct xfrm_selector, family), ~0u },
	{ XFRM_MSG_NEWAE,
	  offsetof(struct xfrm_aevent_id, sa_id) +
		offsetof(struct xfrm_usersa_id, family), ~0u },
	{ XFRM_MSG_GETAE,
	  offsetof(struct xfrm_aevent_id, sa_id) +
		offsetof(struct xfrm_usersa_id, family), ~0u },
	{ XFRM_MSG_REPORT,
	  offsetof(struct xfrm_user_report, sel) +
		offsetof(struct xfrm_selector, family), ~0u },
	{ XFRM_MSG_MAPPING,
	  offsetof(struct xfrm_user_mapping, id) +
		offsetof(struct xfrm_usersa_id, family), ~0u },
};
const size_t xfrm_family_offsets_n = ARRAY_SIZE(xfrm_family_offsets);

/* sock_diag (INET_DIAG_*) request attribute spec table */
const struct nla_attr_spec inet_diag_specs[] = {
	{ INET_DIAG_REQ_BYTECODE,        NLA_KIND_BINARY, 256 },
	{ INET_DIAG_REQ_SK_BPF_STORAGES, NLA_KIND_NESTED, 0 },
	{ INET_DIAG_REQ_PROTOCOL,        NLA_KIND_U8,     1 },
};
const size_t inet_diag_specs_n = ARRAY_SIZE(inet_diag_specs);
