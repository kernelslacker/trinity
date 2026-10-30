/*
 * Genetlink family grammar: TIPC (Transparent Inter-Process Communication,
 * family "TIPCv2"), targeting net/tipc/netlink.c and the per-command
 * handlers in bearer.c, net.c, node.c, socket.c and udp_media.c.  Every
 * top-level attribute is a nest that the handler parses against its own
 * policy.
 */

#if __has_include(<linux/tipc_netlink.h>)

#include <sys/socket.h>
#include <linux/tipc.h>
#include <linux/tipc_config.h>
#include <linux/tipc_netlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The inner namespaces, each from the tipc_nl_*_policy the handlers parse
 * its nest under with nla_parse_nested_deprecated().  The three PROP nests
 * share tipc_nl_prop_policy.  The UDP policy has no slot for MULTI_REMOTEIP,
 * but udp_media.c reads it as a flag.  The two addresses are a
 * sockaddr_storage at most, which tipc_parse_udp_addr() reads by its
 * family.  LINK_NAME and BEARER_NAME are NLA_NUL_STRING, so a
 * byte at least, and MEDIA_NAME an NLA_STRING.  A PROP nest's MTU is at
 * most U16_MAX (tipc_nl_mtu_range), and tipc_nl_parse_link_prop(), which
 * every PROP nest goes through, refuses a PRIO, TOL or WIN outside the
 * TIPC_*_LINK_* bounds, as the broadcast link does a BROADCAST_RATIO
 * outside 1 to 100.  Every handler of a bearer, link or
 * media nest answers -EINVAL to one without its NAME, and PUBL_GET's
 * dumpit to a SOCK nest without REF, the one attribute of the nest that a
 * request is read for.  A NAME is one the handlers find: "broadcast-link",
 * the link every node has and the one the link handlers serve by name; the
 * UDP media, which alone takes a PROP MTU; and a bearer on that media,
 * which bearer_name_validate() passes.  What only replies carry is left
 * out.
 */
static const struct nla_attr_spec tipc_prop_attrs[] = {
	{ TIPC_NLA_PROP_PRIO,		NLA_KIND_U32_RANGE, TIPC_MAX_LINK_PRI, 0 },
	{ TIPC_NLA_PROP_TOL,		NLA_KIND_U32_RANGE, TIPC_MAX_LINK_TOL,
	  TIPC_MIN_LINK_TOL },
	{ TIPC_NLA_PROP_WIN,		NLA_KIND_U32_RANGE, TIPC_MAX_LINK_WIN,
	  TIPC_DEF_LINK_WIN },
	{ TIPC_NLA_PROP_MTU,		NLA_KIND_U32_RANGE, 65535, 0 },
	{ TIPC_NLA_PROP_BROADCAST,	NLA_KIND_U32,    4 },
	{ TIPC_NLA_PROP_BROADCAST_RATIO, NLA_KIND_U32_RANGE, 100, 1 },
};

/*
 * A UDP bearer's addresses: tipc_udp_enable() wants both, the local one on
 * a device of the netns, as the loopback address is, and a UDP bearer's
 * add the remote one.
 */
static const struct nla_attr_spec tipc_udp_attrs[] = {
	{ TIPC_NLA_UDP_LOCAL,		NLA_KIND_SOCKADDR, 0, 0,
	  .required = true },
	{ TIPC_NLA_UDP_REMOTE,		NLA_KIND_SOCKADDR, 0, 0,
	  .required = true },
	{ TIPC_NLA_UDP_MULTI_REMOTEIP,	NLA_KIND_FLAG,   0 },
};

static const struct nla_attr_spec tipc_bearer_attrs[] = {
	{ TIPC_NLA_BEARER_NAME,		NLA_KIND_STRING_WORD, 0, 0,
	  .word = "udp:trinity", .required = true },
	{ TIPC_NLA_BEARER_PROP,		NLA_KIND_NESTED, 0, 0,
	  tipc_prop_attrs, ARRAY_SIZE(tipc_prop_attrs) },
};

/* What ENABLE reads, and ADD: a UDP bearer has no enable or add without
 * its UDP_OPTS. */
static const struct nla_attr_spec tipc_bearer_udp_attrs[] = {
	{ TIPC_NLA_BEARER_NAME,		NLA_KIND_STRING_WORD, 0, 0,
	  .word = "udp:trinity", .required = true },
	{ TIPC_NLA_BEARER_PROP,		NLA_KIND_NESTED, 0, 0,
	  tipc_prop_attrs, ARRAY_SIZE(tipc_prop_attrs) },
	{ TIPC_NLA_BEARER_DOMAIN,	NLA_KIND_U32,    4 },
	{ TIPC_NLA_BEARER_UDP_OPTS,	NLA_KIND_NESTED, 0, 0,
	  tipc_udp_attrs, ARRAY_SIZE(tipc_udp_attrs), .required = true },
};

static const struct nla_attr_spec tipc_sock_attrs[] = {
	{ TIPC_NLA_SOCK_REF,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec tipc_link_attrs[] = {
	{ TIPC_NLA_LINK_NAME,		NLA_KIND_STRING_WORD, 0, 0,
	  .word = "broadcast-link", .required = true },
	{ TIPC_NLA_LINK_PROP,		NLA_KIND_NESTED, 0, 0,
	  tipc_prop_attrs, ARRAY_SIZE(tipc_prop_attrs) },
};

/* LINK_GET's dumpit refuses a LINK nest without BROADCAST, which asks it
 * for the broadcast-receiver links as well. */
static const struct nla_attr_spec tipc_link_bcast_attrs[] = {
	{ TIPC_NLA_LINK_BROADCAST,	NLA_KIND_FLAG,   0 },
};

static const struct nla_attr_spec tipc_media_attrs[] = {
	{ TIPC_NLA_MEDIA_NAME,		NLA_KIND_STRING_WORD, 0, 0,
	  .word = "udp", .required = true },
	{ TIPC_NLA_MEDIA_PROP,		NLA_KIND_NESTED, 0, 0,
	  tipc_prop_attrs, ARRAY_SIZE(tipc_prop_attrs) },
};

/* tipc_nl_net_set() refuses a NET_ID outside 1 to 9999 and a zero
 * NET_ADDR. */
static const struct nla_attr_spec tipc_net_attrs[] = {
	{ TIPC_NLA_NET_ID,		NLA_KIND_U32_RANGE, 9999, 1 },
	{ TIPC_NLA_NET_ADDR,		NLA_KIND_U32_RANGE, UINT32_MAX, 1 },
	{ TIPC_NLA_NET_NODEID,		NLA_KIND_U64,    8 },
	{ TIPC_NLA_NET_NODEID_W1,	NLA_KIND_U64,    8 },
};

/* tipc_nl_monitor_set_threshold() refuses a threshold past
 * TIPC_CLUSTER_SIZE. */
static const struct nla_attr_spec tipc_mon_attrs[] = {
	{ TIPC_NLA_MON_ACTIVATION_THRESHOLD, NLA_KIND_U32_RANGE,
	  TIPC_CLUSTER_SIZE, 0 },
};

/* MON_PEER_GET's dumpit refuses a MON nest without REF, the bearer whose
 * monitor peers it lists. */
static const struct nla_attr_spec tipc_mon_peer_attrs[] = {
	{ TIPC_NLA_MON_REF,		NLA_KIND_U32,    4 },
};

/*
 * KEY_SET's nest, which it parses strictly against tipc_nl_node_policy.  ID
 * is at most TIPC_NODEID_LEN bytes and the handler wants that many; KEY is
 * a struct tipc_aead_key and its key, at most TIPC_AEAD_KEY_SIZE_MAX bytes.
 * The handler needs KEY or REKEYING, which a mark cannot say.
 */
static const struct nla_attr_spec tipc_node_attrs[] = {
	{ TIPC_NLA_NODE_ID,		NLA_KIND_BINARY, TIPC_NODEID_LEN,
	  TIPC_NODEID_LEN },
	{ TIPC_NLA_NODE_KEY,		NLA_KIND_BINARY, TIPC_AEAD_KEY_SIZE_MAX,
	  sizeof(struct tipc_aead_key) },
	{ TIPC_NLA_NODE_KEY_MASTER,	NLA_KIND_FLAG,   0 },
	{ TIPC_NLA_NODE_REKEYING,	NLA_KIND_U32,    4 },
};

/*
 * tipc_nl_policy, the one policy of the ops, whose validation is liberal;
 * it types nine ids NLA_NESTED, which an attribute holds empty or with
 * NLA_HDRLEN bytes at least.  Each op's handler reads one of the nests and
 * answers -EINVAL without it, or reads none, so a cmd draws from a table of
 * that nest alone or from none: what a nest takes is its namespace's own,
 * and a handler ignores the other nests.  A dump that reads nothing is
 * sent nothing.
 */
static const struct nla_attr_spec tipc_bearer_req_attrs[] = {
	{ TIPC_NLA_BEARER,		NLA_KIND_NESTED, 0, 0,
	  tipc_bearer_attrs, ARRAY_SIZE(tipc_bearer_attrs) },
};

static const struct nla_attr_spec tipc_bearer_udp_req_attrs[] = {
	{ TIPC_NLA_BEARER,		NLA_KIND_NESTED, 0, 0,
	  tipc_bearer_udp_attrs, ARRAY_SIZE(tipc_bearer_udp_attrs) },
};

static const struct nla_attr_spec tipc_sock_req_attrs[] = {
	{ TIPC_NLA_SOCK,		NLA_KIND_NESTED, 0, 0,
	  tipc_sock_attrs, ARRAY_SIZE(tipc_sock_attrs) },
};

static const struct nla_attr_spec tipc_link_req_attrs[] = {
	{ TIPC_NLA_LINK,		NLA_KIND_NESTED, 0, 0,
	  tipc_link_attrs, ARRAY_SIZE(tipc_link_attrs) },
};

static const struct nla_attr_spec tipc_link_dump_attrs[] = {
	{ TIPC_NLA_LINK,		NLA_KIND_NESTED, 0, 0,
	  tipc_link_bcast_attrs, ARRAY_SIZE(tipc_link_bcast_attrs) },
};

static const struct nla_attr_spec tipc_media_req_attrs[] = {
	{ TIPC_NLA_MEDIA,		NLA_KIND_NESTED, 0, 0,
	  tipc_media_attrs, ARRAY_SIZE(tipc_media_attrs) },
};

static const struct nla_attr_spec tipc_net_req_attrs[] = {
	{ TIPC_NLA_NET,			NLA_KIND_NESTED, 0, 0,
	  tipc_net_attrs, ARRAY_SIZE(tipc_net_attrs) },
};

static const struct nla_attr_spec tipc_mon_req_attrs[] = {
	{ TIPC_NLA_MON,			NLA_KIND_NESTED, 0, 0,
	  tipc_mon_attrs, ARRAY_SIZE(tipc_mon_attrs) },
};

static const struct nla_attr_spec tipc_mon_peer_req_attrs[] = {
	{ TIPC_NLA_MON,			NLA_KIND_NESTED, 0, 0,
	  tipc_mon_peer_attrs, ARRAY_SIZE(tipc_mon_peer_attrs) },
};

static const struct nla_attr_spec tipc_node_req_attrs[] = {
	{ TIPC_NLA_NODE,		NLA_KIND_NESTED, 0, 0,
	  tipc_node_attrs, ARRAY_SIZE(tipc_node_attrs) },
};

static const struct genl_cmd_grammar tipc_cmds[] = {
	{ TIPC_NL_BEARER_ENABLE,	"TIPC_NL_BEARER_ENABLE",
	  tipc_bearer_udp_req_attrs, ARRAY_SIZE(tipc_bearer_udp_req_attrs) },
	{ TIPC_NL_BEARER_DISABLE,	"TIPC_NL_BEARER_DISABLE",
	  tipc_bearer_req_attrs, ARRAY_SIZE(tipc_bearer_req_attrs) },
	{ TIPC_NL_BEARER_GET,		"TIPC_NL_BEARER_GET",
	  tipc_bearer_req_attrs, ARRAY_SIZE(tipc_bearer_req_attrs),
	  genl_no_attrs },
	{ TIPC_NL_BEARER_SET,		"TIPC_NL_BEARER_SET",
	  tipc_bearer_req_attrs, ARRAY_SIZE(tipc_bearer_req_attrs) },
	{ TIPC_NL_BEARER_ADD,		"TIPC_NL_BEARER_ADD",
	  tipc_bearer_udp_req_attrs, ARRAY_SIZE(tipc_bearer_udp_req_attrs) },
	{ TIPC_NL_UDP_GET_REMOTEIP,	"TIPC_NL_UDP_GET_REMOTEIP",
	  tipc_bearer_req_attrs, ARRAY_SIZE(tipc_bearer_req_attrs) },
	{ TIPC_NL_NET_GET,		"TIPC_NL_NET_GET", genl_no_attrs },
	{ TIPC_NL_NET_SET,		"TIPC_NL_NET_SET",
	  tipc_net_req_attrs, ARRAY_SIZE(tipc_net_req_attrs) },
	{ TIPC_NL_PEER_REMOVE,		"TIPC_NL_PEER_REMOVE",
	  tipc_net_req_attrs, ARRAY_SIZE(tipc_net_req_attrs) },
	{ TIPC_NL_NODE_GET,		"TIPC_NL_NODE_GET", genl_no_attrs },
	{ TIPC_NL_LINK_GET,		"TIPC_NL_LINK_GET",
	  tipc_link_req_attrs, ARRAY_SIZE(tipc_link_req_attrs),
	  tipc_link_dump_attrs, ARRAY_SIZE(tipc_link_dump_attrs) },
	{ TIPC_NL_LINK_SET,		"TIPC_NL_LINK_SET",
	  tipc_link_req_attrs, ARRAY_SIZE(tipc_link_req_attrs) },
	{ TIPC_NL_LINK_RESET_STATS,	"TIPC_NL_LINK_RESET_STATS",
	  tipc_link_req_attrs, ARRAY_SIZE(tipc_link_req_attrs) },
	{ TIPC_NL_NAME_TABLE_GET,	"TIPC_NL_NAME_TABLE_GET", genl_no_attrs },
	{ TIPC_NL_PUBL_GET,		"TIPC_NL_PUBL_GET",
	  tipc_sock_req_attrs, ARRAY_SIZE(tipc_sock_req_attrs) },
	{ TIPC_NL_SOCK_GET,		"TIPC_NL_SOCK_GET", genl_no_attrs },
	{ TIPC_NL_MEDIA_GET,		"TIPC_NL_MEDIA_GET",
	  tipc_media_req_attrs, ARRAY_SIZE(tipc_media_req_attrs),
	  genl_no_attrs },
	{ TIPC_NL_MEDIA_SET,		"TIPC_NL_MEDIA_SET",
	  tipc_media_req_attrs, ARRAY_SIZE(tipc_media_req_attrs) },
	{ TIPC_NL_MON_GET,		"TIPC_NL_MON_GET", genl_no_attrs },
	{ TIPC_NL_MON_SET,		"TIPC_NL_MON_SET",
	  tipc_mon_req_attrs, ARRAY_SIZE(tipc_mon_req_attrs) },
	{ TIPC_NL_MON_PEER_GET,		"TIPC_NL_MON_PEER_GET",
	  tipc_mon_peer_req_attrs, ARRAY_SIZE(tipc_mon_peer_req_attrs) },
	{ TIPC_NL_KEY_SET,		"TIPC_NL_KEY_SET",
	  tipc_node_req_attrs, ARRAY_SIZE(tipc_node_req_attrs) },
	{ TIPC_NL_KEY_FLUSH,		"TIPC_NL_KEY_FLUSH", genl_no_attrs },
	{ TIPC_NL_ADDR_LEGACY_GET,	"TIPC_NL_ADDR_LEGACY_GET", genl_no_attrs },
};

struct genl_family_grammar fam_tipc = {
	.name = TIPC_GENL_V2_NAME,
	.cmds = tipc_cmds,
	.n_cmds = ARRAY_SIZE(tipc_cmds),
	.default_version = TIPC_GENL_V2_VERSION,
};

#endif /* __has_include(<linux/tipc_netlink.h>) */
