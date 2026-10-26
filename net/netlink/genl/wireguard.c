/*
 * Genetlink family grammar: wireguard, targeting
 * drivers/net/wireguard/netlink.c and its generated policy in
 * drivers/net/wireguard/generated/netlink.c.  Both ops are
 * GENL_UNS_ADMIN_PERM.  SET_DEVICE walks the nested PEERS / ALLOWEDIPS
 * tree and feeds wg_allowedips_insert_v4 / _v6.
 */

#if __has_include(<linux/wireguard.h>)

#include <linux/wireguard.h>

#include "netlink-genl-families.h"
#include "utils.h"

#include "kernel/wireguard.h"

/*
 * The ops validate strictly, and each nest's policy reuses ids 1 to 4 for
 * other types: WGDEVICE_A_IFINDEX, WGPEER_A_PUBLIC_KEY and
 * WGALLOWEDIP_A_FAMILY are all id 1.  So each level is a table, and PEERS
 * and ALLOWEDIPS, which are NLA_POLICY_NESTED_ARRAY, are arrays of elements
 * that each hold a stream of the next level down.
 *
 * The keys and LAST_HANDSHAKE_TIME are NLA_POLICY_EXACT_LEN.  ENDPOINT and
 * IPADDR are NLA_POLICY_MIN_LEN, but set_peer() takes only a sockaddr_in or
 * sockaddr_in6 (16 or 28 bytes) and set_allowedip() only 4 or 16, the
 * triple of family, ipaddr and cidr that feeds wg_allowedips_insert_v4/v6.
 * The FLAGS words are masks, which are not shaped.
 */
static const struct nla_attr_spec wireguard_allowedip_attrs[] = {
	{ WGALLOWEDIP_A_FAMILY,		NLA_KIND_U16,    2 },
	{ WGALLOWEDIP_A_IPADDR,		NLA_KIND_BINARY_FIXED2, 16, 4 },
	{ WGALLOWEDIP_A_CIDR_MASK,	NLA_KIND_U8,     1 },
	{ WGALLOWEDIP_A_FLAGS,		NLA_KIND_U32,    4 },
};

static const struct nla_attr_spec wireguard_peer_attrs[] = {
	{ WGPEER_A_PUBLIC_KEY,		NLA_KIND_BINARY_FIXED2, WG_KEY_LEN, WG_KEY_LEN },
	{ WGPEER_A_PRESHARED_KEY,	NLA_KIND_BINARY_FIXED2, WG_KEY_LEN, WG_KEY_LEN },
	{ WGPEER_A_FLAGS,		NLA_KIND_U32,    4 },
	{ WGPEER_A_ENDPOINT,		NLA_KIND_BINARY_FIXED2, 28, 16 },
	{ WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, NLA_KIND_U16, 2 },
	{ WGPEER_A_LAST_HANDSHAKE_TIME,	NLA_KIND_BINARY_FIXED2, 16, 16 },
	{ WGPEER_A_RX_BYTES,		NLA_KIND_U64,    8 },
	{ WGPEER_A_TX_BYTES,		NLA_KIND_U64,    8 },
	{ WGPEER_A_ALLOWEDIPS,		NLA_KIND_NESTED_ARRAY, 0, 0,
	  wireguard_allowedip_attrs, ARRAY_SIZE(wireguard_allowedip_attrs) },
	{ WGPEER_A_PROTOCOL_VERSION,	NLA_KIND_U32,    4 },
};

/* IFNAME is an NLA_NUL_STRING of at most IFNAMSIZ - 1 bytes. */
static const struct nla_attr_spec wireguard_get_device_attrs[] = {
	{ WGDEVICE_A_IFINDEX,		NLA_KIND_U32,    4 },
	{ WGDEVICE_A_IFNAME,		NLA_KIND_STRING, 15, 1 },
};

static const struct nla_attr_spec wireguard_set_device_attrs[] = {
	{ WGDEVICE_A_IFINDEX,		NLA_KIND_U32,    4 },
	{ WGDEVICE_A_IFNAME,		NLA_KIND_STRING, 15, 1 },
	{ WGDEVICE_A_PRIVATE_KEY,	NLA_KIND_BINARY_FIXED2, WG_KEY_LEN, WG_KEY_LEN },
	{ WGDEVICE_A_PUBLIC_KEY,	NLA_KIND_BINARY_FIXED2, WG_KEY_LEN, WG_KEY_LEN },
	{ WGDEVICE_A_FLAGS,		NLA_KIND_U32,    4 },
	{ WGDEVICE_A_LISTEN_PORT,	NLA_KIND_U16,    2 },
	{ WGDEVICE_A_FWMARK,		NLA_KIND_U32,    4 },
	{ WGDEVICE_A_PEERS,		NLA_KIND_NESTED_ARRAY, 0, 0,
	  wireguard_peer_attrs, ARRAY_SIZE(wireguard_peer_attrs) },
};

/*
 * GET_DEVICE is a dump and its policy ends at IFNAME, so the keys and the
 * peers a flat table drew for it were an -EINVAL.
 */
static const struct genl_cmd_grammar wireguard_cmds[] = {
	{ WG_CMD_GET_DEVICE, "WG_CMD_GET_DEVICE",
	  wireguard_get_device_attrs, ARRAY_SIZE(wireguard_get_device_attrs) },
	{ WG_CMD_SET_DEVICE, "WG_CMD_SET_DEVICE",
	  wireguard_set_device_attrs, ARRAY_SIZE(wireguard_set_device_attrs) },
};

struct genl_family_grammar fam_wireguard = {
	.name = WG_GENL_NAME,
	.cmds = wireguard_cmds,
	.n_cmds = ARRAY_SIZE(wireguard_cmds),
	.default_version = WG_GENL_VERSION,
};

#endif /* __has_include(<linux/wireguard.h>) */
