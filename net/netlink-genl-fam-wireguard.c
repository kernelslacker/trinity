/*
 * Genetlink family grammar: wireguard.
 *
 * The WireGuard tunnel control plane is a single generic-netlink family
 * (WG_GENL_NAME = "wireguard") with just two commands: GET_DEVICE and
 * SET_DEVICE.  The interesting surface area is the deeply nested
 * attribute tree the kernel parses on SET — drivers/net/wireguard/netlink.c
 * walks WGDEVICE_A_PEERS (a list of WGPEER_A_* nests), and inside each
 * peer it walks WGPEER_A_ALLOWEDIPS (a list of WGALLOWEDIP_A_* nests).
 * The per-allowedip handler then feeds the family/ipaddr/cidr triple to
 * wg_allowedips_insert_v4 / wg_allowedips_insert_v6, which mutate a
 * shared radix trie — a parser path that's never been routinely fuzzed
 * because random nlmsg_type IDs essentially never match the runtime
 * family_id the kernel assigns this family.
 *
 * Spec-driven coverage flips that around: at first NETLINK_GENERIC use
 * the controller dump resolves "wireguard" -> family_id, and from then
 * on the message generator addresses real WG messages whose attribute
 * shapes plausibly survive the per-cmd policy.  Random IFINDEX values
 * cause the post-parse handler to bail with -ENODEV, but that's after
 * the full attribute tree has been walked, so coverage of the parser
 * (and the radix-tree insert in the SET path) is preserved.
 *
 * Per-namespace attribute IDs collide across the three nests
 * (WGDEVICE_A_IFINDEX = WGPEER_A_PUBLIC_KEY = WGALLOWEDIP_A_FAMILY = 1,
 * etc.) but the kernel only validates each child against the policy of
 * whichever nest is currently being parsed, so the single flat spec
 * table below is the same shape tipc and mptcp_pm use.
 *
 * Header gating mirrors the mptcp_pm family: <linux/wireguard.h> is the
 * upstream UAPI header that ships with kernel headers from 5.6 onward.
 * Older build hosts silently drop the family from the registry instead
 * of failing the build.
 */

#if __has_include(<linux/wireguard.h>)

#include <linux/wireguard.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar wireguard_cmds[] = {
	{ WG_CMD_GET_DEVICE, "WG_CMD_GET_DEVICE" },
	{ WG_CMD_SET_DEVICE, "WG_CMD_SET_DEVICE" },
};

/*
 * Attribute spec follows the per-nest enums in <linux/wireguard.h>.
 * Outer (WGDEVICE_A_*) carries the device selector + key/port/fwmark
 * scalars and the WGDEVICE_A_PEERS NESTED list.  Inner peer (WGPEER_A_*)
 * carries per-peer key material, the ENDPOINT sockaddr blob, and the
 * WGPEER_A_ALLOWEDIPS NESTED list.  Innermost allowedip (WGALLOWEDIP_A_*)
 * carries family/ipaddr/cidr — the trio that drives the radix-tree
 * insert in wg_allowedips_insert_v4/v6.
 *
 * Variable-length sizes:
 *   IFNAME           IFNAMSIZ - 1 (NUL_STRING upper bound)
 *   PRIVATE/PUBLIC/PRESHARED_KEY  WG_KEY_LEN (32, EXACT_LEN)
 *   ENDPOINT         28 (max of sockaddr_in 16, sockaddr_in6 28)
 *   LAST_HANDSHAKE_TIME           16 (struct __kernel_timespec)
 *   IPADDR           16 (max of in_addr 4, in6_addr 16)
 */
static const struct nla_attr_spec wireguard_attrs[] = {
	/* WGDEVICE_A_* — top-level for both GET and SET */
	{ WGDEVICE_A_IFINDEX,			NLA_KIND_U32,    4 },
	{ WGDEVICE_A_IFNAME,			NLA_KIND_STRING, 15 },
	{ WGDEVICE_A_PRIVATE_KEY,		NLA_KIND_BINARY, WG_KEY_LEN },
	{ WGDEVICE_A_PUBLIC_KEY,		NLA_KIND_BINARY, WG_KEY_LEN },
	{ WGDEVICE_A_FLAGS,			NLA_KIND_U32,    4 },
	{ WGDEVICE_A_LISTEN_PORT,		NLA_KIND_U16,    2 },
	{ WGDEVICE_A_FWMARK,			NLA_KIND_U32,    4 },
	{ WGDEVICE_A_PEERS,			NLA_KIND_NESTED, 0 },

	/* WGPEER_A_* — inner.  IDs intentionally overlap with WGDEVICE_A_*;
	 * the kernel only matches each child against the policy of the
	 * currently-walked nest, so collisions are harmless. */
	{ WGPEER_A_PUBLIC_KEY,			NLA_KIND_BINARY, WG_KEY_LEN },
	{ WGPEER_A_PRESHARED_KEY,		NLA_KIND_BINARY, WG_KEY_LEN },
	{ WGPEER_A_FLAGS,			NLA_KIND_U32,    4 },
	{ WGPEER_A_ENDPOINT,			NLA_KIND_BINARY, 28 },
	{ WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, NLA_KIND_U16, 2 },
	{ WGPEER_A_LAST_HANDSHAKE_TIME,		NLA_KIND_BINARY, 16 },
	{ WGPEER_A_RX_BYTES,			NLA_KIND_U64,    8 },
	{ WGPEER_A_TX_BYTES,			NLA_KIND_U64,    8 },
	{ WGPEER_A_ALLOWEDIPS,			NLA_KIND_NESTED, 0 },
	{ WGPEER_A_PROTOCOL_VERSION,		NLA_KIND_U32,    4 },

	/* WGALLOWEDIP_A_* — innermost.  family + ipaddr + cidr is the
	 * triple consumed by wg_allowedips_insert_v4/v6, the trie mutator
	 * that's the highest-value target reachable through this family. */
	{ WGALLOWEDIP_A_FAMILY,			NLA_KIND_U16,    2 },
	{ WGALLOWEDIP_A_IPADDR,			NLA_KIND_BINARY, 16 },
	{ WGALLOWEDIP_A_CIDR_MASK,		NLA_KIND_U8,     1 },
	{ WGALLOWEDIP_A_FLAGS,			NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_wireguard = {
	.name = WG_GENL_NAME,
	.cmds = wireguard_cmds,
	.n_cmds = ARRAY_SIZE(wireguard_cmds),
	.attrs = wireguard_attrs,
	.n_attrs = ARRAY_SIZE(wireguard_attrs),
	.default_version = WG_GENL_VERSION,
};

#endif /* __has_include(<linux/wireguard.h>) */
