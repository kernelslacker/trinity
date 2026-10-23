/*
 * Genetlink family grammar: ovpn (OpenVPN data-channel offload), targeting
 * drivers/net/ovpn/netlink-gen.c and the handlers beside it.  All eight ops
 * are GENL_ADMIN_PERM; only the top-level OVPN_A_* namespace is listed.
 */

/* Keeps the TU non-empty when the guard below drops the family. */
#include "arch.h"

#if __has_include(<linux/ovpn.h>)

#include "kernel/ovpn.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * ovpn exposes eight user-callable commands: a four-command peer
 * lifecycle (NEW / SET / GET / DEL) and a four-command symmetric-key
 * lifecycle (NEW / GET / SWAP / DEL).  All eight are GENL_ADMIN_PERM,
 * which the genl core checks before the nla_policy walker runs, so
 * listing all eight ids exercises every per-cmd parser symmetrically
 * for a child that passes that check.  The two *_NTF notification ids
 * (PEER_DEL_NTF, KEY_SWAP_NTF) are kernel-to-userspace only and the
 * dispatcher rejects them on input — they are omitted by design.
 */
static const struct genl_cmd_grammar ovpn_cmds[] = {
	{ OVPN_CMD_PEER_NEW,	"OVPN_CMD_PEER_NEW" },
	{ OVPN_CMD_PEER_SET,	"OVPN_CMD_PEER_SET" },
	{ OVPN_CMD_PEER_GET,	"OVPN_CMD_PEER_GET" },
	{ OVPN_CMD_PEER_DEL,	"OVPN_CMD_PEER_DEL" },
	{ OVPN_CMD_KEY_NEW,	"OVPN_CMD_KEY_NEW" },
	{ OVPN_CMD_KEY_GET,	"OVPN_CMD_KEY_GET" },
	{ OVPN_CMD_KEY_SWAP,	"OVPN_CMD_KEY_SWAP" },
	{ OVPN_CMD_KEY_DEL,	"OVPN_CMD_KEY_DEL" },
};

/*
 * Attribute spec follows the top-level OVPN_A_* enum in <linux/ovpn.h>.
 * IFINDEX is a u32 ovpn-device netdev selector that every command keys
 * on.  PEER and KEYCONF are the two nested attrs, NLA_POLICY_NESTED in
 * every doit policy (drivers/net/ovpn/netlink-gen.c), so the kernel
 * checks the children the generator draws from this table against the
 * inner OVPN_A_PEER_* / OVPN_A_KEYCONF_* policy by id.  Those enums
 * and OVPN_A_KEYDIR_* share id 1..N with the top-level OVPN_A_*
 * namespace and a single flat table cannot disambiguate the
 * overlapping keys, so they are not enumerated here.
 */
static const struct nla_attr_spec ovpn_attrs[] = {
	{ OVPN_A_IFINDEX,	NLA_KIND_U32,    4 },
	{ OVPN_A_PEER,		NLA_KIND_NESTED, 0 },
	{ OVPN_A_KEYCONF,	NLA_KIND_NESTED, 0 },
};

struct genl_family_grammar fam_ovpn = {
	.name = OVPN_FAMILY_NAME,
	.cmds = ovpn_cmds,
	.n_cmds = ARRAY_SIZE(ovpn_cmds),
	.attrs = ovpn_attrs,
	.n_attrs = ARRAY_SIZE(ovpn_attrs),
	.default_version = OVPN_FAMILY_VERSION,
};

#endif /* __has_include(<linux/ovpn.h>) */
