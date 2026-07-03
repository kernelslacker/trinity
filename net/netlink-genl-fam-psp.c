/*
 * Genetlink family grammar: psp (PSP Security Protocol).
 *
 * Target: the per-cmd nla_policy walkers in net/psp/psp_nl.c plus the
 * assoc-install and key-rotate dispatch chains.  Random nlmsg_type
 * ids essentially never matched the runtime-assigned "psp" family_id,
 * so these arms stayed cold; resolving the family once at first
 * NETLINK_GENERIC use lets the generator address real psp commands
 * whose attribute shapes plausibly survive each per-cmd policy.
 *
 * PSP devices are netdev-attached (in-tree probe vehicle is netdevsim
 * with its psp shim in drivers/net/netdevsim/psp.c) so on a host
 * without a PSP-capable netdev each command bails -ENODEV after the
 * full attribute walk -- which is the parser-level coverage this
 * grammar exists to provide.  DEV_SET and KEY_ROTATE are
 * CAP_NET_ADMIN gated, but the per-cmd policy walker runs before the
 * capability check so unprivileged traffic still exercises the
 * validator.
 *
 * Flat attribute table.  The four nests (DEV / ASSOC / KEYS / STATS)
 * all restart their attribute numbering at 1, so the same numeric id
 * recurs across namespaces -- collisions are harmless because the
 * kernel only validates each child against whichever nest is
 * currently being walked.  RX_KEY / TX_KEY (ASSOC) plus the
 * KEYS-namespace KEY blob and STATS-namespace u64 counters are
 * emitted as empty NLA_KIND_NESTED containers so nla_validate accepts
 * them at the outer level without recursing.  PSP_A_KEYS_KEY is a
 * variable-length binary blob bounded above at 64 so a single greedy
 * entry can't eat the whole netlink buffer.
 *
 * Header gating: include/kernel/psp.h wraps the upstream UAPI header
 * with per-symbol #ifndef shims so build hosts whose installed uapi
 * predates this family still compile.  Shim is shared with
 * childops/psp-key-rotate.c -- additive only, leaves symbols the
 * childop already depends on untouched.
 */

#include "kernel/psp.h"
#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar psp_cmds[] = {
	{ PSP_CMD_DEV_GET,	"PSP_CMD_DEV_GET" },
	{ PSP_CMD_DEV_SET,	"PSP_CMD_DEV_SET" },
	{ PSP_CMD_KEY_ROTATE,	"PSP_CMD_KEY_ROTATE" },
	{ PSP_CMD_RX_ASSOC,	"PSP_CMD_RX_ASSOC" },
	{ PSP_CMD_TX_ASSOC,	"PSP_CMD_TX_ASSOC" },
	{ PSP_CMD_GET_STATS,	"PSP_CMD_GET_STATS" },
};

/*
 * Attribute spec follows the per-nest enums in <linux/psp.h>.
 * Numeric ids intentionally overlap across the four namespaces; the
 * kernel only matches each child against the policy of the currently-
 * walked nest, so collisions are harmless under the team / l2tp /
 * wireguard precedent.  The empty-container NLA_KIND_NESTED entries
 * keep nla_validate from recursing into a sub-policy the flat table
 * cannot describe.
 */
static const struct nla_attr_spec psp_attrs[] = {
	/* PSP_A_DEV_* -- DEV_GET / DEV_SET selector + reply payload */
	{ PSP_A_DEV_ID,			NLA_KIND_U32,    4 },
	{ PSP_A_DEV_IFINDEX,		NLA_KIND_U32,    4 },
	{ PSP_A_DEV_PSP_VERSIONS_CAP,	NLA_KIND_U32,    4 },
	{ PSP_A_DEV_PSP_VERSIONS_ENA,	NLA_KIND_U32,    4 },

	/* PSP_A_ASSOC_* -- RX_ASSOC / TX_ASSOC request + reply payload */
	{ PSP_A_ASSOC_DEV_ID,		NLA_KIND_U32,    4 },
	{ PSP_A_ASSOC_VERSION,		NLA_KIND_U32,    4 },
	{ PSP_A_ASSOC_RX_KEY,		NLA_KIND_NESTED, 0 },
	{ PSP_A_ASSOC_TX_KEY,		NLA_KIND_NESTED, 0 },
	{ PSP_A_ASSOC_SOCK_FD,		NLA_KIND_U32,    4 },

	/* PSP_A_KEYS_* -- nested under RX_KEY / TX_KEY containers above */
	{ PSP_A_KEYS_KEY,		NLA_KIND_BINARY, 64 },
	{ PSP_A_KEYS_SPI,		NLA_KIND_U32,    4 },

	/* PSP_A_STATS_* -- GET_STATS reply payload (device counters) */
	{ PSP_A_STATS_DEV_ID,		NLA_KIND_U32,    4 },
	{ PSP_A_STATS_KEY_ROTATIONS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_STALE_EVENTS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_PACKETS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_BYTES,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_AUTH_FAIL,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_ERROR,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_RX_BAD,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_TX_PACKETS,	NLA_KIND_U64,    8 },
	{ PSP_A_STATS_TX_BYTES,		NLA_KIND_U64,    8 },
	{ PSP_A_STATS_TX_ERROR,		NLA_KIND_U64,    8 },
};

struct genl_family_grammar fam_psp = {
	.name = PSP_FAMILY_NAME,
	.cmds = psp_cmds,
	.n_cmds = ARRAY_SIZE(psp_cmds),
	.attrs = psp_attrs,
	.n_attrs = ARRAY_SIZE(psp_attrs),
	.default_version = PSP_FAMILY_VERSION,
};
