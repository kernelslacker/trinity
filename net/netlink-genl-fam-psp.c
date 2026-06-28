/*
 * Genetlink family grammar: psp (PSP Security Protocol).
 *
 * The PSP module exposes its userspace control plane through a single
 * generic-netlink family ("psp") covering device enumeration / config,
 * device-key rotation, and per-socket Rx/Tx association install plus
 * device statistics retrieval.  PSP devices are netdev-attached -- the
 * in-tree probe vehicle is netdevsim with its psp shim in
 * drivers/net/netdevsim/psp.c -- so on a host without a PSP-capable
 * netdev each command bails -ENODEV after the full attribute walk
 * completes, which is the parser-level coverage spec-driven fuzzing
 * exists to provide.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-
 * assigned family_id for "psp", so the per-cmd nla_policy walkers in
 * net/psp/psp_nl.c plus the assoc-install / key-rotate dispatch
 * chains have been routinely cold under generic netlink fuzzing;
 * resolving the family at first NETLINK_GENERIC use lets the message
 * generator address real psp messages whose attribute shapes
 * plausibly survive each per-cmd policy.
 *
 * The user-callable command set covered here mirrors the
 * non-notification entries of enum psp_cmd in <linux/psp.h>:
 * DEV_GET / DEV_SET (device enumeration + version-mask config),
 * KEY_ROTATE (rotate the device key generation), RX_ASSOC / TX_ASSOC
 * (allocate or attach an Rx/Tx SA to a TCP socket fd), and GET_STATS
 * (dump the device statistics block).  DEV_SET and KEY_ROTATE are
 * CAP_NET_ADMIN gated on the kernel side, but the per-cmd nla_policy
 * walker runs before the capability check so unprivileged fuzz
 * traffic still exercises the validator.  The four *_NTF entries
 * (DEV_ADD_NTF / DEV_DEL_NTF / DEV_CHANGE_NTF / KEY_ROTATE_NTF) are
 * kernel-to-userspace multicast events with no .doit / .dumpit handler
 * and are omitted from cmds[].
 *
 * Per the team / l2tp / wireguard model, a single flat nla_attr_spec
 * table lists every id used by any nest reachable from this family's
 * commands.  The four nests in play (DEV / ASSOC / KEYS / STATS) all
 * restart their attribute numbering at 1, so the same numeric id
 * recurs across namespaces (PSP_A_DEV_ID = PSP_A_ASSOC_DEV_ID =
 * PSP_A_KEYS_KEY = PSP_A_STATS_DEV_ID = 1, etc.).  The kernel only
 * validates each child against the policy of whichever nest is
 * currently being walked, so the collisions are harmless and the
 * single flat table is the same shape team / l2tp / wireguard use.
 *
 * Attribute kinds follow the YAML in Documentation/netlink/specs/
 * psp.yaml.  Most ids are u32 scalars (device ids, ifindex, version
 * masks, association version, sock fd, SPI).  The four nested entries
 * (RX_KEY / TX_KEY in the ASSOC namespace, plus the KEYS-namespace
 * KEY blob and the STATS-namespace u64 counters) are emitted as empty
 * NLA_KIND_NESTED containers following the psample-TUNNEL precedent
 * so the kernel's nla_validate accepts them at the outer level
 * without recursing into a per-key sub-policy.  PSP_A_KEYS_KEY is a
 * variable-length binary blob (the actual key bytes), bounded above
 * at 64 so a single greedy entry can't eat the whole netlink buffer.
 * The PSP_A_STATS_* device counters are u64 wire scalars (UAPI calls
 * them "uint"); listing them here exercises the GET_STATS reply
 * shape that the validator's "ignore on input" branch silently
 * tolerates, the same way the fou / psample / handshake reply-side
 * attrs do.
 *
 * The family carries a nonzero declared version
 * (PSP_FAMILY_VERSION = 1) so the default_version member is
 * initialised -- the kernel's dispatcher doesn't gate on the
 * genlmsghdr.version byte today, but matching the declared family
 * version keeps the message generator honest against any future
 * version-gated dispatch.  hdrsize stays 0: psp has no
 * family-specific fixed header, attributes follow the genlmsghdr
 * directly.
 *
 * Header gating mirrors the handshake / dpll / ovpn families:
 * include/kernel/psp.h wraps the upstream UAPI header with per-symbol
 * #ifndef shims so build hosts whose installed uapi predates this
 * family still compile.  The shim is shared with childops/psp-key-
 * rotate.c -- additive only, leaves the symbols that childop already
 * depends on untouched.
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
