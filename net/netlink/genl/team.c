/*
 * Genetlink family grammar: team (NET_TEAM driver).
 *
 * The NET_TEAM link-aggregation driver exposes its userspace control
 * plane through a single generic-netlink family ("team") with four
 * user-callable commands: TEAM_CMD_NOOP, TEAM_CMD_OPTIONS_SET,
 * TEAM_CMD_OPTIONS_GET, and TEAM_CMD_PORT_LIST_GET.  Every cmd gates
 * on TEAM_ATTR_TEAM_IFINDEX referencing an existing team netdev; on
 * a host with no team device every path bails -ENODEV after the
 * full attribute walk completes — that's the parser-level coverage
 * spec-driven fuzzing exists to provide.
 *
 * Random nlmsg_type IDs essentially never matched the runtime-
 * assigned family_id for "team", so the per-cmd nla_policy walkers
 * in drivers/net/team/team_nl.c plus the option/port nest validators
 * have been routinely cold under generic netlink fuzzing; resolving
 * the family at first NETLINK_GENERIC use lets the message generator
 * address real team messages whose attribute shapes plausibly survive
 * each per-cmd policy.
 *
 * Per the wireguard / tipc / l2tp model, a single flat nla_attr_spec
 * table lists every id used by any nest reachable from this family's
 * commands.  The five nests in play are:
 *   TEAM_ATTR_*           outer (TEAM_IFINDEX + LIST_OPTION + LIST_PORT)
 *   TEAM_ATTR_ITEM_OPTION_* container under TEAM_ATTR_LIST_OPTION
 *   TEAM_ATTR_OPTION_*    inner under TEAM_ATTR_ITEM_OPTION
 *   TEAM_ATTR_ITEM_PORT_* container under TEAM_ATTR_LIST_PORT
 *   TEAM_ATTR_PORT_*      inner under TEAM_ATTR_ITEM_PORT
 * Numeric ids collide across these namespaces (TEAM_ATTR_ITEM_OPTION=1
 * vs TEAM_ATTR_OPTION_NAME=1 vs TEAM_ATTR_PORT_IFINDEX=1, etc.) but
 * the kernel only validates each child against the policy of whichever
 * nest is currently being walked, so the collisions are harmless and
 * the single flat table is the same shape wireguard / tipc / l2tp use.
 *
 * Header gating mirrors the wireguard family: <linux/if_team.h> is
 * the upstream UAPI header carrying TEAM_GENL_NAME plus every
 * TEAM_CMD_* and TEAM_ATTR_* enum referenced below.  Build hosts
 * lacking the header silently drop the family from the registry
 * instead of failing the build.
 */

#if __has_include(<linux/if_team.h>)

#include <linux/if_team.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar team_cmds[] = {
	{ TEAM_CMD_NOOP,		"TEAM_CMD_NOOP" },
	{ TEAM_CMD_OPTIONS_SET,		"TEAM_CMD_OPTIONS_SET" },
	{ TEAM_CMD_OPTIONS_GET,		"TEAM_CMD_OPTIONS_GET" },
	{ TEAM_CMD_PORT_LIST_GET,	"TEAM_CMD_PORT_LIST_GET" },
};

/*
 * Attribute spec follows the per-nest enums in <linux/if_team.h>.
 * Outer TEAM_ATTR_* carries the TEAM_IFINDEX selector consumed by
 * every cmd and the two NESTED list containers (LIST_OPTION /
 * LIST_PORT) that open the option- and port-tree sub-namespaces.
 * The container nests (ITEM_OPTION / ITEM_PORT) hold a single
 * NESTED child each, which in turn opens the per-option /
 * per-port attribute namespace where the name, type, data, and
 * port-state scalars actually live.
 *
 * Variable-length sizes:
 *   OPTION_NAME      TEAM_STRING_MAX_LEN - 1 (NUL-terminated upper bound)
 *   OPTION_DATA      TEAM_STRING_MAX_LEN (kernel accepts u8/u32/string/binary
 *                    payloads; the upper bound here covers the string case)
 */
static const struct nla_attr_spec team_attrs[] = {
	/* TEAM_ATTR_* — outer */
	{ TEAM_ATTR_TEAM_IFINDEX,		NLA_KIND_U32,    4 },
	{ TEAM_ATTR_LIST_OPTION,		NLA_KIND_NESTED, 0 },
	{ TEAM_ATTR_LIST_PORT,			NLA_KIND_NESTED, 0 },

	/* TEAM_ATTR_ITEM_OPTION_* — container under LIST_OPTION.  IDs
	 * intentionally overlap with the outer and inner namespaces; the
	 * kernel only matches each child against the policy of the
	 * currently-walked nest, so collisions are harmless. */
	{ TEAM_ATTR_ITEM_OPTION,		NLA_KIND_NESTED, 0 },

	/* TEAM_ATTR_OPTION_* — inner under ITEM_OPTION */
	{ TEAM_ATTR_OPTION_NAME,		NLA_KIND_STRING, TEAM_STRING_MAX_LEN - 1 },
	{ TEAM_ATTR_OPTION_CHANGED,		NLA_KIND_FLAG,   0 },
	{ TEAM_ATTR_OPTION_TYPE,		NLA_KIND_U8,     1 },
	{ TEAM_ATTR_OPTION_DATA,		NLA_KIND_BINARY, TEAM_STRING_MAX_LEN },
	{ TEAM_ATTR_OPTION_REMOVED,		NLA_KIND_FLAG,   0 },
	{ TEAM_ATTR_OPTION_PORT_IFINDEX,	NLA_KIND_U32,    4 },
	{ TEAM_ATTR_OPTION_ARRAY_INDEX,		NLA_KIND_U32,    4 },

	/* TEAM_ATTR_ITEM_PORT_* — container under LIST_PORT */
	{ TEAM_ATTR_ITEM_PORT,			NLA_KIND_NESTED, 0 },

	/* TEAM_ATTR_PORT_* — inner under ITEM_PORT */
	{ TEAM_ATTR_PORT_IFINDEX,		NLA_KIND_U32,    4 },
	{ TEAM_ATTR_PORT_CHANGED,		NLA_KIND_FLAG,   0 },
	{ TEAM_ATTR_PORT_LINKUP,		NLA_KIND_FLAG,   0 },
	{ TEAM_ATTR_PORT_SPEED,			NLA_KIND_U32,    4 },
	{ TEAM_ATTR_PORT_DUPLEX,		NLA_KIND_U8,     1 },
	{ TEAM_ATTR_PORT_REMOVED,		NLA_KIND_FLAG,   0 },
};

struct genl_family_grammar fam_team = {
	.name = TEAM_GENL_NAME,
	.cmds = team_cmds,
	.n_cmds = ARRAY_SIZE(team_cmds),
	.attrs = team_attrs,
	.n_attrs = ARRAY_SIZE(team_attrs),
	.default_version = TEAM_GENL_VERSION,
};

#endif /* __has_include(<linux/if_team.h>) */
