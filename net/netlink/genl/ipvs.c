/*
 * Genetlink family grammar: IPVS (IP Virtual Server), targeting
 * ip_vs_genl_ops in net/netfilter/ipvs/ip_vs_ctl.c.  Only the read-side
 * GET_* commands are listed: the mutators would tear down live virtual
 * services and destinations.  Every op is GENL_ADMIN_PERM.
 */

#if __has_include(<linux/ip_vs.h>)

#include "kernel/ip_vs.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * IPVS_CMD_SET_INFO only labels the GET_INFO reply and is not an op, so
 * it is not listed.
 */
static const struct genl_cmd_grammar ipvs_cmds[] = {
	{ IPVS_CMD_GET_SERVICE,	"IPVS_CMD_GET_SERVICE" },
	{ IPVS_CMD_GET_DEST,	"IPVS_CMD_GET_DEST" },
	{ IPVS_CMD_GET_DAEMON,	"IPVS_CMD_GET_DAEMON" },
	{ IPVS_CMD_GET_CONFIG,	"IPVS_CMD_GET_CONFIG" },
	{ IPVS_CMD_GET_INFO,	"IPVS_CMD_GET_INFO" },
};

/*
 * Attribute spec follows the IPVS_CMD_ATTR_* enum in <linux/ip_vs.h>.
 * SERVICE / DEST / DAEMON are bare NLA_NESTED in ip_vs_cmd_policy, so
 * nla_validate does not recurse into them; the handlers parse each with
 * nla_parse_nested_deprecated() against ip_vs_svc_policy /
 * ip_vs_dest_policy / ip_vs_daemon_policy.  Of the listed commands only
 * GET_SERVICE (doit) and GET_DEST (dump) read a nest: SERVICE must name
 * a service (AF plus a fwmark, or protocol, address and port) or the
 * doit fails with -EINVAL and the dump is empty.  DEST and DAEMON are
 * read only by the mutators this table leaves out.  TIMEOUT_TCP /
 * TIMEOUT_TCP_FIN / TIMEOUT_UDP are u32 second counts the
 * GET_CONFIG path emits on dump and SET_CONFIG validates on input;
 * listing them here exercises the validator's ignore-on-input branch
 * for GET_CONFIG the same way the OVS dp/flow STATS attrs do.
 */
static const struct nla_attr_spec ipvs_attrs[] = {
	{ IPVS_CMD_ATTR_SERVICE,	NLA_KIND_NESTED, 0 },
	{ IPVS_CMD_ATTR_DEST,		NLA_KIND_NESTED, 0 },
	{ IPVS_CMD_ATTR_DAEMON,		NLA_KIND_NESTED, 0 },
	{ IPVS_CMD_ATTR_TIMEOUT_TCP,	NLA_KIND_U32,    4 },
	{ IPVS_CMD_ATTR_TIMEOUT_TCP_FIN, NLA_KIND_U32,   4 },
	{ IPVS_CMD_ATTR_TIMEOUT_UDP,	NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_ipvs = {
	.name = "IPVS",
	.cmds = ipvs_cmds,
	.n_cmds = ARRAY_SIZE(ipvs_cmds),
	.attrs = ipvs_attrs,
	.n_attrs = ARRAY_SIZE(ipvs_attrs),
};

#endif /* __has_include(<linux/ip_vs.h>) */
