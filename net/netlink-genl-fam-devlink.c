/*
 * Genetlink family grammar: devlink.
 *
 * devlink is the configuration interface for hardware switches, NICs,
 * and bus-level devices.  It carries ~80 commands and ~190 attribute
 * types behind the "devlink" generic netlink family.  Even a small
 * grammar reaches a substantial slice of net/devlink/ that the
 * random-id netlink fuzzer never touches: the family's nla_policy
 * gate validates the BUS_NAME / DEV_NAME pair and dispatches into
 * dev.c, port.c, sb.c, and the param/region/info/health subsystems.
 *
 * Starter command set covers the dump-able read-side variants
 * (DEVLINK_CMD_*_GET) for the four most-trafficked subgroups: device
 * itself, ports, params, and regions.  Write-side commands (NEW/SET/
 * DEL) require admin perms in most cases and are left for a follow-up
 * once the read paths are stably exercised.
 */

#include <linux/devlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

static const struct genl_cmd_grammar devlink_cmds[] = {
	{ DEVLINK_CMD_GET,        "DEVLINK_CMD_GET" },
	{ DEVLINK_CMD_PORT_GET,   "DEVLINK_CMD_PORT_GET" },
	{ DEVLINK_CMD_SB_GET,     "DEVLINK_CMD_SB_GET" },
	{ DEVLINK_CMD_PARAM_GET,  "DEVLINK_CMD_PARAM_GET" },
	{ DEVLINK_CMD_REGION_GET, "DEVLINK_CMD_REGION_GET" },
	{ DEVLINK_CMD_INFO_GET,   "DEVLINK_CMD_INFO_GET" },
};

/*
 * Attribute spec table: the identifying string/index pair that every
 * devlink command needs (BUS_NAME + DEV_NAME), plus the per-subgroup
 * selector each starter command branches on.  Lengths follow the
 * kernel's NLA_NUL_STRING policy entries; 32 is well under the
 * driver-side limits and matches typical "pci/0000:01:00.0" payloads
 * with room to spare.
 */
static const struct nla_attr_spec devlink_attrs[] = {
	{ DEVLINK_ATTR_BUS_NAME,             NLA_KIND_STRING, 32 },
	{ DEVLINK_ATTR_DEV_NAME,             NLA_KIND_STRING, 32 },
	{ DEVLINK_ATTR_PORT_INDEX,           NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_PORT_TYPE,            NLA_KIND_U16,    2 },
	{ DEVLINK_ATTR_SB_INDEX,             NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_SB_POOL_INDEX,        NLA_KIND_U16,    2 },
	{ DEVLINK_ATTR_SB_POOL_TYPE,         NLA_KIND_U8,     1 },
	{ DEVLINK_ATTR_PARAM_NAME,           NLA_KIND_STRING, 32 },
	{ DEVLINK_ATTR_REGION_NAME,          NLA_KIND_STRING, 32 },
	{ DEVLINK_ATTR_REGION_SNAPSHOT_ID,   NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_NETNS_FD,             NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_NETNS_PID,            NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_NETNS_ID,             NLA_KIND_U32,    4 },
};

struct genl_family_grammar fam_devlink = {
	.name = DEVLINK_GENL_NAME,
	.cmds = devlink_cmds,
	.n_cmds = ARRAY_SIZE(devlink_cmds),
	.attrs = devlink_attrs,
	.n_attrs = ARRAY_SIZE(devlink_attrs),
	.default_version = DEVLINK_GENL_VERSION,
};
