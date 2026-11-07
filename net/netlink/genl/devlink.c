/*
 * Genetlink family grammar: devlink (hardware switch, NIC and bus-device
 * configuration), targeting net/devlink/ and its per-op policies in
 * net/devlink/netlink_gen.c.  Only the unprivileged *_GET commands are
 * listed, keyed on the BUS_NAME / DEV_NAME pair; the NEW / SET / DEL
 * writers are GENL_ADMIN_PERM.
 */

#include <linux/devlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Each op takes the table of its own policy.  The doits validate
 * liberally, but the dumpits of PORT_GET, SB_GET, PARAM_GET and REGION_GET
 * strictly, refusing an id their policy has no slot for, and those of GET
 * and INFO_GET have no policy, which the genl core makes a reject-all one.
 * A doit's pre_doit answers -EINVAL without both names, PORT_GET's without
 * the port's index, and the handlers of SB_GET, PARAM_GET and REGION_GET
 * without the SB index, the param's name and the region's; a dump without
 * the names walks every instance.  Lengths follow the kernel's
 * NLA_NUL_STRING policy entries; 32 is well under the driver-side limits
 * and matches typical "pci/0000:01:00.0" payloads with room to spare.
 * DEVLINK_ATTR_INDEX, which every policy takes too, is an enum value only
 * the newest uapi headers have, so it is left out.
 */
#define DEVLINK_NAME_SPECS(...) \
	{ DEVLINK_ATTR_BUS_NAME,	NLA_KIND_STRING, 32, 1, ##__VA_ARGS__ }, \
	{ DEVLINK_ATTR_DEV_NAME,	NLA_KIND_STRING, 32, 1, ##__VA_ARGS__ }

static const struct nla_attr_spec devlink_get_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
};

static const struct nla_attr_spec devlink_dump_attrs[] = {
	DEVLINK_NAME_SPECS(),
};

static const struct nla_attr_spec devlink_port_get_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
	{ DEVLINK_ATTR_PORT_INDEX,	NLA_KIND_U32,    4, .required = true },
};

static const struct nla_attr_spec devlink_sb_get_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
	{ DEVLINK_ATTR_SB_INDEX,	NLA_KIND_U32,    4, .required = true },
};

static const struct nla_attr_spec devlink_param_get_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
	{ DEVLINK_ATTR_PARAM_NAME,	NLA_KIND_STRING, 32, 1, .required = true },
};

static const struct nla_attr_spec devlink_region_get_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
	{ DEVLINK_ATTR_PORT_INDEX,	NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_REGION_NAME,	NLA_KIND_STRING, 32, 1, .required = true },
};

static const struct genl_cmd_grammar devlink_cmds[] = {
	{ DEVLINK_CMD_GET,        "DEVLINK_CMD_GET",
	  devlink_get_attrs, ARRAY_SIZE(devlink_get_attrs), genl_no_attrs },
	{ DEVLINK_CMD_PORT_GET,   "DEVLINK_CMD_PORT_GET",
	  devlink_port_get_attrs, ARRAY_SIZE(devlink_port_get_attrs),
	  devlink_dump_attrs, ARRAY_SIZE(devlink_dump_attrs) },
	{ DEVLINK_CMD_SB_GET,     "DEVLINK_CMD_SB_GET",
	  devlink_sb_get_attrs, ARRAY_SIZE(devlink_sb_get_attrs),
	  devlink_dump_attrs, ARRAY_SIZE(devlink_dump_attrs) },
	{ DEVLINK_CMD_PARAM_GET,  "DEVLINK_CMD_PARAM_GET",
	  devlink_param_get_attrs, ARRAY_SIZE(devlink_param_get_attrs),
	  devlink_dump_attrs, ARRAY_SIZE(devlink_dump_attrs) },
	{ DEVLINK_CMD_REGION_GET, "DEVLINK_CMD_REGION_GET",
	  devlink_region_get_attrs, ARRAY_SIZE(devlink_region_get_attrs),
	  devlink_dump_attrs, ARRAY_SIZE(devlink_dump_attrs) },
	{ DEVLINK_CMD_INFO_GET,   "DEVLINK_CMD_INFO_GET",
	  devlink_get_attrs, ARRAY_SIZE(devlink_get_attrs), genl_no_attrs },
};

struct genl_family_grammar fam_devlink = {
	.name = DEVLINK_GENL_NAME,
	.cmds = devlink_cmds,
	.n_cmds = ARRAY_SIZE(devlink_cmds),
	.default_version = DEVLINK_GENL_VERSION,
};
