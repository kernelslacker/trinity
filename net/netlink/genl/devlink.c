/*
 * Genetlink family grammar: devlink (hardware switch, NIC and bus-device
 * configuration), targeting net/devlink/ and its per-op policies in
 * net/devlink/netlink_gen.c.  The unprivileged *_GET commands and
 * NOTIFY_FILTER_SET are listed, keyed on the BUS_NAME / DEV_NAME pair,
 * with REGION_READ, a dump, and PORT_NEW and PORT_DEL, which are
 * GENL_ADMIN_PERM like the other NEW / SET / DEL writers.
 */

#include <linux/devlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * Each op takes the table of its own policy.  The GETs' doits validate
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

/* NOTIFY_FILTER_SET validates strictly and needs no instance: the filter
 * it builds from whichever of these it gets replaces the socket's. */
static const struct nla_attr_spec devlink_notify_filter_set_attrs[] = {
	DEVLINK_NAME_SPECS(),
	{ DEVLINK_ATTR_PORT_INDEX,	NLA_KIND_U32,    4 },
};

/* REGION_READ reads a snapshot, or the region itself under DIRECT, from
 * CHUNK_ADDR for CHUNK_LEN bytes, resuming across dump calls.  It answers
 * -EINVAL without the region's name, or with neither SNAPSHOT_ID nor
 * DIRECT, which a mark cannot say. */
static const struct nla_attr_spec devlink_region_read_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
	{ DEVLINK_ATTR_PORT_INDEX,		NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_REGION_NAME,		NLA_KIND_STRING, 32, 1,
	  .required = true },
	{ DEVLINK_ATTR_REGION_SNAPSHOT_ID,	NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_REGION_DIRECT,		NLA_KIND_FLAG,   0 },
	{ DEVLINK_ATTR_REGION_CHUNK_ADDR,	NLA_KIND_U64,    8 },
	{ DEVLINK_ATTR_REGION_CHUNK_LEN,	NLA_KIND_U64,    8 },
};

/* PORT_NEW asks the driver's port_new for a port and answers -EINVAL
 * without the flavour, which its policy holds to PCI_SF at most, or the
 * PCI PF number; it reads the SF number only for a PCI_SF port.  PORT_DEL
 * takes PORT_GET's table, its pre_doit needing the port's index too. */
static const struct nla_attr_spec devlink_port_new_attrs[] = {
	DEVLINK_NAME_SPECS(.required = true),
	{ DEVLINK_ATTR_PORT_INDEX,		NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_PORT_FLAVOUR,		NLA_KIND_U16_RANGE,
	  DEVLINK_PORT_FLAVOUR_PCI_SF, 0, .required = true },
	{ DEVLINK_ATTR_PORT_PCI_PF_NUMBER,	NLA_KIND_U16,    2,
	  .required = true },
	{ DEVLINK_ATTR_PORT_PCI_SF_NUMBER,	NLA_KIND_U32,    4 },
	{ DEVLINK_ATTR_PORT_CONTROLLER_NUMBER,	NLA_KIND_U32,    4 },
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
	{ DEVLINK_CMD_NOTIFY_FILTER_SET, "DEVLINK_CMD_NOTIFY_FILTER_SET",
	  devlink_notify_filter_set_attrs,
	  ARRAY_SIZE(devlink_notify_filter_set_attrs) },
	{ DEVLINK_CMD_REGION_READ, "DEVLINK_CMD_REGION_READ",
	  devlink_region_read_attrs, ARRAY_SIZE(devlink_region_read_attrs) },
	{ DEVLINK_CMD_PORT_NEW,   "DEVLINK_CMD_PORT_NEW",
	  devlink_port_new_attrs, ARRAY_SIZE(devlink_port_new_attrs) },
	{ DEVLINK_CMD_PORT_DEL,   "DEVLINK_CMD_PORT_DEL",
	  devlink_port_get_attrs, ARRAY_SIZE(devlink_port_get_attrs) },
};

struct genl_family_grammar fam_devlink = {
	.name = DEVLINK_GENL_NAME,
	.cmds = devlink_cmds,
	.n_cmds = ARRAY_SIZE(devlink_cmds),
	.default_version = DEVLINK_GENL_VERSION,
};
