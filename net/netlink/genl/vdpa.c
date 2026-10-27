/*
 * Genetlink family grammar: vdpa (virtual data path acceleration),
 * targeting drivers/vdpa/vdpa.c.  DEV_NEW, DEV_DEL, DEV_VSTATS_GET and
 * DEV_ATTR_SET are GENL_ADMIN_PERM.  One flat VDPA_ATTR_* namespace, no
 * nested containers.
 */

#if __has_include(<linux/vdpa.h>)

#include "kernel/vdpa.h"
#include "netlink-genl-families.h"
#include "utils.h"

/*
 * The ops share one policy, vdpa_nl_policy, and validate strictly, so an id
 * it leaves untyped, the reply-side counts and feature words among them,
 * costs an -EINVAL on any command.  It types eight: the three names
 * (NLA_STRING or NLA_NUL_STRING, so a byte at least), MACADDR (exactly an
 * ethernet address), the u16 MAX_VQP and MTU (68 at least), the u32
 * QUEUE_INDEX and the u64 FEATURES.  No dumpit reads an attribute, so a dump
 * draws from all eight.
 */
static const struct nla_attr_spec vdpa_attrs[] = {
	{ VDPA_ATTR_MGMTDEV_BUS_NAME,		NLA_KIND_STRING, 32, 1 },
	{ VDPA_ATTR_MGMTDEV_DEV_NAME,		NLA_KIND_STRING, 32, 1 },
	{ VDPA_ATTR_DEV_NAME,			NLA_KIND_STRING, 32, 1 },
	{ VDPA_ATTR_DEV_NET_CFG_MACADDR,	NLA_KIND_BINARY_FIXED2, 6, 6 },
	{ VDPA_ATTR_DEV_NET_CFG_MAX_VQP,	NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_NET_CFG_MTU,		NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_QUEUE_INDEX,		NLA_KIND_U32,    4 },
	{ VDPA_ATTR_DEV_FEATURES,		NLA_KIND_U64,    8 },
};

/*
 * What each doit reads, and of that what it answers -EINVAL without.
 * vdpa_mgmtdev_get_from_attr() wants MGMTDEV_DEV_NAME, from MGMTDEV_GET and
 * DEV_NEW; every cmd but MGMTDEV_GET wants DEV_NAME, and VSTATS_GET
 * QUEUE_INDEX as well.  It reads MGMTDEV_BUS_NAME too, which
 * mgmtdev_handle_match() wants for a device on a bus and refuses for one that
 * is not, so that is not marked.  A cmd that wants DEV_NAME alone draws from
 * a table of one, which every request with an attribute carries, so it marks
 * nothing.  DEV_ATTR_SET reads only MACADDR, of the net config.
 */
static const struct nla_attr_spec vdpa_mgmtdev_get_attrs[] = {
	{ VDPA_ATTR_MGMTDEV_BUS_NAME,		NLA_KIND_STRING, 32, 1 },
	{ VDPA_ATTR_MGMTDEV_DEV_NAME,		NLA_KIND_STRING, 32, 1,
	  .required = true },
};

static const struct nla_attr_spec vdpa_dev_new_attrs[] = {
	{ VDPA_ATTR_MGMTDEV_BUS_NAME,		NLA_KIND_STRING, 32, 1 },
	{ VDPA_ATTR_MGMTDEV_DEV_NAME,		NLA_KIND_STRING, 32, 1,
	  .required = true },
	{ VDPA_ATTR_DEV_NAME,			NLA_KIND_STRING, 32, 1,
	  .required = true },
	{ VDPA_ATTR_DEV_NET_CFG_MACADDR,	NLA_KIND_BINARY_FIXED2, 6, 6 },
	{ VDPA_ATTR_DEV_NET_CFG_MAX_VQP,	NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_NET_CFG_MTU,		NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_FEATURES,		NLA_KIND_U64,    8 },
};

static const struct nla_attr_spec vdpa_dev_name_attrs[] = {
	{ VDPA_ATTR_DEV_NAME,			NLA_KIND_STRING, 32, 1 },
};

static const struct nla_attr_spec vdpa_dev_vstats_attrs[] = {
	{ VDPA_ATTR_DEV_NAME,			NLA_KIND_STRING, 32, 1,
	  .required = true },
	{ VDPA_ATTR_DEV_QUEUE_INDEX,		NLA_KIND_U32,    4,
	  .required = true },
};

static const struct nla_attr_spec vdpa_dev_attr_set_attrs[] = {
	{ VDPA_ATTR_DEV_NAME,			NLA_KIND_STRING, 32, 1,
	  .required = true },
	{ VDPA_ATTR_DEV_NET_CFG_MACADDR,	NLA_KIND_BINARY_FIXED2, 6, 6 },
};

/*
 * MGMTDEV_NEW only labels the MGMTDEV_GET replies and is not an op, so it
 * is not listed.  MGMTDEV_GET, DEV_GET and DEV_CONFIG_GET have a dumpit as
 * well as a doit, and the dump takes the family's table.
 */
static const struct genl_cmd_grammar vdpa_cmds[] = {
	{ VDPA_CMD_MGMTDEV_GET,		"VDPA_CMD_MGMTDEV_GET",
	  vdpa_mgmtdev_get_attrs, ARRAY_SIZE(vdpa_mgmtdev_get_attrs),
	  vdpa_attrs, ARRAY_SIZE(vdpa_attrs) },
	{ VDPA_CMD_DEV_NEW,		"VDPA_CMD_DEV_NEW",
	  vdpa_dev_new_attrs, ARRAY_SIZE(vdpa_dev_new_attrs) },
	{ VDPA_CMD_DEV_DEL,		"VDPA_CMD_DEV_DEL",
	  vdpa_dev_name_attrs, ARRAY_SIZE(vdpa_dev_name_attrs) },
	{ VDPA_CMD_DEV_GET,		"VDPA_CMD_DEV_GET",
	  vdpa_dev_name_attrs, ARRAY_SIZE(vdpa_dev_name_attrs),
	  vdpa_attrs, ARRAY_SIZE(vdpa_attrs) },
	{ VDPA_CMD_DEV_CONFIG_GET,	"VDPA_CMD_DEV_CONFIG_GET",
	  vdpa_dev_name_attrs, ARRAY_SIZE(vdpa_dev_name_attrs),
	  vdpa_attrs, ARRAY_SIZE(vdpa_attrs) },
	{ VDPA_CMD_DEV_VSTATS_GET,	"VDPA_CMD_DEV_VSTATS_GET",
	  vdpa_dev_vstats_attrs, ARRAY_SIZE(vdpa_dev_vstats_attrs) },
	{ VDPA_CMD_DEV_ATTR_SET,	"VDPA_CMD_DEV_ATTR_SET",
	  vdpa_dev_attr_set_attrs, ARRAY_SIZE(vdpa_dev_attr_set_attrs) },
};

struct genl_family_grammar fam_vdpa = {
	.name = VDPA_GENL_NAME,
	.cmds = vdpa_cmds,
	.n_cmds = ARRAY_SIZE(vdpa_cmds),
	.attrs = vdpa_attrs,
	.n_attrs = ARRAY_SIZE(vdpa_attrs),
	.default_version = VDPA_GENL_VERSION,
	.hdrsize = 0,
};

#endif /* __has_include(<linux/vdpa.h>) */
