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
 * MGMTDEV_NEW only labels the MGMTDEV_GET replies and is not an op, so it
 * is not listed.
 */
static const struct genl_cmd_grammar vdpa_cmds[] = {
	{ VDPA_CMD_MGMTDEV_GET,		"VDPA_CMD_MGMTDEV_GET" },
	{ VDPA_CMD_DEV_NEW,		"VDPA_CMD_DEV_NEW" },
	{ VDPA_CMD_DEV_DEL,		"VDPA_CMD_DEV_DEL" },
	{ VDPA_CMD_DEV_GET,		"VDPA_CMD_DEV_GET" },
	{ VDPA_CMD_DEV_CONFIG_GET,	"VDPA_CMD_DEV_CONFIG_GET" },
	{ VDPA_CMD_DEV_VSTATS_GET,	"VDPA_CMD_DEV_VSTATS_GET" },
	{ VDPA_CMD_DEV_ATTR_SET,	"VDPA_CMD_DEV_ATTR_SET" },
};

/*
 * Attribute spec follows the VDPA_ATTR_* enum in <linux/vdpa.h>.
 * MGMTDEV_BUS_NAME / MGMTDEV_DEV_NAME / DEV_NAME / VENDOR_ATTR_NAME
 * are NUL-terminated strings naming the management parent and child
 * device.  DEV_ID / DEV_VENDOR_ID / DEV_MAX_VQS / DEV_QUEUE_INDEX /
 * DEV_MGMTDEV_MAX_VQS are u32 scalars (queue-index selects which of
 * the device's VQs DEV_VSTATS_GET reads back).  DEV_MAX_VQ_SIZE /
 * DEV_MIN_VQ_SIZE / DEV_NET_CFG_MAX_VQP / DEV_NET_CFG_MTU are u16
 * scalars.  DEV_NET_CFG_MACADDR is the 6-byte ethernet address pushed
 * by DEV_NEW / DEV_ATTR_SET.  DEV_NET_STATUS is a u8 (virtio_net
 * link-status word).  DEV_NEGOTIATED_FEATURES / DEV_SUPPORTED_FEATURES
 * / MGMTDEV_SUPPORTED_CLASSES / VENDOR_ATTR_VALUE are u64 bitmasks /
 * stat values.  The kernel's vdpa_nl_policy validates a subset of
 * these on input; the remainder are response-side payloads emitted by
 * the GET commands.  The ops validate strictly, so each of those costs
 * an -EINVAL on every command.
 */
static const struct nla_attr_spec vdpa_attrs[] = {
	{ VDPA_ATTR_MGMTDEV_BUS_NAME,		NLA_KIND_STRING, 0 },
	{ VDPA_ATTR_MGMTDEV_DEV_NAME,		NLA_KIND_STRING, 0 },
	{ VDPA_ATTR_MGMTDEV_SUPPORTED_CLASSES,	NLA_KIND_U64,    8 },
	{ VDPA_ATTR_DEV_NAME,			NLA_KIND_STRING, 0 },
	{ VDPA_ATTR_DEV_ID,			NLA_KIND_U32,    4 },
	{ VDPA_ATTR_DEV_VENDOR_ID,		NLA_KIND_U32,    4 },
	{ VDPA_ATTR_DEV_MAX_VQS,		NLA_KIND_U32,    4 },
	{ VDPA_ATTR_DEV_MAX_VQ_SIZE,		NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_MIN_VQ_SIZE,		NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_NET_CFG_MACADDR,	NLA_KIND_BINARY, 6 },
	{ VDPA_ATTR_DEV_NET_STATUS,		NLA_KIND_U8,     1 },
	{ VDPA_ATTR_DEV_NET_CFG_MAX_VQP,	NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_NET_CFG_MTU,		NLA_KIND_U16,    2 },
	{ VDPA_ATTR_DEV_NEGOTIATED_FEATURES,	NLA_KIND_U64,    8 },
	{ VDPA_ATTR_DEV_MGMTDEV_MAX_VQS,	NLA_KIND_U32,    4 },
	{ VDPA_ATTR_DEV_SUPPORTED_FEATURES,	NLA_KIND_U64,    8 },
	{ VDPA_ATTR_DEV_QUEUE_INDEX,		NLA_KIND_U32,    4 },
	{ VDPA_ATTR_DEV_VENDOR_ATTR_NAME,	NLA_KIND_STRING, 0 },
	{ VDPA_ATTR_DEV_VENDOR_ATTR_VALUE,	NLA_KIND_U64,    8 },
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
