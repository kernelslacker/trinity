/*
 * The generic netlink controller (GENL_ID_CTRL), targeting genl_ctrl_ops[]
 * in net/netlink/genetlink.c.  Its id is fixed, so it is not in the family
 * registry: gen_genl_body() and pick_spec_table() ask for it by id.  Only
 * GETFAMILY and GETPOLICY have handlers, and both look up a family.
 */

#include <linux/genetlink.h>

#include "netlink-genl-families.h"
#include "utils.h"

/*
 * ctrl_policy_policy, GETPOLICY's, whose first two slots are all that
 * ctrl_policy_family, GETFAMILY's, has.  GETPOLICY and the dump of GETFAMILY
 * parse strictly, so each request meets only the ids of its cmd's policy,
 * and FAMILY_NAME is an NLA_NUL_STRING of at most GENL_NAMSIZ - 1 bytes.
 */
static const struct nla_attr_spec ctrl_attrs[] = {
	{ CTRL_ATTR_FAMILY_ID,		NLA_KIND_U16,    2 },
	{ CTRL_ATTR_FAMILY_NAME,	NLA_KIND_STRING, GENL_NAMSIZ, 1 },
	{ CTRL_ATTR_OP,			NLA_KIND_U32,    4 },
};

const struct nla_attr_spec *genl_ctrl_attrs(unsigned char cmd, size_t *nr_out)
{
	switch (cmd) {
	case CTRL_CMD_GETFAMILY:
		*nr_out = 2;
		return ctrl_attrs;
	case CTRL_CMD_GETPOLICY:
		*nr_out = ARRAY_SIZE(ctrl_attrs);
		return ctrl_attrs;
	default:
		/* No handler: genl_family_rcv_msg() answers -EOPNOTSUPP
		 * before it reads an attribute. */
		*nr_out = 0;
		return genl_no_attrs;
	}
}
