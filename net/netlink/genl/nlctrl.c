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
 * The values are random: the table for when no family has resolved.
 */
static const struct nla_attr_spec ctrl_attrs[] = {
	{ CTRL_ATTR_FAMILY_ID,		NLA_KIND_U16,    2 },
	{ CTRL_ATTR_FAMILY_NAME,	NLA_KIND_STRING, GENL_NAMSIZ, 1 },
	{ CTRL_ATTR_OP,			NLA_KIND_U32,    4 },
};

/*
 * ctrl_getfamily() and ctrl_dumppolicy_start() answer a family that does not
 * exist -ENOENT, and ctrl_getfamily() first asks for a module of a name it
 * does not know, so a request names a resolved family.  The table is built
 * from one the registry picks, with its id, its name and, for GETPOLICY, one
 * of its cmds, which genl_get_cmd_both() answers -ENOENT if the family lacks.
 * Each draws its value seven times in eight and random bytes the eighth, so
 * the lookups that miss still see traffic.  Every request builds its own table.
 */
const struct nla_attr_spec *genl_ctrl_attrs(unsigned char cmd, size_t *nr_out)
{
	static struct nla_attr_spec named[ARRAY_SIZE(ctrl_attrs)];
	const struct genl_family_grammar *fam;
	unsigned int op;

	switch (cmd) {
	case CTRL_CMD_GETFAMILY:
		*nr_out = 2;
		break;
	case CTRL_CMD_GETPOLICY:
		*nr_out = ARRAY_SIZE(ctrl_attrs);
		break;
	default:
		/* No handler: genl_family_rcv_msg() answers -EOPNOTSUPP
		 * before it reads an attribute. */
		*nr_out = 0;
		return genl_no_attrs;
	}

	genl_resolve_families();
	fam = genl_pick_resolved_family();
	if (fam == NULL)
		return ctrl_attrs;

	op = genl_pick_cmd(fam);
	named[0] = (struct nla_attr_spec) {
		CTRL_ATTR_FAMILY_ID, NLA_KIND_U16_RANGE, fam->family_id, fam->family_id,
	};
	named[1] = (struct nla_attr_spec) {
		CTRL_ATTR_FAMILY_NAME, NLA_KIND_STRING_WORD, .word = fam->name,
	};
	named[2] = (struct nla_attr_spec) {
		CTRL_ATTR_OP, NLA_KIND_U32_RANGE, op, op,
	};
	return named;
}
