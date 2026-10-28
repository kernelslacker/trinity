/*
 * Self-check for the nfnetlink grammars as the message generator draws from
 * them: each case holds a grammar, or the buffers built from it, to a fact
 * about the kernel's policy or dispatch for the subsystem.  The RNG helpers
 * netlink_gen_msg() reaches are the fakes in genl_ops_test.c; no netlink
 * socket is opened.
 */

#include <arpa/inet.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_acct.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "netlink-attrs.h"	/* struct nla_attr_spec */
#include "netlink-nfnl-subsystems.h"
#include "rnd.h"		/* rnd_modulo_u32 */
#include "socketinfo.h"		/* struct socket_triplet */
#include "utils.h"		/* ARRAY_SIZE */

size_t append_specced_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs,
			     uint64_t *used);
size_t append_required_attrs(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs,
			     uint64_t *used);
const struct nla_attr_spec *pick_spec_table(int protocol, const struct nlmsghdr *nlh,
					    size_t *nr_out);
void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

#define ROUNDS		50000

/*
 * ct_nla_policy marks CTA_TIMESTAMP_EVENT, the last ctattr_type, NLA_REJECT,
 * so the commands that carry that policy answer a message with it -EINVAL
 * before the handler runs.
 */
#define KERNEL_CTA_TIMESTAMP_EVENT	27

/* NF_CT_HELPER_NAME_LEN, which include/net/netfilter/nf_conntrack_helper.h
 * keeps from uapi: the room nfnl_cthelper_policy's name has with its NUL. */
#define KERNEL_NF_CT_HELPER_NAME_LEN	16

/* Whether the attribute at buf, or a child of it when it is a nest, has
 * type id. */
static bool carries_type(const unsigned char *buf, unsigned short id)
{
	struct nlattr nla;
	size_t off;

	memcpy(&nla, buf, sizeof(nla));
	if ((nla.nla_type & NLA_TYPE_MASK) == id)
		return true;
	if (!(nla.nla_type & NLA_F_NESTED))
		return false;

	for (off = NLA_HDRLEN; off + NLA_HDRLEN <= nla.nla_len; ) {
		struct nlattr child;

		memcpy(&child, buf + off, sizeof(child));
		if (child.nla_len < NLA_HDRLEN || off + child.nla_len > nla.nla_len)
			break;
		if ((child.nla_type & NLA_TYPE_MASK) == id)
			return true;
		off += NLA_ALIGN(child.nla_len);
	}
	return false;
}

static void check_no_rejected_attr(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_CTNETLINK);
	unsigned char buf[1024];
	unsigned int round, hits = 0;

	if (sub == NULL)
		BUG("nfnl grammar: ctnetlink is not registered");

	for (round = 0; round < ROUNDS; round++) {
		memset(buf, 0, sizeof(buf));
		if (append_specced_nlattr(buf, 0, sizeof(buf), sub->attrs,
					  sub->n_attrs, NULL) == 0)
			BUG("nfnl grammar: the ctnetlink table emitted nothing");
		if (carries_type(buf, KERNEL_CTA_TIMESTAMP_EVENT))
			hits++;
	}

	if (hits != 0) {
		fprintf(stderr, "ctnetlink: %u of %u attributes carry CTA_TIMESTAMP_EVENT\n",
			hits, ROUNDS);
		BUG("nfnl grammar: ctnetlink emits an attribute its policy rejects");
	}
}

/*
 * cttimeout_cb[] in nfnetlink_cttimeout.c registers five callbacks, NEW
 * through DEFAULT_GET, which all share cttimeout_nla_policy.  The picker
 * draws uniformly from the grammar's command table, so each of the five
 * is a fifth of the draws.
 */
static void check_cttimeout_commands(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_CTNETLINK_TIMEOUT);
	unsigned int picked[IPCTNL_MSG_TIMEOUT_MAX] = { 0 };
	unsigned int round, cmd;

	if (sub == NULL)
		BUG("nfnl grammar: cttimeout is not registered");

	for (round = 0; round < ROUNDS; round++) {
		cmd = nfnl_pick_cmd(sub);
		if (cmd >= IPCTNL_MSG_TIMEOUT_MAX) {
			fprintf(stderr, "cttimeout: picked cmd %u, the kernel registers %u\n",
				cmd, IPCTNL_MSG_TIMEOUT_MAX);
			BUG("nfnl grammar: cttimeout lists a command the kernel lacks");
		}
		picked[cmd]++;
	}

	for (cmd = 0; cmd < IPCTNL_MSG_TIMEOUT_MAX; cmd++) {
		if (picked[cmd] >= ROUNDS / 10)
			continue;
		fprintf(stderr, "cttimeout: cmd %u picked %u times in %u draws\n",
			cmd, picked[cmd], ROUNDS);
		BUG("nfnl grammar: cttimeout leaves out a command the kernel registers");
	}
}

/*
 * nfnl_cmd_attrs() gives a cmd the table its grammar names for it, and a cmd
 * with none, or one the grammar does not list, the subsystem's.  A subsystem
 * with neither, or none at all, has nothing for a request to draw from.
 */
static void check_cmd_attrs_lookup(void)
{
	static const struct nla_attr_spec flat[] = {
		{ 1, NLA_KIND_U32, 4 },
	};
	static const struct nla_attr_spec own[] = {
		{ 2, NLA_KIND_U32, 4 },
		{ 3, NLA_KIND_U32, 4 },
	};
	static const struct nfnl_cmd_grammar cmds[] = {
		{ 0, "OWN", false, own, ARRAY_SIZE(own) },
		{ 1, "FLAT" },
	};
	const struct nfnl_subsys_grammar sub = {
		.name = "lookup",
		.cmds = cmds,
		.n_cmds = ARRAY_SIZE(cmds),
		.attrs = flat,
		.n_attrs = ARRAY_SIZE(flat),
	};
	const struct nfnl_subsys_grammar bare = {
		.name = "bare",
		.cmds = cmds + 1,
		.n_cmds = 1,
	};
	size_t n = 0;

	if (nfnl_cmd_attrs(&sub, 0, &n) != own || n != ARRAY_SIZE(own))
		BUG("nfnl grammar: a cmd with a table of its own does not draw from it");
	if (nfnl_cmd_attrs(&sub, 1, &n) != flat || n != ARRAY_SIZE(flat))
		BUG("nfnl grammar: a cmd with no table of its own does not draw from the subsystem's");
	n = 0;
	if (nfnl_cmd_attrs(&sub, 9, &n) != flat || n != ARRAY_SIZE(flat))
		BUG("nfnl grammar: a cmd the grammar does not list does not draw from the subsystem's");
	if (nfnl_cmd_attrs(&bare, 1, &n) != NULL)
		BUG("nfnl grammar: a subsystem with no table has attributes to draw from");
	if (nfnl_cmd_attrs(NULL, 0, &n) != NULL)
		BUG("nfnl grammar: a missing subsystem has attributes to draw from");
}

/*
 * The generator draws a message's attributes from the table its nlmsg_type
 * names: for every cmd of every registered subsystem, and for one it does not
 * list, pick_spec_table() must return what nfnl_cmd_attrs() does.
 */
static void check_spec_table_dispatch(void)
{
	unsigned int id, i;

	for (id = 0; id < 256; id++) {
		const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(id);

		if (sub == NULL)
			continue;
		for (i = 0; i <= sub->n_cmds; i++) {
			unsigned char cmd = i < sub->n_cmds ? sub->cmds[i].cmd : 255;
			struct nlmsghdr nlh = { .nlmsg_type = (id << 8) | cmd };
			size_t want = 0, got = 0;
			const struct nla_attr_spec *table;

			table = pick_spec_table(NETLINK_NETFILTER, &nlh, &got);
			if (table != nfnl_cmd_attrs(sub, cmd, &want) || (table && got != want)) {
				fprintf(stderr, "%s: cmd %u draws from another table than its grammar names\n",
					sub->name, cmd);
				BUG("nfnl grammar: the generator draws from the wrong table for a cmd");
			}
		}
	}
}

#define SLOT_ROUNDS	20000

struct bounded_slot {
	const char *name;
	unsigned char subsys;
	unsigned short id;
	unsigned short kind;	/* the kind the grammar declares, which fixes the width */
	unsigned short limit;	/* the policy's mask or maximum; 0 for a value list */
	const unsigned int *values;	/* what a *_ONEOF slot's handler accepts */
	unsigned int n_values;
	unsigned int lo;	/* a range's smallest number; 0 for the rest */
};

/*
 * The attributes the netfilter policies bound with NLA_POLICY_MASK or
 * NLA_POLICY_MAX, and the words their handlers bound where the policy does
 * not, all read in network byte order, with the bound each gives.  The ids
 * are the attribute enums' positions.
 */
static const struct bounded_slot slots[] = {
	/* nfnl_acct_policy, NFACCT_F_QUOTA: both quota bits */
	{ "NFACCT_FLAGS", NFNL_SUBSYS_ACCT, 5, NLA_KIND_BE32_MASK, 0x3 },
	/* nfqa_cfg_policy, NFQA_CFG_F_MAX - 1 */
	{ "NFQA_CFG_FLAGS", NFNL_SUBSYS_QUEUE, 5, NLA_KIND_BE32_MASK, 0x1f },
	/* nfula_cfg_policy: SEQ, SEQ_GLOBAL and CONNTRACK */
	{ "NFULA_CFG_FLAGS", NFNL_SUBSYS_ULOG, 6, NLA_KIND_BE16_MASK, 0x7 },
	/* exp_nla_policy, NF_CT_EXPECT_MASK */
	{ "CTA_EXPECT_FLAGS", NFNL_SUBSYS_CTNETLINK_EXP, 8, NLA_KIND_BE32_MASK, 0x7 },
	/* nft_table_policy, nft_chain_policy, nft_set_policy,
	 * nft_set_elem_policy and nft_flowtable_policy */
	{ "NFTA_TABLE_FLAGS", NFNL_SUBSYS_NFTABLES, 2, NLA_KIND_BE32_MASK, 0x7 },
	{ "NFTA_CHAIN_FLAGS", NFNL_SUBSYS_NFTABLES, 10, NLA_KIND_BE32_MASK, 0x7 },
	{ "NFTA_SET_FLAGS", NFNL_SUBSYS_NFTABLES, 3, NLA_KIND_BE32_MASK, 0x1ff },
	{ "NFTA_SET_ELEM_FLAGS", NFNL_SUBSYS_NFTABLES, 3, NLA_KIND_BE32_MASK, 0x3 },
	{ "NFTA_FLOWTABLE_FLAGS", NFNL_SUBSYS_NFTABLES, 7, NLA_KIND_BE32_MASK, 0x3 },
	/* nf_tables_newset() reads NFTA_SET_KEY_LEN and NFTA_SET_DATA_LEN, which
	 * nft_set_policy types NLA_U32, with ntohl() and answers a 0 or one over
	 * NFT_DATA_VALUE_MAXLEN -EINVAL */
	{ .name = "NFTA_SET_KEY_LEN", .subsys = NFNL_SUBSYS_NFTABLES, .id = 5,
	  .kind = NLA_KIND_BE32_RANGE, .limit = 64, .lo = 1 },
	{ .name = "NFTA_SET_DATA_LEN", .subsys = NFNL_SUBSYS_NFTABLES, .id = 7,
	  .kind = NLA_KIND_BE32_RANGE, .limit = 64, .lo = 1 },
	/* nf_tables_newobj() reads NFTA_OBJ_TYPE, which nft_obj_policy types
	 * NLA_U32, with ntohl(), and a number that no object type has costs
	 * nft_obj_type_get() a request_module(): the types are 1, the counter,
	 * to NFT_OBJECT_MAX, 10 */
	{ .name = "NFTA_OBJ_TYPE", .subsys = NFNL_SUBSYS_NFTABLES, .id = 3,
	  .kind = NLA_KIND_BE32_RANGE, .limit = 10, .lo = 1 },
	/* nfnl_cthelper_create() reads NFCTH_PRIV_DATA_LEN, which
	 * nfnl_cthelper_policy types NLA_U32, with ntohl() and answers more
	 * than the 32 bytes of nf_conn_help's data -ENOMEM.  An expectation
	 * policy's SET_NUM is NLA_POLICY_MAX(NLA_BE32, 4), the kernel's
	 * NF_CT_MAX_EXPECT_CLASSES, and nfnl_cthelper_parse_expect_policy()
	 * answers 0 -EINVAL; nfnl_cthelper_expect_policy() answers an
	 * EXPECT_MAX over NF_CT_EXPECT_MAX_CNT, 255, -EINVAL */
	{ .name = "NFCTH_PRIV_DATA_LEN", .subsys = NFNL_SUBSYS_CTHELPER, .id = 5,
	  .kind = NLA_KIND_BE32_RANGE, .limit = 32 },
	{ .name = "NFCTH_POLICY_SET_NUM", .subsys = NFNL_SUBSYS_CTHELPER, .id = 1,
	  .kind = NLA_KIND_BE32_RANGE, .limit = 4, .lo = 1 },
	{ .name = "NFCTH_POLICY_EXPECT_MAX", .subsys = NFNL_SUBSYS_CTHELPER,
	  .id = 2, .kind = NLA_KIND_BE32_RANGE, .limit = 255 },
};

/*
 * nf_ct_l4proto_find() answers l4proto with a tracker whose own l4proto
 * matches it for ICMP, TCP and UDP, for GRE, ICMPv6 and SCTP when the kernel
 * is built with them, and for 255, the generic tracker's; any other number
 * gets the generic tracker, whose 255 differs, and cttimeout_new_timeout(),
 * cttimeout_default_set() and cttimeout_default_get() answer that
 * -EOPNOTSUPP.
 */
static const unsigned int l4protos[] = { 1, 6, 17, 47, 58, 132, 255 };

/* The families a conntrack timeout policy binds to: NFPROTO_IPV4 and
 * NFPROTO_IPV6, which nf_ct_set_timeout() compares with the user's. */
static const unsigned int l3protos[] = { 2, 10 };

/*
 * nfnl_compat_get_rcu() reads NFTA_COMPAT_TYPE as target = (nla_get_be32() ==
 * htonl(1)): 1 is a target and any other number a match, so 0 and 1 reach
 * both arms.
 */
static const unsigned int compat_types[] = { 0, 1 };

/*
 * xt_find_revision() reaches nfnl_compat_fill_info() only for a revision the
 * extension has, and answers any other -EPROTONOSUPPORT.  The extensions that
 * the grammar names have revisions 0 to 3: xt_conntrack's and xt_NFQUEUE's
 * run to 3, and no other goes past 2.  nfnl_compat_policy_get takes up to 255.
 */
static const unsigned int compat_revs[] = { 0, 1, 2, 3 };

/*
 * nfnl_hook_entries_head() answers a hook number past the family's array
 * -EINVAL.  IPv4, IPv6 and bridge, the families gen_nfnl_body() names that it
 * knows, have NF_INET_NUMHOOKS entries; nfnl_hook_nla_policy only caps the
 * number at 255.  nft_chain_parse_hook() takes the same five of an IPv4, IPv6
 * or bridge filter chain, below NFT_MAX_HOOKS and in the chain type's
 * hook_mask.
 */
static const unsigned int hooknums[] = { 0, 1, 2, 3, 4 };

/* nf_tables_newchain() takes NF_DROP and NF_ACCEPT as a base chain's policy
 * and answers any other -EINVAL. */
static const unsigned int policies[] = { 0, 1 };

/* nf_tables_newset() takes NFT_SET_POL_PERFORMANCE and NFT_SET_POL_MEMORY and
 * answers any other policy -EOPNOTSUPP. */
static const unsigned int set_policies[] = { 0, 1 };

/* nft_flowtable_parse_hook() takes NF_NETDEV_INGRESS and no other hook number
 * for a new flowtable, and answers -EOPNOTSUPP to the rest. */
static const unsigned int flowtable_hooknums[] = { 0 };

/* nfnl_cthelper_create() and nfnl_cthelper_update() act on
 * NFCT_HELPER_STATUS_DISABLED and ENABLED and pass over any other status. */
static const unsigned int helper_statuses[] = { 0, 1 };

/* A helper's tuple takes any L4 number, but the cthelper commands find a
 * helper by its name and tuple together, so the tuple keeps to the ones a
 * userspace helper serves, TCP and UDP, as its L3 number does to IPv4 and
 * IPv6, which NLA_POLICY_MAX(NLA_BE16, NFPROTO_IPV6) also takes. */
static const unsigned int helper_l4protos[] = { 6, 17 };

/*
 * The top-level attributes whose handlers accept a few values and no others,
 * read as a byte or in network byte order, with the values each accepts.
 * The ids are the attribute enums' positions.
 */
static const struct bounded_slot oneof_slots[] = {
	/* cttimeout_nla_policy types L3PROTO NLA_U16, but the handlers read
	 * it with ntohs(nla_get_be16()), and none of them checks it */
	{ "CTA_TIMEOUT_L3PROTO", NFNL_SUBSYS_CTNETLINK_TIMEOUT, 2,
	  NLA_KIND_BE16_ONEOF, 0, l3protos, ARRAY_SIZE(l3protos) },
	{ "CTA_TIMEOUT_L4PROTO", NFNL_SUBSYS_CTNETLINK_TIMEOUT, 3,
	  NLA_KIND_U8_ONEOF, 0, l4protos, ARRAY_SIZE(l4protos) },
	/* nfnl_hook_nla_policy: NLA_POLICY_MAX(NLA_BE32, 255) */
	{ "NFNLA_HOOK_HOOKNUM", NFNL_SUBSYS_HOOK, 1,
	  NLA_KIND_BE32_ONEOF, 0, hooknums, ARRAY_SIZE(hooknums) },
	/* nfnl_compat_policy_get types TYPE NLA_U32 and REV NLA_POLICY_MAX(255) */
	{ "NFTA_COMPAT_TYPE", NFNL_SUBSYS_NFT_COMPAT, 3,
	  NLA_KIND_BE32_ONEOF, 0, compat_types, ARRAY_SIZE(compat_types) },
	{ "NFTA_COMPAT_REV", NFNL_SUBSYS_NFT_COMPAT, 2,
	  NLA_KIND_BE32_ONEOF, 0, compat_revs, ARRAY_SIZE(compat_revs) },
	/* nft_hook_policy and nft_chain_policy type both NLA_U32 */
	{ "NFTA_HOOK_HOOKNUM", NFNL_SUBSYS_NFTABLES, 1,
	  NLA_KIND_BE32_ONEOF, 0, hooknums, ARRAY_SIZE(hooknums) },
	{ "NFTA_CHAIN_POLICY", NFNL_SUBSYS_NFTABLES, 5,
	  NLA_KIND_BE32_ONEOF, 0, policies, ARRAY_SIZE(policies) },
	/* nft_set_policy types POLICY NLA_U32 */
	{ "NFTA_SET_POLICY", NFNL_SUBSYS_NFTABLES, 8,
	  NLA_KIND_BE32_ONEOF, 0, set_policies, ARRAY_SIZE(set_policies) },
	/* nft_flowtable_hook_policy types NUM NLA_U32 */
	{ "NFTA_FLOWTABLE_HOOK_NUM", NFNL_SUBSYS_NFTABLES, 1,
	  NLA_KIND_BE32_ONEOF, 0, flowtable_hooknums, ARRAY_SIZE(flowtable_hooknums) },
	/* nfnl_cthelper_policy types STATUS NLA_U32 */
	{ "NFCTH_STATUS", NFNL_SUBSYS_CTHELPER, 6,
	  NLA_KIND_BE32_ONEOF, 0, helper_statuses, ARRAY_SIZE(helper_statuses) },
	{ "NFCTH_TUPLE_L3PROTONUM", NFNL_SUBSYS_CTHELPER, 1,
	  NLA_KIND_BE16_ONEOF, 0, l3protos, ARRAY_SIZE(l3protos) },
	{ "NFCTH_TUPLE_L4PROTONUM", NFNL_SUBSYS_CTHELPER, 2,
	  NLA_KIND_U8_ONEOF, 0, helper_l4protos, ARRAY_SIZE(helper_l4protos) },
};

static bool has_value(const struct bounded_slot *slot, unsigned int v)
{
	unsigned int i;

	for (i = 0; i < slot->n_values; i++) {
		if (slot->values[i] == v)
			return true;
	}
	return false;
}

/* The spec for the slot's id in table, or in a nest below it, that declares
 * the slot's kind and bound or values; a plain U32 there would send random
 * bytes. */
static const struct nla_attr_spec *search_slot_spec(const struct nla_attr_spec *table,
						    size_t n_specs,
						    const struct bounded_slot *slot)
{
	size_t i;
	unsigned int j;

	for (i = 0; i < n_specs; i++) {
		const struct nla_attr_spec *spec = &table[i];

		if (spec->type == slot->id && spec->kind == slot->kind &&
		    spec->max_len == slot->limit && spec->min_len == slot->lo &&
		    spec->n_oneof == slot->n_values) {
			for (j = 0; j < spec->n_oneof; j++) {
				if (!has_value(slot, spec->oneof[j]))
					break;
			}
			if (j == spec->n_oneof)
				return spec;
		}
		if (spec->nest != NULL) {
			const struct nla_attr_spec *found;

			found = search_slot_spec(spec->nest, spec->n_nest, slot);
			if (found != NULL)
				return found;
		}
	}
	return NULL;
}

/* The slot's spec in the subsystem's table or in the table of one of its
 * cmds. */
static const struct nla_attr_spec *find_slot_spec(const struct bounded_slot *slot)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(slot->subsys);
	const struct nla_attr_spec *found;
	unsigned int i;

	if (sub == NULL) {
		fprintf(stderr, "%s: subsystem %u is not registered\n",
			slot->name, slot->subsys);
		BUG("nfnl grammar: a bounded scalar's subsystem is missing");
	}

	found = search_slot_spec(sub->attrs, sub->n_attrs, slot);
	for (i = 0; found == NULL && i < sub->n_cmds; i++)
		found = search_slot_spec(sub->cmds[i].attrs, sub->cmds[i].n_attrs, slot);
	if (found != NULL)
		return found;

	fprintf(stderr, "%s: no spec of kind %u with bound %#x from %u and %u listed values at id %u\n",
		slot->name, slot->kind, slot->limit, slot->lo, slot->n_values, slot->id);
	BUG("nfnl grammar: a bounded scalar is not declared with the kernel's bound");
}

static unsigned int slot_width(unsigned short kind)
{
	switch (kind) {
	case NLA_KIND_U8_ONEOF:
		return 1;
	case NLA_KIND_BE16_MASK:
	case NLA_KIND_BE16_ONEOF:
		return 2;
	default:
		return 4;
	}
}

/* One attribute drawn from the slot's spec, held to its width and header,
 * and its value in host order. */
static uint32_t draw_slot(const struct nla_attr_spec *spec,
			  const struct bounded_slot *slot)
{
	const unsigned int width = slot_width(slot->kind);
	unsigned char buf[64];
	struct nlattr nla;

	memset(buf, 0, sizeof(buf));
	if (append_specced_nlattr(buf, 0, sizeof(buf), spec, 1, NULL) !=
	    NLA_ALIGN(NLA_HDRLEN + width))
		BUG("nfnl grammar: a bounded scalar is not sized to its width");
	memcpy(&nla, buf, sizeof(nla));
	if (nla.nla_type != slot->id || nla.nla_len != NLA_HDRLEN + width)
		BUG("nfnl grammar: a bounded scalar has the wrong header");

	if (width == 1)
		return buf[NLA_HDRLEN];
	if (width == 2) {
		uint16_t be;

		memcpy(&be, buf + NLA_HDRLEN, sizeof(be));
		return ntohs(be);
	} else {
		uint32_t be;

		memcpy(&be, buf + NLA_HDRLEN, sizeof(be));
		return ntohl(be);
	}
}

/*
 * One draw in eight is random bytes, so 0.875 of the draws sit inside the
 * bound and almost none of the rest do.  Over SLOT_ROUNDS draws the fraction
 * has a standard deviation of 0.0024, so the limits 0.80 and 0.95 are 30
 * sigma off; they turn away both a spec that sends nothing but random bytes
 * and one that never leaves the bound.
 */
static void check_slot_fraction(const char *name, unsigned int in_bounds)
{
	double frac = (double) in_bounds / SLOT_ROUNDS;

	if (frac < 0.80 || frac > 0.95) {
		fprintf(stderr, "%s: %u of %u draws inside the bound, want a fraction in [0.80, 0.95]\n",
			name, in_bounds, SLOT_ROUNDS);
		BUG("nfnl grammar: a bounded scalar is not drawn from its bound");
	}
}

/* A mask draw must also set and clear every bit of the mask, and a range
 * draw reach both ends of the range, which an always-zero or always-full
 * word does not.  Under a small floor the only draws are random bytes, which
 * come out under it about once in 2^16 draws or less, so a range that is
 * drawn from under its floor shows at once. */
static void check_bounded_spec(const struct nla_attr_spec *spec,
			       const struct bounded_slot *slot)
{
	const bool mask = slot->kind != NLA_KIND_BE32_RANGE;
	uint32_t min_v = UINT32_MAX, max_v = 0, or_all = 0, and_all = UINT32_MAX;
	unsigned int round, in_bounds = 0, below = 0;

	for (round = 0; round < SLOT_ROUNDS; round++) {
		uint32_t v = draw_slot(spec, slot);

		if (v < slot->lo)
			below++;
		if (mask ? (v & ~(uint32_t) slot->limit) != 0 :
			   (v < slot->lo || v > slot->limit))
			continue;
		in_bounds++;
		or_all |= v;
		and_all &= v;
		if (v < min_v)
			min_v = v;
		if (v > max_v)
			max_v = v;
	}

	check_slot_fraction(slot->name, in_bounds);

	if (slot->lo != 0 && slot->lo < 65536 && below != 0) {
		fprintf(stderr, "%s: %u draws under the floor %u\n",
			slot->name, below, slot->lo);
		BUG("nfnl grammar: a range is drawn from under its floor");
	}
	if (mask ? (or_all != slot->limit || and_all != 0) :
		   (min_v != slot->lo || max_v != slot->limit)) {
		fprintf(stderr, "%s: draws inside the bound span or %#x and %#x, min %u max %u\n",
			slot->name, or_all, and_all, min_v, max_v);
		BUG("nfnl grammar: a bounded scalar does not cover its bound");
	}
}

static void check_bounded_slot(const struct bounded_slot *slot)
{
	check_bounded_spec(find_slot_spec(slot), slot);
}

/*
 * NLA_KIND_BE32_RANGE fills a number from min_len to max_len, both ends
 * included, in network byte order: seven draws in eight inside, both ends
 * reached, and read back with ntohl() as a handler does.
 */
static void check_be32_range(void)
{
	const struct nla_attr_spec spec = {
		.type = 9,
		.kind = NLA_KIND_BE32_RANGE,
		.max_len = 64,
		.min_len = 1,
	};
	const struct bounded_slot slot = {
		.name = "the range",
		.id = 9,
		.kind = NLA_KIND_BE32_RANGE,
		.limit = 64,
		.lo = 1,
	};

	check_bounded_spec(&spec, &slot);
}

/* Every value the handler accepts must be drawn, and a value it does not
 * accept only as one of the random bytes the fraction allows for. */
static void check_oneof_slot(const struct bounded_slot *slot)
{
	const struct nla_attr_spec *spec = find_slot_spec(slot);
	unsigned int round, i, in_bounds = 0, seen = 0;

	for (round = 0; round < SLOT_ROUNDS; round++) {
		uint32_t v = draw_slot(spec, slot);

		if (!has_value(slot, v))
			continue;
		in_bounds++;
		for (i = 0; i < slot->n_values; i++) {
			if (slot->values[i] == v)
				seen |= 1U << i;
		}
	}

	check_slot_fraction(slot->name, in_bounds);

	if (seen != (1U << slot->n_values) - 1) {
		fprintf(stderr, "%s: draws inside the list reached %#x of %#x\n",
			slot->name, seen, (1U << slot->n_values) - 1);
		BUG("nfnl grammar: a listed value is never drawn");
	}
}

/*
 * nf_tables_cb[] makes the NEW, DEL and DESTROY commands NFNL_CB_BATCH,
 * which nfnetlink dispatches only inside a batch, and the GETs NFNL_CB_RCU:
 * 21 and 11 of the 32.  The GET names tell the two apart.
 */
static void check_nftables_batch_flags(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	unsigned int i, batch = 0, rcu = 0;

	if (sub == NULL)
		BUG("nfnl grammar: nftables is not registered");

	for (i = 0; i < sub->n_cmds; i++) {
		bool is_get = strncmp(sub->cmds[i].name, "NFT_MSG_GET", 11) == 0;

		if (sub->cmds[i].batch == is_get) {
			fprintf(stderr, "%s: marked %s\n", sub->cmds[i].name,
				sub->cmds[i].batch ? "batch" : "not batch");
			BUG("nfnl grammar: an nftables command is marked the wrong way");
		}
		if (is_get)
			rcu++;
		else
			batch++;
	}

	if (batch != 21 || rcu != 11) {
		fprintf(stderr, "nftables: %u batch and %u other commands, want 21 and 11\n",
			batch, rcu);
		BUG("nfnl grammar: nftables lists a different set of commands");
	}
}

/*
 * nf_tables_api.c finds what a command names by name.  The table is the
 * attribute at id 1 in every namespace (NFTA_TABLE_NAME, NFTA_CHAIN_TABLE,
 * NFTA_RULE_TABLE, NFTA_SET_TABLE, NFTA_SET_ELEM_LIST_TABLE, NFTA_OBJ_TABLE,
 * NFTA_FLOWTABLE_TABLE); inside it the rule's chain, the set, the object and
 * the flowtable are at id 2 (NFTA_RULE_CHAIN, NFTA_SET_NAME,
 * NFTA_SET_ELEM_LIST_SET, NFTA_OBJ_NAME, NFTA_FLOWTABLE_NAME), and a chain's
 * own name is at 3 (NFTA_CHAIN_NAME).  All are NLA_STRING, matched by their
 * text in nft_table_lookup() and its kin (nla_strcmp(), or nla_strscpy() into
 * a hash key), so a command finds what an earlier one made only when its
 * string is that one's.
 */
#define NFT_NAME_ID_MAX		3

/*
 * One word at every name id, which a table, a chain, a set, an object and a
 * flowtable can all carry since nf_tables keeps them in separate namespaces,
 * for seven draws in eight; the eighth is random lowercase letters.
 */
static void check_word_spec(const struct nla_attr_spec *spec)
{
	const size_t wlen = strlen(spec->word) + 1;
	unsigned int round, i, matching = 0;
	char name[48];

	for (round = 0; round < SLOT_ROUNDS; round++) {
		unsigned char buf[64];
		struct nlattr nla;

		memset(buf, 0, sizeof(buf));
		if (append_specced_nlattr(buf, 0, sizeof(buf), spec, 1, NULL) !=
		    NLA_ALIGN(NLA_HDRLEN + wlen))
			BUG("nfnl grammar: a word is not sized to its length");
		memcpy(&nla, buf, sizeof(nla));
		if (nla.nla_type != spec->type || nla.nla_len != NLA_HDRLEN + wlen)
			BUG("nfnl grammar: a word has the wrong header");
		if (buf[NLA_HDRLEN + wlen - 1] != '\0')
			BUG("nfnl grammar: a word is not NUL-terminated");
		for (i = 0; i + 1 < wlen; i++) {
			if (buf[NLA_HDRLEN + i] < 'a' || buf[NLA_HDRLEN + i] > 'z')
				BUG("nfnl grammar: a word draws something but lowercase letters");
		}
		if (memcmp(buf + NLA_HDRLEN, spec->word, wlen) == 0)
			matching++;
	}

	snprintf(name, sizeof(name), "the word at nftables id %u", spec->type);
	check_slot_fraction(name, matching);
}

/* The name ids of table must all be the one word; word is the one found so
 * far, and seen has the ids that have one. */
static void check_name_specs(const struct nla_attr_spec *table, size_t n_specs,
			     const char **word, bool *seen)
{
	size_t i;

	for (i = 0; i < n_specs; i++) {
		const struct nla_attr_spec *spec = &table[i];

		if (spec->type < 1 || spec->type > NFT_NAME_ID_MAX)
			continue;
		if (spec->kind == NLA_KIND_STRING) {
			fprintf(stderr, "nftables: the string at id %u is random text\n",
				spec->type);
			BUG("nfnl grammar: an nftables name is not the shared word");
		}
		if (spec->kind != NLA_KIND_STRING_WORD)
			continue;
		if (*word == NULL)
			*word = spec->word;
		else if (strcmp(*word, spec->word) != 0)
			BUG("nfnl grammar: nftables names are not all the same word");
		seen[spec->type] = true;
		check_word_spec(spec);
	}
}

/*
 * A NLA_KIND_STRING_ONEOF spec draws one of its words, NUL-terminated, on
 * seven draws in eight, and on the eighth random lowercase letters as long as
 * some word.  Each word is 0.875 of the draws shared by the n words, and half
 * of that is a floor that a word which only the random letters ever spell does
 * not reach.
 */
static void check_word_draws(const char *name, const struct nla_attr_spec *spec)
{
	unsigned int round, i, in_list = 0, seen[32] = { 0 };

	if (spec->n_words == 0 || spec->n_words > ARRAY_SIZE(seen))
		BUG("nfnl grammar: a word list is empty or too long to judge");

	for (round = 0; round < SLOT_ROUNDS; round++) {
		unsigned char buf[64];
		struct nlattr nla;
		size_t plen;
		bool matched = false, sized = false;

		memset(buf, 0, sizeof(buf));
		if (append_specced_nlattr(buf, 0, sizeof(buf), spec, 1, NULL) == 0)
			BUG("nfnl grammar: a word list emitted nothing");
		memcpy(&nla, buf, sizeof(nla));
		plen = nla.nla_len - NLA_HDRLEN;
		if (nla.nla_type != spec->type || plen == 0 ||
		    buf[NLA_HDRLEN + plen - 1] != '\0')
			BUG("nfnl grammar: a word from a list is not a NUL-terminated string");

		for (i = 0; i < spec->n_words; i++) {
			if (plen != strlen(spec->words[i]) + 1)
				continue;
			sized = true;
			if (memcmp(buf + NLA_HDRLEN, spec->words[i], plen) == 0) {
				matched = true;
				seen[i]++;
			}
		}
		if (matched) {
			in_list++;
			continue;
		}
		if (!sized)
			BUG("nfnl grammar: a word from a list is as long as none of them");
		for (i = 0; i + 1 < plen; i++) {
			if (buf[NLA_HDRLEN + i] < 'a' || buf[NLA_HDRLEN + i] > 'z')
				BUG("nfnl grammar: a word from a list draws something but lowercase letters");
		}
	}

	check_slot_fraction(name, in_list);
	for (i = 0; i < spec->n_words; i++) {
		if (seen[i] >= SLOT_ROUNDS * 7 / 8 / spec->n_words / 2)
			continue;
		fprintf(stderr, "%s: \"%s\" drawn %u times in %u\n",
			name, spec->words[i], seen[i], SLOT_ROUNDS);
		BUG("nfnl grammar: a word of a list is hardly drawn");
	}
}

static void check_string_oneof(void)
{
	static const char *const words[] = { "ab", "cde", "fghi", "jk" };
	const struct nla_attr_spec spec = {
		.type = 7,
		.kind = NLA_KIND_STRING_ONEOF,
		.words = words,
		.n_words = ARRAY_SIZE(words),
	};

	check_word_draws("the word list", &spec);
}

/*
 * Every string the nftables grammar has at a name id, in a cmd's table, must
 * be the one word, and each of the ids must have one.  Returns the word.
 */
static const char *check_nftables_names(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	bool seen[NFT_NAME_ID_MAX + 1] = { false };
	const char *word = NULL;
	unsigned int i, id;

	if (sub == NULL)
		BUG("nfnl grammar: nftables is not registered");

	for (i = 0; i < sub->n_cmds; i++)
		check_name_specs(sub->cmds[i].attrs, sub->cmds[i].n_attrs, &word, seen);

	for (id = 1; id <= NFT_NAME_ID_MAX; id++) {
		if (!seen[id]) {
			fprintf(stderr, "nftables: no word at id %u\n", id);
			BUG("nfnl grammar: an nftables name id has no word");
		}
	}
	return word;
}

/*
 * The names that a command finds an object by, which each must be one word
 * for a later command to find what an earlier one made: cttimeout_get_timeout(),
 * cttimeout_del_timeout() and the NLM_F_REPLACE arm of cttimeout_new_timeout()
 * find a timeout with strncmp() on its name, nfnl_acct_new(), _get() and
 * _del() find an object the same way, and nfnl_cthelper_new(), _get() and
 * _del() a helper, by its tuple as well.  A name drawn at random would make
 * another object on each NEW and let nothing else find them.  name_max is
 * the room the policy's NLA_NUL_STRING has for the name and its NUL.
 */
struct word_name {
	const char *what;
	unsigned char subsys;
	unsigned short id;
	unsigned int name_max;
};

static const struct word_name word_names[] = {
	{ "cttimeout", NFNL_SUBSYS_CTNETLINK_TIMEOUT, 1, CTNL_TIMEOUT_NAME_MAX },
	{ "acct", NFNL_SUBSYS_ACCT, 1, NFACCT_NAME_MAX },
	{ "cthelper", NFNL_SUBSYS_CTHELPER, 1, KERNEL_NF_CT_HELPER_NAME_LEN },
};

static void check_name_id_specs(const struct word_name *name,
				const struct nla_attr_spec *table, size_t n_specs,
				unsigned int *words)
{
	size_t i;

	for (i = 0; i < n_specs; i++) {
		const struct nla_attr_spec *spec = &table[i];

		if (spec->type != name->id)
			continue;
		if (spec->kind == NLA_KIND_STRING) {
			fprintf(stderr, "%s: the string at id %u is random text\n",
				name->what, name->id);
			BUG("nfnl grammar: a name is not the shared word");
		}
		if (spec->kind != NLA_KIND_STRING_WORD)
			continue;
		if (strlen(spec->word) >= name->name_max)
			BUG("nfnl grammar: a name is longer than its policy takes");
		check_word_spec(spec);
		(*words)++;
	}
}

/* Every declaration of the name, in the subsystem's table or a command's. */
static void check_word_name(const struct word_name *name)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(name->subsys);
	unsigned int i, words = 0;

	if (sub == NULL)
		BUG("nfnl grammar: a name's subsystem is not registered");

	check_name_id_specs(name, sub->attrs, sub->n_attrs, &words);
	for (i = 0; i < sub->n_cmds; i++)
		check_name_id_specs(name, sub->cmds[i].attrs, sub->cmds[i].n_attrs, &words);
	if (words == 0) {
		fprintf(stderr, "%s: declares no name\n", name->what);
		BUG("nfnl grammar: a subsystem's name is not declared as a word");
	}
}

/*
 * nft_supported_family() takes NFPROTO_INET, IPV4, ARP, NETDEV, BRIDGE and
 * IPV6 and nothing else, and a table is found by its family and name
 * together, so these are the families a batch can name its table in.
 */
static const unsigned char nft_families[] = { 1, 2, 3, 5, 7, 10 };

/*
 * nfnl_hook_entries_head() takes NFPROTO_IPV4, IPV6, ARP, BRIDGE and
 * NETDEV, the last the one family that reads DEV, and answers any other
 * -EPROTONOSUPPORT.
 */
static const unsigned char hook_families[] = { 2, 3, 5, 7, 10 };

/* The subsystem lists exactly the families its handlers take. */
static void expect_families(unsigned char subsys_id, const char *name,
			    const unsigned char *want, unsigned int n_want)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(subsys_id);
	unsigned int i, j;

	if (sub == NULL || sub->n_families != n_want) {
		fprintf(stderr, "%s: lists %u families, want %u\n", name,
			sub != NULL ? sub->n_families : 0, n_want);
		BUG("nfnl grammar: a subsystem lists a different set of families");
	}

	for (i = 0; i < n_want; i++) {
		for (j = 0; j < sub->n_families; j++) {
			if (sub->families[j] == want[i])
				break;
		}
		if (j == sub->n_families) {
			fprintf(stderr, "%s: family %u is not listed\n", name, want[i]);
			BUG("nfnl grammar: a subsystem leaves out a family it supports");
		}
	}
}

/*
 * A lone nftables message, one that opens no batch, names one of the
 * families nftables supports seven times in eight, as a batch's commands
 * do, so that a GETTABLE looks in a family a batch may have made its table
 * in; each of the six turns up.  Before, the lone ones drew from a fixed
 * four that leave INET, ARP and NETDEV out.
 */
#define LONE_ROUNDS	40000

static void check_nftables_lone_families(void)
{
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_NETFILTER,
	};
	unsigned int family[256] = { 0 };
	unsigned int round, lone = 0, listed = 0, i;

	for (round = 0; round < LONE_ROUNDS; round++) {
		struct nlmsghdr nlh;
		struct nfgenmsg nfg;
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		if (len >= NLMSG_HDRLEN + sizeof(nfg)) {
			memcpy(&nlh, buf, sizeof(nlh));
			memcpy(&nfg, (unsigned char *) buf + NLMSG_HDRLEN,
			       sizeof(nfg));
			if (nlh.nlmsg_type >> 8 == NFNL_SUBSYS_NFTABLES) {
				lone++;
				family[nfg.nfgen_family]++;
			}
		}
		free(buf);
	}

	for (i = 0; i < ARRAY_SIZE(nft_families); i++) {
		listed += family[nft_families[i]];
		if (family[nft_families[i]] * 20 < lone) {
			fprintf(stderr, "nftables: %u of %u lone messages in family %u\n",
				family[nft_families[i]], lone, nft_families[i]);
			BUG("nfnl: a lone message seldom names a family nftables has");
		}
	}
	if (lone < 500 || listed * 10 < lone * 9) {
		fprintf(stderr, "nftables: %u of %u lone messages in a listed family\n",
			listed, lone);
		BUG("nfnl: lone messages do not draw nftables' families");
	}
}

/*
 * What a cmd's own table must be, as the kernel's policy and the handler
 * have it: the attributes of the policy that the handler reads, which of
 * them it cannot do without, and for a nest the grammar types, the policy
 * of its children.  The ids are the attribute enums' positions.
 */
struct pslot {
	unsigned short id;
	bool required;		/* the handler returns early without it */
	bool array;		/* the nest is an NLA_POLICY_NESTED_ARRAY */
	unsigned short kind;	/* the kind the spec must have; 0 for any */
	bool bounded;		/* a mask or a range: the spec's min_len and max_len */
	unsigned int lo, hi;	/* ... are lo and hi; a mask is from 0 to its bits */
	struct pslot *nest;	/* the nest's own policy; NULL if the grammar leaves it untyped */
	unsigned int n_nest;
	unsigned int streams;	/* streams of the policy counted, for a required slot */
	unsigned int present;	/* ... of which held the slot */
};

#define PS(i, req, k)	{ .id = i, .required = req, .kind = k }
#define PSB(i, req, k, l, h) \
			{ .id = i, .required = req, .kind = k, .bounded = true, \
			  .lo = l, .hi = h }
#define PSN(i, req, n)	{ .id = i, .required = req, .kind = NLA_KIND_NESTED, \
			  .nest = n, .n_nest = ARRAY_SIZE(n) }
#define PSA(i, req, n)	{ .id = i, .required = req, .array = true, \
			  .kind = NLA_KIND_NESTED_ARRAY, .nest = n, .n_nest = ARRAY_SIZE(n) }

/* One cmd, with the policy its own table must hold. */
struct cmd_row {
	const char *name;
	unsigned char subsys;
	unsigned char cmd;
	struct pslot *pol;
	unsigned int n_slots;
};

/*
 * The table must hold the policy's attributes, each once, marked required
 * as the policy's are, of the kind the policy names, and a nest with its own
 * table exactly where the policy has one.
 */
static void expect_declared(const struct nla_attr_spec *specs, size_t n_specs,
			    const struct pslot *pol, unsigned int n_slots,
			    const char *what)
{
	unsigned long long used = 0;
	size_t i;

	if (n_specs != n_slots) {
		fprintf(stderr, "%s: the table holds %zu attributes, the policy %u\n",
			what, n_specs, n_slots);
		BUG("nfnl grammar: a cmd's table does not hold the attributes its handler reads");
	}

	for (i = 0; i < n_specs; i++) {
		const struct nla_attr_spec *spec = &specs[i];
		unsigned int j;

		for (j = 0; j < n_slots && pol[j].id != spec->type; j++)
			;
		if (j == n_slots || (used & (1ULL << j))) {
			fprintf(stderr, "%s: attribute %u is %s\n", what, spec->type,
				j == n_slots ? "not one the handler reads" : "listed twice");
			BUG("nfnl grammar: a cmd's table does not hold the attributes its handler reads");
		}
		used |= 1ULL << j;

		if (spec->required != pol[j].required) {
			fprintf(stderr, "%s: attribute %u is %smarked required\n", what,
				spec->type, spec->required ? "" : "not ");
			BUG("nfnl grammar: a cmd's required attribute is marked wrongly");
		}
		if (pol[j].kind != 0 && spec->kind != pol[j].kind) {
			fprintf(stderr, "%s: attribute %u is of kind %u, want %u\n", what,
				spec->type, spec->kind, pol[j].kind);
			BUG("nfnl grammar: a cmd's attribute is of the wrong kind");
		}
		if (pol[j].bounded &&
		    (spec->min_len != pol[j].lo || spec->max_len != pol[j].hi)) {
			fprintf(stderr, "%s: attribute %u is bounded %u to %#x, want %u to %#x\n",
				what, spec->type, spec->min_len, spec->max_len,
				pol[j].lo, pol[j].hi);
			BUG("nfnl grammar: a cmd's attribute has the wrong bound");
		}
		if ((spec->nest != NULL) != (pol[j].nest != NULL)) {
			fprintf(stderr, "%s: attribute %u %s a table of its own\n", what,
				spec->type, spec->nest ? "has" : "lacks");
			BUG("nfnl grammar: a nest has the wrong table");
		}
		if (pol[j].nest != NULL)
			expect_declared(spec->nest, spec->n_nest, pol[j].nest,
					pol[j].n_nest, what);
	}
}

static struct pslot *find_pslot(struct pslot *pol, unsigned int n_slots,
				unsigned short id)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		if (pol[i].id == id)
			return &pol[i];
	}
	return NULL;
}

static void tally_stream(const unsigned char *p, size_t len,
			 struct pslot *pol, unsigned int n_slots);

/* The elements of an array, each a stream of the policy the slot names. */
static void tally_elements(const unsigned char *p, size_t len,
			   const struct pslot *slot)
{
	size_t off = 0;

	while (off + NLA_HDRLEN <= len) {
		struct nlattr elem;

		memcpy(&elem, p + off, sizeof(elem));
		if (elem.nla_len < NLA_HDRLEN || off + elem.nla_len > len)
			return;
		tally_stream(p + off + NLA_HDRLEN, elem.nla_len - NLA_HDRLEN,
			     slot->nest, slot->n_nest);
		off += NLA_ALIGN(elem.nla_len);
	}
}

/*
 * A stream of attributes of a policy of up to 64 slots: every slot marked
 * required counts the stream, and counts it again if the stream holds the
 * attribute.  A nest, and each element of an array, is a stream of the
 * policy its slot names and counts the same way.
 */
static void tally_stream(const unsigned char *p, size_t len,
			 struct pslot *pol, unsigned int n_slots)
{
	unsigned long long got = 0;
	size_t off = 0;
	unsigned int i;

	while (off + NLA_HDRLEN <= len) {
		struct nlattr nla;
		struct pslot *slot;

		memcpy(&nla, p + off, sizeof(nla));
		if (nla.nla_len < NLA_HDRLEN || off + nla.nla_len > len)
			break;
		slot = find_pslot(pol, n_slots, nla.nla_type & NLA_TYPE_MASK);
		if (slot != NULL) {
			const unsigned char *payload = p + off + NLA_HDRLEN;
			size_t plen = nla.nla_len - NLA_HDRLEN;

			got |= 1ULL << (slot - pol);
			if (slot->nest != NULL && slot->array)
				tally_elements(payload, plen, slot);
			else if (slot->nest != NULL)
				tally_stream(payload, plen, slot->nest, slot->n_nest);
		}
		off += NLA_ALIGN(nla.nla_len);
	}

	for (i = 0; i < n_slots; i++) {
		if (!pol[i].required)
			continue;
		pol[i].streams++;
		if (got & (1ULL << i))
			pol[i].present++;
	}
}

/* The fewest streams any required slot of pol, or below it, has been counted
 * in; UINT_MAX when it has none. */
static unsigned int min_streams(const struct pslot *pol, unsigned int n_slots)
{
	unsigned int least = UINT_MAX;
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		unsigned int below;

		if (pol[i].required && pol[i].streams < least)
			least = pol[i].streams;
		if (pol[i].nest == NULL)
			continue;
		below = min_streams(pol[i].nest, pol[i].n_nest);
		if (below < least)
			least = below;
	}
	return least;
}

#define REQUIRED_STREAMS	600
#define STREAMS_MIN		2000
#define STREAMS_MAX		400000

/*
 * A required slot is left out of some streams and is in most of them.  The
 * emitter skips it one time in eight, and the draws that follow bring some of
 * those back, so it is in 0.875 of them or more, fewer where a nest has no
 * room left for it.  Unmarked it would be in 0.2 to 0.75 of the streams of
 * the tables here.  Over 600 streams the fraction has a standard deviation
 * under 0.02, so 0.70 is five of them under a rate of 0.80.  A slot that is
 * never left out leaves the handler's missing-attribute arm without traffic;
 * a nest is never emitted empty, so the one attribute of a nest of one has no
 * arm of that kind.  A small table gets the slot into most streams unmarked,
 * which is why the marks are also checked outright.
 */
static void expect_required(const struct pslot *pol, unsigned int n_slots,
			    const char *what, bool nested)
{
	unsigned int i;

	for (i = 0; i < n_slots; i++) {
		const struct pslot *slot = &pol[i];

		if (slot->nest != NULL)
			expect_required(slot->nest, slot->n_nest, what, true);
		if (!slot->required)
			continue;

		if (slot->streams < REQUIRED_STREAMS) {
			fprintf(stderr, "%s: attribute %u has %u streams, want %u\n",
				what, slot->id, slot->streams, REQUIRED_STREAMS);
			BUG("nfnl grammar: too few streams to judge a required attribute");
		}
		if (slot->present < slot->streams * 7 / 10) {
			fprintf(stderr, "%s: attribute %u is in %u of %u streams, want at least 0.70\n",
				what, slot->id, slot->present, slot->streams);
			BUG("nfnl grammar: a required attribute is left out too often");
		}
		if (slot->present == slot->streams && !(nested && n_slots == 1)) {
			fprintf(stderr, "%s: attribute %u is in all %u streams\n",
				what, slot->id, slot->streams);
			BUG("nfnl grammar: a required attribute is never left out");
		}
	}
}

/*
 * What build_one_nlmsg() puts after a message's header: the attributes the
 * cmd's handler needs, then up to seven drawn from its table.
 */
static size_t build_stream(unsigned char *buf, size_t buflen,
			   const struct nla_attr_spec *table, size_t n_specs)
{
	uint64_t used = 0;
	size_t off = append_required_attrs(buf, 0, buflen, table, n_specs, &used);
	unsigned int draws = rnd_modulo_u32(8);

	while (draws-- > 0 && off < buflen) {
		size_t new_off = append_specced_nlattr(buf, off, buflen, table,
						       n_specs, &used);

		if (new_off == off)
			break;
		off = new_off;
	}
	return off;
}

static const struct nfnl_cmd_grammar *find_cmd(const struct nfnl_subsys_grammar *sub,
					       unsigned char cmd)
{
	unsigned int i;

	for (i = 0; i < sub->n_cmds; i++) {
		if (sub->cmds[i].cmd == cmd)
			return &sub->cmds[i];
	}
	return NULL;
}

/*
 * A cmd with a row has a table of its own that is its policy as the handler
 * reads it, the generator draws a message of its type from that table, and
 * the attributes the handler needs are in most of those messages and not in
 * all.
 */
static void check_cmd_row(struct cmd_row *row)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(row->subsys);
	const struct nfnl_cmd_grammar *cmd;
	struct nlmsghdr nlh = { .nlmsg_type = (row->subsys << 8) | row->cmd };
	const struct nla_attr_spec *table;
	size_t n_table = 0;
	unsigned int round;

	if (sub == NULL)
		BUG("nfnl grammar: a cmd's subsystem is not registered");
	cmd = find_cmd(sub, row->cmd);
	if (cmd == NULL) {
		fprintf(stderr, "%s: the grammar does not list it\n", row->name);
		BUG("nfnl grammar: a command is missing");
	}
	if (cmd->attrs == NULL) {
		fprintf(stderr, "%s: it has no table of its own\n", row->name);
		BUG("nfnl grammar: a command draws from its subsystem's table");
	}

	expect_declared(cmd->attrs, cmd->n_attrs, row->pol, row->n_slots, row->name);

	table = pick_spec_table(NETLINK_NETFILTER, &nlh, &n_table);
	if (table != cmd->attrs || n_table != cmd->n_attrs) {
		fprintf(stderr, "%s: the generator draws from another table\n", row->name);
		BUG("nfnl grammar: the generator ignores a cmd's table");
	}

	for (round = 0; round < STREAMS_MAX &&
	     (round < STREAMS_MIN || min_streams(row->pol, row->n_slots) < REQUIRED_STREAMS);
	     round++) {
		unsigned char buf[1280];
		size_t end;

		memset(buf, 0, sizeof(buf));
		end = build_stream(buf, sizeof(buf), cmd->attrs, cmd->n_attrs);
		tally_stream(buf, end, row->pol, row->n_slots);
	}
	expect_required(row->pol, row->n_slots, row->name, false);
}

/*
 * nft_table_policy has the name (1), the flags (2) and the user data (6) that
 * a table command can use, and the handle (4) a delete may name a table by.
 * The grammar leaves the handle out.  NEWTABLE and a GETTABLE that is not a
 * dump answer a missing name -EINVAL; a delete without a name or a handle
 * flushes the family, so its name is not marked.
 */
static struct pslot table_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PSB(2, false, NLA_KIND_BE32_MASK, 0, 0x7),
	PS(6, false, 0),
};
static struct pslot table_get[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
};
static struct pslot table_del[] = {
	PS(1, false, NLA_KIND_STRING_WORD),
};

/*
 * nft_chain_policy has the table (1), the handle (2), the name (3), HOOK (4),
 * POLICY (5), TYPE (7), COUNTERS (8), the flags (10), the id (11) and the user
 * data (12).  NEWCHAIN reads all but the handle and the id, which the grammar
 * leaves out; the other three commands read the table and the name.  HOOK is
 * nft_hook_policy's hook number (1) and priority (2), which a base chain
 * needs both of, and COUNTERS nft_counter_policy's bytes (1) and packets (2),
 * of which nft_stats_alloc() wants both; the hook's device (3 and 4) is only
 * for a netdev chain, and a chain of another family answers one -EOPNOTSUPP.
 */
static struct pslot chain_hook[] = {
	PS(1, true, NLA_KIND_BE32_ONEOF),
	PS(2, true, 0),
};
static struct pslot chain_counters[] = {
	PS(1, true, 0),
	PS(2, true, 0),
};
static struct pslot chain_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(3, true, NLA_KIND_STRING_WORD),
	PSN(4, false, chain_hook),
	PS(5, false, NLA_KIND_BE32_ONEOF),
	PS(7, false, NLA_KIND_STRING_ONEOF),
	PSN(8, false, chain_counters),
	PSB(10, false, NLA_KIND_BE32_MASK, 0, 0x7),
	PS(12, false, 0),
};
static struct pslot chain_name[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(3, true, NLA_KIND_STRING_WORD),
};

/*
 * nft_rule_policy has the table (1), the chain (2), the handle (3), the
 * expressions (4), COMPAT (5), POSITION (6), the user data (7), the id (9),
 * POSITION_ID (10) and CHAIN_ID (11).  NEWRULE reads the table and the chain,
 * and answers -EINVAL to a request without a table or with neither a chain
 * nor a chain id; it also reads the expressions, the user data and the id.
 * GETRULE and GETRULE_RESET read the table and the chain, and a dump takes
 * them as the filters of what it lists.  DELRULE and DESTROYRULE need the
 * table, and with no chain delete the rules of every chain in it.  The
 * grammar leaves out the handle, POSITION, POSITION_ID and CHAIN_ID, which
 * name a rule or a chain by a number that a draw cannot know, and COMPAT, which
 * only the nft_compat expressions read.
 */
static struct pslot rule_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PS(4, false, NLA_KIND_NESTED),
	PS(7, false, 0),
	PS(9, false, 0),
};
static struct pslot rule_get[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
};
static struct pslot rule_del[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, false, NLA_KIND_STRING_WORD),
};

/*
 * nft_set_policy has the table (1), the name (2), the flags (3), KEY_TYPE (4),
 * KEY_LEN (5), DATA_TYPE (6), DATA_LEN (7), POLICY (8), DESC (9), the id (10),
 * TIMEOUT (11), GC_INTERVAL (12), the user data (13), OBJ_TYPE (15), the
 * handle (16), EXPR (17), EXPRESSIONS (18) and two that it rejects, TYPE (19)
 * and COUNT (20).  NEWSET answers -EINVAL unless the request holds the table,
 * the name, KEY_LEN and the set's id, and reads the rest of what a set is made
 * from; the grammar leaves out DESC, EXPR and EXPRESSIONS, nests it cannot
 * build, and the handle, which a draw cannot know.  GETSET, DELSET and
 * DESTROYSET need the table and the name.
 */
static struct pslot set_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSB(3, false, NLA_KIND_BE32_MASK, 0, 0x1ff),
	PS(4, false, 0),
	PSB(5, true, NLA_KIND_BE32_RANGE, 1, 64),
	PS(6, false, 0),
	PSB(7, false, NLA_KIND_BE32_RANGE, 1, 64),
	PS(8, false, NLA_KIND_BE32_ONEOF),
	PS(10, true, 0),
	PS(11, false, 0),
	PS(12, false, 0),
	PS(13, false, 0),
	PS(15, false, 0),
};
static struct pslot set_name[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
};

/*
 * nft_set_elem_list_policy has the table (1), the set's name (2), ELEMENTS
 * (3), an array of nft_set_elem_policy, and the set's id (4).  NEWSETELEM
 * answers -EINVAL without ELEMENTS, then without the table, then without the
 * set, which the id can stand in for.  GETSETELEM wants ELEMENTS unless it is
 * a dump, and then the table and the set; DELSETELEM and DESTROYSETELEM want
 * the table and the set, and without ELEMENTS empty the set.  Only NEWSETELEM
 * reads the id.
 *
 * An element is nft_set_elem_policy's KEY (1), DATA (2), FLAGS (3), TIMEOUT
 * (4), EXPIRATION (5), the user data (6), EXPR (7), OBJREF (9), KEY_END (10)
 * and EXPRESSIONS (11).  Adding one reads all of them and answers -EINVAL
 * without a KEY unless the flags say CATCHALL; getting and deleting one read
 * the KEY, the flags and KEY_END.  A key is nft_data_policy's VALUE (1), which
 * it must hold, the VERDICT (2) being no key.  The grammar types the key
 * nests and leaves DATA, EXPR and EXPRESSIONS to the table the element is in.
 */
static struct pslot setelem_key[] = {
	PS(1, true, 0),
};
static struct pslot setelem_add[] = {
	PSN(1, true, setelem_key),
	PS(2, false, NLA_KIND_NESTED),
	PSB(3, false, NLA_KIND_BE32_MASK, 0, 0x3),
	PS(4, false, 0),
	PS(5, false, 0),
	PS(6, false, 0),
	PS(7, false, NLA_KIND_NESTED),
	PS(9, false, NLA_KIND_STRING),
	PSN(10, false, setelem_key),
	PS(11, false, NLA_KIND_NESTED),
};
static struct pslot setelem_find[] = {
	PSN(1, true, setelem_key),
	PSB(3, false, NLA_KIND_BE32_MASK, 0, 0x3),
	PSN(10, false, setelem_key),
};
static struct pslot setelem_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSA(3, true, setelem_add),
	PS(4, false, 0),
};
static struct pslot setelem_get[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSA(3, true, setelem_find),
};
static struct pslot setelem_del[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSA(3, false, setelem_find),
};

/*
 * nft_obj_policy has the table (1), the name (2), the type (3), DATA (4), the
 * handle (6) and the user data (8); the use count (5) is for replies.
 * NEWOBJ answers -EINVAL unless the request holds the type, the name and
 * DATA, and fails a missing table the same way, so it marks all four.
 * GETOBJ and GETOBJ_RESET need the table, the name and the type, as do
 * DELOBJ and DESTROYOBJ, which may name the object by its handle instead of
 * its name; the grammar leaves the handle out, as a number a draw cannot
 * know.  DATA is a bare nest that the handler parses against the policy of
 * the object's type, which nothing in a request ties to the type drawn.
 */
static struct pslot obj_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSB(3, true, NLA_KIND_BE32_RANGE, 1, 10),
	PS(4, true, NLA_KIND_NESTED),
	PS(8, false, 0),
};
static struct pslot obj_name[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSB(3, true, NLA_KIND_BE32_RANGE, 1, 10),
};

/*
 * nft_flowtable_policy has the table (1), the name (2), HOOK (3), the handle
 * (5) and the flags (7); the use count (4) is for replies.  NEWFLOWTABLE
 * answers -EINVAL unless the request holds the table, the name and HOOK, so it
 * marks all three.  HOOK is nft_flowtable_hook_policy's NUM (1), PRIORITY (2)
 * and DEVS (3): nft_flowtable_parse_hook() answers -ENOENT unless it has the
 * first two, and the grammar leaves DEVS out, since a flowtable without
 * devices is accepted.  GETFLOWTABLE needs the name and the table, and the
 * deletes the table and the name or the handle, which the grammar leaves out;
 * a HOOK in a delete takes devices out of the flowtable, so it is left out too.
 */
static struct pslot flowtable_hook[] = {
	PS(1, true, NLA_KIND_BE32_ONEOF),
	PS(2, true, 0),
};
static struct pslot flowtable_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
	PSN(3, true, flowtable_hook),
	PSB(7, false, NLA_KIND_BE32_MASK, 0, 0x3),
};
static struct pslot flowtable_name[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_STRING_WORD),
};

/*
 * cttimeout_nla_policy has the name (1), L3PROTO (2), L4PROTO (3) and DATA (4);
 * the use count (5) is for replies.  NEW answers -EINVAL unless the request
 * holds the first four.  GET wants the name unless it is a dump.  DELETE takes
 * a name, and without one deletes every timeout, so its name is not marked.
 * DEFAULT_SET wants L4PROTO and DATA and DEFAULT_GET wants L3PROTO and
 * L4PROTO; neither reads a name.  DATA is parsed against the policy of the L4
 * protocol, each of which is NLA_U32 timeouts numbered from 1, TCP's 11 the
 * most, so one table of 11 serves them all.
 */
static struct pslot cttimeout_data[] = {
	PS(1, false, 0), PS(2, false, 0), PS(3, false, 0), PS(4, false, 0),
	PS(5, false, 0), PS(6, false, 0), PS(7, false, 0), PS(8, false, 0),
	PS(9, false, 0), PS(10, false, 0), PS(11, false, 0),
};
static struct pslot cttimeout_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, true, NLA_KIND_BE16_ONEOF),
	PS(3, true, NLA_KIND_U8_ONEOF),
	PSN(4, true, cttimeout_data),
};
static struct pslot cttimeout_get[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
};
static struct pslot cttimeout_del[] = {
	PS(1, false, NLA_KIND_STRING_WORD),
};
static struct pslot cttimeout_default_set[] = {
	PS(3, true, NLA_KIND_U8_ONEOF),
	PSN(4, true, cttimeout_data),
};
static struct pslot cttimeout_default_get[] = {
	PS(2, true, NLA_KIND_BE16_ONEOF),
	PS(3, true, NLA_KIND_U8_ONEOF),
};

/*
 * nfnl_compat_policy_get has the name (1), REV (2) and TYPE (3), and
 * nfnl_compat_get_rcu() answers -EINVAL unless all three are there.
 */
static struct pslot compat_get[] = {
	PS(1, true, NLA_KIND_STRING_ONEOF),
	PS(2, true, NLA_KIND_BE32_ONEOF),
	PS(3, true, NLA_KIND_BE32_ONEOF),
};

/*
 * nfnl_acct_policy types the name (1), PKTS (2), BYTES (3), FLAGS (5), QUOTA
 * (6) and FILTER (7); 4 is the use count, which only a reply carries.  NEW
 * answers -EINVAL without a name, and reads the counters, the flags and the
 * quota.  GET wants a name unless it is a dump; a dump reads FILTER, a nest
 * whose MASK (1) and VALUE (2) nfnl_acct_start() wants both of, answering
 * -EINVAL if either is missing.  DEL takes a name, and without one deletes
 * every object, so its name is not marked.
 */
static struct pslot acct_filter[] = {
	PS(1, true, 0),
	PS(2, true, 0),
};
static struct pslot acct_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PS(2, false, 0),
	PS(3, false, 0),
	PSB(5, false, NLA_KIND_BE32_MASK, 0, 0x3),
	PS(6, false, 0),
};
static struct pslot acct_get[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PSN(7, false, acct_filter),
};
static struct pslot acct_del[] = {
	PS(1, false, NLA_KIND_STRING_WORD),
};

/*
 * nfnl_hook_nla_policy has HOOKNUM (1), PRIORITY (2), DEV (3), FUNCTION_NAME
 * (4), MODULE_NAME (5) and CHAIN_INFO (6).  nfnl_hook_get() answers -EINVAL
 * without HOOKNUM, and nfnl_hook_dump_start() reads DEV only for
 * NFPROTO_NETDEV, so DEV is not marked; it names lo.  The other four are
 * what a reply carries, and no handler reads them.
 */
static struct pslot hook_get[] = {
	PS(1, true, NLA_KIND_BE32_ONEOF),
	PS(3, false, NLA_KIND_STRING_WORD),
};

/*
 * nfnl_cthelper_policy types the name (1), QUEUE_NUM (3), PRIV_DATA_LEN (5)
 * and STATUS (6), and leaves TUPLE (2) and POLICY (4) to the handlers' own
 * parse.  NEW answers -EINVAL without the name or the tuple, and so does
 * nfnl_cthelper_create() without the policy or PRIV_DATA_LEN.  Wherever the
 * tuple is parsed it needs its L3PROTONUM (1) and L4PROTONUM (2).  The
 * policy needs its SET_NUM (1) and as many SETs (2 to 5) as that counts,
 * which a mark cannot tie to the count, so all four are marked: a SET past
 * the count is passed over.  Each SET needs its name (1), EXPECT_MAX (2) and
 * EXPECT_TIMEOUT (3).  GET and DEL read the name and the tuple and need
 * neither: without them GET answers the first helper and DEL deletes them
 * all.
 */
static struct pslot cthelper_tuple[] = {
	PS(1, true, NLA_KIND_BE16_ONEOF),
	PS(2, true, NLA_KIND_U8_ONEOF),
};
static struct pslot cthelper_expect[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PSB(2, true, NLA_KIND_BE32_RANGE, 0, 255),
	PS(3, true, 0),
};
static struct pslot cthelper_policy[] = {
	PSB(1, true, NLA_KIND_BE32_RANGE, 1, 4),
	PSN(2, true, cthelper_expect),
	PSN(3, true, cthelper_expect),
	PSN(4, true, cthelper_expect),
	PSN(5, true, cthelper_expect),
};
static struct pslot cthelper_new[] = {
	PS(1, true, NLA_KIND_STRING_WORD),
	PSN(2, true, cthelper_tuple),
	PS(3, false, 0),
	PSN(4, true, cthelper_policy),
	PSB(5, true, NLA_KIND_BE32_RANGE, 0, 32),
	PS(6, false, NLA_KIND_BE32_ONEOF),
};
static struct pslot cthelper_find[] = {
	PS(1, false, NLA_KIND_STRING_WORD),
	PSN(2, false, cthelper_tuple),
};

#define NFTABLES	NFNL_SUBSYS_NFTABLES
#define CTTIMEOUT	NFNL_SUBSYS_CTNETLINK_TIMEOUT
#define NFT_COMPAT	NFNL_SUBSYS_NFT_COMPAT
#define ACCT		NFNL_SUBSYS_ACCT
#define HOOK		NFNL_SUBSYS_HOOK
#define CTHELPER	NFNL_SUBSYS_CTHELPER

static struct cmd_row cmd_rows[] = {
	{ "NFT_MSG_NEWTABLE", NFTABLES, 0, table_new, ARRAY_SIZE(table_new) },
	{ "NFT_MSG_GETTABLE", NFTABLES, 1, table_get, ARRAY_SIZE(table_get) },
	{ "NFT_MSG_DELTABLE", NFTABLES, 2, table_del, ARRAY_SIZE(table_del) },
	{ "NFT_MSG_DESTROYTABLE", NFTABLES, 26, table_del, ARRAY_SIZE(table_del) },
	{ "NFT_MSG_NEWCHAIN", NFTABLES, 3, chain_new, ARRAY_SIZE(chain_new) },
	{ "NFT_MSG_GETCHAIN", NFTABLES, 4, chain_name, ARRAY_SIZE(chain_name) },
	{ "NFT_MSG_DELCHAIN", NFTABLES, 5, chain_name, ARRAY_SIZE(chain_name) },
	{ "NFT_MSG_DESTROYCHAIN", NFTABLES, 27, chain_name, ARRAY_SIZE(chain_name) },
	{ "NFT_MSG_NEWRULE", NFTABLES, 6, rule_new, ARRAY_SIZE(rule_new) },
	{ "NFT_MSG_GETRULE", NFTABLES, 7, rule_get, ARRAY_SIZE(rule_get) },
	{ "NFT_MSG_GETRULE_RESET", NFTABLES, 25, rule_get, ARRAY_SIZE(rule_get) },
	{ "NFT_MSG_DELRULE", NFTABLES, 8, rule_del, ARRAY_SIZE(rule_del) },
	{ "NFT_MSG_DESTROYRULE", NFTABLES, 28, rule_del, ARRAY_SIZE(rule_del) },
	{ "NFT_MSG_NEWSET", NFTABLES, 9, set_new, ARRAY_SIZE(set_new) },
	{ "NFT_MSG_GETSET", NFTABLES, 10, set_name, ARRAY_SIZE(set_name) },
	{ "NFT_MSG_DELSET", NFTABLES, 11, set_name, ARRAY_SIZE(set_name) },
	{ "NFT_MSG_DESTROYSET", NFTABLES, 29, set_name, ARRAY_SIZE(set_name) },
	{ "NFT_MSG_NEWSETELEM", NFTABLES, 12, setelem_new, ARRAY_SIZE(setelem_new) },
	{ "NFT_MSG_GETSETELEM", NFTABLES, 13, setelem_get, ARRAY_SIZE(setelem_get) },
	{ "NFT_MSG_GETSETELEM_RESET", NFTABLES, 33, setelem_get, ARRAY_SIZE(setelem_get) },
	{ "NFT_MSG_DELSETELEM", NFTABLES, 14, setelem_del, ARRAY_SIZE(setelem_del) },
	{ "NFT_MSG_DESTROYSETELEM", NFTABLES, 30, setelem_del, ARRAY_SIZE(setelem_del) },
	{ "NFT_MSG_NEWOBJ", NFTABLES, 18, obj_new, ARRAY_SIZE(obj_new) },
	{ "NFT_MSG_GETOBJ", NFTABLES, 19, obj_name, ARRAY_SIZE(obj_name) },
	{ "NFT_MSG_GETOBJ_RESET", NFTABLES, 21, obj_name, ARRAY_SIZE(obj_name) },
	{ "NFT_MSG_DELOBJ", NFTABLES, 20, obj_name, ARRAY_SIZE(obj_name) },
	{ "NFT_MSG_DESTROYOBJ", NFTABLES, 31, obj_name, ARRAY_SIZE(obj_name) },
	{ "NFT_MSG_NEWFLOWTABLE", NFTABLES, 22, flowtable_new, ARRAY_SIZE(flowtable_new) },
	{ "NFT_MSG_GETFLOWTABLE", NFTABLES, 23, flowtable_name, ARRAY_SIZE(flowtable_name) },
	{ "NFT_MSG_DELFLOWTABLE", NFTABLES, 24, flowtable_name, ARRAY_SIZE(flowtable_name) },
	{ "NFT_MSG_DESTROYFLOWTABLE", NFTABLES, 32, flowtable_name, ARRAY_SIZE(flowtable_name) },
	{ "IPCTNL_MSG_TIMEOUT_NEW", CTTIMEOUT, 0, cttimeout_new, ARRAY_SIZE(cttimeout_new) },
	{ "IPCTNL_MSG_TIMEOUT_GET", CTTIMEOUT, 1, cttimeout_get, ARRAY_SIZE(cttimeout_get) },
	{ "IPCTNL_MSG_TIMEOUT_DELETE", CTTIMEOUT, 2, cttimeout_del, ARRAY_SIZE(cttimeout_del) },
	{ "IPCTNL_MSG_TIMEOUT_DEFAULT_SET", CTTIMEOUT, 3, cttimeout_default_set,
	  ARRAY_SIZE(cttimeout_default_set) },
	{ "IPCTNL_MSG_TIMEOUT_DEFAULT_GET", CTTIMEOUT, 4, cttimeout_default_get,
	  ARRAY_SIZE(cttimeout_default_get) },
	{ "NFNL_MSG_COMPAT_GET", NFT_COMPAT, 0, compat_get, ARRAY_SIZE(compat_get) },
	{ "NFNL_MSG_ACCT_NEW", ACCT, 0, acct_new, ARRAY_SIZE(acct_new) },
	{ "NFNL_MSG_ACCT_GET", ACCT, 1, acct_get, ARRAY_SIZE(acct_get) },
	{ "NFNL_MSG_ACCT_DEL", ACCT, 3, acct_del, ARRAY_SIZE(acct_del) },
	{ "NFNL_MSG_HOOK_GET", HOOK, 0, hook_get, ARRAY_SIZE(hook_get) },
	{ "NFNL_MSG_CTHELPER_NEW", CTHELPER, 0, cthelper_new, ARRAY_SIZE(cthelper_new) },
	{ "NFNL_MSG_CTHELPER_GET", CTHELPER, 1, cthelper_find, ARRAY_SIZE(cthelper_find) },
	{ "NFNL_MSG_CTHELPER_DEL", CTHELPER, 2, cthelper_find, ARRAY_SIZE(cthelper_find) },
};

/*
 * Every command that has a table of its own has a mirror of its policy in
 * cmd_rows[], which is what holds the table to the kernel's.
 */
static void check_rows_cover_tables(void)
{
	unsigned int id, i, j;

	for (id = 0; id < 256; id++) {
		const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(id);

		for (i = 0; sub != NULL && i < sub->n_cmds; i++) {
			if (sub->cmds[i].attrs == NULL)
				continue;
			for (j = 0; j < ARRAY_SIZE(cmd_rows); j++) {
				if (cmd_rows[j].subsys == id &&
				    cmd_rows[j].cmd == sub->cmds[i].cmd)
					break;
			}
			if (j == ARRAY_SIZE(cmd_rows)) {
				fprintf(stderr, "%s: has a table and no mirror of its policy\n",
					sub->cmds[i].name);
				BUG("nfnl grammar: a command's table is not held to a policy");
			}
		}
	}
}

/*
 * nf_tables_cb[] gives every nftables command but NFT_MSG_GETGEN a policy,
 * and the grammar a table for each; GETGEN takes no attribute at all, so it
 * has none and the subsystem has no union to fall back on.
 */
static void check_nftables_tables(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	unsigned int i;

	if (sub == NULL)
		BUG("nfnl grammar: nftables is not registered");
	if (sub->n_attrs != 0)
		BUG("nfnl grammar: nftables draws from a union again");

	for (i = 0; i < sub->n_cmds; i++) {
		bool getgen = sub->cmds[i].cmd == 16;

		if ((sub->cmds[i].attrs == NULL) != getgen) {
			fprintf(stderr, "%s: %s a table of its own\n", sub->cmds[i].name,
				getgen ? "has" : "lacks");
			BUG("nfnl grammar: an nftables command has the wrong table");
		}
	}
}

/*
 * The names a handler looks up in a registry, which a word list must hold and
 * no others: nft_chain_filter.c, nft_chain_nat.c and nft_chain_route.c
 * register the chain types "filter", "nat" and "route", and any other name
 * costs nf_tables_chain_type_lookup() a request_module().
 */
struct word_slot {
	const char *name;
	unsigned char subsys;
	unsigned char cmd;	/* the cmd whose own table holds the spec */
	unsigned short id;
	const char *const *words;
	unsigned int n_words;
};

static const char *const chain_types[] = { "filter", "nat", "route" };

/*
 * nfnl_compat_get_rcu() hands the name to xt_find_revision(), which looks for
 * a match or, for TYPE 1, a target of that name registered for the family,
 * and has try_then_request_module() run modprobe for "ipt_<name>" and its
 * kin when there is none.  These are the matches that xt_tcpudp.c, xt_mark.c,
 * xt_limit.c, xt_state.c, xt_conntrack.c, xt_comment.c and xt_pkttype.c
 * register, and the targets that xt_mark.c, xt_NFQUEUE.c, xt_CT.c, xt_NFLOG.c,
 * xt_TRACE.c and xt_CLASSIFY.c do, each for IPv4 and IPv6 or for every
 * family, under module aliases that load them.
 */
static const char *const xt_names[] = {
	"tcp", "udp", "mark", "limit", "state", "conntrack", "comment", "pkttype",
	"MARK", "NFQUEUE", "CT", "NFLOG", "TRACE", "CLASSIFY",
};

static const struct word_slot word_slots[] = {
	{ "NFTA_CHAIN_TYPE", NFTABLES, 3, 7, chain_types, ARRAY_SIZE(chain_types) },
	{ "NFTA_COMPAT_NAME", NFT_COMPAT, 0, 1, xt_names, ARRAY_SIZE(xt_names) },
};

static void check_word_slot(const struct word_slot *slot)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(slot->subsys);
	const struct nfnl_cmd_grammar *cmd = sub ? find_cmd(sub, slot->cmd) : NULL;
	const struct nla_attr_spec *spec = NULL;
	unsigned int i, j, matched = 0;

	if (cmd == NULL || cmd->attrs == NULL)
		BUG("nfnl grammar: a word list's command has no table of its own");
	for (i = 0; i < cmd->n_attrs; i++) {
		if (cmd->attrs[i].type == slot->id)
			spec = &cmd->attrs[i];
	}
	if (spec == NULL || spec->kind != NLA_KIND_STRING_ONEOF ||
	    spec->n_words != slot->n_words) {
		fprintf(stderr, "%s: no word list of %u words at id %u\n",
			slot->name, slot->n_words, slot->id);
		BUG("nfnl grammar: a name is not drawn from the registry's words");
	}
	for (i = 0; i < spec->n_words; i++) {
		for (j = 0; j < slot->n_words; j++) {
			if (strcmp(spec->words[i], slot->words[j]) == 0)
				matched |= 1U << j;
		}
	}
	if (matched != (1U << slot->n_words) - 1) {
		fprintf(stderr, "%s: the words are not the registry's\n", slot->name);
		BUG("nfnl grammar: a name is not drawn from the registry's words");
	}
	check_word_draws(slot->name, spec);
}

#define BATCH_ROUNDS	60000

/* BEGIN or END at buf: just the header and an nfgenmsg, and a request. */
static bool is_marker(const unsigned char *buf, unsigned short type)
{
	struct nlmsghdr nlh;

	memcpy(&nlh, buf, sizeof(nlh));
	return nlh.nlmsg_type == type &&
	       nlh.nlmsg_len == NLMSG_LENGTH(sizeof(struct nfgenmsg)) &&
	       (nlh.nlmsg_flags & NLM_F_REQUEST);
}

#define MAX_CMDS	8	/* the generator puts at most four in a batch */

/* What the commands of a batch hold, when every length ran true. */
struct batch_cmds {
	const char *word;		/* in: the word the names should be */
	unsigned int n;			/* commands; 0 when a length did not run true */
	bool stray;			/* one of them is no batch command */
	unsigned char family[MAX_CMDS];	/* each one's nfgen_family */
	unsigned int named;		/* attributes at id 1 as long as the word */
	unsigned int matching;		/* ... of which are the word */
};

/* Count the attributes at id 1 of the command at msg, len long, that are as
 * long as the word, which makes them table names, and those that are the
 * word. */
static void count_names(const unsigned char *msg, size_t len,
			struct batch_cmds *cmds)
{
	const size_t wlen = strlen(cmds->word) + 1;
	size_t off = NLMSG_SPACE(sizeof(struct nfgenmsg));

	while (off + NLA_HDRLEN <= len) {
		struct nlattr nla;

		memcpy(&nla, msg + off, sizeof(nla));
		if (nla.nla_len < NLA_HDRLEN || off + nla.nla_len > len)
			return;
		if (nla.nla_type == 1 && nla.nla_len == NLA_HDRLEN + wlen) {
			cmds->named++;
			if (memcmp(msg + off + NLA_HDRLEN, cmds->word, wlen) == 0)
				cmds->matching++;
		}
		off += NLA_ALIGN(nla.nla_len);
	}
}

/*
 * Check what lies after BEGIN in a buffer that opens with it, up to END, or to
 * the end of the buffer when ended is false.  BEGIN names nftables in
 * res_id, and the commands are batch commands of that subsystem:
 * nfnetlink_rcv_batch() answers any other -EINVAL, and a batch with an error
 * in it cannot commit.  The first command's header sits right after BEGIN, so
 * its type is held to that outright.  A later header sits where the lengths
 * before it put it, which a length the generator corrupted on purpose throws
 * off into the bytes of another message, and what is read there is noise.  So
 * the later commands are judged only when every length ran true and the chain
 * ended exactly where the commands do, and then only reported, in *out.
 * Returns the first command's type, or 0 when there is none.
 */
static unsigned short check_batch_buffer(const unsigned char *buf, size_t len,
					 bool ended, struct batch_cmds *out)
{
	const size_t marker = NLMSG_SPACE(sizeof(struct nfgenmsg));
	const size_t end_off = ended ? len - marker : len;
	struct batch_cmds seen = { .word = out->word };
	unsigned short first = 0;
	struct nfgenmsg nfg;
	size_t off = marker;

	memcpy(&nfg, buf + NLMSG_HDRLEN, sizeof(nfg));
	if (nfg.res_id != htons(NFNL_SUBSYS_NFTABLES))
		BUG("nfnl batch: BEGIN does not name the nftables subsystem");

	out->n = 0;
	while (off + NLMSG_HDRLEN <= end_off) {
		struct nlmsghdr nlh;
		bool batch_cmd, holds;

		memcpy(&nlh, buf + off, sizeof(nlh));
		holds = nlh.nlmsg_len >= NLMSG_LENGTH(sizeof(struct nfgenmsg)) &&
			nlh.nlmsg_len <= end_off - off;
		if (seen.n > 0 && !holds)
			return first;

		batch_cmd = NFNL_SUBSYS_ID(nlh.nlmsg_type) == NFNL_SUBSYS_NFTABLES &&
			    nfnl_type_is_batch(nlh.nlmsg_type);
		if (seen.n == 0) {
			first = nlh.nlmsg_type;
			if (!batch_cmd) {
				fprintf(stderr, "nfnl batch: type %#x opens a batch\n", first);
				BUG("nfnl batch: the first message is no nftables batch command");
			}
		} else if (!batch_cmd) {
			seen.stray = true;
		}
		if (!holds)
			return first;
		if (seen.n < MAX_CMDS)
			seen.family[seen.n] = buf[off + NLMSG_HDRLEN];
		seen.n++;
		count_names(buf + off, nlh.nlmsg_len, &seen);
		off += NLMSG_ALIGN(nlh.nlmsg_len);
	}

	if (off == end_off && seen.n <= MAX_CMDS)
		*out = seen;
	return first;
}

struct batch_tally {
	unsigned int wrapped;	/* opens with BEGIN and closes with END */
	unsigned int unended;	/* opens with BEGIN and has no END */
	unsigned int bare;	/* opens with a batch command, nothing around it */
	unsigned int multi;	/* opens with BEGIN, two commands or more, every length true */
	unsigned int stray;	/* ... of which hold a message that is no batch command */
	unsigned int same;	/* ... of which send every command in one family */
	unsigned int counted;	/* opens with BEGIN, one command or more, every length true */
	unsigned int named;	/* ... table names in them */
	unsigned int matching;	/* ... of which are the word */
	unsigned int family[256];	/* ... by the family of the first command */
	const char *word;
	bool led[256];		/* batch commands that opened a batch, by id */
};

static void tally_buffer(struct batch_tally *t, const unsigned char *buf,
			 size_t len)
{
	const size_t marker = NLMSG_SPACE(sizeof(struct nfgenmsg));
	struct nlmsghdr nlh;

	if (len < NLMSG_HDRLEN)
		return;
	memcpy(&nlh, buf, sizeof(nlh));

	if (len >= marker && is_marker(buf, NFNL_MSG_BATCH_BEGIN)) {
		bool ended = len >= 2 * marker &&
			     is_marker(buf + len - marker, NFNL_MSG_BATCH_END);
		struct batch_cmds cmds = { .word = t->word };
		unsigned short first;
		unsigned int i;

		first = check_batch_buffer(buf, len, ended, &cmds);
		if (ended)
			t->wrapped++;
		else
			t->unended++;
		if (cmds.n >= 1) {
			t->counted++;
			t->named += cmds.named;
			t->matching += cmds.matching;
			t->family[cmds.family[0]]++;
		}
		if (cmds.n >= 2) {
			t->multi++;
			if (cmds.stray)
				t->stray++;
			for (i = 1; i < cmds.n && cmds.family[i] == cmds.family[0]; i++)
				;
			if (i == cmds.n)
				t->same++;
		}
		if (first != 0)
			t->led[first & 0xff] = true;
	} else if (nfnl_type_is_batch(nlh.nlmsg_type)) {
		t->bare++;
	}
}

/*
 * A buffer whose first message is a batch command goes out behind BEGIN seven
 * times in eight, and bare the eighth, so 0.875 of those buffers open with
 * BEGIN.  A run draws about 3000 of them, so the fraction has a standard
 * deviation of 0.006 and the limits 0.80 and 0.95 are 12 sigma off; they turn
 * away a generator that never wraps and one that always does.  One batch in
 * eight leaves END off, which nfnetlink_rcv_batch() ends with
 * NFNL_ABORT_VALIDATE when no command failed, so 0.125 of the batches have no
 * END; a run has about 2700 batches, so the fraction has a standard deviation
 * of 0.006 and the limits 0.05 and 0.25 are 12 and 19 sigma off, and turn away
 * a generator that always writes END and one that mostly leaves it off.  A
 * quarter of the batches hold two commands or more, about 500 with every
 * length true.  Their later commands are batch callbacks too; picked as the
 * first message of any buffer is, nearly every such batch would hold some
 * other message, where as built none does, so a tenth is a wide limit.  And
 * each of the 21 batch commands must open some batch.
 *
 * Of the batches whose lengths all ran true, a run has about 1200 table names
 * in them, and a command names its table with the word seven times in eight,
 * so the fraction has a standard deviation of 0.01 and the limits 0.80 and
 * 0.95 are 8 sigma off.  A batch of two commands or more keeps one family
 * unless a command draws its own, about 0.7 of some 480 batches, with a
 * standard deviation of 0.02; commands that each drew a family share one about
 * 0.08 of the time and ones that never drew their own always, so the limits
 * 0.50 and 0.90 are 10 sigma off.  A sixth of the batches open in each of the
 * six families, and a twentieth is a wide floor.
 */
static void check_nftables_batches(const char *word)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_NETFILTER,
	};
	struct batch_tally t = { .word = word };
	unsigned int round, i, opened, led = 0;
	double frac;

	if (sub == NULL)
		BUG("nfnl grammar: nftables is not registered");

	for (round = 0; round < BATCH_ROUNDS; round++) {
		void *buf;
		size_t len;

		netlink_gen_msg(&triplet, &buf, &len);
		tally_buffer(&t, buf, len);
		free(buf);
	}

	opened = t.wrapped + t.unended;
	if (opened + t.bare < 1000) {
		fprintf(stderr, "nftables: %u batched and %u bare batch commands in %u buffers\n",
			opened, t.bare, BATCH_ROUNDS);
		BUG("nfnl batch: too few batch commands to judge the wrapping");
	}
	frac = (double) opened / (opened + t.bare);
	if (frac < 0.80 || frac > 0.95) {
		fprintf(stderr, "nftables: %u of %u batch commands went out inside a batch, want a fraction in [0.80, 0.95]\n",
			opened, opened + t.bare);
		BUG("nfnl batch: batch commands are not wrapped most of the time");
	}
	frac = (double) t.unended / opened;
	if (frac < 0.05 || frac > 0.25) {
		fprintf(stderr, "nftables: %u of %u batches have no END, want a fraction in [0.05, 0.25]\n",
			t.unended, opened);
		BUG("nfnl batch: batches do not leave END off some of the time");
	}
	if (t.multi < 100) {
		fprintf(stderr, "nftables: %u of %u batches hold two commands or more\n",
			t.multi, opened);
		BUG("nfnl batch: batches never hold more than one command");
	}
	if (t.stray * 10 > t.multi) {
		fprintf(stderr, "nftables: %u of %u batches of two commands or more hold a message that is no batch command\n",
			t.stray, t.multi);
		BUG("nfnl batch: a batch holds commands that are not batch callbacks");
	}

	for (i = 0; i < sub->n_cmds; i++) {
		if (!sub->cmds[i].batch)
			continue;
		if (t.led[sub->cmds[i].cmd])
			led++;
		else
			fprintf(stderr, "%s never opened a batch\n", sub->cmds[i].name);
	}
	if (led != 21)
		BUG("nfnl batch: a batch command is never wrapped");

	if (t.named < 500) {
		fprintf(stderr, "nftables: %u table names in %u batches\n",
			t.named, t.counted);
		BUG("nfnl batch: too few table names to judge the vocabulary");
	}
	frac = (double) t.matching / t.named;
	if (frac < 0.80 || frac > 0.95) {
		fprintf(stderr, "nftables: %u of %u table names in batches are the word, want a fraction in [0.80, 0.95]\n",
			t.matching, t.named);
		BUG("nfnl batch: a batch does not name its table with the word most of the time");
	}
	frac = (double) t.same / t.multi;
	if (frac < 0.50 || frac > 0.90) {
		fprintf(stderr, "nftables: %u of %u batches of two commands or more send every command in one family, want a fraction in [0.50, 0.90]\n",
			t.same, t.multi);
		BUG("nfnl batch: the commands of a batch do not share a family most of the time");
	}
	for (i = 0; i < ARRAY_SIZE(nft_families); i++) {
		if (t.family[nft_families[i]] * 20 >= t.counted)
			continue;
		fprintf(stderr, "nftables: %u of %u batches open in family %u\n",
			t.family[nft_families[i]], t.counted, nft_families[i]);
		BUG("nfnl batch: a family opens too few batches");
	}
}

void nfnl_gen_self_check(void);
void nfnl_gen_self_check(void)
{
	const char *word;
	unsigned int i;

	check_no_rejected_attr();
	check_cmd_attrs_lookup();
	check_spec_table_dispatch();
	check_string_oneof();
	check_be32_range();
	check_cttimeout_commands();
	for (i = 0; i < ARRAY_SIZE(slots); i++)
		check_bounded_slot(&slots[i]);
	for (i = 0; i < ARRAY_SIZE(oneof_slots); i++)
		check_oneof_slot(&oneof_slots[i]);
	word = check_nftables_names();
	expect_families(NFNL_SUBSYS_NFTABLES, "nftables", nft_families,
			ARRAY_SIZE(nft_families));
	expect_families(NFNL_SUBSYS_HOOK, "hook", hook_families,
			ARRAY_SIZE(hook_families));
	check_nftables_lone_families();
	for (i = 0; i < ARRAY_SIZE(word_names); i++)
		check_word_name(&word_names[i]);
	check_nftables_batch_flags();
	check_nftables_batches(word);
	check_nftables_tables();
	check_rows_cover_tables();
	for (i = 0; i < ARRAY_SIZE(cmd_rows); i++)
		check_cmd_row(&cmd_rows[i]);
	for (i = 0; i < ARRAY_SIZE(word_slots); i++)
		check_word_slot(&word_slots[i]);
}
