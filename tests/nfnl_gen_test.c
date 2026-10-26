/*
 * Self-check for the nfnetlink grammars as the message generator draws from
 * them: each case holds a grammar to a fact about the kernel's policy for
 * the subsystem.  The RNG helpers netlink_gen_msg() reaches are the fakes in
 * genl_ops_test.c; no netlink socket is opened.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "netlink-attrs.h"	/* struct nla_attr_spec */
#include "netlink-nfnl-subsystems.h"
#include "utils.h"		/* ARRAY_SIZE */

size_t append_specced_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs);

#define ROUNDS		50000

/*
 * ct_nla_policy marks CTA_TIMESTAMP_EVENT, the last ctattr_type, NLA_REJECT,
 * so the commands that carry that policy answer a message with it -EINVAL
 * before the handler runs.
 */
#define KERNEL_CTA_TIMESTAMP_EVENT	27

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
		if (append_specced_nlattr(buf, 0, sizeof(buf), sub->attrs, sub->n_attrs) == 0)
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

#define SLOT_ROUNDS	20000

struct bounded_slot {
	const char *name;
	unsigned char subsys;
	unsigned short id;
	unsigned short kind;	/* NLA_POLICY_MASK or NLA_POLICY_MAX, and the width */
	unsigned short limit;
};

/*
 * The top-level attributes the netfilter policies bound with NLA_POLICY_MASK
 * or NLA_POLICY_MAX, all read in network byte order, with the bound each
 * policy gives.  The ids are the attribute enums' positions.
 */
static const struct bounded_slot slots[] = {
	/* nfnl_acct_policy, NFACCT_F_QUOTA: both quota bits */
	{ "NFACCT_FLAGS", NFNL_SUBSYS_ACCT, 5, NLA_KIND_BE32_MASK, 0x3 },
	/* nfnl_hook_nla_policy */
	{ "NFNLA_HOOK_HOOKNUM", NFNL_SUBSYS_HOOK, 1, NLA_KIND_BE32_MAX, 255 },
	/* nfnl_compat_policy_get */
	{ "NFTA_COMPAT_REV", NFNL_SUBSYS_NFT_COMPAT, 2, NLA_KIND_BE32_MAX, 255 },
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
};

/* The subsystem's spec for the slot's id that declares the slot's kind and
 * bound; a plain U32 there would send random bytes. */
static const struct nla_attr_spec *find_slot_spec(const struct bounded_slot *slot)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(slot->subsys);
	unsigned int i;

	if (sub == NULL) {
		fprintf(stderr, "%s: subsystem %u is not registered\n",
			slot->name, slot->subsys);
		BUG("nfnl grammar: a bounded scalar's subsystem is missing");
	}

	for (i = 0; i < sub->n_attrs; i++) {
		const struct nla_attr_spec *spec = &sub->attrs[i];

		if (spec->type == slot->id && spec->kind == slot->kind &&
		    spec->max_len == slot->limit)
			return spec;
	}

	fprintf(stderr, "%s: no spec of kind %u with bound %#x at id %u\n",
		slot->name, slot->kind, slot->limit, slot->id);
	BUG("nfnl grammar: a bounded scalar is not declared with the kernel's bound");
}

/*
 * One draw in eight is random bytes, so 0.875 of the draws sit inside the
 * bound and almost none of the rest do.  Over SLOT_ROUNDS draws the fraction
 * has a standard deviation of 0.0024, so the limits 0.80 and 0.95 are 30
 * sigma off; they turn away both a spec that sends nothing but random bytes
 * and one that never leaves the bound.  A mask draw must also set and clear
 * every bit of the mask, and a max draw reach both ends of the range, which
 * an always-zero or always-full word does not.
 */
static void check_bounded_slot(const struct bounded_slot *slot)
{
	const struct nla_attr_spec *spec = find_slot_spec(slot);
	const unsigned int width = slot->kind == NLA_KIND_BE16_MASK ? 2 : 4;
	const bool mask = slot->kind != NLA_KIND_BE32_MAX;
	uint32_t min_v = UINT32_MAX, max_v = 0, or_all = 0, and_all = UINT32_MAX;
	unsigned int round, in_bounds = 0;
	unsigned char buf[64];
	double frac;

	for (round = 0; round < SLOT_ROUNDS; round++) {
		struct nlattr nla;
		uint32_t v;

		memset(buf, 0, sizeof(buf));
		if (append_specced_nlattr(buf, 0, sizeof(buf), spec, 1) !=
		    NLA_ALIGN(NLA_HDRLEN + width))
			BUG("nfnl grammar: a bounded scalar is not sized to its width");
		memcpy(&nla, buf, sizeof(nla));
		if (nla.nla_type != slot->id || nla.nla_len != NLA_HDRLEN + width)
			BUG("nfnl grammar: a bounded scalar has the wrong header");

		if (width == 2) {
			uint16_t be;

			memcpy(&be, buf + NLA_HDRLEN, sizeof(be));
			v = ntohs(be);
		} else {
			uint32_t be;

			memcpy(&be, buf + NLA_HDRLEN, sizeof(be));
			v = ntohl(be);
		}

		if (mask ? (v & ~(uint32_t) slot->limit) != 0 : v > slot->limit)
			continue;
		in_bounds++;
		or_all |= v;
		and_all &= v;
		if (v < min_v)
			min_v = v;
		if (v > max_v)
			max_v = v;
	}

	frac = (double) in_bounds / SLOT_ROUNDS;
	if (frac < 0.80 || frac > 0.95) {
		fprintf(stderr, "%s: %u of %u draws inside %s %#x, want a fraction in [0.80, 0.95]\n",
			slot->name, in_bounds, SLOT_ROUNDS,
			mask ? "mask" : "maximum", slot->limit);
		BUG("nfnl grammar: a bounded scalar is not drawn from its bound");
	}

	if (mask ? (or_all != slot->limit || and_all != 0) :
		   (min_v != 0 || max_v != slot->limit)) {
		fprintf(stderr, "%s: draws inside the bound span or %#x and %#x, min %u max %u\n",
			slot->name, or_all, and_all, min_v, max_v);
		BUG("nfnl grammar: a bounded scalar does not cover its bound");
	}
}

void nfnl_gen_self_check(void);
void nfnl_gen_self_check(void)
{
	unsigned int i;

	check_no_rejected_attr();
	check_cttimeout_commands();
	for (i = 0; i < ARRAY_SIZE(slots); i++)
		check_bounded_slot(&slots[i]);
}
