/*
 * Self-check for the nfnetlink grammars as the message generator draws from
 * them: each case holds a grammar, or the buffers built from it, to a fact
 * about the kernel's policy or dispatch for the subsystem.  The RNG helpers
 * netlink_gen_msg() reaches are the fakes in genl_ops_test.c; no netlink
 * socket is opened.
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "netlink-attrs.h"	/* struct nla_attr_spec */
#include "netlink-nfnl-subsystems.h"
#include "socketinfo.h"		/* struct socket_triplet */
#include "utils.h"		/* ARRAY_SIZE */

size_t append_specced_nlattr(unsigned char *buf, size_t offset, size_t buflen,
			     const struct nla_attr_spec *table, size_t nr_specs);
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
};

/*
 * The top-level attributes the netfilter policies bound with NLA_POLICY_MASK
 * or NLA_POLICY_MAX, all read in network byte order, with the bound each
 * policy gives.  The ids are the attribute enums' positions.
 */
static const struct bounded_slot slots[] = {
	/* nfnl_acct_policy, NFACCT_F_QUOTA: both quota bits */
	{ "NFACCT_FLAGS", NFNL_SUBSYS_ACCT, 5, NLA_KIND_BE32_MASK, 0x3 },
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
 * nfnl_hook_entries_head() answers a hook number past the family's array
 * -EINVAL.  IPv4, IPv6 and bridge, the families gen_nfnl_body() names that it
 * knows, have NF_INET_NUMHOOKS entries; nfnl_hook_nla_policy only caps the
 * number at 255.
 */
static const unsigned int hooknums[] = { 0, 1, 2, 3, 4 };

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
	/* nfnl_compat_policy_get types TYPE NLA_U32 */
	{ "NFTA_COMPAT_TYPE", NFNL_SUBSYS_NFT_COMPAT, 3,
	  NLA_KIND_BE32_ONEOF, 0, compat_types, ARRAY_SIZE(compat_types) },
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

/* The subsystem's spec for the slot's id that declares the slot's kind and
 * bound or values; a plain U32 there would send random bytes. */
static const struct nla_attr_spec *find_slot_spec(const struct bounded_slot *slot)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(slot->subsys);
	unsigned int i, j;

	if (sub == NULL) {
		fprintf(stderr, "%s: subsystem %u is not registered\n",
			slot->name, slot->subsys);
		BUG("nfnl grammar: a bounded scalar's subsystem is missing");
	}

	for (i = 0; i < sub->n_attrs; i++) {
		const struct nla_attr_spec *spec = &sub->attrs[i];

		if (spec->type != slot->id || spec->kind != slot->kind ||
		    spec->max_len != slot->limit || spec->n_oneof != slot->n_values)
			continue;
		for (j = 0; j < spec->n_oneof; j++) {
			if (!has_value(slot, spec->oneof[j]))
				break;
		}
		if (j == spec->n_oneof)
			return spec;
	}

	fprintf(stderr, "%s: no spec of kind %u with bound %#x and %u listed values at id %u\n",
		slot->name, slot->kind, slot->limit, slot->n_values, slot->id);
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
	if (append_specced_nlattr(buf, 0, sizeof(buf), spec, 1) !=
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

/* A mask draw must also set and clear every bit of the mask, and a max draw
 * reach both ends of the range, which an always-zero or always-full word
 * does not. */
static void check_bounded_slot(const struct bounded_slot *slot)
{
	const struct nla_attr_spec *spec = find_slot_spec(slot);
	const bool mask = slot->kind != NLA_KIND_BE32_MAX;
	uint32_t min_v = UINT32_MAX, max_v = 0, or_all = 0, and_all = UINT32_MAX;
	unsigned int round, in_bounds = 0;

	for (round = 0; round < SLOT_ROUNDS; round++) {
		uint32_t v = draw_slot(spec, slot);

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

	check_slot_fraction(slot->name, in_bounds);

	if (mask ? (or_all != slot->limit || and_all != 0) :
		   (min_v != 0 || max_v != slot->limit)) {
		fprintf(stderr, "%s: draws inside the bound span or %#x and %#x, min %u max %u\n",
			slot->name, or_all, and_all, min_v, max_v);
		BUG("nfnl grammar: a bounded scalar does not cover its bound");
	}
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
		if (append_specced_nlattr(buf, 0, sizeof(buf), spec, 1) !=
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

/*
 * Every string the nftables grammar has at a name id must be the one word,
 * and each of the ids must have one.  Returns the word.
 */
static const char *check_nftables_names(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	bool seen[NFT_NAME_ID_MAX + 1] = { false };
	const char *word = NULL;
	unsigned int i, id;

	if (sub == NULL)
		BUG("nfnl grammar: nftables is not registered");

	for (i = 0; i < sub->n_attrs; i++) {
		const struct nla_attr_spec *spec = &sub->attrs[i];

		if (spec->type < 1 || spec->type > NFT_NAME_ID_MAX)
			continue;
		if (spec->kind == NLA_KIND_STRING) {
			fprintf(stderr, "nftables: the string at id %u is random text\n",
				spec->type);
			BUG("nfnl grammar: an nftables name is not the shared word");
		}
		if (spec->kind != NLA_KIND_STRING_WORD)
			continue;
		if (word == NULL)
			word = spec->word;
		else if (strcmp(word, spec->word) != 0)
			BUG("nfnl grammar: nftables names are not all the same word");
		seen[spec->type] = true;
		check_word_spec(spec);
	}

	for (id = 1; id <= NFT_NAME_ID_MAX; id++) {
		if (!seen[id]) {
			fprintf(stderr, "nftables: no word at id %u\n", id);
			BUG("nfnl grammar: an nftables name id has no word");
		}
	}
	return word;
}

/*
 * nft_supported_family() takes NFPROTO_INET, IPV4, ARP, NETDEV, BRIDGE and
 * IPV6 and nothing else, and a table is found by its family and name
 * together, so these are the families a batch can name its table in.
 */
static const unsigned char nft_families[] = { 1, 2, 3, 5, 7, 10 };

static void check_nftables_families(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	unsigned int i, j;

	if (sub == NULL)
		BUG("nfnl grammar: nftables is not registered");
	if (sub->n_families != ARRAY_SIZE(nft_families))
		BUG("nfnl grammar: nftables lists a different set of families");

	for (i = 0; i < ARRAY_SIZE(nft_families); i++) {
		for (j = 0; j < sub->n_families; j++) {
			if (sub->families[j] == nft_families[i])
				break;
		}
		if (j == sub->n_families) {
			fprintf(stderr, "nftables: family %u is not listed\n",
				nft_families[i]);
			BUG("nfnl grammar: nftables leaves out a family it supports");
		}
	}
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
	check_cttimeout_commands();
	for (i = 0; i < ARRAY_SIZE(slots); i++)
		check_bounded_slot(&slots[i]);
	for (i = 0; i < ARRAY_SIZE(oneof_slots); i++)
		check_oneof_slot(&oneof_slots[i]);
	word = check_nftables_names();
	check_nftables_families();
	check_nftables_batch_flags();
	check_nftables_batches(word);
}
