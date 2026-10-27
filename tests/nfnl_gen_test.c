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
static void check_slot_fraction(const struct bounded_slot *slot,
				unsigned int in_bounds)
{
	double frac = (double) in_bounds / SLOT_ROUNDS;

	if (frac < 0.80 || frac > 0.95) {
		fprintf(stderr, "%s: %u of %u draws inside the bound, want a fraction in [0.80, 0.95]\n",
			slot->name, in_bounds, SLOT_ROUNDS);
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

	check_slot_fraction(slot, in_bounds);

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

	check_slot_fraction(slot, in_bounds);

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

/*
 * Check what lies between BEGIN and END in a buffer that has both.  BEGIN
 * names nftables in res_id, and the commands are batch commands of that
 * subsystem: nfnetlink_rcv_batch() answers any other -EINVAL, and a batch
 * with an error in it cannot commit.  The first command's header sits right
 * after BEGIN, so its type is held to that outright.  A later header sits
 * where the lengths before it put it, which a length the generator
 * corrupted on purpose throws off into the bytes of another message, and
 * what is read there is noise.  So the later commands are judged only when
 * every length ran true and the chain ended exactly at END, and then only
 * reported: *cmds is their number and *stray whether one is no batch
 * command.  Returns the first command's type, or 0 when there is none.
 */
static unsigned short check_batch_buffer(const unsigned char *buf, size_t len,
					 unsigned int *cmds, bool *stray)
{
	const size_t marker = NLMSG_SPACE(sizeof(struct nfgenmsg));
	const size_t end_off = len - marker;
	unsigned short first = 0;
	bool any_stray = false;
	unsigned int n = 0;
	struct nfgenmsg nfg;
	size_t off = marker;

	memcpy(&nfg, buf + NLMSG_HDRLEN, sizeof(nfg));
	if (nfg.res_id != htons(NFNL_SUBSYS_NFTABLES))
		BUG("nfnl batch: BEGIN does not name the nftables subsystem");

	*cmds = 0;
	*stray = false;
	while (off + NLMSG_HDRLEN <= end_off) {
		struct nlmsghdr nlh;
		bool batch_cmd, holds;

		memcpy(&nlh, buf + off, sizeof(nlh));
		holds = nlh.nlmsg_len >= NLMSG_LENGTH(sizeof(struct nfgenmsg)) &&
			nlh.nlmsg_len <= end_off - off;
		if (n > 0 && !holds)
			return first;

		batch_cmd = NFNL_SUBSYS_ID(nlh.nlmsg_type) == NFNL_SUBSYS_NFTABLES &&
			    nfnl_type_is_batch(nlh.nlmsg_type);
		if (n == 0) {
			first = nlh.nlmsg_type;
			if (!batch_cmd) {
				fprintf(stderr, "nfnl batch: type %#x opens a batch\n", first);
				BUG("nfnl batch: the first message is no nftables batch command");
			}
		} else if (!batch_cmd) {
			any_stray = true;
		}
		n++;
		if (!holds)
			return first;
		off += NLMSG_ALIGN(nlh.nlmsg_len);
	}

	if (off == end_off) {
		*cmds = n;
		*stray = any_stray;
	}
	return first;
}

struct batch_tally {
	unsigned int wrapped;	/* opens with BEGIN and closes with END */
	unsigned int bare;	/* opens with a batch command, nothing around it */
	unsigned int multi;	/* wrapped, two commands or more, every length true */
	unsigned int stray;	/* ... of which hold a message that is no batch command */
	bool led[256];		/* batch commands that opened a wrapped buffer, by id */
};

static void tally_buffer(struct batch_tally *t, const unsigned char *buf,
			 size_t len)
{
	const size_t marker = NLMSG_SPACE(sizeof(struct nfgenmsg));
	struct nlmsghdr nlh;

	if (len < NLMSG_HDRLEN)
		return;
	memcpy(&nlh, buf, sizeof(nlh));

	if (len >= 2 * marker && is_marker(buf, NFNL_MSG_BATCH_BEGIN) &&
	    is_marker(buf + len - marker, NFNL_MSG_BATCH_END)) {
		unsigned short first;
		unsigned int cmds;
		bool stray;

		first = check_batch_buffer(buf, len, &cmds, &stray);
		t->wrapped++;
		if (cmds >= 2) {
			t->multi++;
			if (stray)
				t->stray++;
		}
		if (first != 0)
			t->led[first & 0xff] = true;
	} else if (nfnl_type_is_batch(nlh.nlmsg_type)) {
		t->bare++;
	}
}

/*
 * A buffer whose first message is a batch command goes out inside BEGIN and
 * END seven times in eight, and bare the eighth, so 0.875 of those buffers
 * open with BEGIN.  A run draws about 3000 of them, so the fraction has a
 * standard deviation of 0.006 and the limits 0.80 and 0.95 are 12 sigma off;
 * they turn away a generator that never wraps and one that always does.  A
 * quarter of the wrapped buffers hold two commands or more, about 500 with
 * every length true.  Their later commands are batch callbacks too; picked
 * as the first message of any buffer is, nearly every such batch would hold
 * some other message, where as built none does, so a tenth is a wide limit.
 * And each of the 21 batch commands must open some batch.
 */
static void check_nftables_batches(void)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(NFNL_SUBSYS_NFTABLES);
	struct socket_triplet triplet = {
		.family = PF_NETLINK,
		.type = SOCK_RAW,
		.protocol = NETLINK_NETFILTER,
	};
	struct batch_tally t = { 0 };
	unsigned int round, i, led = 0;
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

	if (t.wrapped + t.bare < 1000) {
		fprintf(stderr, "nftables: %u wrapped and %u bare batch commands in %u buffers\n",
			t.wrapped, t.bare, BATCH_ROUNDS);
		BUG("nfnl batch: too few batch commands to judge the wrapping");
	}
	frac = (double) t.wrapped / (t.wrapped + t.bare);
	if (frac < 0.80 || frac > 0.95) {
		fprintf(stderr, "nftables: %u of %u batch commands went out inside a batch, want a fraction in [0.80, 0.95]\n",
			t.wrapped, t.wrapped + t.bare);
		BUG("nfnl batch: batch commands are not wrapped most of the time");
	}
	if (t.multi < 100) {
		fprintf(stderr, "nftables: %u of %u batches hold two commands or more\n",
			t.multi, t.wrapped);
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
}

void nfnl_gen_self_check(void);
void nfnl_gen_self_check(void)
{
	unsigned int i;

	check_no_rejected_attr();
	check_cttimeout_commands();
	for (i = 0; i < ARRAY_SIZE(slots); i++)
		check_bounded_slot(&slots[i]);
	for (i = 0; i < ARRAY_SIZE(oneof_slots); i++)
		check_oneof_slot(&oneof_slots[i]);
	check_nftables_batch_flags();
	check_nftables_batches();
}
