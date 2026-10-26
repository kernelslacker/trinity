/*
 * Self-check for the nfnetlink grammars as the message generator draws from
 * them: each case holds a grammar to a fact about the kernel's policy for
 * the subsystem.  The RNG helpers netlink_gen_msg() reaches are the fakes in
 * genl_ops_test.c; no netlink socket is opened.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_cttimeout.h>
#include <linux/netlink.h>

#include "debug.h"		/* BUG */
#include "netlink-attrs.h"	/* struct nla_attr_spec */
#include "netlink-nfnl-subsystems.h"

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

void nfnl_gen_self_check(void);
void nfnl_gen_self_check(void)
{
	check_no_rejected_attr();
	check_cttimeout_commands();
}
