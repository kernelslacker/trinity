/*
 * NETLINK_NETFILTER per-subsystem grammar registry.
 *
 * Per-subsystem grammar tables (net/netlink-nfnl-sub-*.c) declare
 * their commands and attribute kinds statically; this file exposes
 * lookup helpers used by the netlink message generator to size
 * attributes per the subsystem's nla_policy and to bias nlmsg_type
 * picks toward (subsys, cmd) pairs the kernel's per-subsys
 * nfnl_callback dispatcher accepts.
 *
 * Unlike the generic netlink registry there's no controller dump to
 * resolve dynamic family IDs against — NFNL_SUBSYS_x is a compile-time
 * constant, so the only runtime work is a stamping pass that wires
 * each grammar's call_counter pointer into the shared stats arena.
 * That stamping is idempotent and deferred to first use so the
 * registry file stays free of init-order coupling.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <linux/netfilter/nfnetlink.h>

#include "netlink-nfnl-subsystems.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

extern struct nfnl_subsys_grammar sub_ctnetlink;
extern struct nfnl_subsys_grammar sub_ctnetlink_exp;
extern struct nfnl_subsys_grammar sub_nftables;

/*
 * Per-subsys grammar definitions live in net/netlink-nfnl-sub-*.c;
 * each new subsys adds an extern declaration above and a pointer
 * here.  Lookups skip NULL entries so a temporary placeholder is
 * harmless if a subsys ever needs to be ifdef'd out.
 */
static struct nfnl_subsys_grammar *registry[] = {
	&sub_ctnetlink,
	&sub_ctnetlink_exp,
	&sub_nftables,
};

const struct nfnl_subsys_grammar *nfnl_lookup_by_subsys(unsigned char subsys_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL)
			continue;
		if (registry[i]->subsys_id == subsys_id)
			return registry[i];
	}
	return NULL;
}

const struct nfnl_subsys_grammar *nfnl_pick_subsys(void)
{
	unsigned int real_count = 0;
	unsigned int i;
	unsigned int pick;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] != NULL)
			real_count++;
	}
	if (real_count == 0)
		return NULL;

	pick = rand() % real_count;
	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL)
			continue;
		if (pick-- == 0)
			return registry[i];
	}
	return NULL;
}

unsigned char nfnl_pick_cmd(const struct nfnl_subsys_grammar *sub)
{
	if (!sub || sub->n_cmds == 0)
		return 0;
	return sub->cmds[rand() % sub->n_cmds].cmd;
}

void nfnl_subsys_bump_calls(const struct nfnl_subsys_grammar *sub)
{
	if (!sub || !sub->call_counter)
		return;
	__atomic_add_fetch(sub->call_counter, 1, __ATOMIC_RELAXED);
}
