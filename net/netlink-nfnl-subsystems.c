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
#include "stats.h"
#include "trinity.h"
#include "utils.h"

extern struct nfnl_subsys_grammar sub_ctnetlink;
extern struct nfnl_subsys_grammar sub_ctnetlink_exp;
extern struct nfnl_subsys_grammar sub_nftables;
extern struct nfnl_subsys_grammar sub_ipset;

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
	&sub_ipset,
};

/*
 * Per-subsys stats counter offsets.  Kept here (instead of carried by
 * the per-subsys grammar files) so the subsys files don't have to
 * pull in stats.h — adding a counter for a new subsys is a one-line
 * append below paired with a one-line addition in struct stats_s.
 * Walk the table at first-use time and stamp registry[i]->call_counter
 * for any subsys whose name matches.  Subsystems absent from this
 * table get a NULL call_counter; the bump helper degrades to a no-op
 * for them.
 */
static const struct {
	const char *name;
	size_t off;
} subsys_calls_off[] = {
	{ "ctnetlink",     offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink) },
	{ "ctnetlink_exp", offsetof(struct stats_s, nfnl_subsys_calls_ctnetlink_exp) },
	{ "nftables",      offsetof(struct stats_s, nfnl_subsys_calls_nftables) },
	{ "ipset",         offsetof(struct stats_s, nfnl_subsys_calls_ipset) },
};

static int counters_stamped;

static void stamp_call_counters(void)
{
	unsigned int i, j;

	if (counters_stamped)
		return;
	counters_stamped = 1;

	for (i = 0; i < ARRAY_SIZE(registry); i++) {
		if (registry[i] == NULL || registry[i]->call_counter != NULL)
			continue;
		for (j = 0; j < ARRAY_SIZE(subsys_calls_off); j++) {
			if (strcmp(registry[i]->name, subsys_calls_off[j].name) != 0)
				continue;
			registry[i]->call_counter = (unsigned long *)
				((char *)&shm->stats + subsys_calls_off[j].off);
			break;
		}
	}
}

const struct nfnl_subsys_grammar *nfnl_lookup_by_subsys(unsigned char subsys_id)
{
	unsigned int i;

	stamp_call_counters();

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

	stamp_call_counters();

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
