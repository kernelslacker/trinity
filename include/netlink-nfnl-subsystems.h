#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "netlink-attrs.h"

/*
 * Per-nfnetlink-subsystem grammar registry.
 *
 * NETLINK_NETFILTER (proto 12) multiplexes a dozen distinct subsystems
 * into a single socket via the (NFNL_SUBSYS_x << 8) | NFNL_MSG_x_*
 * encoding of nlmsg_type.  Unlike NETLINK_GENERIC, the subsystem ID
 * is a compile-time constant — there's no runtime controller dump and
 * no family_id resolution to do.  The registry below is therefore
 * purely a static dispatch table keyed by subsys_id, mirroring the
 * shape of the NETLINK_GENERIC family registry so the message
 * generator's spec-driven nlattr path looks the same on both sides.
 *
 * Adding a subsystem is a small, isolated change: drop a new
 * net/netlink/nfnl/<name>.c containing static cmds[] and attrs[]
 * tables and an extern struct nfnl_subsys_grammar sub_<name>; then
 * append &sub_<name> to nfnl_registry[] in
 * net/netlink/nfnl/subsystems.c.  No dispatcher edits required.
 *
 * The cmds[] table feeds nfnl_pick_cmd(), which lets the type picker
 * bias toward (subsys, cmd) pairs the kernel's per-subsys nfnl_callback
 * dispatcher actually accepts instead of bouncing off an unknown-cmd
 * fast-reject.  The attrs[] table feeds the message generator's
 * spec-driven nlattr path so each emitted attribute is sized to the
 * kind the subsystem's nla_policy gate expects.
 */

struct nfnl_cmd_grammar {
	unsigned char cmd;
	const char *name;	/* for debugging only */
	/* The callback is NFNL_CB_BATCH: nfnetlink dispatches it only
	 * inside a NFNL_MSG_BATCH_BEGIN ... NFNL_MSG_BATCH_END batch and
	 * answers -EINVAL to it anywhere else. */
	bool batch;

	/* The attributes the cmd's own policy takes, when that is narrower
	 * than the subsystem's table or types an id differently from it: a
	 * request for the cmd draws only from these.  nfnetlink parses the
	 * attributes leniently, so an id the policy has no slot for is
	 * ignored rather than refused and the table decides what a request
	 * carries, not what the kernel turns away.  NULL keeps the
	 * subsystem's table. */
	const struct nla_attr_spec *attrs;
	unsigned int n_attrs;
};

struct nfnl_subsys_grammar {
	const char *name;		/* "ctnetlink", "nftables", "ipset", ... */
	unsigned char subsys_id;	/* NFNL_SUBSYS_x */
	const struct nfnl_cmd_grammar *cmds;
	unsigned int n_cmds;
	const struct nla_attr_spec *attrs;
	unsigned int n_attrs;

	/* The nfgen_family values the subsystem's commands act on, for a
	 * subsystem that finds its objects by family and name together: a
	 * batch sends every command in one of them, so that a command can
	 * find what an earlier one made.  Empty for a subsystem that has no
	 * use for the family. */
	const unsigned char *families;
	unsigned int n_families;

	/* Pointer into shm->stats stamped lazily on first use via a
	 * static name->offset table maintained alongside the registry
	 * (so the per-subsys grammar files don't have to pull in
	 * stats.h).  NULL for any subsys that lacks a counter slot —
	 * bumping degrades to a no-op. */
	unsigned long *call_counter;
};

/*
 * Look up a registered subsystem by its NFNL_SUBSYS_x ID.  Returns
 * NULL when no grammar covers that subsys — caller falls back to the
 * legacy random-attr generator path.
 */
const struct nfnl_subsys_grammar *nfnl_lookup_by_subsys(unsigned char subsys_id);

/*
 * The attribute table a request for cmd of sub draws from, with its length
 * in *nr_out: the cmd's own table, else the subsystem's.  NULL when neither
 * exists, or sub is NULL, which sends the caller to the legacy
 * random-attribute path.
 */
const struct nla_attr_spec *nfnl_cmd_attrs(const struct nfnl_subsys_grammar *sub,
					   unsigned char cmd, size_t *nr_out);

/*
 * Pick a random subsystem from the registry.  Returns NULL only if the
 * registry is empty.  Used by the nlmsg_type picker to bias toward
 * (subsys, cmd) pairs the kernel will actually dispatch.
 */
const struct nfnl_subsys_grammar *nfnl_pick_subsys(void);

/*
 * Pick a random command from the subsystem's cmds[] table.  Returns 0
 * when the table is empty — a reasonable fallback that the kernel's
 * subsys dispatcher rejects cleanly via -EOPNOTSUPP.
 */
unsigned char nfnl_pick_cmd(const struct nfnl_subsys_grammar *sub);

/*
 * Whether nlmsg_type names a command the registry lists as a batch
 * callback.  False for a subsystem or a command it does not list.
 */
bool nfnl_type_is_batch(unsigned short nlmsg_type);

/*
 * Pick a random batch callback from the subsystem's cmds[] table.  Returns
 * 0 when it lists none.
 */
unsigned char nfnl_pick_batch_cmd(const struct nfnl_subsys_grammar *sub);

/*
 * Pick a random nfgen_family from the subsystem's families[] table.
 * Returns -1 when it lists none.
 */
int nfnl_pick_family(const struct nfnl_subsys_grammar *sub);

/*
 * Bump the per-subsys dispatch counter for sub.  No-op when sub is
 * NULL or its call_counter pointer is unset (subsys lacks a stats
 * slot).  Called from gen_nfnl_body() once per built nfnetlink
 * message so a non-zero count proves both that the subsys was
 * selected by the type picker and that the body generator routed
 * through this code path.
 */
void nfnl_subsys_bump_calls(const struct nfnl_subsys_grammar *sub);
