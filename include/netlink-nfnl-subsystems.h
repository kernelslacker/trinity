#pragma once

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
 * net/netlink-nfnl-sub-<name>.c containing static cmds[] and attrs[]
 * tables and an extern struct nfnl_subsys_grammar sub_<name>; then
 * append &sub_<name> to nfnl_registry[] in
 * net/netlink-nfnl-subsystems.c.  No dispatcher edits required.
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
};

struct nfnl_subsys_grammar {
	const char *name;		/* "ctnetlink", "nftables", "ipset", ... */
	unsigned char subsys_id;	/* NFNL_SUBSYS_x */
	const struct nfnl_cmd_grammar *cmds;
	unsigned int n_cmds;
	const struct nla_attr_spec *attrs;
	unsigned int n_attrs;

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
 * Bump the per-subsys dispatch counter for sub.  No-op when sub is
 * NULL or its call_counter pointer is unset (subsys lacks a stats
 * slot).  Called from gen_nfnl_body() once per built nfnetlink
 * message so a non-zero count proves both that the subsys was
 * selected by the type picker and that the body generator routed
 * through this code path.
 */
void nfnl_subsys_bump_calls(const struct nfnl_subsys_grammar *sub);
