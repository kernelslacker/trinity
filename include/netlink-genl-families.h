#pragma once

#include "netlink-attrs.h"

/*
 * Per-genetlink-family grammar registry.
 *
 * Generic netlink families (NETLINK_GENERIC) are dynamically registered
 * in the kernel and each one is assigned a runtime nlmsg_type "family
 * ID" by the controller.  A fuzzer that picks a random nlmsg_type in
 * the GENL_MIN_ID..1023 range almost never matches a real family ID,
 * so the kernel's family demuxer fast-rejects the message and the
 * actual per-family parsers — where the bugs live — stay cold.
 *
 * The registry below pairs a static command + attribute grammar (one
 * file per family in net/netlink-genl-fam-*.c) with the runtime-resolved
 * family_id.  At first NETLINK_GENERIC use, genl_resolve_families()
 * walks the kernel's controller via CTRL_CMD_GETFAMILY/NLM_F_DUMP and
 * stamps each registered grammar with its assigned ID (or marks it
 * unavailable when the family isn't loaded in the running kernel).
 *
 * Adding a family is a small, isolated change: drop a new
 * net/netlink-genl-fam-<name>.c containing static cmds[] and attrs[]
 * tables and an extern struct genl_family_grammar fam_<name>; then
 * append &fam_<name> to genl_registry[] in
 * net/netlink-genl-families.c.  No dispatcher edits required.
 */

struct genl_cmd_grammar {
	unsigned char cmd;
	const char *name;	/* for debugging only */
};

struct genl_family_grammar {
	const char *name;	/* GENL family name (e.g. "devlink") */
	const struct genl_cmd_grammar *cmds;
	unsigned int n_cmds;
	const struct nla_attr_spec *attrs;
	unsigned int n_attrs;
	unsigned char default_version; /* genlmsghdr.version when nonzero */

	/* Filled in at runtime by genl_resolve_families(): */
	unsigned short family_id; /* 0 == unresolved */
	unsigned char resolved;
	unsigned char unavailable; /* set when CTRL didn't return this name */

	/* Pointer into shm->stats stamped during genl_resolve_families()
	 * via a static name->offset table maintained alongside the
	 * registry (so the per-family grammar files don't have to pull
	 * in stats.h).  NULL for any family that lacks a counter slot
	 * — bumping degrades to a no-op. */
	unsigned long *call_counter;
};

/*
 * Open a NETLINK_GENERIC socket and resolve every registered family's
 * family_id via CTRL_CMD_GETFAMILY/NLM_F_DUMP.  Idempotent — first call
 * does the work, subsequent calls are no-ops.  Safe to call from the
 * netlink_gen_msg path on first NETLINK_GENERIC use; runs once per
 * process so a forked child resolves in its own (potentially distinct)
 * netns the first time it builds a NETLINK_GENERIC message.
 */
void genl_resolve_families(void);

/*
 * Pick a registered family that resolved to a real family_id.  Returns
 * NULL when no family in the registry matched the running kernel.  The
 * caller is expected to have already invoked genl_resolve_families().
 */
struct genl_family_grammar *genl_pick_resolved_family(void);

/*
 * Look up a registered family by its kernel-assigned family_id.  Used
 * by the message body / attribute generators to recover the grammar
 * after the dispatcher has stamped nlmsg_type with a resolved id.
 * Returns NULL if the id wasn't issued by us.
 */
const struct genl_family_grammar *genl_lookup_by_id(unsigned short family_id);

/*
 * Pick a random command from the family's cmds[] table.  When the table
 * is empty, returns 0 (CTRL_CMD_UNSPEC) — a reasonable fallback that
 * the kernel rejects cleanly via -EOPNOTSUPP.
 */
unsigned char genl_pick_cmd(const struct genl_family_grammar *fam);

/*
 * Bump the per-family dispatch counter for fam.  Called from
 * gen_genl_body() once per built genl message after the family has
 * been resolved.  No-op when fam is NULL or its call_counter pointer
 * was not stamped at resolve time (family lacks a stats slot).
 */
void genl_family_bump_calls(const struct genl_family_grammar *fam);
