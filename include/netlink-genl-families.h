#pragma once

#include <stdbool.h>
#include <stddef.h>

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
 * file per family in net/netlink/genl/<family>.c) with the runtime-resolved
 * family_id.  At first NETLINK_GENERIC use, genl_resolve_families()
 * walks the kernel's controller via CTRL_CMD_GETFAMILY/NLM_F_DUMP and
 * stamps each registered grammar with its assigned ID and the
 * doit/dumpit shape of each op the controller lists (or marks it
 * unavailable when the family isn't loaded in the running kernel).
 *
 * Adding a family is a small, isolated change: drop a new
 * net/netlink/genl/<name>.c containing static cmds[] and attrs[]
 * tables and an extern struct genl_family_grammar fam_<name>; then
 * append &fam_<name> to genl_registry[] in
 * net/netlink/genl/families.c.  No dispatcher edits required.
 */

struct genl_cmd_grammar {
	unsigned char cmd;
	const char *name;	/* for debugging only */

	/* The attributes the cmd's own policy takes, when that is narrower
	 * than the family's table: a request for the cmd draws only from
	 * these.  A strict op answers an id its policy has no slot for with
	 * -EINVAL, and a split op with no policy gets a reject-all one, so a
	 * cmd that takes nothing names genl_no_attrs and leaves n_attrs 0.
	 * NULL keeps the family's table. */
	const struct nla_attr_spec *attrs;
	unsigned int n_attrs;

	/* The same for a dump request, when the dumpit's policy is not the
	 * doit's.  NULL keeps attrs. */
	const struct nla_attr_spec *dump_attrs;
	unsigned int n_dump_attrs;
};

/*
 * The table of a cmd that takes no attribute.  Nothing is drawn from it,
 * its cmd's n_attrs being 0; it exists because a NULL table means the
 * family's.
 */
extern const struct nla_attr_spec genl_no_attrs[];

struct genl_family_grammar {
	const char *name;	/* GENL family name (e.g. "devlink") */
	const struct genl_cmd_grammar *cmds;
	unsigned int n_cmds;
	const struct nla_attr_spec *attrs;
	unsigned int n_attrs;
	unsigned char default_version; /* genlmsghdr.version when nonzero */
	unsigned char hdrsize;	/* family-specific fixed header that the
				 * kernel skips past before attribute parsing
				 * (e.g. struct ovs_header for the openvswitch
				 * families).  0 for the common case where
				 * attributes follow the genlmsghdr directly. */

	/* Filled in at runtime by genl_resolve_families(): */
	unsigned short family_id; /* 0 == unresolved */
	unsigned char resolved;
	unsigned char unavailable; /* set when CTRL didn't return this name */

	/* Per cmd, the GENL_CMD_CAP_DO / GENL_CMD_CAP_DUMP bits of the op
	 * the controller listed for it: which kinds of request reach a
	 * handler.  genl_family_rcv_msg() routes on NLM_F_DUMP and rejects
	 * a request whose routed handler is missing, so a cmd with only
	 * one kind wants the matching nlmsg_flags.  0 == unknown: the cmd
	 * was not listed, or the reply carried no op list. */
	unsigned char cmd_caps[256];

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
 * The attribute table a request for cmd draws from, with its length in
 * *nr_out: the cmd's own table, its dump table for a dump request that
 * has one, else the family's.  NULL when none of them exists, which
 * sends the caller to the legacy random-attribute path.
 */
const struct nla_attr_spec *genl_cmd_attrs(const struct genl_family_grammar *fam,
					   unsigned char cmd, bool dump,
					   size_t *nr_out);

/*
 * The attribute table a request to the controller (GENL_ID_CTRL) draws from
 * for cmd, with its length in *nr_out.  The controller is not in the
 * registry, so genl_cmd_attrs() cannot serve it.  A cmd with no handler
 * takes none, which is genl_no_attrs.
 */
const struct nla_attr_spec *genl_ctrl_attrs(unsigned char cmd, size_t *nr_out);

/*
 * Bump the per-family dispatch counter for fam.  Called from
 * gen_genl_body() once per built genl message after the family has
 * been resolved.  No-op when fam is NULL or its call_counter pointer
 * was not stamped at resolve time (family lacks a stats slot).
 */
void genl_family_bump_calls(const struct genl_family_grammar *fam);
