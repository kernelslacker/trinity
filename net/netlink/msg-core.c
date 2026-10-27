/*
 * Structured netlink message generation for fuzzing.
 *
 * Builds nlmsghdr messages with protocol-appropriate types and flags,
 * optional nlattr TLVs, and occasional deliberate corruption to test
 * both valid code paths and error handling in the kernel.
 */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <linux/if_addrlabel.h>
#include <linux/if_link.h>
#include <linux/if_bridge.h>
#include <linux/neighbour.h>
#include <linux/fib_rules.h>
#include <linux/netconf.h>
#include <linux/net_namespace.h>
#include <linux/nexthop.h>
#include <linux/dcbnl.h>
#include <linux/genetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/xfrm.h>
#include <linux/audit.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <linux/connector.h>
#include <string.h>
#include "net.h"
#include "netlink-attrs.h"
#include "netlink-genl-families.h"
#include "msg-internal.h"
#include "rtnl-ack-oracle.h"
#include "netlink-nfnl-subsystems.h"
#include "random.h"
#include "shm.h"
#include "text-payloads.h"
#include "trinity.h"
#include "rnd.h"

#include "kernel/netlink.h"
#include "kernel/nfnetlink.h"
#include "kernel/socket.h"
/* Forward declaration — called via gen_msg hook from net/proto/netlink.c */
void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len);

/*
 * The flags that change what a request does rather than which handler it
 * reaches: NLM_F_ATOMIC and the NEW- and DELETE-style modifiers.
 */
static unsigned short gen_nlmsg_modifiers(void)
{
	unsigned short flags = 0;

	if (RAND_BOOL())
		flags |= NLM_F_ATOMIC;

	/* NEW-style: create/replace flags */
	if (RAND_BOOL()) {
		if (RAND_BOOL())
			flags |= NLM_F_CREATE;
		if (RAND_BOOL())
			flags |= NLM_F_REPLACE;
		if (RAND_BOOL())
			flags |= NLM_F_EXCL;
		if (RAND_BOOL())
			flags |= NLM_F_APPEND;
	}

	/* DELETE-style: bulk/non-recursive flags */
	if (RAND_BOOL())
		flags |= NLM_F_NONREC;
	if (RAND_BOOL())
		flags |= NLM_F_BULK;

	return flags;
}

/*
 * Generate a random set of nlmsg flags biased toward valid combos.
 * chaos is the message in ten whose flags are a random word, returned
 * unpinned so the kernel's flag rejects keep seeing traffic.
 *
 * For every cmd at or past its family's resv_start_op, the genl core
 * turns away any flag outside REQUEST, ACK, ECHO and the dump pair, and
 * does so before it looks the op up.  A genl message therefore draws the
 * modifiers one time in 8 rather than every time.  That leaves about
 * nine in ten of the rest clear of the check, while the older families,
 * which skip it, and the handlers that read the modifiers (gtp tests EXCL
 * and REPLACE) still get them.
 *
 * genl_caps is the GENL_CMD_CAP_DO / GENL_CMD_CAP_DUMP shape of the genl
 * command the message carries, 0 when unknown or not genl.  The genl core
 * routes on (flags & NLM_F_DUMP) == NLM_F_DUMP and turns away a request
 * whose routed handler is missing, so a cmd with only a dumpit gets both
 * dump bits and one with only a doit gets neither.  The NEW and DELETE
 * modifiers share those two bits (REPLACE/NONREC, EXCL/BULK), so the pin
 * comes after them.
 */
static unsigned short gen_nlmsg_flags(bool chaos, int protocol,
				      unsigned char genl_caps)
{
	unsigned short flags = NLM_F_REQUEST; /* almost always set */

	if (chaos)
		return rand16(); /* pure chaos */

	if (RAND_BOOL())
		flags |= NLM_F_ACK;

	if (RAND_BOOL())
		flags |= NLM_F_ECHO;

	/* GET-style: dump flags */
	if (RAND_BOOL())
		flags |= NLM_F_DUMP;

	if (protocol != NETLINK_GENERIC || ONE_IN(8))
		flags |= gen_nlmsg_modifiers();

	if (genl_caps == GENL_CMD_CAP_DUMP)
		flags |= NLM_F_DUMP;
	else if (genl_caps == GENL_CMD_CAP_DO)
		flags &= ~NLM_F_DUMP;

	return flags;
}

/* Pick an nlmsg_type appropriate for the netlink protocol */
static unsigned short pick_nlmsg_type(int protocol)
{
	/* 1 in 20: completely random type to probe unknown handlers */
	if (ONE_IN(20))
		return rand16();

	switch (protocol) {
	case NETLINK_ROUTE:
		return rtnl_types[rnd_modulo_u32(rtnl_types_n)];
	case NETLINK_XFRM:
		return xfrm_types[rnd_modulo_u32(xfrm_types_n)];
	case NETLINK_AUDIT:
		return audit_types[rnd_modulo_u32(audit_types_n)];
	case NETLINK_NETFILTER: {
		/* nfnetlink: subsys << 8 | msg.
		 *
		 * Bias toward (subsys, cmd) pairs from the registry so the
		 * kernel's per-subsys nfnl_callback dispatcher actually
		 * accepts the type byte; the registered cmd set comes from
		 * net/netlink/nfnl/<subsystem>.c.  Keep an unknown-cmd path with
		 * low probability to keep exercising the
		 * dispatcher-not-registered fast-reject. */
		static const unsigned char nfnl_subsys[] = {
			NFNL_SUBSYS_CTNETLINK, NFNL_SUBSYS_CTNETLINK_EXP,
			NFNL_SUBSYS_QUEUE, NFNL_SUBSYS_ULOG,
			NFNL_SUBSYS_OSF, NFNL_SUBSYS_IPSET,
			NFNL_SUBSYS_ACCT, NFNL_SUBSYS_CTNETLINK_TIMEOUT,
			NFNL_SUBSYS_CTHELPER, NFNL_SUBSYS_NFTABLES,
			NFNL_SUBSYS_NFT_COMPAT, NFNL_SUBSYS_HOOK,
		};
		unsigned char subsys;

		if (!ONE_IN(4)) {
			const struct nfnl_subsys_grammar *sub;

			sub = nfnl_pick_subsys();
			if (sub != NULL)
				return (sub->subsys_id << 8) | nfnl_pick_cmd(sub);
		}
		if (ONE_IN(8))
			subsys = rnd_modulo_u32(16);
		else
			subsys = RAND_ARRAY(nfnl_subsys);
		return (subsys << 8) | (rnd_modulo_u32(16));
	}
	case NETLINK_GENERIC:
		/* genl: prefer a runtime-resolved family id from the
		 * grammar registry when one is available; that gets the
		 * message past the kernel's family demuxer into the
		 * actual per-family parser.  Fall back to GENL_ID_CTRL or
		 * a random nlmsg_type in the dynamic-allocation range to
		 * keep exercising the unknown-family fast-reject path. */
		if (!ONE_IN(4)) {
			struct genl_family_grammar *fam;

			genl_resolve_families();
			fam = genl_pick_resolved_family();
			if (fam != NULL)
				return fam->family_id;
		}
		if (RAND_BOOL())
			return GENL_ID_CTRL;
		return RAND_RANGE(GENL_MIN_ID, GENL_MIN_ID + 64);
	case NETLINK_SOCK_DIAG:
		/* SOCK_DIAG_BY_FAMILY=20, SOCK_DESTROY=21 are the main ones.
		 * Also cover legacy inet_diag range and INET_DIAG_GETSOCK_MAX. */
		if (RAND_BOOL())
			return RAND_BOOL() ? SOCK_DIAG_BY_FAMILY : SOCK_DESTROY;
		return RAND_RANGE(NLMSG_MIN_TYPE, INET_DIAG_GETSOCK_MAX);
	case NETLINK_CONNECTOR:
		return RAND_RANGE(0, 4);
	default:
		/* Unknown protocol: use NLMSG_MIN_TYPE or random */
		if (RAND_BOOL())
			return RAND_RANGE(NLMSG_MIN_TYPE, NLMSG_MIN_TYPE + 32);
		return rand16();
	}
}

/*
 * Build a structured netlink message. The caller must free *buf.
 *
 * Structure: [nlmsghdr][protocol body][nlattr...nlattr]
 *
 * Protocol bodies are generated per-family: rtnetlink uses the correct
 * struct (ifinfomsg, rtmsg, etc.), genl uses genlmsghdr, nfnetlink uses
 * nfgenmsg, xfrm uses per-type structs, audit uses binary structs or
 * text, and sock_diag uses inet_diag_req_v2. Unknown protocols fall
 * back to random bytes.
 *
 * ~1 in 4 messages are multi-message batches (2-4 nlmsghdr chained
 * together) to exercise the kernel's NLMSG_NEXT iteration path.  A
 * NETLINK_NETFILTER buffer that opens with an NFNL_CB_BATCH command is
 * also put behind NFNL_MSG_BATCH_BEGIN and, most of the time, followed by
 * NFNL_MSG_BATCH_END, which build_nfnl_batch() explains.
 */

/*
 * Pick a protocol-appropriate nlattr type for the given netlink protocol
 * and message type.  Returns 0 when the family has no curated table, in
 * which case the caller should fall back to a random type.  Centralised
 * here so both the flat append path and the nested container helper draw
 * from the same per-family tables.
 */
unsigned short pick_attr_hint(int protocol, unsigned short nlmsg_type)
{
	switch (protocol) {
	case NETLINK_ROUTE:
		return pick_rtnl_attr_type(nlmsg_type);
	case NETLINK_GENERIC:
		return pick_genl_attr_type(nlmsg_type);
	default:
		/* XFRM, SOCK_DIAG, ctnetlink, nftables, genl-ctrl now have
		 * dedicated nla_attr_spec tables consulted directly by
		 * build_one_nlmsg, so they no longer need a raw type pick
		 * here.  Anything that lands in this default returns 0 and
		 * the caller falls back to a random type. */
		return 0;
	}
}

/*
 * Build a single nlmsghdr of the caller's nlmsg_type at msg+offset.  Returns
 * new offset (NLMSG_ALIGN'd).  nfgen_family is the family a batch pins on the
 * nfgenmsg of a NETLINK_NETFILTER command, or -1 to draw one from the
 * command's subsystem's families.
 */
/*
 * Single iteration of build_one_nlmsg()'s inner attr-append loop.
 * Returns the new offset, or 0 to signal "no progress, caller break".
 * 0 is an unambiguous sentinel here because the caller has already
 * advanced offset past NLMSG_HDRLEN before the loop runs.
 */
static size_t iter_nlmsg_attr(unsigned char *msg, size_t offset, size_t buflen,
			      const struct nla_attr_spec *spec_table,
			      size_t nr_specs, uint64_t *used,
			      struct socket_triplet *triplet,
			      unsigned short nlmsg_type,
			      unsigned char body_family,
			      int rtnl_group)
{
	unsigned short attr_hint;
	size_t new_off;

	/* Spec-driven path: families with a curated nla_attr_spec table
	 * (XFRM, ctnetlink, nftables, genl-ctrl, sock_diag) emit attrs
	 * sized to their per-type kind.  This dramatically lowers the
	 * EINVAL rejection rate at the family's nla_policy gate. */
	if (spec_table) {
		new_off = append_specced_nlattr(msg, offset, buflen,
						spec_table, nr_specs, used);
		if (new_off == offset)
			return 0;
		return new_off;
	}

	/* Legacy random-payload path for families without a spec table —
	 * currently NETLINK_ROUTE (which has its own structured per-group
	 * payload generators) and unknown families. */
	attr_hint = pick_attr_hint(triplet->protocol, nlmsg_type);

	if (ONE_IN(7)) {
		unsigned short outer = attr_hint ? attr_hint : rand16();

		new_off = append_nested_attr_container(msg, offset, buflen,
						       outer,
						       triplet->protocol,
						       nlmsg_type, body_family,
						       rtnl_group);
		if (new_off > offset)
			return new_off;
	}

	return append_nlattr(msg, offset, buflen, attr_hint,
			     body_family, rtnl_group);
}

static size_t build_one_nlmsg(unsigned char *msg, size_t offset, size_t buflen,
			      struct socket_triplet *triplet,
			      unsigned short nlmsg_type, int nfgen_family)
{
	const struct nla_attr_spec *spec_table;
	struct nlmsghdr *nlh;
	size_t nr_specs = 0;
	size_t body_len;
	size_t msg_start = offset;
	unsigned char body_family = AF_UNSPEC;
	unsigned char genl_caps = 0;
	bool chaos;
	int rtnl_group = -1;
	int num_attrs;
	uint64_t once_used = 0;

	/* Floor: nlmsghdr + genlmsghdr + a small per-family fixed header.
	 * Real buffers are >=1280 bytes so this is just a sanity gate. */
	if (offset + NLMSG_HDRLEN + 8 > buflen)
		return offset;

	/* One message in ten is chaos: its flags are a random word and, for
	 * genl, its reserved field may be too.  A genl message that is not
	 * chaos keeps to the flags and the zero reserved word that the genl
	 * core's header check lets through. */
	chaos = ONE_IN(10);

	nlh = (struct nlmsghdr *) (msg + offset);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_seq = rand32();
	nlh->nlmsg_pid = RAND_BOOL() ? 0 : rand32();

	offset += NLMSG_HDRLEN;

	/* Generate protocol-appropriate body struct */
	if (triplet->protocol == NETLINK_ROUTE &&
	    nlmsg_type >= RTM_BASE && nlmsg_type < RTM_MAX) {
		body_len = gen_rtnl_body(msg + offset, nlmsg_type,
					 buflen - offset, &body_family);
		rtnl_group = (nlmsg_type - RTM_BASE) / 4;
	} else if (triplet->protocol == NETLINK_GENERIC) {
		body_len = gen_genl_body(msg + offset, nlmsg_type,
					 buflen - offset, chaos, &genl_caps);
	} else if (triplet->protocol == NETLINK_NETFILTER) {
		/* A lone message names one of its subsystem's families, as
		 * the commands of a batch do. */
		if (nfgen_family < 0)
			nfgen_family = nfnl_pick_family(
				nfnl_lookup_by_subsys(nlmsg_type >> 8));
		body_len = gen_nfnl_body(msg + offset, nlmsg_type,
					 buflen - offset, nfgen_family);
	} else if (triplet->protocol == NETLINK_XFRM) {
		body_len = gen_xfrm_body(msg + offset, nlmsg_type,
					 buflen - offset);
	} else if (triplet->protocol == NETLINK_AUDIT) {
		body_len = gen_audit_body(msg + offset, nlmsg_type,
					  buflen - offset);
	} else if (triplet->protocol == NETLINK_SOCK_DIAG) {
		body_len = gen_sockdiag_body(msg + offset, nlmsg_type,
					     buflen - offset);
	} else {
		body_len = RAND_RANGE(4, 64);
		if (offset + body_len > buflen)
			body_len = buflen - offset;
		generate_rand_bytes(msg + offset, body_len);
	}
	offset += body_len;

	/* After the body: a genl cmd's handlers decide the dump bits. */
	nlh->nlmsg_flags = gen_nlmsg_flags(chaos, triplet->protocol, genl_caps);

	/* Append nlattr TLVs with protocol-appropriate types.  A genl
	 * cmd's table depends on its cmd and dump flag, both set above.
	 * Audit messages don't use nlattr — skip for that protocol. */
	num_attrs = (triplet->protocol == NETLINK_AUDIT) ? 0 : rnd_modulo_u32(8);
	spec_table = pick_spec_table(triplet->protocol, nlh, &nr_specs);

	/* What the cmd's handler cannot do without goes in ahead of the
	 * random draws, and so is in most requests, not the few that happen
	 * to draw it. */
	offset = append_required_attrs(msg, offset, buflen, spec_table, nr_specs,
				       &once_used);

	while (num_attrs-- > 0 && offset < buflen) {
		size_t new_off = iter_nlmsg_attr(msg, offset, buflen,
						 spec_table, nr_specs,
						 &once_used,
						 triplet, nlmsg_type,
						 body_family, rtnl_group);
		if (new_off == 0)
			break;
		offset = new_off;
	}

	/* Set nlmsg_len — usually correct, sometimes corrupted */
	if (ONE_IN(10)) {
		switch (rnd_modulo_u32(5)) {
		case 0: nlh->nlmsg_len = 0; break;
		case 1: nlh->nlmsg_len = NLMSG_HDRLEN - 1; break;
		case 2: nlh->nlmsg_len = (offset - msg_start) * 2; break;
		case 3: nlh->nlmsg_len = rand32(); break;
		case 4: /* understate by K — leave K trailing bytes for the next NLMSG_NEXT walk */
			nlh->nlmsg_len = (offset - msg_start) - RAND_RANGE(NLMSG_HDRLEN, 64);
			break;
		}
	} else {
		nlh->nlmsg_len = offset - msg_start;
	}

	/* NLMSG_ALIGN for chaining; clamp at buflen so a downstream
	 * memcpy(gen_buf, gen_len) can never over-read the allocation when
	 * total_len is not a multiple of NLMSG_ALIGNTO. */
	size_t aligned = NLMSG_ALIGN(offset);
	return aligned > buflen ? buflen : aligned;
}

/*
 * One of the two messages that bracket an nfnetlink batch: an nlmsghdr and
 * an nfgenmsg whose res_id names the subsystem, and no attributes.  A
 * NFNL_BATCH_GENID would have to be the current generation or the batch
 * ends with -ERESTART before a command runs, and the generator cannot know
 * it.  END needs NLM_F_REQUEST like every message in the batch: the kernel
 * tests the flag before the type, so without it END is answered -EINVAL and
 * the batch never ends.  The caller keeps the room.
 */
static size_t put_nfnl_batch_marker(unsigned char *msg, size_t offset,
				    unsigned short type, unsigned char subsys)
{
	struct nlmsghdr nlh = {
		.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg)),
		.nlmsg_type = type,
		.nlmsg_flags = NLM_F_REQUEST,
		.nlmsg_seq = rand32(),
	};
	struct nfgenmsg nfg = {
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = htons(subsys),
	};

	memcpy(msg + offset, &nlh, sizeof(nlh));
	memcpy(msg + offset + NLMSG_HDRLEN, &nfg, sizeof(nfg));
	return offset + NLMSG_SPACE(sizeof(nfg));
}

/*
 * nfnetlink dispatches an NFNL_CB_BATCH callback, 21 of the 32 nftables
 * commands, only inside a batch, and answers -EINVAL to one sent alone.
 * nfnetlink_rcv() hands the whole buffer to nfnetlink_rcv_batch() when its
 * first message is NFNL_MSG_BATCH_BEGIN, which names the subsystem; the
 * batch takes only that subsystem's batch callbacks, runs to the first
 * NFNL_MSG_BATCH_END and commits only if every command in it succeeded.
 * So this builds BEGIN, then num_msgs commands, the first of type
 * first_type and the rest picked from the same subsystem's batch
 * callbacks, then END, all in the buffer the caller sized.  One batch in
 * eight leaves END off: the walk ends with the buffer, and when no command
 * failed nfnetlink_rcv_batch() aborts with NFNL_ABORT_VALIDATE, which
 * validates the transaction and then rolls it back.  A command finds what
 * an earlier one made by name, inside a table that nf_tables finds by family
 * and name together, so the commands of a batch share one family, which the
 * subsystem's grammar lists, and the attribute grammar gives them one name.
 */
static size_t build_nfnl_batch(unsigned char *msg, size_t buflen,
			       struct socket_triplet *triplet,
			       unsigned short first_type, int num_msgs)
{
	const struct nfnl_subsys_grammar *sub = nfnl_lookup_by_subsys(first_type >> 8);
	unsigned char subsys = first_type >> 8;
	unsigned short type = first_type;
	int family = nfnl_pick_family(sub);
	/* Room for END, and aligned, so it starts where the kernel steps
	 * to after the last command. */
	size_t cmds_end = (buflen - NLMSG_SPACE(sizeof(struct nfgenmsg))) &
			  ~(size_t)(NLMSG_ALIGNTO - 1);
	size_t offset;

	offset = put_nfnl_batch_marker(msg, 0, NFNL_MSG_BATCH_BEGIN, subsys);
	while (num_msgs-- > 0 && offset < cmds_end) {
		offset = build_one_nlmsg(msg, offset, cmds_end, triplet, type,
					 family);
		type = (first_type & 0xff00) | nfnl_pick_batch_cmd(sub);
	}
	if (ONE_IN(8))
		return offset;
	return put_nfnl_batch_marker(msg, offset, NFNL_MSG_BATCH_END, subsys);
}

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len)
{
	size_t total_len;
	size_t offset;
	unsigned char *msg;
	unsigned short nlmsg_type;
	int num_msgs;
	int is_single;

	/* Total buffer: room for messages with protocol body + attrs.
	 * XFRM bodies can be up to 280 bytes, audit_rule_data is 1040 bytes,
	 * so base size must accommodate the largest possible body. */
	total_len = NLMSG_HDRLEN + 1280 + (rnd_modulo_u32(512));
	/* Multi-message batches need more space */
	if (ONE_IN(4)) {
		num_msgs = RAND_RANGE(2, 4);
		total_len *= num_msgs;
	} else {
		num_msgs = 1;
	}
	is_single = (num_msgs == 1);
	if (total_len > 8192)
		total_len = 8192;

	msg = zmalloc(total_len);

	/* A buffer that opens with a batch callback goes out inside a batch
	 * seven times in eight; the eighth leaves the command alone, which
	 * nfnetlink answers -EINVAL, so that arm keeps seeing traffic. */
	nlmsg_type = pick_nlmsg_type(triplet->protocol);
	if (triplet->protocol == NETLINK_NETFILTER &&
	    nfnl_type_is_batch(nlmsg_type) && !ONE_IN(8)) {
		offset = build_nfnl_batch(msg, total_len, triplet, nlmsg_type,
					  num_msgs);
	} else {
		offset = build_one_nlmsg(msg, 0, total_len, triplet, nlmsg_type,
					 -1);
		while (--num_msgs > 0 && offset < total_len)
			offset = build_one_nlmsg(msg, offset, total_len, triplet,
						 pick_nlmsg_type(triplet->protocol),
						 -1);
	}

	/*
	 * ACK oracle: for 1-in-32 single-message NETLINK_ROUTE packets,
	 * OR NLM_F_ACK into the already-built nlmsghdr flags and record
	 * the message type so rtnl_oracle_drain() can classify the reply
	 * after the real sendmsg() returns.
	 *
	 * Called AFTER build_one_nlmsg() has finalised the buffer (including
	 * any nlmsg_len corruption arm) so generation stays side-effect free:
	 * no private socket is opened and no send occurs here.
	 */
	if (is_single && triplet->protocol == NETLINK_ROUTE &&
	    offset >= NLMSG_HDRLEN)
		rtnl_oracle_sample(
			((struct nlmsghdr *)(void *)msg)->nlmsg_type, msg);

	*buf = msg;
	*len = offset;
}
