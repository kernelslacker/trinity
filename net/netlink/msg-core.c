/*
 * Structured netlink message generation for fuzzing.
 *
 * Builds nlmsghdr messages with protocol-appropriate types and flags,
 * optional nlattr TLVs, and occasional deliberate corruption to test
 * both valid code paths and error handling in the kernel.
 */
#include <sys/socket.h>
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

/* Generate a random set of nlmsg flags biased toward valid combos */
static unsigned short gen_nlmsg_flags(void)
{
	unsigned short flags = NLM_F_REQUEST; /* almost always set */

	if (ONE_IN(10))
		return rand16(); /* pure chaos */

	if (RAND_BOOL())
		flags |= NLM_F_ACK;

	if (RAND_BOOL())
		flags |= NLM_F_ECHO;

	/* GET-style: dump flags */
	if (RAND_BOOL())
		flags |= NLM_F_DUMP;

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
 * together) to exercise the kernel's NLMSG_NEXT iteration path.
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

/* Build a single nlmsghdr at msg+offset. Returns new offset (NLMSG_ALIGN'd). */
/*
 * Single iteration of build_one_nlmsg()'s inner attr-append loop.
 * Returns the new offset, or 0 to signal "no progress, caller break".
 * 0 is an unambiguous sentinel here because the caller has already
 * advanced offset past NLMSG_HDRLEN before the loop runs.
 */
static size_t iter_nlmsg_attr(unsigned char *msg, size_t offset, size_t buflen,
			      const struct nla_attr_spec *spec_table,
			      size_t nr_specs,
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
						spec_table, nr_specs);
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
			      struct socket_triplet *triplet)
{
	struct nlmsghdr *nlh;
	unsigned short nlmsg_type;
	size_t body_len;
	size_t msg_start = offset;
	unsigned char body_family = AF_UNSPEC;
	int rtnl_group = -1;
	int num_attrs;

	/* Floor: nlmsghdr + genlmsghdr + a small per-family fixed header.
	 * Real buffers are >=1280 bytes so this is just a sanity gate. */
	if (offset + NLMSG_HDRLEN + 8 > buflen)
		return offset;

	nlmsg_type = pick_nlmsg_type(triplet->protocol);

	nlh = (struct nlmsghdr *) (msg + offset);
	nlh->nlmsg_type = nlmsg_type;
	nlh->nlmsg_flags = gen_nlmsg_flags();
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
					 buflen - offset);
	} else if (triplet->protocol == NETLINK_NETFILTER) {
		body_len = gen_nfnl_body(msg + offset, nlmsg_type,
					 buflen - offset);
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

	/* Append nlattr TLVs with protocol-appropriate types.
	 * Audit messages don't use nlattr — skip for that protocol. */
	num_attrs = (triplet->protocol == NETLINK_AUDIT) ? 0 : rnd_modulo_u32(8);
	if (num_attrs > 0) {
		const struct nla_attr_spec *spec_table;
		size_t nr_specs = 0;

		spec_table = pick_spec_table(triplet->protocol, nlmsg_type,
					     &nr_specs);

		while (num_attrs-- > 0 && offset < buflen) {
			size_t new_off = iter_nlmsg_attr(msg, offset, buflen,
							 spec_table, nr_specs,
							 triplet, nlmsg_type,
							 body_family,
							 rtnl_group);
			if (new_off == 0)
				break;
			offset = new_off;
		}
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

void netlink_gen_msg(struct socket_triplet *triplet, void **buf, size_t *len)
{
	size_t total_len;
	size_t offset;
	unsigned char *msg;
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

	offset = 0;
	while (num_msgs-- > 0 && offset < total_len)
		offset = build_one_nlmsg(msg, offset, total_len, triplet);

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
