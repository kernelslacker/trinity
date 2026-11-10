/*
 * Self-check for the rtnl ACK oracle's sampling.  rtnl_oracle_sample() has
 * one eligible message in 32 ask for an ACK and passes over a dump, which
 * ends in NLMSG_DONE instead.  rtnetlink_rcv_msg() takes only a GET with a
 * dump bit for a dump: on the other kinds the two bits are the
 * REPLACE/NONREC and EXCL/BULK modifiers, and the request is ACKed.
 */

#include <stdio.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "debug.h"				/* BUG */
#include "net/netlink/rtnl-ack-oracle.h"
#include "shm.h"				/* shm->stats.rtnl_ack_oracle */

/*
 * Twice the oracle's sample rate.  Its counter carries over from earlier
 * offers, and a passed-over dump steps it back, but any run of this many
 * offers of a request it samples steps past exactly two multiples of 32.
 */
#define OFFERS		64

static void expect_acks(unsigned short type, unsigned short flags,
			unsigned int want, const char *msg)
{
	struct nlmsghdr nlh = { .nlmsg_len = NLMSG_HDRLEN, .nlmsg_type = type };
	unsigned int i, acks = 0;

	for (i = 0; i < OFFERS; i++) {
		nlh.nlmsg_flags = flags;
		rtnl_oracle_sample(type, (unsigned char *) &nlh);
		acks += (nlh.nlmsg_flags & NLM_F_ACK) != 0;
	}
	if (acks != want) {
		printf("type %u flags %#x: %u ACKs asked in %u offers, want %u\n",
		       type, flags, acks, OFFERS, want);
		BUG(msg);
	}
}

void rtnl_ack_oracle_self_check(void);
void rtnl_ack_oracle_self_check(void)
{
	unsigned long skipped = shm->stats.rtnl_ack_oracle.dump_skipped;

	expect_acks(RTM_GETLINK, NLM_F_REQUEST, 2,
		    "rtnl oracle: a GET for its doit is not sampled");
	expect_acks(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 0,
		    "rtnl oracle: a dump is sampled");
	expect_acks(RTM_GETROUTE, NLM_F_REQUEST | NLM_F_MATCH, 0,
		    "rtnl oracle: a GET with one dump bit is sampled");
	if (shm->stats.rtnl_ack_oracle.dump_skipped == skipped)
		BUG("rtnl oracle: a dump passed over is not counted");

	skipped = shm->stats.rtnl_ack_oracle.dump_skipped;
	expect_acks(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE, 2,
		    "rtnl oracle: a NEW with NLM_F_REPLACE is taken for a dump");
	expect_acks(RTM_DELROUTE, NLM_F_REQUEST | NLM_F_NONREC | NLM_F_BULK, 2,
		    "rtnl oracle: a DELETE with NLM_F_BULK is taken for a dump");
	expect_acks(RTM_SETLINK, NLM_F_REQUEST | NLM_F_EXCL, 2,
		    "rtnl oracle: a SET with NLM_F_EXCL is taken for a dump");
	/* Past RTM_MAX, rtnetlink_rcv_msg() answers -EOPNOTSUPP to anything. */
	expect_acks(RTM_MAX + 3, NLM_F_REQUEST | NLM_F_DUMP, 2,
		    "rtnl oracle: a type past RTM_MAX is taken for a dump");
	if (shm->stats.rtnl_ack_oracle.dump_skipped != skipped)
		BUG("rtnl oracle: a request that is not a dump is counted as one");

	/* Leave no probe for a later send to drain. */
	rtnl_oracle_drain(-1, 0);
}
