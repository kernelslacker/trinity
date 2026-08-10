/*
 * net/netlink/rtnl-ack-oracle.c
 *
 * Sampled ACK oracle for the NETLINK_ROUTE fuzz path.
 *
 * MOTIVATION
 *
 * netlink_nested_attrs_emitted counts nested-attr containers written into
 * generated NETLINK_ROUTE messages, but the counter increments identically
 * whether the kernel accepted or silently discarded the message.  The oracle
 * closes that gap: for 1-in-N sampled messages it arranges for the kernel
 * to emit an NLMSG_ERROR reply, drains that reply after the real sendmsg
 * returns, and classifies the outcome into a per-nlmsg_type histogram.
 *
 * DESIGN (correcting the reverted first attempt)
 *
 * The first attempt opened a private NETLINK_ROUTE socket
 * inside netlink_gen_msg(), sent a copy of the message, and read the ACK
 * synchronously.  Three failures:
 *
 *   1. Mutation before generation: the private send happened while
 *      netlink_gen_msg() was still building the payload, so RTM_NEW/DEL
 *      requests changed kernel state during generation and the real path
 *      sent the same payload a second time.
 *
 *   2. 150ms blocking timeout: ~1 in 10 messages corrupts nlmsg_len;
 *      four of five corruption arms produce a header the kernel drops
 *      without an ACK, so the synchronous recv timed out on ~8% of
 *      probes -- ~12ms average per rtnl generation.
 *
 *   3. Undrained fuzz socket: forcing NLM_F_ACK unconditionally on the
 *      real message left ACK replies accumulating in the fuzz socket's
 *      receive queue across thousands of messages.
 *
 * This implementation fixes all three:
 *
 *   1. Generation stays side-effect free: rtnl_oracle_sample() ORs
 *      NLM_F_ACK into the *already-built* buffer in-place and records
 *      state.  No socket is opened or used here.
 *
 *   2. Non-blocking drain: rtnl_oracle_drain() uses MSG_DONTWAIT.  A
 *      corrupted nlmsg_len that causes the kernel to drop the message
 *      returns EAGAIN immediately; that is counted as no_reply rather
 *      than blocking for 150 ms.
 *
 *   3. Drain after send, not before: rtnl_oracle_drain() is called from
 *      the proto->post_send hook in syscalls/socket/send.c, which fires
 *      after the real sendmsg() syscall has completed.  Only sampled
 *      messages have NLM_F_ACK set, so the fuzz socket's receive queue
 *      stays empty for the other N-1 messages.
 *
 * SAMPLING RATE
 *
 * RTNL_ACK_ORACLE_SAMPLE_RATE 32 means every 32nd eligible
 * single-message NETLINK_ROUTE call is probed.  At typical fuzz rates
 * (~10 000 rtnl sends/s per worker) this yields ~300 probes/s -- more
 * than enough resolution to detect a ratio shift within seconds.  Each
 * probe costs one MSG_DONTWAIT recv (< 1 us when the reply is queued,
 * < 1 us EAGAIN when not) compared to the 150 ms blocking timeout of the
 * first attempt.  Increase the rate (lower N) to improve signal density;
 * decrease it (raise N) to reduce recv overhead.
 *
 * DRAIN LOOP
 *
 * Dump requests (NLM_F_DUMP set in the original flags) produce data
 * messages before the ACK.  RTNL_ACK_ORACLE_DRAIN_MAX caps the drain
 * loop: we read up to that many messages with MSG_DONTWAIT, stop when we
 * see NLMSG_ERROR or exhaust the cap, and count anything else as
 * no_reply.  Eight iterations is well above the typical dump response
 * depth while keeping the fast path cheap.
 */
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "shm.h"
#include "rtnl-ack-oracle.h"

/*
 * 1-in-N sampling: probe every Nth eligible message.  32 is the default;
 * lower values give denser signal at the cost of more MSG_DONTWAIT recvs.
 */
#define RTNL_ACK_ORACLE_SAMPLE_RATE	32

/*
 * Maximum MSG_DONTWAIT recvs per probe.  Needed to drain data messages
 * that arrive before the NLMSG_ERROR ACK on dump requests.
 */
#define RTNL_ACK_ORACLE_DRAIN_MAX	8

/*
 * Per-worker-process oracle state.  Each child inherits a fresh copy
 * from the parent fork; no cross-process locking is needed.
 *
 * counter:    modular send counter; active when counter % SAMPLE_RATE == 0.
 * active:     1 when the current message was sampled and a drain is due.
 * nlmsg_type: RTM_* type of the sampled message, captured for group accounting.
 */
static struct {
	unsigned int   counter;
	int            active;
	unsigned short nlmsg_type;
} oracle_state;

/*
 * rtnl_oracle_sample - mark a message for oracle sampling.
 *
 * Called from netlink_gen_msg() AFTER build_one_nlmsg() has finalised the
 * buffer (including any nlmsg_len corruption arm).  On sampled calls it
 * ORs NLM_F_ACK into the first nlmsghdr so the kernel generates an
 * NLMSG_ERROR reply when the message is sent by the real fuzz path.
 *
 * The buffer is the one that will be handed directly to sendmsg() --
 * generation is complete, so ORing NLM_F_ACK here is purely in-place
 * annotation of an already-built payload, not a pre-flight send.
 */
void rtnl_oracle_sample(unsigned short nlmsg_type, unsigned char *msg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)(void *)msg;

	oracle_state.active = 0;

	oracle_state.counter++;
	if ((oracle_state.counter % RTNL_ACK_ORACLE_SAMPLE_RATE) != 0)
		return;

	/*
	 * Request an ACK from the kernel.  OR-in rather than assign so
	 * any chaos flags already set by gen_nlmsg_flags() are preserved.
	 * NLM_F_ACK causes the kernel to emit NLMSG_ERROR regardless of
	 * whether the operation succeeds or fails.
	 */
	nlh->nlmsg_flags |= (unsigned short)NLM_F_ACK;
	oracle_state.nlmsg_type = nlmsg_type;
	oracle_state.active = 1;
}

/*
 * rtnl_oracle_drain - drain the ACK reply after the real sendmsg.
 *
 * Called from the proto->post_send hook in syscalls/socket/send.c after
 * the sendmsg() syscall has returned.  Returns immediately if this
 * message was not sampled (oracle_state.active == 0).
 *
 * MSG_DONTWAIT is used throughout: a corrupted nlmsg_len that causes the
 * kernel to drop the message (and emit no reply) produces EAGAIN in
 * microseconds rather than blocking for a timeout.
 */
void rtnl_oracle_drain(int fd)
{
	unsigned char rbuf[512];
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;
	ssize_t n;
	int e, grp, i;

	if (!oracle_state.active)
		return;

	/*
	 * Clear active before the recv loop so a signal or async event
	 * during draining cannot double-count this probe.
	 */
	oracle_state.active = 0;

	/*
	 * Drain up to DRAIN_MAX messages with MSG_DONTWAIT.  Data messages
	 * from dump replies arrive before the NLMSG_ERROR ACK; we consume
	 * them and keep looking.  EAGAIN means the kernel hasn't enqueued
	 * anything yet (e.g. nlmsg_len was corrupted and the kernel
	 * silently dropped the message), so we count that as no_reply.
	 */
	for (i = 0; i < RTNL_ACK_ORACLE_DRAIN_MAX; i++) {
		n = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n < 0)
			goto out_noreply; /* EAGAIN or real error */

		if ((size_t)n < NLMSG_HDRLEN)
			continue; /* undersized — skip, keep draining */

		nlh = (struct nlmsghdr *)(void *)rbuf;
		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue; /* data or multipart — keep draining */

		/* Found NLMSG_ERROR: extract error code */
		if ((size_t)n < NLMSG_HDRLEN + sizeof(struct nlmsgerr))
			goto out_noreply; /* truncated ACK */

		err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		e   = err->error; /* 0 on success, negated errno on failure */
		goto got_ack;
	}
	/* Exhausted the drain limit without seeing NLMSG_ERROR */
	goto out_noreply;

got_ack:
	/*
	 * RTM group index: (nlmsg_type - RTM_BASE) / 4.
	 * Clamped to [-1, MAX_GROUPS); -1 means out of the RTM range
	 * (e.g. a chaos-mode random type below RTM_BASE).
	 */
	grp = ((int)(unsigned short)oracle_state.nlmsg_type - RTM_BASE) / 4;
	if (grp < 0 || grp >= RTNL_ACK_ORACLE_MAX_GROUPS)
		grp = -1;

	if (e == 0) {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.accepted,
				   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.netlink_nested_attrs_accepted,
				   1, __ATOMIC_RELAXED);
		if (grp >= 0)
			__atomic_add_fetch(
				&shm->stats.rtnl_ack_oracle
				 .type_accepted_per_group[grp],
				1, __ATOMIC_RELAXED);
	} else if (e == -EINVAL) {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.einval,
				   1, __ATOMIC_RELAXED);
	} else if (e == -ERANGE) {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.erange,
				   1, __ATOMIC_RELAXED);
	} else if (e == -EOPNOTSUPP) {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.eopnotsupp,
				   1, __ATOMIC_RELAXED);
	} else if (e == -EPERM) {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.eperm,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.other,
				   1, __ATOMIC_RELAXED);
	}
	return;

out_noreply:
	__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.no_reply,
			   1, __ATOMIC_RELAXED);
}
