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
 * Dump requests (NLM_F_DUMP set in the original flags) are excluded from
 * sampling.  __netlink_dump_start() returns -EINTR to suppress the ACK
 * regardless of NLM_F_ACK (af_netlink.c: "We successfully started a dump,
 * by returning -EINTR we signal not to send ACK even if it was requested").
 * A sampled dump therefore never produces NLMSG_ERROR; it produces data
 * messages followed by NLMSG_DONE.  Excluding NLM_F_DUMP messages from
 * sampling avoids two problems: (1) every successful dump being filed as
 * no_reply, corrupting the accepted-rate signal; (2) up to DRAIN_MAX recvs
 * on a socket with a running dump advancing cb_running state so the next
 * recv on that fd continues the stale dump.
 *
 * Crucially, rtnl_oracle_sample() rolls counter back by one on the
 * NLM_F_DUMP return so the budget slot is not consumed: the next eligible
 * (non-dump) message fires the gate.  Without this correction, counter
 * sits at a multiple of SAMPLE_RATE after the return; the next increment
 * moves it off zero, and no probe fires for the full following period.
 * gen_nlmsg_flags() sets NLM_F_DUMP on a bare RAND_BOOL(), so roughly
 * half of every period's single slot would be silently lost — halving the
 * effective rate to ~1-in-64.  The correction keeps the rate at the
 * documented 1-in-32.  Each skipped dump is counted into dump_skipped.
 *
 * RTNL_ACK_ORACLE_DRAIN_MAX caps the drain loop for non-dump probes.  We
 * perform up to that many MSG_DONTWAIT recv() calls (datagrams) and stop on
 * NLMSG_ERROR (the explicit ACK path).  Each datagram may pack multiple
 * messages; rtnl_oracle_drain() iterates them all with NLMSG_OK/NLMSG_NEXT.
 * NLMSG_DONE cannot belong to our probe because NLM_F_DUMP is excluded from
 * sampling; each DONE terminator is queue pollution from concurrent dump
 * traffic, counted into stale_done.  Ordinary data/multipart messages are
 * counted into stale_other (per-message, not per-datagram).  If the budget
 * is exhausted before NLMSG_ERROR surfaces, the probe books
 * no_reply_exhausted; an early EAGAIN before the budget is consumed books
 * no_reply_clean.  A truncated NLMSG_ERROR (framing failure) is counted
 * separately into bad_framing and does not touch no_reply_clean.
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
 * Maximum MSG_DONTWAIT recvs (datagrams) per probe.  Each recv() may carry
 * more than one nlmsghdr; the inner NLMSG_OK/NLMSG_NEXT loop classifies
 * every message in the datagram before the outer loop moves to the next
 * recv().  DRAIN_MAX therefore caps datagrams, not individual messages.
 * Non-dump probes should see their NLMSG_ERROR in at most one or two
 * datagrams; the cap exists as a safety bound against spinning on a
 * socket with a long queue of stale replies from earlier dump traffic.
 */
#define RTNL_ACK_ORACLE_DRAIN_MAX	8

/*
 * Per-worker-process oracle state.  Each child inherits a fresh copy
 * from the parent fork; no cross-process locking is needed.
 *
 * counter:    modular send counter; active when counter % SAMPLE_RATE == 0.
 * active:     1 when the current message was sampled and a drain is due.
 * nlmsg_type: RTM_* type of the sampled message, captured for group accounting.
 * nlmsg_seq:  sequence number of the sampled message; used in the drain loop
 *             to verify that an NLMSG_ERROR reply belongs to this probe and
 *             not to a stale earlier message still in the receive queue.
 */
static struct {
	unsigned int      counter;
	int               active;
	unsigned short    nlmsg_type;
	__u32             nlmsg_seq;
	struct nlmsghdr  *sampled_nlh; /* message buffer that had NLM_F_ACK ORed in */
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
	oracle_state.sampled_nlh = NULL;

	oracle_state.counter++;
	if ((oracle_state.counter % RTNL_ACK_ORACLE_SAMPLE_RATE) != 0)
		return;

	/*
	 * Dump requests produce NLMSG_DONE on success, not NLMSG_ERROR.
	 * __netlink_dump_start() returns -EINTR to suppress the ACK even
	 * when NLM_F_ACK is set, so sampling a dump yields no drainable
	 * reply and leaves cb_running advanced across drain iterations.
	 *
	 * Roll the counter back before returning so the budget slot is not
	 * wasted: counter-- leaves it at (SAMPLE_RATE-1) mod SAMPLE_RATE,
	 * and the next non-dump increment brings it to 0 mod SAMPLE_RATE,
	 * firing the gate for the next eligible message.  Identical to the
	 * counter correction in rtnl_oracle_abort();
	 * e881da483f4b ("net/netlink: rtnl_oracle_abort steps sample counter back by one").
	 */
	if (nlh->nlmsg_flags & NLM_F_DUMP) {
		oracle_state.counter--;
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.dump_skipped,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Request an ACK from the kernel.  OR-in rather than assign so
	 * any chaos flags already set by gen_nlmsg_flags() are preserved.
	 * NLM_F_ACK causes the kernel to emit NLMSG_ERROR regardless of
	 * whether the operation succeeds or fails.
	 */
	nlh->nlmsg_flags |= (unsigned short)NLM_F_ACK;
	oracle_state.nlmsg_type  = nlmsg_type;
	oracle_state.nlmsg_seq   = nlh->nlmsg_seq;
	oracle_state.sampled_nlh = nlh;
	oracle_state.active = 1;
}

/*
 * rtnl_oracle_abort - cancel a pending sample without draining.
 *
 * Called when gen_msg was taken on a path that cannot call rtnl_oracle_drain()
 * (e.g. the grammar-path bare sendmsg in sfg_default_data_leg).  Undoes the
 * in-place NLM_F_ACK annotation and rolls the counter back so the budget slot
 * is not consumed on a path where draining is impossible.  No-ops immediately
 * when the oracle is not active.
 */
void rtnl_oracle_abort(void)
{
	if (!oracle_state.active)
		return;

	/*
	 * Undo the NLM_F_ACK flag we ORed into the buffer so the message goes
	 * out without requesting an ACK and the socket receive queue stays clean.
	 */
	if (oracle_state.sampled_nlh != NULL)
		oracle_state.sampled_nlh->nlmsg_flags &=
			(unsigned short)~NLM_F_ACK;

	/*
	 * Step the counter back by one so it sits at (SAMPLE_RATE - 1) mod
	 * SAMPLE_RATE.  The next increment brings it to 0 mod SAMPLE_RATE,
	 * which fires the sample — giving the slot to the next message on a
	 * drainable path rather than wasting a full period.
	 */
	oracle_state.counter--;

	oracle_state.active = 0;
	oracle_state.sampled_nlh = NULL;
}

/*
 * rtnl_oracle_drain - drain the ACK reply after the real sendmsg.
 *
 * Called from the proto->post_send hook in syscalls/socket/send.c after
 * the sendmsg() syscall has returned.  Returns immediately if this
 * message was not sampled (oracle_state.active == 0).
 *
 * send_ok is 1 when sendmsg() returned a non-negative byte count (the
 * message reached the kernel) and 0 when sendmsg() returned -1 (the
 * message never left userspace).  On a failed send the NLM_F_ACK flag
 * we ORed in is moot; the oracle counts the event as send_fail rather
 * than draining the socket.
 *
 * MSG_DONTWAIT is used throughout: a corrupted nlmsg_len that causes the
 * kernel to drop the message (and emit no reply) produces EAGAIN in
 * microseconds rather than blocking for a timeout.
 */
void rtnl_oracle_drain(int fd, int send_ok)
{
	unsigned char rbuf[4096];
	struct nlmsghdr *nlh;
	struct nlmsgerr *err;
	int nleft;
	ssize_t n;
	int e, grp, i;

	if (!oracle_state.active)
		return;

	/*
	 * Clear active before the recv loop so a signal or async event
	 * during draining cannot double-count this probe.
	 */
	oracle_state.active = 0;
	oracle_state.sampled_nlh = NULL;

	/*
	 * The message never reached the kernel: sendmsg() itself failed.
	 * Count as send_fail so the caller can distinguish 'kernel dropped'
	 * (no_reply) from 'never sent' (send_fail).  No recv to drain.
	 */
	if (!send_ok) {
		__atomic_add_fetch(&shm->stats.rtnl_ack_oracle.send_fail,
				   1, __ATOMIC_RELAXED);
		return;
	}

	/*
	 * Drain up to DRAIN_MAX datagrams (recv() calls) with MSG_DONTWAIT.
	 * Each recv() may return a datagram containing multiple nlmsghdr
	 * messages packed end-to-end; the inner NLMSG_OK/NLMSG_NEXT loop
	 * classifies every message in the datagram before the outer loop
	 * moves on to the next recv().
	 *
	 * DRAIN_MAX therefore caps recv() calls (datagrams), not individual
	 * messages.  This avoids silently discarding an NLMSG_ERROR ACK that
	 * happens to be packed behind a data message in the same datagram
	 * — a situation that caused the outer loop to classify by the first
	 * header only, drop the ACK, and book no_reply instead.
	 *
	 * MSG_TRUNC is added so that datagrams larger than rbuf are flagged:
	 * recv() returns the wire length rather than sizeof(rbuf) when the
	 * datagram was clipped.  We do not act on truncation beyond detecting
	 * it; the NLMSG_OK/NLMSG_NEXT walk naturally stops at the last
	 * complete header within the received bytes.
	 *
	 * Stop on NLMSG_ERROR (the ACK path for non-dump probes).
	 * NLMSG_DONE cannot be attributed to our probe because NLM_F_DUMP is
	 * excluded from sampling (see rtnl_oracle_sample()); each DONE
	 * terminator is counted into stale_done.  Ordinary data/multipart
	 * payload messages are counted into stale_other — per-message, not
	 * per-datagram.  If the budget is exhausted without seeing NLMSG_ERROR
	 * the probe books no_reply_exhausted; an early EAGAIN books
	 * no_reply_clean.  A truncated NLMSG_ERROR (framing failure) is counted
	 * into bad_framing and does not touch no_reply_clean.
	 */
	/*
	 * Every recv() that consumes a budget slot now increments at least
	 * one counter: stale_truncated records MSG_TRUNC clips, stale_unparsed
	 * catches datagrams whose first NLMSG_OK fails (e.g. oversized
	 * single-message RTM_NEWLINK with IFLA_VFINFO_LIST clipped to 4096
	 * bytes), and the remaining stale_* counters cover the inner-loop
	 * paths.  A slot that reaches the end of the outer body without any
	 * stale_* increment means the inner loop ran but every message fell
	 * through to got_ack — which terminates the function before the
	 * outer loop continues.
	 */
	for (i = 0; i < RTNL_ACK_ORACLE_DRAIN_MAX; i++) {
		n = recv(fd, rbuf, sizeof(rbuf), MSG_DONTWAIT | MSG_TRUNC);
		if (n < 0) {
			int saved_errno = errno;

			if (saved_errno == EAGAIN)
				goto out_noreply; /* queue empty: probe not replied */
			if (saved_errno == ENOBUFS) {
				/*
				 * Receive-queue overflow: sk_err is self-clearing.
				 * The ACK may be sitting behind the overflow marker;
				 * consume this budget slot and keep draining rather
				 * than laundering ENOBUFS into no_reply_clean.
				 */
				__atomic_add_fetch(
					&shm->stats.rtnl_ack_oracle.recv_enobufs,
					1, __ATOMIC_RELAXED);
				continue;
			}
			if (saved_errno == EINTR) {
				/*
				 * Signal interrupted recv(); do not consume a
				 * budget slot — retry this iteration.
				 */
				__atomic_add_fetch(
					&shm->stats.rtnl_ack_oracle.recv_eintr,
					1, __ATOMIC_RELAXED);
				i--;
				continue;
			}
			/* Real socket error: give up on this probe. */
			__atomic_add_fetch(
				&shm->stats.rtnl_ack_oracle.recv_error,
				1, __ATOMIC_RELAXED);
			goto out_noreply;
		}

		if ((size_t)n < NLMSG_HDRLEN) {
			/* Too short to hold even one nlmsghdr; skip but count.
			 * Kept separate from stale_other (data/multipart messages
			 * classified inside the NLMSG_OK walk) so that stale_other
			 * remains strictly per-message while stale_undersized flags
			 * a distinct recv-level anomaly. */
			__atomic_add_fetch(
				&shm->stats.rtnl_ack_oracle.stale_undersized,
				1, __ATOMIC_RELAXED);
			continue;
		}

		/*
		 * MSG_TRUNC: recv() returned the wire length rather than the
		 * number of bytes copied.  Count it so the flag is visible in
		 * stats; we still attempt the NLMSG_OK walk over the received
		 * bytes (clamped below) because a partial datagram may still
		 * contain a complete NLMSG_ERROR if the probe reply arrived
		 * with other messages appended after the ACK payload.
		 */
		if ((size_t)n > sizeof(rbuf))
			__atomic_add_fetch(
				&shm->stats.rtnl_ack_oracle.stale_truncated,
				1, __ATOMIC_RELAXED);

		/*
		 * Clamp nleft to the bytes we actually received (sizeof(rbuf)
		 * at most).  When MSG_TRUNC causes recv() to return the wire
		 * length (n > sizeof(rbuf)) we must not walk beyond the buffer;
		 * the walk stays safe because kernel netlink messages are
		 * 4-byte aligned (__nlmsg_put() uses NLMSG_ALIGN), so nleft
		 * stays ≡ 0 mod 4 and NLMSG_ALIGN(nlmsg_len) <= nleft whenever
		 * nlmsg_len <= nleft — NLMSG_NEXT never overshoots.
		 */
		nleft = (int)((size_t)n <= sizeof(rbuf)
			      ? (size_t)n : sizeof(rbuf));

		/*
		 * Walk every message packed into this datagram.
		 * inner_loop_ran is set to 1 on the first iteration so we can
		 * detect the case where NLMSG_OK fails immediately (e.g. an
		 * oversized single message clipped to 4096 bytes whose header
		 * indicates a longer payload) and count that uncounted budget
		 * slot into stale_unparsed.
		 */
		{
		int inner_loop_ran = 0;
		for (nlh = (struct nlmsghdr *)(void *)rbuf;
		     NLMSG_OK(nlh, nleft);
		     nlh = NLMSG_NEXT(nlh, nleft)) {
			inner_loop_ran = 1;

			if (nlh->nlmsg_type == NLMSG_DONE) {
				/*
				 * NLMSG_DONE from an unsampled dump in the
				 * queue.  NLM_F_DUMP is excluded from sampling
				 * so this cannot belong to our probe.
				 */
				__atomic_add_fetch(
					&shm->stats.rtnl_ack_oracle.stale_done,
					1, __ATOMIC_RELAXED);
				continue;
			}

			if (nlh->nlmsg_type != NLMSG_ERROR) {
				/* data or multipart payload message */
				__atomic_add_fetch(
					&shm->stats.rtnl_ack_oracle.stale_other,
					1, __ATOMIC_RELAXED);
				continue;
			}

			/* Found NLMSG_ERROR: check payload is intact */
			if (nlh->nlmsg_len < NLMSG_HDRLEN + sizeof(struct nlmsgerr)) {
				__atomic_add_fetch(
					&shm->stats.rtnl_ack_oracle.bad_framing,
					1, __ATOMIC_RELAXED);
				return; /* truncated ACK -- framing failure, not a dropped probe */
			}

			err = (struct nlmsgerr *)NLMSG_DATA(nlh);
			/*
			 * Correlate by sequence number: the NLMSG_ERROR
			 * payload echoes the original nlmsghdr, whose
			 * nlmsg_seq must match the one we recorded at sample
			 * time.  A mismatch means this reply belongs to a
			 * different (unsampled) message that happened to have
			 * NLM_F_ACK set; treat it as stale and keep draining.
			 */
			if (err->msg.nlmsg_seq != oracle_state.nlmsg_seq) {
				/* NLMSG_ERROR for a different probe: another path
				 * in this process used NLM_F_ACK.  Count into
				 * stale_foreign_ack; a rising rate confirms foreign
				 * NLM_F_ACK traffic is polluting the receive queue. */
				__atomic_add_fetch(
					&shm->stats.rtnl_ack_oracle.stale_foreign_ack,
					1, __ATOMIC_RELAXED);
				continue;
			}

			e = err->error; /* 0 on success, negated errno on failure */
			goto got_ack;
		}
		if (!inner_loop_ran)
			__atomic_add_fetch(
				&shm->stats.rtnl_ack_oracle.stale_unparsed,
				1, __ATOMIC_RELAXED);
		} /* end inner block */
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
	if (i == RTNL_ACK_ORACLE_DRAIN_MAX)
		__atomic_add_fetch(
			&shm->stats.rtnl_ack_oracle.no_reply_exhausted,
			1, __ATOMIC_RELAXED);
	else
		__atomic_add_fetch(
			&shm->stats.rtnl_ack_oracle.no_reply_clean,
			1, __ATOMIC_RELAXED);
}
