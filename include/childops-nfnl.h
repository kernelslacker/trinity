#pragma once

/*
 * childops-nfnl: NETLINK_NETFILTER scaffolding for the childops/ tree.
 *
 * Companion layer to include/childops-netlink.h.  Several childops open
 * NETLINK_NETFILTER sockets and emit nfnetlink-shaped messages
 * (nlmsghdr with type = (subsys << 8) | msg_type, followed by an
 * nfgenmsg payload carrying family + version + res_id).  Each per-file
 * copy reimplemented the same socket / bind / SO_RCVTIMEO sequence and
 * the same nfgenmsg-envelope stamper.  A couple also reimplemented the
 * BATCH_BEGIN ... ops ... BATCH_END coalesced sendmsg + drain that
 * nf_tables transactions ride on top of.  This header consolidates that
 * wire scaffolding so per-childop code can stay focused on the
 * per-message attribute / op selection that is the actual fuzzing
 * surface.
 *
 * Scope of this layer (intentionally narrow):
 *   - Open / close a NETLINK_NETFILTER socket via the shared nl_open()
 *     plumbing, with an optional multicast subscribe mask and
 *     SO_RCVTIMEO.
 *   - Stamp an nfnetlink envelope (nlmsghdr with the subsys-encoded
 *     type + an nfgenmsg payload) into a caller-provided buffer.
 *   - Stamp BATCH_BEGIN / BATCH_END markers for nf_tables transactions
 *     so callers can compose a multi-op batch into one sendmsg.
 *   - Single-ack send/recv with the same -EIO-on-non-error semantic as
 *     nl_send_recv().
 *   - Coalesced batch send/drain for the BATCH_BEGIN ... BATCH_END
 *     pattern: one sendmsg of the whole transaction, then drain every
 *     queued reply, returning the first NLMSG_ERROR with err != 0.
 *   - Dump-style send/drain that tolerates EAGAIN as "no completion
 *     seen" without wedging on a kernel that doesn't reply.
 *
 * Out of scope (per-childop concerns that stay local):
 *   - Per-op message builders (attribute walk, expression composition,
 *     verdict selection).  These are the fuzzing surface; they belong
 *     next to the per-op coverage rationale.
 *   - Per-subsys constant shims.  NFNL_SUBSYS_NFTABLES,
 *     NFNL_SUBSYS_CTNETLINK and the NFNL_MSG_BATCH_BEGIN / _END marker
 *     IDs live in <linux/netfilter/nfnetlink.h>; the per-subsys
 *     message-type / attribute IDs live in
 *     <linux/netfilter/nfnetlink_*.h> and <linux/netfilter/nf_tables.h>
 *     and are caller business.
 *   - NLMSG_ALIGN and the nla_put_*() family.  Already provided by
 *     <linux/netlink.h> and include/childops-netlink.h respectively.
 */

#include <errno.h>
#include <stddef.h>
#include <sys/types.h>

#include <linux/netlink.h>
#include <linux/types.h>

#include "childops-netlink.h"

#include "kernel/nfnetlink.h"
/*
 * NETLINK_NETFILTER context.  Composes struct nl_ctx so the shared
 * sequence counter and fd plumbing are reused as-is; the wrapper layer
 * is otherwise stateless.  Callers reach the underlying nl_ctx via
 * ctx->nl when they need to mix in a raw nla_put / nl_seq_next on the
 * same socket.
 */
struct nfnl_ctx {
	struct nl_ctx	nl;	/* always proto = NETLINK_NETFILTER */
};

struct nfnl_open_opts {
	__u32	groups;		/* multicast subscribe mask, 0 = unicast only */
	int	recv_timeo_s;	/* SO_RCVTIMEO seconds; 0 = no timeout */
};

/*
 * Open a NETLINK_NETFILTER socket via nl_open() and stash it in ctx.
 * Returns 0 on success, -1 on failure with errno preserved from
 * socket() / bind().  EPROTONOSUPPORT here typically means the kernel
 * is built without CONFIG_NETFILTER_NETLINK — callers usually latch
 * that and skip the childop for the rest of the run.
 */
int nfnl_open(struct nfnl_ctx *ctx, const struct nfnl_open_opts *opts);

/*
 * Close ctx->nl.fd via nl_close() and zero the wrapper.  Idempotent on
 * a -1 fd.
 */
void nfnl_close(struct nfnl_ctx *ctx);

/*
 * Stamp a single nfnetlink request at buf + off:
 *   nlh->nlmsg_type  = (subsys << 8) | msg_type
 *   nlh->nlmsg_flags = flags | NLM_F_REQUEST | NLM_F_ACK
 *   nlh->nlmsg_seq   = seq
 *   nfgenmsg payload: { family, NFNETLINK_V0, htons(0) }
 *
 * Returns the offset past the stamped envelope (NLMSG_HDRLEN +
 * NLMSG_ALIGN(sizeof(nfgenmsg))), or 0 if the write would overflow
 * cap.  Caller appends per-op attributes after the returned offset
 * and patches nlh->nlmsg_len at finalization time.
 */
size_t nfnl_msg_put(unsigned char *buf, size_t off, size_t cap,
		    __u32 seq, __u8 subsys, __u8 msg_type,
		    __u16 flags, __u8 family);

/*
 * Stamp an NFNL_MSG_BATCH_BEGIN / _END marker for an nf_tables-style
 * transaction.  The kernel keys batch routing off the nfgenmsg's
 * res_id field rather than the type's subsys nibble, so subsys is
 * passed in and stamped into res_id (htons(subsys)).  flags are just
 * NLM_F_REQUEST — the batch markers do not solicit an individual ack.
 *
 * Returns the offset past the marker (NLMSG_HDRLEN +
 * NLMSG_ALIGN(sizeof(nfgenmsg))), or 0 on cap overflow.  Caller
 * patches nlh->nlmsg_len before stamping the next message.
 */
size_t nfnl_batch_begin(unsigned char *buf, size_t off, size_t cap,
			__u32 seq, __u8 subsys);
size_t nfnl_batch_end(unsigned char *buf, size_t off, size_t cap,
		      __u32 seq, __u8 subsys);

/*
 * Send msg/len then receive exactly one reply.  Mirrors nl_send_recv():
 *   0                — positive ack (NLMSG_ERROR with err == 0).
 *   negated errno    — NLMSG_ERROR rejection.
 *   -EIO             — local sendmsg/recv failure, short recv, or any
 *                      non-NLMSG_ERROR reply.
 */
int nfnl_send_recv(struct nfnl_ctx *ctx, void *msg, size_t len);

/*
 * Send a pre-built BATCH_BEGIN ... ops ... BATCH_END buffer as one
 * sendmsg, then drain every reply the kernel coalesces back.  One
 * blocking recv waits for the batch result; subsequent reads are
 * MSG_DONTWAIT until the queue drains.  Returns:
 *   0                — clean drain, no NLMSG_ERROR with err != 0.
 *   negated errno    — first non-zero NLMSG_ERROR encountered.
 *   -EIO             — sendmsg failure or initial recv failure.
 */
int nfnl_send_recv_batched(struct nfnl_ctx *ctx, void *msg, size_t len);

/*
 * Dump / streaming send.  Sends msg/len then drains replies until
 * NLMSG_DONE or NLMSG_ERROR.  Reads are MSG_DONTWAIT after an initial
 * blocking recv so a kernel that returns nothing (CONFIG_NF_CONNTRACK
 * absent, the typical case for IPCTNL_MSG_CT_FLUSH on a stripped
 * box) cannot wedge us past the inherited SIGALRM(1s) cap.  Returns:
 *   0                — NLMSG_DONE observed.
 *   negated errno    — first NLMSG_ERROR with err != 0, or err == 0
 *                      treated as a positive ack and returned as 0.
 *   -EIO             — sendmsg failure, initial recv failure, or
 *                      EAGAIN on the drain before any DONE / ERROR
 *                      was seen (matches the per-file MSG_DONTWAIT
 *                      "best-effort drain" behaviour).
 */
int nfnl_send_recv_dump(struct nfnl_ctx *ctx, void *msg, size_t len);
