/*
 * childops/nfnl-util.c — implementation for the shared scaffolding
 * declared in include/childops-nfnl.h.
 *
 * Behavioural choices preserved from the per-file copies this file
 * replaces (nftables-churn.c, flowtable-encap-vlan.c,
 * bridge-conntrack-churn.c):
 *
 *   - The socket is a NETLINK_NETFILTER SOCK_RAW | SOCK_CLOEXEC opened
 *     via nl_open(), so the open / bind / SO_RCVTIMEO sequence and the
 *     EPROTONOSUPPORT-on-CONFIG_NETFILTER_NETLINK-absent failure mode
 *     match the rest of the childops layer.
 *   - nfnl_msg_put() stamps NLM_F_REQUEST | NLM_F_ACK | flags so the
 *     standard ack-on-success / NLMSG_ERROR-on-failure protocol holds
 *     for non-batched RPCs.  Batched callers append BATCH_BEGIN /
 *     BATCH_END markers via nfnl_batch_begin / nfnl_batch_end, whose
 *     stamped flags are bare NLM_F_REQUEST (the markers do not solicit
 *     individual acks; the per-op messages inside the batch do).
 *   - nfnl_send_recv() is a thin shim over nl_send_recv() — the wire
 *     contract is identical at the netlink layer; the nfnetlink-ness
 *     is captured in the message build, not the send.
 *   - nfnl_send_recv_batched() mirrors the open-coded sendmsg + one
 *     blocking recv + MSG_DONTWAIT-drain pattern in
 *     nft_install_bridge_ct() and nft_dormant_abort_sweep().  The
 *     first non-zero NLMSG_ERROR is captured but the drain keeps going
 *     so the kernel's reply queue empties before the next send — the
 *     per-file copies were structured the same way, just inline.
 *   - nfnl_send_recv_dump() tolerates EAGAIN on the drain as "no
 *     completion observed, return -EIO".  This matches the
 *     ctnetlink_flush() per-file behaviour (best-effort send, peek one
 *     reply, move on) on a kernel without CONFIG_NF_CONNTRACK, where
 *     the kernel simply drops the request on the floor and the recv
 *     would otherwise hang waiting for a reply that will not come.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "childops-netlink.h"
#include "childops-nfnl.h"
#include "compat.h"

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER		12
#endif
#ifndef NFNL_MSG_BATCH_BEGIN
#define NFNL_MSG_BATCH_BEGIN		16
#endif
#ifndef NFNL_MSG_BATCH_END
#define NFNL_MSG_BATCH_END		17
#endif

/*
 * Local copy of the nfgenmsg payload.  <linux/netfilter/nfnetlink.h>
 * defines struct nfgenmsg on most distros but a stripped sysroot may
 * not pull the header in; keeping a local copy keeps this file
 * self-contained and matches the per-file copies it replaces.  Layout
 * is stable in the kernel UAPI.
 */
struct nfnl_nfgenmsg_local {
	__u8	nfgen_family;
	__u8	version;
	__u16	res_id;		/* network byte order */
};

int nfnl_open(struct nfnl_ctx *ctx, const struct nfnl_open_opts *opts)
{
	struct nl_open_opts nl_opts;

	if (!ctx || !opts) {
		errno = EINVAL;
		return -1;
	}

	memset(&nl_opts, 0, sizeof(nl_opts));
	nl_opts.proto         = NETLINK_NETFILTER;
	nl_opts.groups        = opts->groups;
	nl_opts.recv_timeo_s  = opts->recv_timeo_s;

	memset(ctx, 0, sizeof(*ctx));
	return nl_open(&ctx->nl, &nl_opts);
}

void nfnl_close(struct nfnl_ctx *ctx)
{
	if (!ctx)
		return;
	nl_close(&ctx->nl);
}

size_t nfnl_msg_put(unsigned char *buf, size_t off, size_t cap,
		    __u32 seq, __u8 subsys, __u8 msg_type,
		    __u16 flags, __u8 family)
{
	struct nlmsghdr *nlh;
	struct nfnl_nfgenmsg_local *nfg;
	size_t env = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));

	if (off + env > cap)
		return 0;

	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = (__u16)(((__u16)subsys << 8) | msg_type);
	nlh->nlmsg_flags = (__u16)(flags | NLM_F_REQUEST | NLM_F_ACK);
	nlh->nlmsg_seq   = seq;
	nlh->nlmsg_pid   = 0;
	nlh->nlmsg_len   = 0;	/* caller patches after attribute walk */

	nfg = (struct nfnl_nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = family;
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons(0);

	return off + env;
}

static size_t nfnl_batch_marker(unsigned char *buf, size_t off, size_t cap,
				__u32 seq, __u16 marker_id, __u8 subsys)
{
	struct nlmsghdr *nlh;
	struct nfnl_nfgenmsg_local *nfg;
	size_t env = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*nfg));

	if (off + env > cap)
		return 0;

	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = marker_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_seq   = seq;
	nlh->nlmsg_pid   = 0;
	nlh->nlmsg_len   = (__u32)env;

	nfg = (struct nfnl_nfgenmsg_local *)NLMSG_DATA(nlh);
	nfg->nfgen_family = 0;	/* AF_UNSPEC */
	nfg->version      = NFNETLINK_V0;
	nfg->res_id       = htons((__u16)subsys);

	return off + env;
}

size_t nfnl_batch_begin(unsigned char *buf, size_t off, size_t cap,
			__u32 seq, __u8 subsys)
{
	return nfnl_batch_marker(buf, off, cap, seq,
				 NFNL_MSG_BATCH_BEGIN, subsys);
}

size_t nfnl_batch_end(unsigned char *buf, size_t off, size_t cap,
		      __u32 seq, __u8 subsys)
{
	return nfnl_batch_marker(buf, off, cap, seq,
				 NFNL_MSG_BATCH_END, subsys);
}

int nfnl_send_recv(struct nfnl_ctx *ctx, void *msg, size_t len)
{
	return nl_send_recv(&ctx->nl, msg, len);
}

/*
 * Shared sendmsg helper for the batched / dump paths.  Builds the
 * dst-kernel sockaddr_nl and the iovec/msghdr each call — these are
 * small stack structs and the dance is identical across all four
 * variants nl_send_recv / nfnl_send_recv_{,batched,dump}, but the
 * receive-side handling differs enough that pulling sendmsg out into
 * a helper keeps each receive loop readable.
 */
static int nfnl_send_only(struct nfnl_ctx *ctx, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(ctx->nl.fd, &mh, 0) < 0)
		return -EIO;
	return 0;
}

/*
 * Upper bound on the MSG_DONTWAIT drain loop in
 * nfnl_send_recv_batched().  A pathological misbehaving peer (or a
 * peer that just keeps producing replies) could otherwise keep the
 * loop running until the kernel's queue empties for unrelated reasons.
 * 64 iterations is far above the batch sizes any current childops
 * caller submits (the largest is the bridge-conntrack churn batch at
 * ~20 ops) and small enough that the worst-case wallclock cost stays
 * well under a millisecond. */
#define MAX_NFNL_DRAIN_ITERS 64

int nfnl_send_recv_batched(struct nfnl_ctx *ctx, void *msg, size_t len)
{
	unsigned char rbuf[2048];
	struct nlmsghdr *nlh;
	ssize_t n;
	int first_err = 0;
	int rc;
	unsigned int iters = 0;

	rc = nfnl_send_only(ctx, msg, len);
	if (rc != 0)
		return rc;

	/* Blocking recv to wait for the batch result; then non-blocking
	 * drain of every coalesced reply so the kernel's queue empties
	 * before the caller's next send.  Bounded at
	 * MAX_NFNL_DRAIN_ITERS so a misbehaving peer can't pin us in
	 * the drain. */
	n = recv(ctx->nl.fd, rbuf, sizeof(rbuf), 0);
	if (n < (ssize_t)NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		int err = ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;

		if (err != 0)
			first_err = err;
	}

	while (iters++ < MAX_NFNL_DRAIN_ITERS &&
	       (n = recv(ctx->nl.fd, rbuf, sizeof(rbuf), MSG_DONTWAIT)) > 0) {
		if (n < (ssize_t)NLMSG_HDRLEN)
			continue;
		nlh = (struct nlmsghdr *)rbuf;
		if (nlh->nlmsg_type != NLMSG_ERROR)
			continue;
		if (first_err == 0) {
			int err = ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;

			if (err != 0)
				first_err = err;
		}
	}

	return first_err;
}

int nfnl_send_recv_dump(struct nfnl_ctx *ctx, void *msg, size_t len)
{
	unsigned char rbuf[4096];
	struct nlmsghdr *nlh;
	ssize_t n;
	int rc;

	rc = nfnl_send_only(ctx, msg, len);
	if (rc != 0)
		return rc;

	n = recv(ctx->nl.fd, rbuf, sizeof(rbuf), 0);
	if (n < (ssize_t)NLMSG_HDRLEN)
		return -EIO;

	for (;;) {
		size_t left = (size_t)n;
		unsigned char *cur = rbuf;

		while (left >= NLMSG_HDRLEN) {
			nlh = (struct nlmsghdr *)cur;
			if (nlh->nlmsg_len < NLMSG_HDRLEN ||
			    (size_t)NLMSG_ALIGN(nlh->nlmsg_len) > left)
				return -EIO;

			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR)
				return ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;

			cur  += NLMSG_ALIGN(nlh->nlmsg_len);
			left -= NLMSG_ALIGN(nlh->nlmsg_len);
		}

		n = recv(ctx->nl.fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n <= 0)
			return -EIO;
	}
}
