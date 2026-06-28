/*
 * childops/genl-util.c — implementation for the shared genetlink
 * scaffolding declared in include/childops-genl.h.
 *
 * The open path opens a NETLINK_GENERIC socket via nl_open() and then
 * issues a single-family CTRL_CMD_GETFAMILY request
 *   nlmsg_type = GENL_ID_CTRL (0x10), cmd = CTRL_CMD_GETFAMILY (0x3)
 *   attrs: CTRL_ATTR_FAMILY_NAME = opts->family_name
 * The reply is either NLMSG_ERROR (-ENOENT for an unknown family, or
 * some other rejection) or a CTRL_NEWFAMILY message whose attribute
 * list carries CTRL_ATTR_FAMILY_ID — we extract the id and stash it
 * in ctx->family_id.
 *
 * The single shared dump-based resolver in net/netlink-genl-families.c
 * is intentionally separate: it walks every registered family in one
 * dump for the genetlink-fuzzer / per-family stats wire-up.  Doing
 * per-ctx resolution here keeps a childop's open path independent of
 * that shared dump and avoids implicit cross-childop state.
 *
 * Behavioural notes preserved from the per-file copies this file
 * replaces (devlink_genl_send_recv in childops/devlink-port-churn.c
 * and genl_send_recv in childops/nl80211-churn.c):
 *
 *   - sendmsg() blocking (no MSG_DONTWAIT).  Matches the underlying
 *     nl_send_recv() in childops/netlink-util.c; a netlink sendmsg
 *     almost never blocks but if it does we'd rather know than wedge.
 *   - SO_RCVTIMEO is the only thing keeping a wedged kernel off the
 *     SIGALRM(1s) child cap, so genl_open() applies a 1 s default
 *     when opts->recv_timeo_s == 0.
 *   - A non-NLMSG_ERROR reply is treated as ack 0 — genl GETs come
 *     back as NEW responses, not explicit acks.  Both per-file
 *     copies this replaces did the same thing.
 *   - EINPROGRESS retry is intentionally NOT folded in here.  The
 *     only existing caller that retries on it (nl80211-churn) keeps
 *     its retry loop local for now.
 */

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "childops-genl.h"
#include "childops-netlink.h"

#define GENL_OPEN_DEFAULT_TIMEO_S	1
#define GENL_OPEN_DEFAULT_VERSION	1

/*
 * Send CTRL_CMD_GETFAMILY for one family name and parse CTRL_ATTR_
 * FAMILY_ID out of the reply.  See file header for the wire shape.
 * Return convention matches genl_open(): 0 on success, -ENOENT for
 * an unknown family, other negated errno for any other rejection,
 * -EIO on local socket / framing failure.
 */
static int resolve_family_id(struct nl_ctx *nl, const char *name,
			     __u16 *out)
{
	unsigned char buf[256];
	/* CTRL_NEWFAMILY for the largest registered family (nl80211)
	 * lands well under 4 KiB; the modest families devlink-port-churn
	 * cares about are a fraction of that.  4 KiB is comfortable. */
	unsigned char rbuf[4096];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	size_t off;
	size_t name_len;
	size_t remaining;
	const unsigned char *p;
	ssize_t n;

	name_len = strlen(name) + 1U;
	if (NLMSG_HDRLEN + GENL_HDRLEN + NLA_HDRLEN + name_len > sizeof(buf))
		return -EIO;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = GENL_ID_CTRL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(nl);

	gnh = (struct genlmsghdr *)((unsigned char *)nlh + NLMSG_HDRLEN);
	gnh->cmd     = CTRL_CMD_GETFAMILY;
	gnh->version = 1;

	off = nla_put(buf, NLMSG_HDRLEN + GENL_HDRLEN, sizeof(buf),
		      CTRL_ATTR_FAMILY_NAME, name, name_len);
	if (!off)
		return -EIO;
	nlh->nlmsg_len = (__u32)off;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = buf;
	iov.iov_len  = off;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(nl->fd, &mh, 0) < 0)
		return -EIO;

	n = recv(nl->fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		return err->error;
	}

	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return -EIO;
	if ((size_t)n < nlh->nlmsg_len)
		return -EIO;

	p = (const unsigned char *)nlh + NLMSG_HDRLEN + GENL_HDRLEN;
	remaining = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
	while (remaining >= NLA_HDRLEN) {
		const struct nlattr *nla = (const struct nlattr *)p;
		size_t alen;

		if (nla->nla_len < NLA_HDRLEN || nla->nla_len > remaining)
			break;
		alen = NLA_ALIGN(nla->nla_len);

		if ((nla->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID &&
		    nla->nla_len >= NLA_HDRLEN + sizeof(__u16)) {
			__u16 id;

			memcpy(&id, p + NLA_HDRLEN, sizeof(id));
			*out = id;
			return 0;
		}
		if (alen > remaining)
			break;
		p += alen;
		remaining -= alen;
	}
	return -EIO;
}

int genl_open(struct genl_ctx *ctx, const struct genl_open_opts *opts)
{
	struct nl_open_opts nlopts;
	__u16 family_id = 0;
	int rc;

	if (!ctx || !opts || !opts->family_name) {
		errno = EINVAL;
		return -EIO;
	}

	memset(ctx, 0, sizeof(*ctx));

	memset(&nlopts, 0, sizeof(nlopts));
	nlopts.proto        = NETLINK_GENERIC;
	nlopts.groups       = opts->groups;
	nlopts.recv_timeo_s = opts->recv_timeo_s > 0 ? opts->recv_timeo_s
						     : GENL_OPEN_DEFAULT_TIMEO_S;
	if (nl_open(&ctx->nl, &nlopts) < 0)
		return -EIO;

	rc = resolve_family_id(&ctx->nl, opts->family_name, &family_id);
	if (rc != 0) {
		nl_close(&ctx->nl);
		memset(ctx, 0, sizeof(*ctx));
		return rc;
	}

	ctx->family_id = family_id;
	ctx->version   = opts->version != 0 ? opts->version
					    : GENL_OPEN_DEFAULT_VERSION;
	return 0;
}

void genl_close(struct genl_ctx *ctx)
{
	if (!ctx)
		return;
	nl_close(&ctx->nl);
	ctx->family_id = 0;
	ctx->version   = 0;
}

size_t genl_msg_put(unsigned char *buf, size_t off, size_t cap,
		    struct genl_ctx *ctx, __u32 seq,
		    __u8 cmd, __u16 flags)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;

	if (!buf || !ctx)
		return 0;
	if (off + NLMSG_HDRLEN + GENL_HDRLEN > cap)
		return 0;

	memset(buf + off, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	nlh = (struct nlmsghdr *)(buf + off);
	nlh->nlmsg_type  = ctx->family_id;
	nlh->nlmsg_flags = flags | NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = seq;

	gnh = (struct genlmsghdr *)((unsigned char *)nlh + NLMSG_HDRLEN);
	gnh->cmd     = cmd;
	gnh->version = ctx->version;

	return off + NLMSG_HDRLEN + GENL_HDRLEN;
}

int genl_send_recv(struct genl_ctx *ctx, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[2048];
	struct nlmsghdr *nlh;
	ssize_t n;

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

	n = recv(ctx->nl.fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		return err->error;
	}
	return 0;
}
