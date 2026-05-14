/*
 * childops/netlink-util.c — implementation for the shared scaffolding
 * declared in include/childops-netlink.h.
 *
 * Behavioural choices preserved from the per-file copies this file
 * replaces:
 *
 *   - SOCK_RAW | SOCK_CLOEXEC, AF_NETLINK, NETLINK_<proto> from opts.
 *   - Bind to {nl_family=AF_NETLINK, nl_pid=0, nl_groups=opts->groups},
 *     letting the kernel auto-assign the port id.  Multicast subscribe
 *     happens atomically with the bind when groups != 0.
 *   - SO_RCVTIMEO is best-effort: setsockopt failure does not fail the
 *     open, matching every per-file rtnl_open() in childops/.
 *   - nl_send_recv() returns 0 only for an explicit positive ack
 *     (NLMSG_ERROR, err->error == 0).  Any other reply (RTM_*,
 *     truncation, short recv, sendmsg/recv failure) returns -EIO.
 *     Dump-style callers want a different helper.
 *   - nl_send_recv_retry() retries on -EAGAIN / -EBUSY only.  -EINPROGRESS
 *     is intentionally NOT retried here: the only existing caller that
 *     retries on it (nl80211-churn.c) builds its own genl envelope and
 *     will get its own helper later.  Adding -EINPROGRESS here would
 *     change the behaviour of every current ROUTE-plane retry caller.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <linux/netlink.h>

#include "childops-netlink.h"

/*
 * Bounded retry budget for nl_send_recv_retry().  Matches the per-file
 * TC_RETRY_MAX / MPLS_RC_RETRY_MAX values in tc-qdisc-churn.c and
 * mpls-route-churn.c.  Eight rounds of EAGAIN/EBUSY is enough to ride
 * out a sibling teardown without blowing the SIGALRM(1s) child cap.
 */
#define NL_RETRY_MAX	8

int nl_open(struct nl_ctx *ctx, const struct nl_open_opts *opts)
{
	struct sockaddr_nl sa;
	int fd;

	if (!ctx || !opts) {
		errno = EINVAL;
		return -1;
	}

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, opts->proto);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = opts->groups;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int saved = errno;

		close(fd);
		errno = saved;
		return -1;
	}

	if (opts->recv_timeo_s > 0) {
		struct timeval tv;

		tv.tv_sec = opts->recv_timeo_s;
		tv.tv_usec = 0;
		(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = fd;
	ctx->proto = opts->proto;
	ctx->groups = opts->groups;
	ctx->recv_timeo_s = opts->recv_timeo_s;
	return 0;
}

void nl_close(struct nl_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->fd >= 0)
		close(ctx->fd);
	memset(ctx, 0, sizeof(*ctx));
	ctx->fd = -1;
}

int nl_send_recv(struct nl_ctx *ctx, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	memset(&dst, 0, sizeof(dst));
	dst.nl_family = AF_NETLINK;

	iov.iov_base = msg;
	iov.iov_len = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov = &iov;
	mh.msg_iovlen = 1;

	if (sendmsg(ctx->fd, &mh, 0) < 0)
		return -EIO;

	n = recv(ctx->fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);

		return err->error;
	}
	return -EIO;
}

int nl_send_recv_retry(struct nl_ctx *ctx, void *msg, size_t len)
{
	int rc = -EIO;
	int i;

	for (i = 0; i < NL_RETRY_MAX; i++) {
		rc = nl_send_recv(ctx, msg, len);
		if (rc != -EAGAIN && rc != -EBUSY)
			return rc;
	}
	return rc;
}

long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}
