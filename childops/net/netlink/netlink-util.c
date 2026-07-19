/*
 * childops/net/netlink/netlink-util.c — implementation for the shared scaffolding
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
 *   - nl_send_recv_any() shares the envelope and the NLMSG_ERROR
 *     decode with nl_send_recv() but accepts any non-NLMSG_ERROR
 *     reply as success.  Used by callers (altname-thrash) where the
 *     dump head is the expected reply shape.
 *   - nl_send_recv_dump() drains an NLM_F_MULTI reply stream until
 *     NLMSG_DONE or NLMSG_ERROR; intermediate replies are skipped.
 *     The recv buffer is 8 KiB so a single page of dump replies fits
 *     in one syscall.
 *   - The shared sendmsg helper nl_sendmsg() keeps the wire envelope
 *     in one place across the variants.
 *   - nl_send_recv_retry() retries on -EAGAIN / -EBUSY only.
 *     -EINPROGRESS is intentionally NOT retried here: the only
 *     caller that needs it (nl80211-churn) wraps genl_send_recv
 *     in its own genl_send_recv_retry (see
 *     childops/net/netlink/nl80211-churn.c:NL80211_RETRY_MAX).  Adding
 *     -EINPROGRESS here would change the behaviour of every
 *     current ROUTE-plane retry caller.
 */

#include <errno.h>
#include <net/if.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "childops-netlink.h"
#include "shm.h"

#include "kernel/socket.h"
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

	/*
	 * Stamp the safe-closed sentinel before the first failing op.
	 * A bare { 0 } caller leaves fd == 0; if socket() fails below
	 * the caller's subsequent nl_close() would otherwise close
	 * stdin (fd 0).  nl_close() treats fd < 0 as a no-op.
	 */
	ctx->fd = -1;

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
	} else if (opts->recv_timeo_us > 0) {
		struct timeval tv;

		tv.tv_sec = 0;
		tv.tv_usec = opts->recv_timeo_us;
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

/*
 * Send msg/len to the kernel on ctx->fd.  Returns 0 on success,
 * -EIO on sendmsg failure.  Shared by nl_send_recv() and the
 * any/dump variants so the wire envelope stays in one place.
 */
static int nl_sendmsg(struct nl_ctx *ctx, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;

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
	return 0;
}

int nl_send_recv(struct nl_ctx *ctx, void *msg, size_t len)
{
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	if (nl_sendmsg(ctx, msg, len) < 0)
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

int nl_send_recv_any(struct nl_ctx *ctx, void *msg, size_t len)
{
	unsigned char rbuf[1024];
	struct nlmsghdr *nlh;
	ssize_t n;

	if (nl_sendmsg(ctx, msg, len) < 0)
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
	return 0;
}

int nl_send_recv_dump(struct nl_ctx *ctx, void *msg, size_t len)
{
	unsigned char rbuf[8192];
	ssize_t n;

	if (nl_sendmsg(ctx, msg, len) < 0)
		return -EIO;

	for (;;) {
		struct nlmsghdr *nlh;
		size_t remaining;

		n = recv(ctx->fd, rbuf, sizeof(rbuf), 0);
		if (n <= 0)
			return -EIO;
		if ((size_t)n < NLMSG_HDRLEN)
			return -EIO;

		nlh = (struct nlmsghdr *)rbuf;
		remaining = (size_t)n;
		while (NLMSG_OK(nlh, remaining)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr *)NLMSG_DATA(nlh);

				return err->error;
			}
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}
}

int nl_send_recv_dump_cb(struct nl_ctx *ctx, void *msg, size_t len,
			 int (*cb)(const struct nlmsghdr *nlh, void *arg),
			 void *arg)
{
	unsigned char rbuf[8192];
	ssize_t n;

	if (!cb)
		return -EIO;

	if (nl_sendmsg(ctx, msg, len) < 0)
		return -EIO;

	for (;;) {
		struct nlmsghdr *nlh;
		size_t remaining;

		n = recv(ctx->fd, rbuf, sizeof(rbuf), 0);
		if (n <= 0)
			return -EIO;
		if ((size_t)n < NLMSG_HDRLEN)
			return -EIO;

		nlh = (struct nlmsghdr *)rbuf;
		remaining = (size_t)n;
		while (NLMSG_OK(nlh, remaining)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr *)NLMSG_DATA(nlh);

				return err->error;
			}
			if (cb(nlh, arg) != 0)
				return -EIO;
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}
}

int nl_send_drain_errors(struct nl_ctx *ctx, void *msg, size_t len,
			 __u32 expect_seq,
			 void (*on_err)(int err, void *arg),
			 void *arg)
{
	unsigned char rbuf[8192];
	ssize_t n;

	if (nl_sendmsg(ctx, msg, len) < 0)
		return -EIO;

	for (;;) {
		struct nlmsghdr *nlh;
		size_t remaining;

		n = recv(ctx->fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
		if (n < 0) {
			/*
			 * EAGAIN == EWOULDBLOCK on Linux; -Wlogical-op
			 * flags the redundant OR.  Check once.
			 */
			if (errno == EAGAIN)
				return 0;
			return -EIO;
		}
		if ((size_t)n < NLMSG_HDRLEN)
			return 0;

		nlh = (struct nlmsghdr *)rbuf;
		remaining = (size_t)n;
		while (NLMSG_OK(nlh, remaining)) {
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr *)NLMSG_DATA(nlh);

				/*
				 * Stale acks from an earlier request (a
				 * prior family or even a prior childop)
				 * may still be queued on this socket.
				 * Attributing them to the current send
				 * misroutes -EPERM/-EACCES decisions
				 * (e.g. latching needs_priv on the wrong
				 * family).  Only fire on_err for an ack
				 * that matches the seq we just sent;
				 * count and drop the rest so the queue
				 * still drains.
				 */
				if (nlh->nlmsg_seq == expect_seq) {
					if (on_err)
						on_err(err->error, arg);
				} else {
					__atomic_add_fetch(&shm->stats.genetlink_fuzzer.stale_seq_drops,
							   1, __ATOMIC_RELAXED);
				}
			}
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}
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

int rtnl_dellink(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

int rtnl_setlink_up(struct nl_ctx *ctx, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

void rtnl_bring_lo_up(struct nl_ctx *ctx)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	int lo_idx = (int)if_nametoindex("lo");

	if (lo_idx <= 0)
		return;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));
	(void)nl_send_recv(ctx, buf, nlh->nlmsg_len);
}
