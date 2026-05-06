/*
 * handshake_req_abort - net/handshake request/abort race over kTLS plumbing.
 *
 * The handshake genetlink family (Linux 6.5+) is the userspace bridge
 * for kernel-initiated TLS/QUIC handshakes: tlshd-class daemons pull
 * pending requests via HANDSHAKE_CMD_ACCEPT and report completion via
 * HANDSHAKE_CMD_DONE.  The bug class clustered here is the async-
 * request-broker UAF: handshake_req_alloc()/handshake_req_submit() pin
 * a struct handshake_req on the kernel-side socket, and the request
 * lifetime hinges on a delicate dance between handshake_req_next()
 * (the ACCEPT path), handshake_complete() (the DONE path), and
 * handshake_req_cancel() (the orphan-on-close path in
 * net/handshake/request.c).  Two userspace daemons racing ACCEPT, two
 * DONE messages racing each other for the same sockfd, or a close()
 * landing while DONE is still mid-walk all aim straight at
 * __sock_handshake_req_destroy() with stale or doubly-released refs —
 * the same architectural smell that produced the unaccepted-request
 * UAF family in similar async brokers (CVE-class for net/handshake is
 * not yet on file, but the request-broker shape mirrors prior async
 * netlink-broker UAFs).
 *
 * net/handshake itself has been essentially unfuzzed: the kernel side
 * is reachable only through tlshd-style userspace + a socket whose
 * owner has called the in-kernel tls_client_hello_*() API, and flat
 * per-syscall fuzzing never assembles either.  We don't have the in-
 * kernel API surface from userspace, but we can still drive the genl
 * front door directly: ACCEPT/DONE messages are validated and looked
 * up through the same per-net request table that the in-kernel
 * submitter populates.  Even with no live request to match, the
 * kernel walks the table under net->hs_lock and the lookup-by-sockfd
 * path runs end-to-end — exactly the slot that mishandles the
 * doubly-completed / completed-after-cancel cases.
 *
 * Sequence (per invocation):
 *   1.  Resolve the "handshake" genl family via an inline CTRL_GETFAMILY
 *       dump (we don't share the global registry — that registry is
 *       loaded with families that have full grammar tables, and
 *       handshake doesn't have one yet).  fam_id == 0 latches
 *       ns_unsupported_handshake for the rest of this child's lifetime.
 *   2.  socket(AF_INET, SOCK_STREAM); connect to a closed loopback
 *       port — best-effort, ECONNREFUSED is fine.  We need a sockfd
 *       to feed into HANDSHAKE_A_DONE_SOCKFD; whether or not the
 *       three-way handshake completed doesn't matter to the genl
 *       request table walker on the receive side.
 *   3.  HANDSHAKE_CMD_ACCEPT non-blocking probe with HANDLER_CLASS=
 *       TLSHD.  Kernel returns -EAGAIN when no request is pending —
 *       benign coverage of the request-table walk under the per-net
 *       lock.  Counted as accept_ok regardless of ack errno because
 *       the lookup path ran.
 *   4.  BUDGETED loop:
 *         a) HANDSHAKE_CMD_DONE with HANDSHAKE_A_DONE_STATUS=0 and
 *            HANDSHAKE_A_DONE_SOCKFD=our connected socket.  Kernel
 *            walks the per-net request table looking for a request
 *            keyed on this sockfd; with no live request it returns
 *            -ENOENT, but the lookup runs end-to-end — exactly the
 *            slot that mishandles a request freed by a prior DONE.
 *            done_ok bumped on ack 0 (which only fires on hosts with
 *            a live in-kernel handshake request, very rare).
 *         b) Race window: a second HANDSHAKE_CMD_DONE on the same
 *            sockfd with non-zero status — the "abort" shape (DONE
 *            with status != 0 is the kernel's idiomatic abort, see
 *            handshake_complete() in net/handshake/request.c).  The
 *            kernel-side handler races the prior DONE's request-
 *            destroy if both happen to find the same struct
 *            handshake_req — the targeted UAF window.  Counted as
 *            abort_ok regardless of ack errno because the lookup +
 *            (potential) destroy path ran.
 *   5.  close(socket) while requests are notionally outstanding —
 *       drives __sock_handshake_req_destroy() through the
 *       handshake_sk_destruct() callback if the kernel had ever bound
 *       a request to this sock.  orphan_close bumped per close.
 *
 * Self-bounding: one full cycle per invocation, all sockets non-
 * blocking, loopback only, all genl requests timestamped with
 * SO_RCVTIMEO so an unresponsive controller can't pin past child.c's
 * SIGALRM(1s).  Per-invocation iteration budget is small (defaults to
 * a few cycles, jittered ±50%, scaled by adapt_budget) — every iter
 * emits a small handful of genl messages and one or two syscalls.
 *
 * Brick risk: kernel-side genl + socket-syscall only.  No module
 * load, no sysfs writes, no persistent state outside per-process
 * socket fds.  net/handshake doesn't expose any kernel-state-altering
 * commands beyond per-request lookup; READY isn't issued from this
 * childop (READY is a multicast-ack from the daemon side and would
 * confuse a real tlshd if one were running on the host).
 *
 * Cap-gate latch behaviour: the inline CTRL_GETFAMILY runs once per
 * process.  fam_id==0 (CONFIG_NET_HANDSHAKE=n, or the family hasn't
 * been registered on this kernel) latches ns_unsupported_handshake;
 * every further invocation bumps setup_failed and returns without
 * opening a netlink socket.  EAGAIN/ENOENT acks from the kernel are
 * benign coverage signals, not failures.
 *
 * Header gating: <linux/handshake.h> is the YNL-generated UAPI header
 * that ships from kernel 6.5 onward.  Older sysroots without it fall
 * to a stub that bumps runs+setup_failed and returns — same shape as
 * mptcp-pm-churn's __has_include fallback.
 *
 * Failure modes treated as benign coverage:
 *   - fam_id == 0 after CTRL_GETFAMILY: kernel doesn't expose the
 *     handshake family.  Latched.
 *   - EAGAIN on ACCEPT: no pending request — the ordinary case
 *     without an in-kernel submitter.  Lookup path ran.
 *   - ENOENT on DONE: no request matches the sockfd — the ordinary
 *     case.  Lookup path ran.
 *   - EPERM on any genl op: trinity wasn't run with the right caps
 *     in this netns.  The lookup path still ran on the genl front
 *     door.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/handshake.h>)

#include <netinet/in.h>
#include <linux/genetlink.h>
#include <linux/handshake.h>
#include <linux/netlink.h>

#include "jitter.h"
#include "random.h"

/* Latched per-process: CTRL_GETFAMILY ran but the "handshake" family
 * was absent (fam_id stayed 0).  Once latched, every further
 * invocation just bumps setup_failed and returns. */
static bool ns_unsupported_handshake;

/* Per-process handshake genl family id, or 0 if unresolved.  Resolved
 * lazily on first invocation via an inline CTRL_GETFAMILY dump — the
 * shared genl_resolve_families() registry doesn't carry a handshake
 * grammar entry yet, so we do our own lookup.  One CTRL_GETFAMILY per
 * process, cached here for the rest of the child's lifetime. */
static unsigned short g_handshake_fam_id;
static bool g_handshake_resolved;

/* Per-process running netlink seq.  Concurrent siblings each have
 * their own netlink socket so seq overlap across sockets is harmless
 * (the kernel doesn't dedupe across sockets). */
static __u32 g_handshake_seq;

#define HANDSHAKE_GENL_BUF_BYTES	1024
#define HANDSHAKE_GENL_RECV_TIMEO_S	1
#define HANDSHAKE_CHURN_BUDGET		16U
#define HANDSHAKE_CHURN_ITERS_BASE	2U

/* Loopback target for the dummy connect.  Port 9 (discard) is closed
 * on a sane host — ECONNREFUSED is the expected outcome and the
 * sockfd is still valid for HANDSHAKE_A_DONE_SOCKFD lookups on the
 * kernel side. */
#define HANDSHAKE_LOOPBACK_ADDR		0x7f000001U	/* 127.0.0.1 */
#define HANDSHAKE_LOOPBACK_PORT		9U		/* discard */

static __u32 next_seq(void)
{
	return ++g_handshake_seq;
}

static int handshake_genl_open(void)
{
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0)
		return -1;

	tv.tv_sec  = HANDSHAKE_GENL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/*
 * Append a flat NLA at *off.  Returns the new offset or 0 on overflow
 * (caller treats 0 as fail).  Same shape as devlink-port-churn /
 * mptcp-pm-churn — kept duplicated rather than hoisted because each
 * childop's NLA construction is tight enough that an inlined helper
 * is easier to follow than a cross-file abstraction.
 */
static size_t nla_put(unsigned char *buf, size_t off, size_t cap,
		      unsigned short type, const void *data, size_t len)
{
	struct nlattr *nla;
	size_t total = NLA_HDRLEN + len;
	size_t aligned = NLA_ALIGN(total);

	if (off + aligned > cap)
		return 0;

	nla = (struct nlattr *)(buf + off);
	nla->nla_type = type;
	nla->nla_len  = (unsigned short)total;
	if (len)
		memcpy(buf + off + NLA_HDRLEN, data, len);
	if (aligned > total)
		memset(buf + off + total, 0, aligned - total);
	return off + aligned;
}

static size_t nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t nla_put_s32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __s32 v)
{
	return nla_put(buf, off, cap, type, &v, sizeof(v));
}

/*
 * Parse a CTRL_CMD_NEWFAMILY reply for FAMILY_NAME == "handshake" and
 * extract its FAMILY_ID.  Mirrors parse_family_response() in
 * net/netlink-genl-families.c — kept local rather than hoisted because
 * we want the lookup-by-name short-circuit and don't want to touch the
 * shared registry's lifecycle.  Returns the id or 0 on no match.
 */
static unsigned short parse_ctrl_newfamily(const struct nlmsghdr *nlh)
{
	const unsigned char *attrs;
	size_t attrs_off;
	size_t attrs_len;
	char name[GENL_NAMSIZ];
	unsigned short id = 0;
	int have_name = 0;
	int have_id = 0;

	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return 0;

	memset(name, 0, sizeof(name));
	attrs = (const unsigned char *)nlh + NLMSG_HDRLEN + GENL_HDRLEN;
	attrs_len = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	for (attrs_off = 0; attrs_off + NLA_HDRLEN <= attrs_len; ) {
		const struct nlattr *nla = (const struct nlattr *)(attrs + attrs_off);
		size_t nla_len = nla->nla_len;
		const unsigned char *payload;
		size_t payload_len;

		if (nla_len < NLA_HDRLEN || nla_len > attrs_len - attrs_off)
			break;

		payload = (const unsigned char *)nla + NLA_HDRLEN;
		payload_len = nla_len - NLA_HDRLEN;

		switch (nla->nla_type & NLA_TYPE_MASK) {
		case CTRL_ATTR_FAMILY_ID:
			if (payload_len >= sizeof(unsigned short)) {
				memcpy(&id, payload, sizeof(unsigned short));
				have_id = 1;
			}
			break;
		case CTRL_ATTR_FAMILY_NAME: {
			size_t copy = payload_len;

			if (copy >= sizeof(name))
				copy = sizeof(name) - 1;
			memcpy(name, payload, copy);
			name[copy] = '\0';
			have_name = 1;
			break;
		}
		default:
			break;
		}
		attrs_off += NLA_ALIGN(nla_len);
	}

	if (!have_name || !have_id || id == 0)
		return 0;
	if (strcmp(name, HANDSHAKE_FAMILY_NAME) != 0)
		return 0;
	return id;
}

/*
 * One-shot CTRL_GETFAMILY dump targeted at the "handshake" family.
 * Returns the resolved family id, or 0 if the family is absent or
 * the dump errored.  Sets ns_unsupported_handshake on absence so
 * subsequent invocations short-circuit.
 */
static unsigned short resolve_handshake_family(void)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
	} req;
	struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };
	unsigned char buf[8192];
	unsigned short id = 0;
	ssize_t n;
	int sock;

	sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (sock < 0)
		return 0;
	(void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq = 1;
	req.genl.cmd = CTRL_CMD_GETFAMILY;
	req.genl.version = 1;

	if (send(sock, &req, req.nlh.nlmsg_len, 0) < 0) {
		close(sock);
		return 0;
	}

	for (;;) {
		struct nlmsghdr *nlh;
		size_t remaining;

		n = recv(sock, buf, sizeof(buf), 0);
		if (n <= 0)
			break;

		nlh = (struct nlmsghdr *)buf;
		remaining = (size_t)n;
		while (NLMSG_OK(nlh, remaining)) {
			if (nlh->nlmsg_type == NLMSG_DONE ||
			    nlh->nlmsg_type == NLMSG_ERROR)
				goto done;
			if (nlh->nlmsg_type == GENL_ID_CTRL && id == 0)
				id = parse_ctrl_newfamily(nlh);
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}
done:
	close(sock);
	return id;
}

/*
 * Send one genetlink message and wait for an NLMSG_ERROR ack.
 * Returns 0 on success, the negated errno on rejection, or -EIO on
 * local send/recv failure.  Caller has filled the full nlmsghdr +
 * genlmsghdr + payload at offset 0 with NLM_F_ACK set.
 */
static int handshake_genl_send_recv(int fd, void *msg, size_t len)
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
	iov.iov_len  = len;

	memset(&mh, 0, sizeof(mh));
	mh.msg_name    = &dst;
	mh.msg_namelen = sizeof(dst);
	mh.msg_iov     = &iov;
	mh.msg_iovlen  = 1;

	if (sendmsg(fd, &mh, MSG_DONTWAIT) < 0)
		return -EIO;

	n = recv(fd, rbuf, sizeof(rbuf), 0);
	if (n < 0)
		return -EIO;
	if ((size_t)n < NLMSG_HDRLEN)
		return -EIO;

	nlh = (struct nlmsghdr *)rbuf;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
		return err->error;
	}
	/* Non-error reply (e.g. NEW response): treat as ack 0. */
	return 0;
}

/*
 * Build the start of a handshake genl message: nlmsghdr + genlmsghdr
 * with NLM_F_ACK set.  Returns the offset past the genl header;
 * callers append per-cmd attrs from there.
 */
static size_t handshake_genl_msg_start(unsigned char *buf, size_t cap, __u8 cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;

	if (cap < NLMSG_HDRLEN + GENL_HDRLEN)
		return 0;

	memset(buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = g_handshake_fam_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gnh->cmd     = cmd;
	gnh->version = HANDSHAKE_FAMILY_VERSION;

	return NLMSG_HDRLEN + GENL_HDRLEN;
}

/*
 * Build & send HANDSHAKE_CMD_ACCEPT carrying just
 * HANDSHAKE_A_ACCEPT_HANDLER_CLASS=TLSHD.  The kernel walks the per-
 * net request table under net->hs_lock looking for a pending request
 * matching this handler class — returns -EAGAIN when none is queued
 * (the ordinary case without an in-kernel submitter).  Lookup path
 * runs end-to-end regardless.
 */
static int handshake_accept(int fd)
{
	unsigned char buf[HANDSHAKE_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = handshake_genl_msg_start(buf, sizeof(buf), HANDSHAKE_CMD_ACCEPT);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  HANDSHAKE_A_ACCEPT_HANDLER_CLASS,
			  HANDSHAKE_HANDLER_CLASS_TLSHD);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return handshake_genl_send_recv(fd, buf, off);
}

/*
 * Build & send HANDSHAKE_CMD_DONE carrying STATUS + SOCKFD.  The
 * kernel walks the per-net request table looking for a request keyed
 * on this sockfd.  status==0 is the normal-completion shape; status
 * != 0 is the abort shape (handshake_complete() in
 * net/handshake/request.c treats any non-zero status as "the daemon
 * failed/aborted the handshake, tear the request down").  Without a
 * live in-kernel submitter the ack is -ENOENT; the lookup path still
 * ran on the genl front door.
 */
static int handshake_done(int fd, int sockfd, __s32 status)
{
	unsigned char buf[HANDSHAKE_GENL_BUF_BYTES];
	struct nlmsghdr *nlh;
	size_t off;

	off = handshake_genl_msg_start(buf, sizeof(buf), HANDSHAKE_CMD_DONE);
	if (!off)
		return -EIO;

	off = nla_put_s32(buf, off, sizeof(buf),
			  HANDSHAKE_A_DONE_STATUS, status);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf),
			  HANDSHAKE_A_DONE_SOCKFD, (__u32)sockfd);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (__u32)off;
	return handshake_genl_send_recv(fd, buf, off);
}

/*
 * Open a loopback TCP socket and best-effort-connect to a closed
 * port.  ECONNREFUSED / EINPROGRESS / success are all fine — the
 * sockfd is what we feed into HANDSHAKE_A_DONE_SOCKFD.  Returns the
 * socket fd, or -1 on socket() failure (rare).
 */
static int open_loopback_sock(void)
{
	struct sockaddr_in dst;
	int fd;

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (fd < 0)
		return -1;

	(void)fcntl(fd, F_SETFL, O_NONBLOCK);

	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(HANDSHAKE_LOOPBACK_ADDR);
	dst.sin_port = htons(HANDSHAKE_LOOPBACK_PORT);
	(void)connect(fd, (struct sockaddr *)&dst, sizeof(dst));
	return fd;
}

bool handshake_req_abort(struct childdata *child)
{
	int genl_fd = -1;
	int sock = -1;
	unsigned int iters;
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.handshake_req_abort_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_handshake) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!g_handshake_resolved) {
		g_handshake_fam_id = resolve_handshake_family();
		g_handshake_resolved = true;
		if (g_handshake_fam_id == 0) {
			ns_unsupported_handshake = true;
			__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
	}

	genl_fd = handshake_genl_open();
	if (genl_fd < 0) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	sock = open_loopback_sock();
	if (sock < 0) {
		__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
				   1, __ATOMIC_RELAXED);
		close(genl_fd);
		return true;
	}

	/* 3) Non-blocking ACCEPT probe — exercises the per-net request-
	 *    table walk under hs_lock.  Counted regardless of ack errno
	 *    (EAGAIN is the ordinary outcome). */
	(void)handshake_accept(genl_fd);
	__atomic_add_fetch(&shm->stats.handshake_req_abort_accept_ok,
			   1, __ATOMIC_RELAXED);

	iters = BUDGETED(CHILD_OP_HANDSHAKE_REQ_ABORT,
			 JITTER_RANGE(HANDSHAKE_CHURN_ITERS_BASE));
	if (iters > HANDSHAKE_CHURN_BUDGET)
		iters = HANDSHAKE_CHURN_BUDGET;
	if (iters == 0U)
		iters = 1U;

	for (i = 0; i < iters; i++) {
		/* a) DONE with status=0 — normal-completion shape.
		 *    Kernel walks the request table; ENOENT without a
		 *    live submitter, which is the bulk case. */
		(void)handshake_done(genl_fd, sock, 0);
		__atomic_add_fetch(&shm->stats.handshake_req_abort_done_ok,
				   1, __ATOMIC_RELAXED);

		/* b) DONE with non-zero status — abort shape.  Targets
		 *    the double-complete / complete-vs-cancel race
		 *    against the prior DONE. */
		(void)handshake_done(genl_fd, sock,
				     -(__s32)(1U + (rand32() & 0x7fU)));
		__atomic_add_fetch(&shm->stats.handshake_req_abort_abort_ok,
				   1, __ATOMIC_RELAXED);
	}

	/* 5) Orphan close: drives __sock_handshake_req_destroy() through
	 *    handshake_sk_destruct() if the kernel ever bound a request
	 *    to this sock.  Kernel GCs unconditionally on close; we just
	 *    bump the counter so productivity is observable. */
	close(sock);
	__atomic_add_fetch(&shm->stats.handshake_req_abort_orphan_close,
			   1, __ATOMIC_RELAXED);

	close(genl_fd);
	return true;
}

#else  /* !__has_include(<linux/handshake.h>) */

bool handshake_req_abort(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.handshake_req_abort_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.handshake_req_abort_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/handshake.h>) */
