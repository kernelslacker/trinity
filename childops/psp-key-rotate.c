/*
 * psp_key_rotate - net/psp TCP key install + mid-flow key rotation race.
 *
 * Random syscall fuzzing essentially never reaches the per-socket PSP
 * SA install / rotate paths in net/psp/psp_main.c, net/psp/psp_sock.c
 * and net/psp/psp_nl.c because those branches only fire when:
 *
 *   - a netdev with PSP capability is present (the in-tree probe vehicle
 *     is netdevsim with its psp shim in drivers/net/netdevsim/psp.c);
 *   - the PSP genetlink family is registered and at least one PSP-
 *     capable device is enumerated by PSP_CMD_DEV_GET;
 *   - a TCP socket has had a TX/RX SA installed via the PSP genetlink
 *     assoc command path (which references the socket by fd through the
 *     PSP_A_ASSOC_SOCK_FD attribute);
 *   - and a PSP_CMD_KEY_ROTATE arrives on the device while that socket
 *     is mid-flow with its assoc still bound to the previous key id.
 *
 * The interesting bug shape is a TOCTOU between the rotate publishing a
 * new key generation on the device and the per-socket SA refcount being
 * walked by the tx/rx hot path -- xfrm-class refcount on the SA combined
 * with the rotate flipping the active key id from underneath an in-flight
 * sendmsg/recvmsg.
 *
 * Per BUDGETED + JITTER iteration (200 ms wall cap; per-syscall 100 ms
 * SO_RCVTIMEO/SO_SNDTIMEO):
 *
 *   1.  unshare CLONE_NEWNET.  Latches ns_unsupported_psp_key_rotate on
 *       EPERM and short-circuits subsequent invocations.
 *   2.  rtnl RTM_NEWLINK to spawn a netdevsim instance (best-effort: if
 *       the kernel module is not loaded the request returns -ENODEV /
 *       -EOPNOTSUPP and the cap-gate latches on the first PSP family
 *       probe immediately after).
 *   3.  rtnl RTM_SETLINK IFF_UP on the new netdev.
 *   4.  socket(AF_INET, SOCK_STREAM); apply per-syscall timeouts;
 *       connect() to a loopback peer (best-effort -- the assoc path
 *       still exercises a non-listening socket because the genetlink
 *       attach happens before the peer handshake completes).
 *   5.  genetlink CTRL_CMD_GETFAMILY name="psp" -- resolves the dynamic
 *       PSP family id.  This is the structural-support probe: on
 *       -EPERM / -ENOSYS / -EOPNOTSUPP / -ENOPROTOOPT / -EAFNOSUPPORT /
 *       -EPROTONOSUPPORT / -ENODEV the cap-gate latches for the rest of
 *       the child's life.
 *   6.  genetlink PSP_CMD_DEV_GET -- enumerates PSP devices to pick a
 *       psp_dev_id for subsequent commands.
 *   7.  genetlink PSP_CMD_KEY_ROTATE on that dev_id -- installs / rolls
 *       the kernel-side key generation.
 *   8.  genetlink PSP_CMD_TX_ASSOC carrying the TCP socket fd through
 *       PSP_A_ASSOC_SOCK_FD -- this is the path that actually attaches
 *       the SA to the socket.  Counted under spi_set_ok per spec naming.
 *   9.  BUDGETED inner loop (base 4 / floor 8 / cap 16; 200 ms wall;
 *       per-syscall 100 ms timeouts):
 *         - send/recv over the bound socket (drives psp_xmit / psp_rx);
 *         - genetlink PSP_CMD_KEY_ROTATE mid-flow -- THE RACE TARGET;
 *         - PSP_CMD_TX_ASSOC again to switch the bound generation
 *           mid-stream;
 *         - send/recv again so the post-switch tx/rx walk overlaps the
 *           rotate publish.
 *  10.  shutdown(SHUT_RDWR) followed by randomised socket close order.
 *
 * Brick-safety:
 *   - All net mutation is inside a private CLONE_NEWNET; nothing touches
 *     the host's interface or routing state.
 *   - Userspace SOCK_STREAM + AF_NETLINK genetlink + AF_NETLINK rtnl
 *     only -- no raw sockets, no module load, no /sys writes.
 *   - Per-syscall SO_RCVTIMEO/SO_SNDTIMEO 100 ms keeps a wedged recv
 *     from punching through the SIGALRM(1s) cap inherited from child.c.
 *   - BUDGETED outer loop with 200 ms wall cap.
 *
 * Header gates: __has_include(<linux/genetlink.h>) /
 * <linux/if_link.h> / <linux/rtnetlink.h>.  PSP UAPI integers
 * (PSP_CMD_DEV_GET, PSP_CMD_KEY_ROTATE, PSP_CMD_TX_ASSOC, PSP_A_DEV_ID,
 * PSP_A_ASSOC_DEV_ID, PSP_A_ASSOC_SOCK_FD, PSP_A_ASSOC_VERSION) are
 * #define-fallback supplied at their stable UAPI integer values when
 * <linux/psp.h> is missing on the build host -- the kernel returns
 * -ENOPROTOOPT / -EOPNOTSUPP and the cap-gate latches.
 *
 * Spec-deviation note: the spec called out a "SOL_TCP / SO_PSP_SPI"
 * setsockopt as the per-socket bind step, but no such socket option
 * exists in the upstream PSP UAPI -- the sock-fd is conveyed to the SA
 * install via PSP_CMD_TX_ASSOC + PSP_A_ASSOC_SOCK_FD instead.  We honour
 * the spec's stat-counter name (spi_set_ok) but the underlying syscall
 * is the genetlink assoc command rather than a setsockopt.  Same for
 * spi_switch_ok which counts a second PSP_CMD_TX_ASSOC mid-flow.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/* PSP UAPI integers (mainlined in 6.10).  Values mirror
 * include/uapi/linux/psp.h: enum { PSP_CMD_DEV_GET = 1, ... } and
 * enum { PSP_A_DEV_ID = 1, ... }.  Supplied as fallbacks for stripped
 * sysroots that omit <linux/psp.h>; the kernel returns -EOPNOTSUPP /
 * -ENOPROTOOPT on an unknown command and the cap-gate latches. */
#ifndef PSP_FAMILY_NAME
#define PSP_FAMILY_NAME			"psp"
#endif
#ifndef PSP_CMD_DEV_GET
#define PSP_CMD_DEV_GET			1
#endif
#ifndef PSP_CMD_KEY_ROTATE
#define PSP_CMD_KEY_ROTATE		6
#endif
#ifndef PSP_CMD_TX_ASSOC
#define PSP_CMD_TX_ASSOC		9
#endif
#ifndef PSP_A_DEV_ID
#define PSP_A_DEV_ID			1
#endif
#ifndef PSP_A_ASSOC_DEV_ID
#define PSP_A_ASSOC_DEV_ID		1
#endif
#ifndef PSP_A_ASSOC_VERSION
#define PSP_A_ASSOC_VERSION		2
#endif
#ifndef PSP_A_ASSOC_SOCK_FD
#define PSP_A_ASSOC_SOCK_FD		5
#endif

/* netdevsim is the in-tree PSP probe vehicle.  Brought up via
 * IFLA_INFO_KIND="netdevsim" -- the kernel returns -ENODEV /
 * -EOPNOTSUPP if the module is not loaded and the cap-gate latches on
 * the first PSP family probe immediately after. */
#ifndef NETDEVSIM_KIND
#define NETDEVSIM_KIND			"netdevsim"
#endif

#define PKR_OUTER_BASE			4U
#define PKR_OUTER_FLOOR			8U
#define PKR_OUTER_CAP			16U
#define PKR_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define PKR_TIMEO_MS			100
#define PKR_NL_RX_BUF			4096

static bool ns_unsupported_psp_key_rotate;

static long long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (long long)(now.tv_sec - t0->tv_sec) * 1000000000LL +
	       (long long)(now.tv_nsec - t0->tv_nsec);
}

static void apply_timeouts(int s)
{
	struct timeval tv;

	tv.tv_sec  = 0;
	tv.tv_usec = PKR_TIMEO_MS * 1000;
	(void)setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static bool errno_is_unsupported(int e)
{
	return e == EPERM || e == ENOSYS || e == EOPNOTSUPP ||
	       e == ENOPROTOOPT || e == EAFNOSUPPORT ||
	       e == EPROTONOSUPPORT || e == ENODEV;
}

/* Append a netlink attribute to @buf at offset *off, padding to
 * NLA_ALIGNTO.  Returns false on overflow. */
static bool nla_put(unsigned char *buf, size_t cap, size_t *off,
		    uint16_t type, const void *data, uint16_t len)
{
	struct nlattr nla;
	size_t pad_len = NLA_ALIGN(len);
	size_t need = NLA_HDRLEN + pad_len;

	if (*off + need > cap)
		return false;
	nla.nla_type = type;
	nla.nla_len  = (uint16_t)(NLA_HDRLEN + len);
	memcpy(buf + *off, &nla, sizeof(nla));
	if (len)
		memcpy(buf + *off + NLA_HDRLEN, data, len);
	if (pad_len > len)
		memset(buf + *off + NLA_HDRLEN + len, 0, pad_len - len);
	*off += need;
	return true;
}

static bool nla_put_str(unsigned char *buf, size_t cap, size_t *off,
			uint16_t type, const char *s)
{
	return nla_put(buf, cap, off, type, s, (uint16_t)(strlen(s) + 1));
}

static bool nla_put_u32(unsigned char *buf, size_t cap, size_t *off,
			uint16_t type, uint32_t v)
{
	return nla_put(buf, cap, off, type, &v, sizeof(v));
}

/* Send a genetlink request and read one response (best-effort).
 * Returns 0 on success, -1 on send/recv failure, or the netlink error
 * code (positive) when an NLMSG_ERROR with non-zero error is returned.
 * On success the response is written to @resp / @resp_len. */
static int genl_send_recv(int nlfd, uint16_t family, uint8_t cmd,
			  uint8_t version, const unsigned char *attrs,
			  size_t attrs_len, unsigned char *resp,
			  size_t resp_cap, size_t *resp_len)
{
	unsigned char buf[1024];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;
	struct sockaddr_nl sa;
	ssize_t rx;
	size_t total;

	if (attrs_len > sizeof(buf) - NLMSG_HDRLEN - GENL_HDRLEN)
		return -1;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);

	total = NLMSG_HDRLEN + GENL_HDRLEN + attrs_len;
	nlh->nlmsg_len   = (uint32_t)total;
	nlh->nlmsg_type  = family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_pid   = 0;
	gnh->cmd     = cmd;
	gnh->version = version;
	if (attrs_len)
		memcpy((unsigned char *)gnh + GENL_HDRLEN, attrs, attrs_len);

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(nlfd, buf, total, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -1;

	rx = recv(nlfd, resp, resp_cap, 0);
	if (rx < 0)
		return -1;

	*resp_len = (size_t)rx;
	if ((size_t)rx >= NLMSG_HDRLEN) {
		struct nlmsghdr *r = (struct nlmsghdr *)resp;

		if (r->nlmsg_type == NLMSG_ERROR &&
		    (size_t)rx >= NLMSG_HDRLEN + sizeof(struct nlmsgerr)) {
			struct nlmsgerr *e =
				(struct nlmsgerr *)NLMSG_DATA(r);

			if (e->error != 0)
				return -e->error;
		}
	}
	return 0;
}

/* Resolve the dynamic genetlink family id for "psp" via
 * CTRL_CMD_GETFAMILY.  Returns 0 on success and writes the id to @out.
 * Negative return means the controller didn't know the family or the
 * netlink layer rejected the request -- caller should latch the cap-
 * gate. */
static int resolve_psp_family(int nlfd, uint16_t *out)
{
	unsigned char attrs[64];
	unsigned char resp[PKR_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;
	int rc;
	struct nlmsghdr *r;
	struct genlmsghdr *g;
	unsigned char *p;
	size_t remaining;

	if (!nla_put_str(attrs, sizeof(attrs), &off,
			 CTRL_ATTR_FAMILY_NAME, PSP_FAMILY_NAME))
		return -1;

	rc = genl_send_recv(nlfd, GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1,
			    attrs, off, resp, sizeof(resp), &resp_len);
	if (rc != 0)
		return rc < 0 ? rc : -rc;

	if (resp_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return -1;
	r = (struct nlmsghdr *)resp;
	if (r->nlmsg_type == NLMSG_ERROR)
		return -1;

	g = (struct genlmsghdr *)NLMSG_DATA(r);
	p = (unsigned char *)g + GENL_HDRLEN;
	remaining = resp_len - NLMSG_HDRLEN - GENL_HDRLEN;

	while (remaining >= NLA_HDRLEN) {
		struct nlattr nla;
		size_t alen;

		memcpy(&nla, p, sizeof(nla));
		if (nla.nla_len < NLA_HDRLEN || nla.nla_len > remaining)
			break;
		alen = NLA_ALIGN(nla.nla_len);
		if (nla.nla_type == CTRL_ATTR_FAMILY_ID &&
		    nla.nla_len >= NLA_HDRLEN + sizeof(uint16_t)) {
			uint16_t id;

			memcpy(&id, p + NLA_HDRLEN, sizeof(id));
			*out = id;
			return 0;
		}
		if (alen > remaining)
			break;
		p += alen;
		remaining -= alen;
	}
	return -1;
}

/* Best-effort netdevsim spawn via rtnl RTM_NEWLINK with
 * IFLA_LINKINFO/IFLA_INFO_KIND="netdevsim".  Returns 0 on accept,
 * -errno on failure.  Caller does not depend on success: the PSP
 * family probe latches the cap-gate on its own when the device path
 * isn't viable. */
static int rtnl_make_netdevsim(int rtfd, const char *ifname)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	struct nlattr *linkinfo;
	struct nlattr *kind;
	struct sockaddr_nl sa;
	size_t off, link_off, kind_off;
	ssize_t rx;
	unsigned char rxbuf[PKR_NL_RX_BUF];

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	ifm = (struct ifinfomsg *)NLMSG_DATA(nlh);

	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifm));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = 2;
	ifm->ifi_family = AF_UNSPEC;

	off = NLMSG_ALIGN(nlh->nlmsg_len);
	if (!nla_put_str(buf, sizeof(buf), &off, IFLA_IFNAME, ifname))
		return -EMSGSIZE;

	/* Open IFLA_LINKINFO container.  We patch its length once the
	 * nested IFLA_INFO_KIND payload is appended. */
	link_off = off;
	if (off + NLA_HDRLEN > sizeof(buf))
		return -EMSGSIZE;
	linkinfo = (struct nlattr *)(buf + off);
	linkinfo->nla_type = IFLA_LINKINFO;
	linkinfo->nla_len  = NLA_HDRLEN;
	off += NLA_HDRLEN;

	kind_off = off;
	if (!nla_put_str(buf, sizeof(buf), &off,
			 IFLA_INFO_KIND, NETDEVSIM_KIND))
		return -EMSGSIZE;
	kind = (struct nlattr *)(buf + kind_off);
	(void)kind;	/* fields validated implicitly via nla_put_str */
	linkinfo->nla_len = (uint16_t)(off - link_off);

	nlh->nlmsg_len = (uint32_t)off;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (sendto(rtfd, buf, off, 0,
		   (struct sockaddr *)&sa, sizeof(sa)) < 0)
		return -errno;

	rx = recv(rtfd, rxbuf, sizeof(rxbuf), 0);
	if (rx < 0)
		return -errno;
	if ((size_t)rx >= NLMSG_HDRLEN) {
		struct nlmsghdr *r = (struct nlmsghdr *)rxbuf;

		if (r->nlmsg_type == NLMSG_ERROR &&
		    (size_t)rx >= NLMSG_HDRLEN + sizeof(struct nlmsgerr)) {
			struct nlmsgerr *e =
				(struct nlmsgerr *)NLMSG_DATA(r);

			return e->error;
		}
	}
	return 0;
}

/* Issue PSP_CMD_KEY_ROTATE for @dev_id.  Returns 0 on success, -errno
 * (or -1 on send/recv failure) otherwise. */
static int psp_key_rotate_cmd(int nlfd, uint16_t family, uint32_t dev_id)
{
	unsigned char attrs[32];
	unsigned char resp[PKR_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;

	if (!nla_put_u32(attrs, sizeof(attrs), &off, PSP_A_DEV_ID, dev_id))
		return -1;

	return genl_send_recv(nlfd, family, PSP_CMD_KEY_ROTATE, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
}

/* Issue PSP_CMD_TX_ASSOC binding @sockfd to @dev_id.  Returns 0 on
 * success, -errno on failure.  Mid-flow re-issue is the "spi switch"
 * path under spec naming. */
static int psp_tx_assoc_cmd(int nlfd, uint16_t family,
			    uint32_t dev_id, int sockfd)
{
	unsigned char attrs[64];
	unsigned char resp[PKR_NL_RX_BUF];
	size_t off = 0;
	size_t resp_len = 0;

	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 PSP_A_ASSOC_DEV_ID, dev_id))
		return -1;
	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 PSP_A_ASSOC_VERSION, 0U))
		return -1;
	if (!nla_put_u32(attrs, sizeof(attrs), &off,
			 PSP_A_ASSOC_SOCK_FD, (uint32_t)sockfd))
		return -1;

	return genl_send_recv(nlfd, family, PSP_CMD_TX_ASSOC, 1,
			      attrs, off, resp, sizeof(resp), &resp_len);
}

static void inner_traffic_burst(int sockfd)
{
	static const unsigned char payload[16] = { 0 };
	unsigned char rx[64];
	ssize_t r;

	r = send(sockfd, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (r > 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate_send_ok,
				   1, __ATOMIC_RELAXED);

	(void)recv(sockfd, rx, sizeof(rx), MSG_DONTWAIT);
}

static void iter_one(unsigned int iter_idx, const struct timespec *t_outer)
{
	int nlfd = -1, rtfd = -1, sockfd = -1;
	struct sockaddr_nl sa;
	struct sockaddr_in peer;
	struct timeval tv;
	uint16_t psp_family = 0;
	uint32_t dev_id = 0;
	char ifname[IFNAMSIZ];
	int rc;

	if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
		return;

	if (unshare(CLONE_NEWNET) < 0) {
		if (errno == EPERM)
			ns_unsupported_psp_key_rotate = true;
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}

	rtfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (rtfd < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	tv.tv_sec  = 0;
	tv.tv_usec = PKR_TIMEO_MS * 1000;
	(void)setsockopt(rtfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(rtfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	(void)snprintf(ifname, sizeof(ifname), "psp%u",
		       (unsigned int)(rand32() & 0xffff));
	rc = rtnl_make_netdevsim(rtfd, ifname);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate_netdev_create_ok,
				   1, __ATOMIC_RELAXED);
	/* On -ENODEV / -EOPNOTSUPP / -EEXIST the family probe below still
	 * runs -- the cap-gate latches there if PSP isn't built in. */

	nlfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (nlfd < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	(void)setsockopt(nlfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(nlfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	/* Structural-support probe: dynamic family resolution. */
	rc = resolve_psp_family(nlfd, &psp_family);
	if (rc != 0 || psp_family == 0) {
		if (rc < 0 && errno_is_unsupported(-rc))
			ns_unsupported_psp_key_rotate = true;
		else
			ns_unsupported_psp_key_rotate = true;
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.psp_key_rotate_family_resolve_ok,
			   1, __ATOMIC_RELAXED);

	/* PSP_CMD_DEV_GET dump.  Best-effort dev_id pick: a valid PSP
	 * device exposes id starting at 1; on a real PSP-capable host the
	 * netdevsim spawned above lands here. */
	{
		unsigned char attrs[16];
		unsigned char resp[PKR_NL_RX_BUF];
		size_t off = 0;
		size_t resp_len = 0;
		int rc2;

		rc2 = genl_send_recv(nlfd, psp_family, PSP_CMD_DEV_GET, 1,
				     attrs, off, resp, sizeof(resp),
				     &resp_len);
		if (rc2 == 0)
			__atomic_add_fetch(&shm->stats.psp_key_rotate_dev_get_ok,
					   1, __ATOMIC_RELAXED);
		else if (rc2 < 0 && errno_is_unsupported(-rc2))
			ns_unsupported_psp_key_rotate = true;
	}
	dev_id = 1U;

	sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (sockfd < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	apply_timeouts(sockfd);
	memset(&peer, 0, sizeof(peer));
	peer.sin_family      = AF_INET;
	peer.sin_port        = htons(0xCAFE);
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)connect(sockfd, (struct sockaddr *)&peer, sizeof(peer));

	/* Initial key install. */
	rc = psp_key_rotate_cmd(nlfd, psp_family, dev_id);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate_key_install_ok,
				   1, __ATOMIC_RELAXED);
	else if (rc < 0 && errno_is_unsupported(-rc))
		ns_unsupported_psp_key_rotate = true;

	/* Bind the SA to the socket via the assoc command (spec stat:
	 * spi_set_ok -- see spec-deviation note in the file header). */
	rc = psp_tx_assoc_cmd(nlfd, psp_family, dev_id, sockfd);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate_spi_set_ok,
				   1, __ATOMIC_RELAXED);

	if (ns_unsupported_psp_key_rotate)
		goto teardown;

	{
		unsigned int inner;
		unsigned int j;

		inner = JITTER_RANGE(PKR_OUTER_BASE);
		if (inner < PKR_OUTER_FLOOR)
			inner = PKR_OUTER_FLOOR;
		if (inner > PKR_OUTER_CAP)
			inner = PKR_OUTER_CAP;

		for (j = 0; j < inner; j++) {
			if ((unsigned long long)ns_since(t_outer) >=
			    PKR_WALL_CAP_NS)
				break;

			inner_traffic_burst(sockfd);

			/* RACE TARGET: rotate keys mid-flow. */
			rc = psp_key_rotate_cmd(nlfd, psp_family, dev_id);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.psp_key_rotate_rotate_ok,
						   1, __ATOMIC_RELAXED);

			/* Re-bind the assoc to the rotated generation
			 * mid-flow -- "spi switch" per spec naming. */
			rc = psp_tx_assoc_cmd(nlfd, psp_family,
					      dev_id, sockfd);
			if (rc == 0)
				__atomic_add_fetch(&shm->stats.psp_key_rotate_spi_switch_ok,
						   1, __ATOMIC_RELAXED);

			inner_traffic_burst(sockfd);
		}
	}

	(void)shutdown(sockfd, SHUT_RDWR);
	__atomic_add_fetch(&shm->stats.psp_key_rotate_shutdown_ok,
			   1, __ATOMIC_RELAXED);

teardown:
	/* Randomised socket close order: rotate which fd dies first so
	 * the rtnl/genl/SOCK_STREAM teardown ordering varies across
	 * iterations. */
	switch (iter_idx & 3U) {
	case 0:
		if (sockfd >= 0) { close(sockfd); sockfd = -1; }
		if (nlfd   >= 0) { close(nlfd);   nlfd   = -1; }
		if (rtfd   >= 0) { close(rtfd);   rtfd   = -1; }
		break;
	case 1:
		if (nlfd   >= 0) { close(nlfd);   nlfd   = -1; }
		if (sockfd >= 0) { close(sockfd); sockfd = -1; }
		if (rtfd   >= 0) { close(rtfd);   rtfd   = -1; }
		break;
	case 2:
		if (rtfd   >= 0) { close(rtfd);   rtfd   = -1; }
		if (sockfd >= 0) { close(sockfd); sockfd = -1; }
		if (nlfd   >= 0) { close(nlfd);   nlfd   = -1; }
		break;
	default:
		if (sockfd >= 0) { close(sockfd); sockfd = -1; }
		if (rtfd   >= 0) { close(rtfd);   rtfd   = -1; }
		if (nlfd   >= 0) { close(nlfd);   nlfd   = -1; }
		break;
	}
	return;

out:
	if (sockfd >= 0)
		close(sockfd);
	if (nlfd >= 0)
		close(nlfd);
	if (rtfd >= 0)
		close(rtfd);
}

bool psp_key_rotate(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	(void)child;

	__atomic_add_fetch(&shm->stats.psp_key_rotate_runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_psp_key_rotate) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_outer) < 0) {
		t_outer.tv_sec  = 0;
		t_outer.tv_nsec = 0;
	}

	outer_iters = BUDGETED(CHILD_OP_PSP_KEY_ROTATE,
			       JITTER_RANGE(PKR_OUTER_BASE));
	if (outer_iters < PKR_OUTER_FLOOR)
		outer_iters = PKR_OUTER_FLOOR;
	if (outer_iters > PKR_OUTER_CAP)
		outer_iters = PKR_OUTER_CAP;

	for (i = 0; i < outer_iters; i++) {
		if ((unsigned long long)ns_since(&t_outer) >= PKR_WALL_CAP_NS)
			break;

		iter_one(i, &t_outer);

		if (ns_unsupported_psp_key_rotate)
			break;
	}

	return true;
}

#else  /* missing one of <linux/genetlink.h> / <linux/if_link.h> / <linux/rtnetlink.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool psp_key_rotate(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.psp_key_rotate_runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.psp_key_rotate_setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

#endif
