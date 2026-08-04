/*
 * psp-key-rotate-lifecycle - grandchild-local key/socket setup carved
 * out of childops/net/psp-key-rotate.c.  Owns the three phases the
 * iter_one_in_ns() callback drives before it hands the bound socket to
 * the traffic loop:
 *
 *   psp_key_rotate_iter_setup           - open the rtnl socket inside
 *                                         the grandchild's private
 *                                         netns and RTM_NEWLINK a
 *                                         netdevsim (best-effort);
 *   psp_key_rotate_iter_family_resolve  - genl_open the PSP family
 *                                         and PSP_CMD_DEV_GET probe;
 *                                         latch the per-grandchild
 *                                         cap-gate on -ENOENT / the
 *                                         other unsupported errnos;
 *   psp_key_rotate_iter_socket_install  - socket() + best-effort
 *                                         loopback connect(), initial
 *                                         PSP_CMD_KEY_ROTATE, then
 *                                         PSP_CMD_TX_ASSOC bind (the
 *                                         spec-named spi_set step).
 *
 * Also owns the private RTM_NEWLINK builder rtnl_make_netdevsim() that
 * only iter_setup calls.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "childops-genl.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"

#include "kernel/psp.h"

#include "psp-key-rotate-internal.h"

/* netdevsim is the in-tree PSP probe vehicle.  Brought up via
 * IFLA_INFO_KIND="netdevsim" -- the kernel returns -ENODEV /
 * -EOPNOTSUPP if the module is not loaded and the cap-gate latches on
 * the first PSP family probe immediately after. */
#ifndef NETDEVSIM_KIND
#define NETDEVSIM_KIND			"netdevsim"
#endif

/* Best-effort netdevsim spawn via rtnl RTM_NEWLINK with
 * IFLA_LINKINFO/IFLA_INFO_KIND="netdevsim".  Returns 0 on accept,
 * -errno on failure.  Caller does not depend on success: the PSP
 * family probe latches the cap-gate on its own when the device path
 * isn't viable. */
static int rtnl_make_netdevsim(struct nl_ctx *rtnl, const char *ifname)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	size_t off, link_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	ifm = (struct ifinfomsg *)NLMSG_DATA(nlh);

	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifm));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifm->ifi_family  = AF_UNSPEC;

	off = NLMSG_ALIGN(nlh->nlmsg_len);
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off)
		return -EMSGSIZE;

	link_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return -EMSGSIZE;
	off = nla_put_str(buf, off, sizeof(buf),
			  IFLA_INFO_KIND, NETDEVSIM_KIND);
	if (!off)
		return -EMSGSIZE;
	nla_nest_end(buf, link_off, off);

	nlh->nlmsg_len = (uint32_t)off;
	return nl_send_recv(rtnl, buf, off);
}

/* Open the rtnl socket inside the grandchild's private netns (set up
 * by userns_run_in_ns() before this callback runs), then issue a
 * best-effort RTM_NEWLINK to spawn a netdevsim instance.  Returns 0
 * on success or -1 if the iteration should bail to iter_one_in_ns'
 * out: cleanup path.  The netdev create is best-effort: even on
 * -ENODEV / -EOPNOTSUPP / -EEXIST the subsequent PSP family probe
 * still runs and the per-grandchild gate latches there if PSP isn't
 * built in. */
int psp_key_rotate_iter_setup(struct nl_ctx *rtnl, unsigned long *dc)
{
	struct nl_open_opts nlopts;
	char ifname[IFNAMSIZ];
	int rc;

	memset(&nlopts, 0, sizeof(nlopts));
	nlopts.proto         = NETLINK_ROUTE;
	nlopts.recv_timeo_s  = 1;
	if (nl_open(rtnl, &nlopts) < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	/* nl_open success: socket() + bind() + setsockopt(SO_RCVTIMEO). */
	*dc += 3;

	(void)snprintf(ifname, sizeof(ifname), "psp%u",
		       (unsigned int)(rand32() & 0xffff));
	rc = rtnl_make_netdevsim(rtnl, ifname);
	/* rtnl_make_netdevsim wraps nl_send_recv: sendmsg() + recv(). */
	*dc += 2;
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate.netdev_create_ok,
				   1, __ATOMIC_RELAXED);
		name_pool_record(NAME_KIND_NETDEV, ifname, strlen(ifname));
	}
	return 0;
}

/* Open the PSP genl family (CTRL_CMD_GETFAMILY under the hood; -ENOENT
 * means the kernel doesn't know "psp" at all -- cap-gate latches) then
 * issue a best-effort PSP_CMD_DEV_GET probe.  Writes the chosen dev_id
 * into *dev_id_out on success.  Returns 0 on success or -1 if the
 * iteration should bail to iter_one's out: cleanup. */
int psp_key_rotate_iter_family_resolve(struct genl_ctx *psp_ctx,
				       uint32_t *dev_id_out,
				       unsigned long *dc)
{
	struct genl_open_opts gopts;
	int rc, rc2;

	memset(&gopts, 0, sizeof(gopts));
	gopts.family_name  = PSP_FAMILY_NAME;
	gopts.recv_timeo_s = 1;
	rc = genl_open(psp_ctx, &gopts);
	if (rc != 0) {
		ns_unsupported_psp_key_rotate = true;
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	/* genl_open success: nl_open (socket + bind + setsockopt) +
	 * resolve_family_id (sendmsg + recv). */
	*dc += 5;
	__atomic_add_fetch(&shm->stats.psp_key_rotate.family_resolve_ok,
			   1, __ATOMIC_RELAXED);

	/* PSP_CMD_DEV_GET dump.  Best-effort dev_id pick: a valid PSP
	 * device exposes id starting at 1; on a real PSP-capable host the
	 * netdevsim spawned above lands here. */
	rc2 = psp_dev_get_probe(psp_ctx);
	/* psp_dev_get_probe wraps genl_send_recv: sendmsg() + recv(). */
	*dc += 2;
	if (rc2 == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.dev_get_ok,
				   1, __ATOMIC_RELAXED);
	else if (rc2 < 0 && errno_is_unsupported(-rc2))
		ns_unsupported_psp_key_rotate = true;

	*dev_id_out = 1U;
	return 0;
}

/* Open a TCP socket, fire a best-effort loopback connect(), then
 * install the initial PSP key and bind the SA to the socket via the
 * assoc command (the spec-named spi_set step).  Returns the socket fd
 * on success or -1 if the iteration should bail to iter_one's out:
 * cleanup.  The key install / assoc themselves are best-effort: their
 * stats are recorded inline and ns_unsupported_psp_key_rotate may
 * latch from psp_key_rotate_cmd's errno, which the caller checks
 * before entering the traffic loop. */
int psp_key_rotate_iter_socket_install(struct genl_ctx *psp_ctx,
				       uint32_t dev_id,
				       unsigned long *dc)
{
	struct sockaddr_in peer;
	int sockfd;
	int rc;

	sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (sockfd < 0) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return -1;
	}
	*dc += 1;			/* socket() */
	apply_timeouts(sockfd);
	*dc += 2;			/* setsockopt(SO_RCVTIMEO) + setsockopt(SO_SNDTIMEO) */
	memset(&peer, 0, sizeof(peer));
	peer.sin_family      = AF_INET;
	peer.sin_port        = htons(0xCAFE);
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)connect(sockfd, (struct sockaddr *)&peer, sizeof(peer));
	*dc += 1;			/* connect() */

	/* Initial key install. */
	rc = psp_key_rotate_cmd(psp_ctx, dev_id);
	/* psp_key_rotate_cmd wraps genl_send_recv: sendmsg() + recv(). */
	*dc += 2;
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.key_install_ok,
				   1, __ATOMIC_RELAXED);
	else if (rc < 0 && errno_is_unsupported(-rc))
		ns_unsupported_psp_key_rotate = true;

	/* Bind the SA to the socket via the assoc command (spec stat:
	 * spi_set_ok -- see spec-deviation note in the file header). */
	rc = psp_tx_assoc_cmd(psp_ctx, dev_id, sockfd);
	/* psp_tx_assoc_cmd wraps genl_send_recv: sendmsg() + recv(). */
	*dc += 2;
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.spi_set_ok,
				   1, __ATOMIC_RELAXED);

	return sockfd;
}

#endif /* __has_include gate matches psp-key-rotate.c */
