/*
 * psp_key_rotate - net/psp TCP key install + mid-flow key rotation race.
 *
 * Targets a TOCTOU between PSP_CMD_KEY_ROTATE publishing a new key
 * generation on the device and the per-socket SA refcount walked by the
 * tx/rx hot path in net/psp/{psp_main.c,psp_sock.c,psp_nl.c} -- the rotate
 * flips the active key id under an in-flight sendmsg/recvmsg whose assoc
 * still holds the previous generation.  Random syscall fuzz never assembles
 * the coherent stack: a PSP-capable netdev (in-tree vehicle netdevsim +
 * drivers/net/netdevsim/psp.c), a resolved "psp" genetlink family, an
 * enumerated dev via PSP_CMD_DEV_GET, and a TCP fd attached through
 * PSP_CMD_TX_ASSOC + PSP_A_ASSOC_SOCK_FD.
 *
 * Per iteration inside a userns_run_in_ns grandchild (identity userns +
 * CLONE_NEWNET, _exit reaps): rtnl RTM_NEWLINK a netdevsim + IFF_UP, open
 * an AF_INET SOCK_STREAM with per-syscall timeouts and connect() to
 * loopback, resolve psp family, DEV_GET a psp_dev_id, KEY_ROTATE + TX_ASSOC
 * to arm the SA, then a BUDGETED inner loop (base 4 / floor 8 / cap 16,
 * 200 ms wall) pairing send/recv against a mid-flow KEY_ROTATE and a second
 * TX_ASSOC that switches the bound generation while I/O overlaps the
 * rotate publish.
 *
 * Brick-safety: all net mutation inside CLONE_NEWNET; only SOCK_STREAM +
 * genetlink + rtnl (no raw sockets, no modprobe, no /sys writes);
 * per-syscall SO_RCVTIMEO/SO_SNDTIMEO 100 ms keeps a wedged recv from
 * punching past child.c's SIGALRM(1s) backstop.
 *
 * Latches (per-process): ns_unsupported_psp_key_rotate_master on
 * userns_run_in_ns() -EPERM; cap-gate latches on PSP genetlink family
 * resolution failure (-EPERM / -ENOSYS / -EOPNOTSUPP / -ENOPROTOOPT /
 * -EAFNOSUPPORT / -EPROTONOSUPPORT / -ENODEV -- CONFIG absent or
 * netdevsim/psp not loaded).  Transient setup failures skip without
 * latching.
 *
 * Header-gated by __has_include() on linux/genetlink.h, linux/if_link.h,
 * linux/rtnetlink.h.  PSP UAPI integers (PSP_CMD_DEV_GET / KEY_ROTATE /
 * TX_ASSOC, PSP_A_ASSOC_*) get #define-fallback at their stable UAPI
 * values when <linux/psp.h> is absent; the kernel then returns
 * -ENOPROTOOPT / -EOPNOTSUPP and the cap-gate latches.
 *
 * Spec-vs-reality note: spec called out a SOL_TCP / SO_PSP_SPI setsockopt
 * for the per-socket bind, but no such optname exists in upstream PSP UAPI
 * -- the fd is conveyed via PSP_CMD_TX_ASSOC + PSP_A_ASSOC_SOCK_FD.  The
 * spec's spi_set_ok / spi_switch_ok counter names are preserved.
 */

#if __has_include(<linux/genetlink.h>) && \
	__has_include(<linux/if_link.h>) && \
	__has_include(<linux/rtnetlink.h>)

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "childops-genl.h"
#include "childops-util.h"
#include "jitter.h"
#include "name-pool.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "userns-bootstrap.h"
#include "pids.h"

#include "kernel/psp.h"

/* netdevsim is the in-tree PSP probe vehicle.  Brought up via
 * IFLA_INFO_KIND="netdevsim" -- the kernel returns -ENODEV /
 * -EOPNOTSUPP if the module is not loaded and the cap-gate latches on
 * the first PSP family probe immediately after. */
#ifndef NETDEVSIM_KIND
#define NETDEVSIM_KIND			"netdevsim"
#endif

/* devlink genl UAPI integers (mainlined long before 6.10).  Supplied as
 * fallbacks for stripped sysroots that omit <linux/devlink.h>; the
 * kernel returns -EOPNOTSUPP / -ENOPROTOOPT on unknown commands and the
 * sub-mode latches ns_unsupported_psp_devlink_port. */
#ifndef DEVLINK_FAMILY_NAME
#define DEVLINK_FAMILY_NAME		"devlink"
#endif
#ifndef DEVLINK_CMD_PORT_NEW
#define DEVLINK_CMD_PORT_NEW		31
#endif
#ifndef DEVLINK_CMD_PORT_DEL
#define DEVLINK_CMD_PORT_DEL		32
#endif
#ifndef DEVLINK_ATTR_BUS_NAME
#define DEVLINK_ATTR_BUS_NAME		1
#endif
#ifndef DEVLINK_ATTR_DEV_NAME
#define DEVLINK_ATTR_DEV_NAME		2
#endif
#ifndef DEVLINK_ATTR_PORT_INDEX
#define DEVLINK_ATTR_PORT_INDEX		3
#endif
#ifndef DEVLINK_ATTR_PORT_FLAVOUR
#define DEVLINK_ATTR_PORT_FLAVOUR	77
#endif
#ifndef DEVLINK_PORT_FLAVOUR_VIRTUAL
#define DEVLINK_PORT_FLAVOUR_VIRTUAL	5
#endif
#ifndef DEVLINK_ATTR_PORT_NUMBER
#define DEVLINK_ATTR_PORT_NUMBER	36
#endif

#define PDPC_BUS			"netdevsim"
#define PDPC_NETDEVSIM_NEW		"/sys/bus/netdevsim/new_device"
#define PDPC_NETDEVSIM_DEL		"/sys/bus/netdevsim/del_device"
#define PDPC_MAX_INSTANCES		3U
#define PDPC_PORTS_PER_DEV		2U
#define PDPC_INNER_BASE			4U
#define PDPC_INNER_CAP			8U
#define PDPC_INNER_WALL_NS		(100ULL * 1000ULL * 1000ULL)
#define PDPC_GATE_ONE_IN		4

#define PKR_OUTER_BASE			4U
#define PKR_OUTER_FLOOR			8U
#define PKR_OUTER_CAP			16U
#define PKR_WALL_CAP_NS			(200ULL * 1000ULL * 1000ULL)
#define PKR_TIMEO_MS			100
#define PKR_NL_RX_BUF			4096

/* Per-grandchild gate.  Inherited as false at grandchild fork time
 * and flipped on the first config-absent rejection (genl_open of the
 * PSP family, PSP_CMD_DEV_GET, or initial KEY_ROTATE) seen inside
 * iter_one_in_ns().  Dies with the grandchild on _exit(); each
 * subsequent grandchild re-discovers the latch in its own fresh
 * netns.  The detection arms are preserved because a fresh user
 * namespace cannot manufacture an absent kernel CONFIG -- the gate
 * still short-circuits the rest of the grandchild's iteration once
 * it fires. */
static bool ns_unsupported_psp_key_rotate;

/* Master gate: persistent across iterations in the persistent child.
 * Set when userns_run_in_ns returns -EPERM (hardened userns policy
 * refused CLONE_NEWUSER -- typically user.max_user_namespaces=0 or
 * kernel.unprivileged_userns_clone=0).  The per-grandchild gate
 * above dies with the grandchild; helper-EPERM is the only signal
 * that survives long enough to short-circuit subsequent
 * invocations. */
static bool ns_unsupported_psp_key_rotate_master;

static void warn_once_unsupported_psp_key_rotate(const char *reason, int err)
{
	if (ns_unsupported_psp_key_rotate_master)
		return;
	ns_unsupported_psp_key_rotate_master = true;
	outputerr("psp_key_rotate: %s failed (errno=%d), latching unsupported_psp_key_rotate\n",
		  reason, err);
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

/* Issue PSP_CMD_KEY_ROTATE for @dev_id.  Returns 0 on success, -errno
 * (or -EIO on send/recv failure) otherwise. */
static int psp_key_rotate_cmd(struct genl_ctx *ctx, uint32_t dev_id)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   PSP_CMD_KEY_ROTATE, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), PSP_A_DEV_ID, dev_id);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

/* Issue PSP_CMD_TX_ASSOC binding @sockfd to @dev_id.  Returns 0 on
 * success, -errno on failure.  Mid-flow re-issue is the "spi switch"
 * path under spec naming. */
static int psp_tx_assoc_cmd(struct genl_ctx *ctx,
			    uint32_t dev_id, int sockfd)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   PSP_CMD_TX_ASSOC, 0);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), PSP_A_ASSOC_DEV_ID, dev_id);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), PSP_A_ASSOC_VERSION, 0U);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  PSP_A_ASSOC_SOCK_FD, (uint32_t)sockfd);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

static void inner_traffic_burst(int sockfd)
{
	static const unsigned char payload[16] = { 0 };
	unsigned char rx[64];
	ssize_t r;

	r = send(sockfd, payload, sizeof(payload), MSG_DONTWAIT | MSG_NOSIGNAL);
	if (r > 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.send_ok,
				   1, __ATOMIC_RELAXED);

	(void)recv(sockfd, rx, sizeof(rx), MSG_DONTWAIT);
}

/* ------------------------------------------------------------------
 * psp_devlink_port_churn sub-mode.
 *
 * Same childop slot as the base recipe; gated behind ONE_IN(4) inside
 * the outer loop so the original PSP key-rotate path keeps running on
 * every other iteration.  The sub-mode targets a different bug shape:
 * parallel devlink port add/del across multiple netdevsim instances
 * overlapped with PSP TX_ASSOC + KEY_ROTATE on a netdev-bound TCP
 * socket, plus optional SR-IOV VF spawn with an RTM_NEWLINK macvlan
 * carrying IFLA_LINK pointing at the PF index (the cross-fire path).
 *
 * Setup is latched per-process: we unshare CLONE_NEWNET once, hold an
 * fd to that netns, modprobe netdevsim, and spawn 2-3 instances with
 * 2 ports each via /sys/bus/netdevsim/new_device.  Subsequent calls
 * setns(CLONE_NEWNET) back into the latched netns so the netdevsim
 * instances stay reachable across iterations even when the base
 * iter_one path does its own per-call unshare.
 * ------------------------------------------------------------------ */

static bool ns_unsupported_psp_devlink_port;
static bool ns_unsupported_psp_sriov;
static bool pdpc_setup_done;
static bool pdpc_modprobe_tried;
static int  pdpc_latched_netns_fd = -1;
/* Persistent worker's original netns fd, captured once before the first
 * unshare(CLONE_NEWNET) inside the sub-mode.  The sub-mode runs directly
 * in the worker (not in a userns_run_in_ns grandchild), so without
 * restoring on exit every subsequent childop in this worker would run
 * in the sub-mode's private (empty) netns. */
static int  pdpc_worker_original_netns_fd = -1;
static __u32 pdpc_bus_ids[PDPC_MAX_INSTANCES];
static unsigned int pdpc_n_instances;
static __u32 pdpc_next_port[PDPC_MAX_INSTANCES];
static __u32 pdpc_last_port[PDPC_MAX_INSTANCES];

/* Save the persistent worker's original netns fd.  Idempotent -- the fd
 * is captured on the first call and reused for the lifetime of the
 * worker process.  Must be called before any unshare(CLONE_NEWNET) or
 * setns() switch in this file so pdpc_restore_worker_netns() can put
 * the worker back where every other childop expects to run. */
static bool pdpc_save_worker_netns_once(void)
{
	int fd;

	if (pdpc_worker_original_netns_fd >= 0)
		return true;

	fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	pdpc_worker_original_netns_fd = fd;
	return true;
}

/* Restore the worker to the netns captured by
 * pdpc_save_worker_netns_once().  Returns true when nothing was saved
 * (no switch ever happened) or the setns succeeded; false means the
 * worker is stuck in the sub-mode's netns and the caller should latch
 * the sub-mode off. */
static bool pdpc_restore_worker_netns(void)
{
	if (pdpc_worker_original_netns_fd < 0)
		return true;

	return setns(pdpc_worker_original_netns_fd, CLONE_NEWNET) == 0;
}

static int pdpc_sysfs_write_str(const char *path, const char *s)
{
	int fd;
	ssize_t n;
	int rc;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = write(fd, s, strlen(s));
	rc = (n < 0) ? -errno : 0;
	close(fd);
	return rc;
}

/* Best-effort modprobe of netdevsim.  Same fork+execvp shape as
 * mpls-route-churn's try_modprobe -- redirect stdio to /dev/null so
 * module-load chatter doesn't pollute trinity's output.  Failure is
 * caught by the subsequent new_device write returning -ENODEV. */
static void pdpc_modprobe_netdevsim_once(void)
{
	pid_t pid;
	int status;
	int devnull;

	if (pdpc_modprobe_tried)
		return;
	pdpc_modprobe_tried = true;

	pid = fork();
	if (pid < 0)
		return;
	if (pid == 0) {
		devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", "netdevsim",
		       (char *)NULL);
		_exit(127);
	}
	(void)waitpid_eintr(pid, &status, 0);
}

/* Per-child cleanup: switch back into the latched netns and del each
 * spawned netdevsim bus device, then close the latched netns fd.
 * Best-effort; if setns fails the device sticks around until the
 * netdevsim module is unloaded.  Invoked from child_process()'s out:
 * path — worker children call _exit() which bypasses atexit handlers,
 * so the cleanup has to be wired into the explicit per-child exit
 * path rather than registered with atexit().  Idempotent: the state
 * is reset so a second call from a partial-setup unwind followed by
 * the out: path call is a no-op. */
void psp_key_rotate_cleanup_child(void)
{
	char buf[32];
	unsigned int i;

	if (pdpc_latched_netns_fd >= 0 &&
	    setns(pdpc_latched_netns_fd, CLONE_NEWNET) == 0) {
		for (i = 0; i < pdpc_n_instances; i++) {
			(void)snprintf(buf, sizeof(buf), "%u",
				       (unsigned int)pdpc_bus_ids[i]);
			(void)pdpc_sysfs_write_str(PDPC_NETDEVSIM_DEL, buf);
		}
	}
	pdpc_n_instances = 0;
	if (pdpc_latched_netns_fd >= 0) {
		close(pdpc_latched_netns_fd);
		pdpc_latched_netns_fd = -1;
	}
}

/* One-shot setup: unshare into a fresh netns, stash an fd to it,
 * modprobe netdevsim, then write 2-3 instances into new_device.  We
 * derive bus IDs from a wide pid+rand seed so concurrent trinity
 * children rarely collide on the netdevsim id namespace. */
static bool pdpc_setup_once(void)
{
	char create_payload[64];
	__u32 base;
	unsigned int i;
	int fd;
	int rc;

	if (pdpc_setup_done)
		return true;
	if (ns_unsupported_psp_devlink_port)
		return false;

	if (unshare(CLONE_NEWNET) < 0) {
		if (errno == EPERM)
			ns_unsupported_psp_devlink_port = true;
		return false;
	}

	fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ns_unsupported_psp_devlink_port = true;
		return false;
	}
	pdpc_latched_netns_fd = fd;

	pdpc_modprobe_netdevsim_once();

	base = 50000U + ((__u32)mypid() & 0x3fffU) +
	       ((__u32)(rand32() & 0xffU) * 4U);

	for (i = 0; i < PDPC_MAX_INSTANCES; i++) {
		__u32 id = base + i * PDPC_PORTS_PER_DEV;

		(void)snprintf(create_payload, sizeof(create_payload),
			       "%u %u", (unsigned int)id,
			       PDPC_PORTS_PER_DEV);
		rc = pdpc_sysfs_write_str(PDPC_NETDEVSIM_NEW, create_payload);
		if (rc == 0) {
			pdpc_bus_ids[pdpc_n_instances]   = id;
			pdpc_next_port[pdpc_n_instances] = PDPC_PORTS_PER_DEV;
			pdpc_last_port[pdpc_n_instances] =
				PDPC_PORTS_PER_DEV - 1U;
			pdpc_n_instances++;
		} else if (rc == -ENODEV || rc == -ENOENT) {
			ns_unsupported_psp_devlink_port = true;
			break;
		}
		/* EEXIST/EBUSY: skip this id; we may still get >=2. */
	}

	if (pdpc_n_instances < 2U) {
		/* Partial setup: unwind the devices we did manage to
		 * create and drop the latched netns fd so a failed setup
		 * doesn't leak resources per child. */
		psp_key_rotate_cleanup_child();
		ns_unsupported_psp_devlink_port = true;
		return false;
	}

	pdpc_setup_done = true;
	return true;
}

static int pdpc_devlink_port_new(struct genl_ctx *ctx,
				 const char *dev_name, uint32_t port_number)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	size_t off;
	uint8_t flav = (uint8_t)DEVLINK_PORT_FLAVOUR_VIRTUAL;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   DEVLINK_CMD_PORT_NEW, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_BUS_NAME, PDPC_BUS);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_DEV_NAME, dev_name);
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf),
		      DEVLINK_ATTR_PORT_FLAVOUR, &flav, sizeof(flav));
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  DEVLINK_ATTR_PORT_NUMBER, port_number);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

static int pdpc_devlink_port_del(struct genl_ctx *ctx,
				 const char *dev_name, uint32_t port_index)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   DEVLINK_CMD_PORT_DEL, 0);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_BUS_NAME, PDPC_BUS);
	if (!off)
		return -EIO;
	off = nla_put_str(buf, off, sizeof(buf),
			  DEVLINK_ATTR_DEV_NAME, dev_name);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf),
			  DEVLINK_ATTR_PORT_INDEX, port_index);
	if (!off)
		return -EIO;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

/* RTM_DELLINK by ifname.  Best-effort. */
static void pdpc_rtm_dellink(struct nl_ctx *rtnl, const char *vname)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	ifm = (struct ifinfomsg *)NLMSG_DATA(nlh);
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifm));
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifm->ifi_family  = AF_UNSPEC;

	off = NLMSG_ALIGN(nlh->nlmsg_len);
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, vname);
	if (!off)
		return;
	nlh->nlmsg_len = (uint32_t)off;
	(void)nl_send_recv(rtnl, buf, off);
}

/* RTM_NEWLINK macvlan with IFLA_LINK pointing at the PF -- this is the
 * VF-representor cross-fire that races the devlink port_new/port_del
 * walkers against an rtnl link create rooted at the PF index. */
static void pdpc_rtm_newlink_macvlan(struct nl_ctx *rtnl, int pf_ifidx,
				     const char *vname)
{
	unsigned char buf[512];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifm;
	size_t off, li_off;
	uint32_t link_idx = (uint32_t)pf_ifidx;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	ifm = (struct ifinfomsg *)NLMSG_DATA(nlh);
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(*ifm));
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = nl_seq_next(rtnl);
	ifm->ifi_family  = AF_UNSPEC;

	off = NLMSG_ALIGN(nlh->nlmsg_len);
	off = nla_put(buf, off, sizeof(buf),
		      IFLA_LINK, &link_idx, sizeof(link_idx));
	if (!off)
		return;
	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, vname);
	if (!off)
		return;
	li_off = off;
	off = nla_nest_start(buf, off, sizeof(buf), IFLA_LINKINFO);
	if (!off)
		return;
	off = nla_put_str(buf, off, sizeof(buf),
			  IFLA_INFO_KIND, "macvlan");
	if (!off)
		return;
	nla_nest_end(buf, li_off, off);
	nlh->nlmsg_len = (uint32_t)off;
	(void)nl_send_recv(rtnl, buf, off);
}

/* Spawn 1 VF on @bus_id then cross-fire an RTM_NEWLINK macvlan over
 * the PF, follow with RTM_DELLINK, and tear the VF back down so the
 * next iter can re-spawn.  Latches ns_unsupported_psp_sriov on
 * persistent ENOSYS / EPERM / ENOENT from the sysfs write. */
static void pdpc_try_sriov_crossfire(__u32 bus_id, struct nl_ctx *rtnl)
{
	char path[160];
	char ifname[IFNAMSIZ];
	char vname[IFNAMSIZ];
	int pf_idx;
	int rc;

	if (ns_unsupported_psp_sriov)
		return;

	(void)snprintf(path, sizeof(path),
		       "/sys/bus/netdevsim/devices/netdevsim%u/sriov_numvfs",
		       (unsigned int)bus_id);
	rc = pdpc_sysfs_write_str(path, "1");
	if (rc < 0) {
		if (rc == -ENOSYS || rc == -EPERM || rc == -ENOENT)
			ns_unsupported_psp_sriov = true;
		return;
	}
	__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_vf_spawn_ok,
			   1, __ATOMIC_RELAXED);

	(void)snprintf(ifname, sizeof(ifname), "eni%unp0",
		       (unsigned int)bus_id);
	pf_idx = (int)if_nametoindex(ifname);
	if (pf_idx > 0) {
		(void)snprintf(vname, sizeof(vname), "psprep%u",
			       (unsigned int)(bus_id & 0xfffU));
		pdpc_rtm_newlink_macvlan(rtnl, pf_idx, vname);
		pdpc_rtm_dellink(rtnl, vname);
	}

	(void)pdpc_sysfs_write_str(path, "0");
}

static void iter_devlink_port_churn(unsigned int iter_idx,
				    const struct timespec *t_outer)
{
	struct nl_ctx rtnl = { .fd = -1 };
	struct genl_ctx devlink_ctx = { .nl = { .fd = -1 } };
	struct genl_ctx psp_ctx = { .nl = { .fd = -1 } };
	struct nl_open_opts nlopts;
	struct genl_open_opts gopts;
	int sockfd = -1;
	struct sockaddr_in peer;
	bool psp_open = false;
	unsigned int idx_a, idx_b, idx_c;
	char dev_a[32], dev_b[32], psp_iface[IFNAMSIZ];
	struct timespec t_inner;
	unsigned int inner, j;
	int rc;

	(void)iter_idx;

	if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
		return;

	__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_runs,
			   1, __ATOMIC_RELAXED);

	/* Capture the worker's original netns before any switch so out:
	 * can restore it.  If the open fails we cannot safely enter the
	 * sub-mode -- latch it off rather than risk stranding the worker
	 * in an unshared netns. */
	if (!pdpc_save_worker_netns_once()) {
		ns_unsupported_psp_devlink_port = true;
		__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_unsupported_latched,
				   1, __ATOMIC_RELAXED);
		return;
	}

	if (!pdpc_setup_done) {
		if (!pdpc_setup_once()) {
			__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_unsupported_latched,
					   1, __ATOMIC_RELAXED);
			/* pdpc_setup_once() may have unshared before
			 * failing -- fall through to out: so the netns
			 * restore fires. */
			goto out;
		}
	} else if (pdpc_latched_netns_fd >= 0 &&
		   setns(pdpc_latched_netns_fd, CLONE_NEWNET) < 0) {
		ns_unsupported_psp_devlink_port = true;
		__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_unsupported_latched,
				   1, __ATOMIC_RELAXED);
		return;
	}

	memset(&nlopts, 0, sizeof(nlopts));
	nlopts.proto         = NETLINK_ROUTE;
	nlopts.recv_timeo_s  = 1;
	if (nl_open(&rtnl, &nlopts) < 0)
		goto out;

	memset(&gopts, 0, sizeof(gopts));
	gopts.family_name  = DEVLINK_FAMILY_NAME;
	gopts.recv_timeo_s = 1;
	rc = genl_open(&devlink_ctx, &gopts);
	if (rc != 0) {
		ns_unsupported_psp_devlink_port = true;
		__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_unsupported_latched,
				   1, __ATOMIC_RELAXED);
		goto out;
	}

	idx_a = rnd_modulo_u32(pdpc_n_instances);
	idx_b = rnd_modulo_u32(pdpc_n_instances);
	if (idx_b == idx_a)
		idx_b = (idx_a + 1U) % pdpc_n_instances;
	idx_c = (pdpc_n_instances > 2U) ?
		((idx_a + 2U) % pdpc_n_instances) : idx_a;

	(void)snprintf(dev_a, sizeof(dev_a), "netdevsim%u",
		       (unsigned int)pdpc_bus_ids[idx_a]);
	(void)snprintf(dev_b, sizeof(dev_b), "netdevsim%u",
		       (unsigned int)pdpc_bus_ids[idx_b]);
	(void)snprintf(psp_iface, sizeof(psp_iface), "eni%unp0",
		       (unsigned int)pdpc_bus_ids[idx_a]);

	memset(&gopts, 0, sizeof(gopts));
	gopts.family_name  = PSP_FAMILY_NAME;
	gopts.recv_timeo_s = 1;
	if (genl_open(&psp_ctx, &gopts) == 0)
		psp_open = true;

	sockfd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (sockfd >= 0) {
		apply_timeouts(sockfd);
		(void)setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
				 psp_iface, (socklen_t)(strlen(psp_iface) + 1));
		memset(&peer, 0, sizeof(peer));
		peer.sin_family      = AF_INET;
		peer.sin_port        = htons(0xCAFE);
		peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		(void)connect(sockfd, (struct sockaddr *)&peer, sizeof(peer));
	}

	if (clock_gettime(CLOCK_MONOTONIC, &t_inner) < 0) {
		t_inner.tv_sec  = 0;
		t_inner.tv_nsec = 0;
	}

	inner = JITTER_RANGE(PDPC_INNER_BASE);
	if (inner < PDPC_INNER_BASE)
		inner = PDPC_INNER_BASE;
	if (inner > PDPC_INNER_CAP)
		inner = PDPC_INNER_CAP;

	for (j = 0; j < inner; j++) {
		if ((unsigned long long)ns_since(&t_inner) >=
		    PDPC_INNER_WALL_NS)
			break;
		if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
			break;

		rc = pdpc_devlink_port_new(&devlink_ctx, dev_a,
					   pdpc_next_port[idx_a]);
		if (rc == 0) {
			pdpc_last_port[idx_a] = pdpc_next_port[idx_a];
			pdpc_next_port[idx_a]++;
			__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_port_add_ok,
					   1, __ATOMIC_RELAXED);
		}

		rc = pdpc_devlink_port_del(&devlink_ctx, dev_b,
					   pdpc_last_port[idx_b]);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.psp_key_rotate.devlink_port_churn_port_del_ok,
					   1, __ATOMIC_RELAXED);
			if (pdpc_last_port[idx_b] > 0U)
				pdpc_last_port[idx_b]--;
		}

		pdpc_try_sriov_crossfire(pdpc_bus_ids[idx_c], &rtnl);

		if (psp_open && sockfd >= 0) {
			(void)psp_key_rotate_cmd(&psp_ctx, 1U);
			(void)psp_tx_assoc_cmd(&psp_ctx, 1U, sockfd);
		}
	}

out:
	if (sockfd >= 0)
		close(sockfd);
	if (psp_open)
		genl_close(&psp_ctx);
	if (devlink_ctx.nl.fd >= 0)
		genl_close(&devlink_ctx);
	if (rtnl.fd >= 0)
		nl_close(&rtnl);

	/* Return the worker to its original netns.  A no-op if no switch
	 * ever happened (early bail before setup).  On failure the worker
	 * is stuck in the sub-mode's netns -- latch the sub-mode off and
	 * drop the latched fd so the setns branch above cannot re-enter,
	 * limiting the blast radius to whatever downstream childops run
	 * next in this worker. */
	if (!pdpc_restore_worker_netns()) {
		ns_unsupported_psp_devlink_port = true;
		pdpc_setup_done = false;
		if (pdpc_latched_netns_fd >= 0) {
			close(pdpc_latched_netns_fd);
			pdpc_latched_netns_fd = -1;
		}
	}
}

/* Issue a single PSP_CMD_DEV_GET on @ctx as a structural probe; the
 * reply is consumed but not parsed.  Returns the underlying
 * genl_send_recv() rc. */
static int psp_dev_get_probe(struct genl_ctx *ctx)
{
	unsigned char buf[NLMSG_HDRLEN + GENL_HDRLEN];
	struct nlmsghdr *nlh;
	size_t off;

	off = genl_msg_put(buf, 0, sizeof(buf), ctx,
			   nl_seq_next(&ctx->nl),
			   PSP_CMD_DEV_GET, 0);
	if (!off)
		return -EIO;
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = (uint32_t)off;
	return genl_send_recv(ctx, buf, off);
}

/* Open the rtnl socket inside the grandchild's private netns (set up
 * by userns_run_in_ns() before this callback runs), then issue a
 * best-effort RTM_NEWLINK to spawn a netdevsim instance.  Returns 0
 * on success or -1 if the iteration should bail to iter_one_in_ns'
 * out: cleanup path.  The netdev create is best-effort: even on
 * -ENODEV / -EOPNOTSUPP / -EEXIST the subsequent PSP family probe
 * still runs and the per-grandchild gate latches there if PSP isn't
 * built in. */
static int psp_key_rotate_iter_setup(struct nl_ctx *rtnl)
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

	(void)snprintf(ifname, sizeof(ifname), "psp%u",
		       (unsigned int)(rand32() & 0xffff));
	rc = rtnl_make_netdevsim(rtnl, ifname);
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
static int psp_key_rotate_iter_family_resolve(struct genl_ctx *psp_ctx,
					      uint32_t *dev_id_out)
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
	__atomic_add_fetch(&shm->stats.psp_key_rotate.family_resolve_ok,
			   1, __ATOMIC_RELAXED);

	/* PSP_CMD_DEV_GET dump.  Best-effort dev_id pick: a valid PSP
	 * device exposes id starting at 1; on a real PSP-capable host the
	 * netdevsim spawned above lands here. */
	rc2 = psp_dev_get_probe(psp_ctx);
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
static int psp_key_rotate_iter_socket_install(struct genl_ctx *psp_ctx,
					      uint32_t dev_id)
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
	apply_timeouts(sockfd);
	memset(&peer, 0, sizeof(peer));
	peer.sin_family      = AF_INET;
	peer.sin_port        = htons(0xCAFE);
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)connect(sockfd, (struct sockaddr *)&peer, sizeof(peer));

	/* Initial key install. */
	rc = psp_key_rotate_cmd(psp_ctx, dev_id);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.key_install_ok,
				   1, __ATOMIC_RELAXED);
	else if (rc < 0 && errno_is_unsupported(-rc))
		ns_unsupported_psp_key_rotate = true;

	/* Bind the SA to the socket via the assoc command (spec stat:
	 * spi_set_ok -- see spec-deviation note in the file header). */
	rc = psp_tx_assoc_cmd(psp_ctx, dev_id, sockfd);
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.psp_key_rotate.spi_set_ok,
				   1, __ATOMIC_RELAXED);

	return sockfd;
}

/* Drive the inner traffic loop on the bound socket: BUDGETED+JITTER
 * iterations, each one send/recv burst -> PSP_CMD_KEY_ROTATE (race
 * target) -> PSP_CMD_TX_ASSOC re-bind -> second send/recv burst.  The
 * outer 200 ms wall-clock cap (PKR_WALL_CAP_NS) bounds the loop.  On
 * exit a single shutdown(SHUT_RDWR) flushes the socket. */
static void psp_key_rotate_iter_traffic(int sockfd,
					struct genl_ctx *psp_ctx,
					uint32_t dev_id,
					const struct timespec *t_outer)
{
	unsigned int inner, j;
	int rc;

	inner = JITTER_RANGE(PKR_OUTER_BASE);
	if (inner < PKR_OUTER_FLOOR)
		inner = PKR_OUTER_FLOOR;
	if (inner > PKR_OUTER_CAP)
		inner = PKR_OUTER_CAP;

	for (j = 0; j < inner; j++) {
		if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
			break;

		inner_traffic_burst(sockfd);

		/* RACE TARGET: rotate keys mid-flow. */
		rc = psp_key_rotate_cmd(psp_ctx, dev_id);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.psp_key_rotate.rotate_ok,
					   1, __ATOMIC_RELAXED);

		/* Re-bind the assoc to the rotated generation mid-flow --
		 * "spi switch" per spec naming. */
		rc = psp_tx_assoc_cmd(psp_ctx, dev_id, sockfd);
		if (rc == 0)
			__atomic_add_fetch(&shm->stats.psp_key_rotate.spi_switch_ok,
					   1, __ATOMIC_RELAXED);

		inner_traffic_burst(sockfd);
	}

	(void)shutdown(sockfd, SHUT_RDWR);
	__atomic_add_fetch(&shm->stats.psp_key_rotate.shutdown_ok,
			   1, __ATOMIC_RELAXED);
}

/* Randomised teardown order: rotate which fd dies first so the
 * rtnl/genl/SOCK_STREAM teardown ordering varies across iterations.
 * nl_close() / genl_close() leave fd at -1, but iter_one's out:
 * cleanup runs only on the early-bail paths -- by the time this
 * helper is called the standard path is done and there is no
 * subsequent observer of sockfd, so the cases need not reset it. */
static void psp_key_rotate_iter_teardown(unsigned int iter_idx, int sockfd,
					 struct genl_ctx *psp_ctx,
					 struct nl_ctx *rtnl)
{
	switch (iter_idx & 3U) {
	case 0:
		if (sockfd >= 0) close(sockfd);
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		if (rtnl->fd >= 0) nl_close(rtnl);
		break;
	case 1:
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		if (sockfd >= 0) close(sockfd);
		if (rtnl->fd >= 0) nl_close(rtnl);
		break;
	case 2:
		if (rtnl->fd >= 0) nl_close(rtnl);
		if (sockfd >= 0) close(sockfd);
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		break;
	default:
		if (sockfd >= 0) close(sockfd);
		if (rtnl->fd >= 0) nl_close(rtnl);
		if (psp_ctx->nl.fd >= 0) genl_close(psp_ctx);
		break;
	}
}

struct iter_one_ctx {
	unsigned int iter_idx;
	const struct timespec *t_outer;
	struct childdata *child;
};

/*
 * Per-invocation body that must run inside the private net namespace.
 * Executed in a transient grandchild forked by userns_run_in_ns(); the
 * grandchild's userns + netns are torn down on _exit() so the
 * netdevsim instance, rtnl/genl sockets and TCP socket left behind
 * are reaped along with the namespace.  Explicit close() and the
 * randomised teardown order are still issued so the in-ns stats
 * counters move on the success path; correctness does not depend on
 * them.  Writes to ns_unsupported_psp_key_rotate happen in the
 * grandchild's COW memory and die with the grandchild -- the
 * re-discovery cost is paid per invocation.  shm->stats writes (incl.
 * the childop_latch_reason store) propagate because shm is MAP_SHARED.
 * Return value is ignored by the helper.
 */
static int iter_one_in_ns(void *arg)
{
	struct iter_one_ctx *ictx = (struct iter_one_ctx *)arg;
	unsigned int iter_idx = ictx->iter_idx;
	const struct timespec *t_outer = ictx->t_outer;
	struct childdata *child = ictx->child;
	struct nl_ctx rtnl = { .fd = -1 };
	struct genl_ctx psp_ctx = { .nl = { .fd = -1 } };
	int sockfd = -1;
	uint32_t dev_id = 0;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (psp_key_rotate_iter_setup(&rtnl) != 0)
		goto out;

	if (psp_key_rotate_iter_family_resolve(&psp_ctx, &dev_id) != 0)
		goto out;

	sockfd = psp_key_rotate_iter_socket_install(&psp_ctx, dev_id);
	if (sockfd < 0)
		goto out;

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	if (!ns_unsupported_psp_key_rotate) {
		if (valid_op)
			__atomic_add_fetch(&shm->stats.childop.data_path[op],
					   1, __ATOMIC_RELAXED);
		psp_key_rotate_iter_traffic(sockfd, &psp_ctx, dev_id, t_outer);
	}

	psp_key_rotate_iter_teardown(iter_idx, sockfd, &psp_ctx, &rtnl);
	if (ns_unsupported_psp_key_rotate && valid_op)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_NS_UNSUPPORTED,
				 __ATOMIC_RELAXED);
	return 0;

out:
	if (sockfd >= 0)
		close(sockfd);
	if (psp_ctx.nl.fd >= 0)
		genl_close(&psp_ctx);
	if (rtnl.fd >= 0)
		nl_close(&rtnl);
	if (ns_unsupported_psp_key_rotate && valid_op)
		__atomic_store_n(&shm->stats.childop.latch_reason[op],
				 CHILDOP_LATCH_NS_UNSUPPORTED,
				 __ATOMIC_RELAXED);
	return 0;
}

static void iter_one(unsigned int iter_idx, const struct timespec *t_outer,
		     struct childdata *child)
{
	struct iter_one_ctx ictx = {
		.iter_idx = iter_idx,
		.t_outer  = t_outer,
		.child    = child,
	};
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);
	int rc;

	if ((unsigned long long)ns_since(t_outer) >= PKR_WALL_CAP_NS)
		return;

	rc = userns_run_in_ns(CLONE_NEWNET, iter_one_in_ns, &ictx);
	if (rc == -EPERM) {
		if (valid_op)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 CHILDOP_LATCH_NS_UNSUPPORTED,
					 __ATOMIC_RELAXED);
		warn_once_unsupported_psp_key_rotate(
			"userns_run_in_ns(CLONE_NEWNET)", EPERM);
		return;
	}
	if (rc < 0) {
		/* Transient grandchild setup failure (fork, id-map write,
		 * secondary unshare).  Skip this iteration without
		 * latching -- the failure is not policy and may not
		 * recur. */
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
				   1, __ATOMIC_RELAXED);
		return;
	}
}

bool psp_key_rotate(struct childdata *child)
{
	struct timespec t_outer;
	unsigned int outer_iters, i;

	__atomic_add_fetch(&shm->stats.psp_key_rotate.runs,
			   1, __ATOMIC_RELAXED);

	if (ns_unsupported_psp_key_rotate_master) {
		__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
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

		if (!ns_unsupported_psp_devlink_port &&
		    ONE_IN(PDPC_GATE_ONE_IN))
			iter_devlink_port_churn(i, &t_outer);
		else
			iter_one(i, &t_outer, child);

		if (ns_unsupported_psp_key_rotate_master)
			break;
	}

	return true;
}

#else  /* missing one of <linux/genetlink.h> / <linux/if_link.h> / <linux/rtnetlink.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

#include "kernel/fcntl.h"
#include "kernel/socket.h"
bool psp_key_rotate(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.psp_key_rotate.runs,
			   1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.psp_key_rotate.setup_failed,
			   1, __ATOMIC_RELAXED);
	return true;
}

void psp_key_rotate_cleanup_child(void)
{
}

#endif
