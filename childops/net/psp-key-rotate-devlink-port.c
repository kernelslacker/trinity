/*
 * psp-key-rotate-devlink-port - devlink port churn sub-mode carved out
 * of childops/net/psp-key-rotate.c.  Shares the psp_key_rotate childop
 * slot but targets a different bug shape: parallel devlink port
 * add/del across multiple netdevsim instances overlapped with PSP
 * TX_ASSOC + KEY_ROTATE on a netdev-bound TCP socket, plus optional
 * SR-IOV VF spawn with an RTM_NEWLINK macvlan carrying IFLA_LINK
 * pointing at the PF index (the cross-fire path).
 *
 * Setup is latched per-process: the sub-mode unshares CLONE_NEWNET
 * once, holds an fd to that netns, modprobes netdevsim, and spawns
 * 2-3 instances with 2 ports each via /sys/bus/netdevsim/new_device.
 * Subsequent calls setns(CLONE_NEWNET) back into the latched netns so
 * the netdevsim instances stay reachable across iterations even when
 * the base iter_one path does its own per-call unshare.
 *
 * Owns:
 *
 *   iter_devlink_port_churn         - the sub-mode entry point invoked
 *                                     by the top-level coordinator in
 *                                     psp-key-rotate.c under
 *                                     ONE_IN(PDPC_GATE_ONE_IN);
 *   psp_key_rotate_cleanup_child    - the per-child cleanup path
 *                                     wired into child_process()'s
 *                                     out: cleanup (external symbol
 *                                     declared in include/child-api.h);
 *   pdpc_* helpers                  - private setup, sysfs writers,
 *                                     devlink port_new / port_del,
 *                                     RTM_DELLINK / macvlan builders,
 *                                     and the SR-IOV cross-fire.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "childops-genl.h"
#include "childops-util.h"
#include "jitter.h"
#include "pids.h"
#include "random.h"
#include "shm.h"
#include "signals.h"

#include "kernel/psp.h"

#include "psp-key-rotate-internal.h"

/* devlink genl UAPI integers (mainlined long before 6.10).  Supplied as
 * fallbacks for stripped sysroots that omit <linux/devlink.h>.  The
 * #ifndef guards mean these shim values ARE the ones actually sent to
 * the kernel on any host whose installed headers do not define the
 * symbol — the header wins only where it already exists.  Wrong values
 * in the valid enum range cause silent misbehaviour (no -EOPNOTSUPP),
 * so each shim must carry the correct kernel value for old-header
 * builds.  The sub-mode latches ns_unsupported_psp_devlink_port on
 * persistent failures regardless. */
#ifndef DEVLINK_FAMILY_NAME
#define DEVLINK_FAMILY_NAME		"devlink"
#endif
#ifndef DEVLINK_CMD_PORT_NEW
#define DEVLINK_CMD_PORT_NEW		7
#endif
#ifndef DEVLINK_CMD_PORT_DEL
#define DEVLINK_CMD_PORT_DEL		8
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
#define DEVLINK_ATTR_PORT_NUMBER	78
#endif

#define PDPC_BUS			"netdevsim"
#define PDPC_NETDEVSIM_NEW		"/sys/bus/netdevsim/new_device"
#define PDPC_NETDEVSIM_DEL		"/sys/bus/netdevsim/del_device"
#define PDPC_MAX_INSTANCES		3U
#define PDPC_PORTS_PER_DEV		2U
#define PDPC_INNER_BASE			4U
#define PDPC_INNER_CAP			8U
#define PDPC_INNER_WALL_NS		(100ULL * 1000ULL * 1000ULL)

bool ns_unsupported_psp_devlink_port;
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
		CHILDOP_GRANDCHILD_ENTER();
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

void iter_devlink_port_churn(unsigned int iter_idx,
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

#else  /* missing one of <linux/genetlink.h> / <linux/if_link.h> / <linux/rtnetlink.h> */

#include "child.h"

void psp_key_rotate_cleanup_child(void)
{
}

#endif
