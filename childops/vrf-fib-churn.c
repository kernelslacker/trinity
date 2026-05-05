/*
 * vrf_fib_churn - VRF / FIB-rule jump-table churn under a bound socket.
 *
 * Flat fuzzing of NETLINK_ROUTE almost never assembles the multi-step
 * dance that drives the l3mdev jump-table: a VRF link only routes via
 * its private FIB table when (a) a fib-rule with FRA_TABLE=N exists,
 * (b) a socket is SO_BINDTODEVICE'd to the VRF, and (c) the bound
 * socket actually emits traffic.  Without (a) the rule list never
 * produces a jump entry, without (b) l3mdev_fib_table is never called,
 * without (c) the FIB lookup never enters fib_trie at all.  This
 * childop assembles the chain, then mid-traffic mutates the rule
 * list and tears the VRF down — the bug class is replace/delete-
 * while-walk inside the rcu-protected rule walker.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) into a private net namespace so any
 *      mutation we make never touches the host main routing table.
 *      Failure (EPERM, no user-namespace privilege) latches the
 *      childop off for the remainder of this child's lifetime.
 *   2. RTM_NEWLINK kind="vrf" with IFLA_VRF_TABLE = N (random
 *      table id in [1024, 524287], well above the kernel's reserved
 *      main/local/default at 254/255/253).
 *   3. RTM_NEWADDR ipv4 /24 on the new VRF dev (any 169.254.x.y).
 *   4. RTM_NEWLINK setlink to bring the dev up (IFF_UP).
 *   5. RTM_NEWRULE with FRA_TABLE=N, FRA_PRIORITY=P (random P).
 *   6. socket(AF_INET, SOCK_DGRAM); SO_BINDTODEVICE = vrf name.
 *   7. sendto a random unreachable destination — this drives
 *      l3mdev_fib_table on the bound socket.  EHOSTUNREACH /
 *      ENETUNREACH on send is fine; the kernel side has already
 *      walked the rule list and the l3mdev jump.
 *   8. RTM_NEWRULE with a HIGHER-priority rule (P-1) targeting the
 *      same table while traffic is still in flight.  The replace-
 *      while-walk window is the targeted race.
 *   9. RTM_DELRULE the original rule (and the higher-priority rule).
 *  10. RTM_DELLINK the VRF.  Final teardown leaves the namespace
 *      empty for the next iteration.
 *
 * CVE class: l3mdev rcu race (CVE-2022-3543 lineage), FRA_PROTOCOL
 * parsing, fib_rule replace-while-walk UAF.  Subsystems reached:
 * net/core/l3mdev.c (jump table + bound-socket lookup), net/ipv4/
 * fib_rules.c (rule add/delete/walk), net/ipv4/fib_trie.c (lookup
 * under l3mdev), drivers/net/vrf.c (link create/delete + setup).
 *
 * Self-bounding: one full cycle per invocation.  All sockets and the
 * rtnl fd are O_CLOEXEC; SO_RCVTIMEO is set on the rtnl socket so an
 * unresponsive netlink path can't wedge the child past the alarm(1)
 * cap.  Failure on every step (EPERM in the host namespace, ENODEV
 * on the bind, EINVAL from a kernel without CONFIG_NET_VRF / no
 * fib_rules) is treated as benign coverage rather than childop
 * failure.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/fib_rules.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef IFLA_VRF_TABLE
#define IFLA_VRF_TABLE	1
#endif

/* Random table-id range: above the kernel's reserved 253 (default),
 * 254 (main), 255 (local), and outside of the small set of common
 * userspace-reserved IDs.  Caps at ~525k so the ID encodes cleanly
 * into the four-byte u32 attribute payload while staying memorable
 * in the per-namespace state if we ever inspect it under gdb. */
#define VRF_TABLE_MIN		1024U
#define VRF_TABLE_RANGE		524288U	/* gives [1024, 525311] */

/* Rule-priority window.  Linux fib-rule priorities are u32; the
 * built-in defaults sit at 0 (local), 32766 (main), 32767 (default).
 * Pick well below 32766 so we never have to negotiate against the
 * built-ins. */
#define VRF_PRIO_MIN		1024U
#define VRF_PRIO_RANGE		16384U	/* gives [1024, 17407] */

#define RTNL_BUF_BYTES		2048
#define RTNL_RECV_TIMEO_S	1

/* Latched per-child: unshare(CLONE_NEWNET) returned EPERM (or any
 * other fatal error) once.  Trinity doesn't grant CAP_SYS_ADMIN
 * inside the host namespace under default execution, and we MUST
 * NOT touch the host's main routing table — so when we can't enter
 * a private netns we permanently disable the op for this child. */
static bool ns_unsupported;

/* Latched once a successful unshare puts us in a private netns.
 * The trinity child process is long-lived; we only need to unshare
 * once and inherit the private namespace across subsequent
 * invocations.  Re-unsharing each call would just leak namespaces. */
static bool ns_unshared;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static int rtnl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = RTNL_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	return fd;
}

/*
 * Append a flat NLA at *off with the given type and payload.
 * Returns the new offset, or 0 on overflow (caller treats 0 as fail).
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

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Send a complete netlink message and wait for an NLMSG_ERROR (ack).
 * Returns the kernel's ack errno (0 on success, negated errno on
 * rejection, or -EIO on local send/recv failure).  The buffer must
 * already contain a single nlmsghdr at offset 0 with NLM_F_ACK set.
 */
static int rtnl_send_recv(int fd, void *msg, size_t len)
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

	if (sendmsg(fd, &mh, 0) < 0)
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
	return -EIO;
}

/*
 * Build & send RTM_NEWLINK creating a VRF dev named `name` bound to
 * routing table `table`.  Returns 0 on accept, negated errno on
 * rejection, or -EIO on local failure.
 */
static int build_vrf_link(int fd, const char *name, __u32 table)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	struct nlattr *infodata;
	size_t off;
	size_t li_off, id_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = nla_put_str(buf, off, sizeof(buf), IFLA_IFNAME, name);
	if (!off)
		return -EIO;

	li_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "vrf");
	if (!off)
		return -EIO;

	id_off = off;
	off = nla_put(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off)
		return -EIO;

	off = nla_put_u32(buf, off, sizeof(buf), IFLA_VRF_TABLE, table);
	if (!off)
		return -EIO;

	infodata = (struct nlattr *)(buf + id_off);
	infodata->nla_len = (unsigned short)(off - id_off);

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * Build & send RTM_NEWADDR adding an IPv4 /24 address to ifindex.
 * Address is link-local (169.254.x.y) so even if the host accidentally
 * sees it, the prefix is non-routable.
 */
static int build_addaddr(int fd, int ifindex)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifaddrmsg *ifa;
	__u32 addr;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWADDR;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_seq();

	ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
	ifa->ifa_family    = AF_INET;
	ifa->ifa_prefixlen = 24;
	ifa->ifa_flags     = 0;
	ifa->ifa_scope     = RT_SCOPE_UNIVERSE;
	ifa->ifa_index     = (unsigned int)ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifa));

	addr = htonl(0xa9fe0000u | (rand32() & 0x0000fffeu) | 1u);
	off = nla_put(buf, off, sizeof(buf), IFA_LOCAL, &addr, sizeof(addr));
	if (!off)
		return -EIO;
	off = nla_put(buf, off, sizeof(buf), IFA_ADDRESS, &addr, sizeof(addr));
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * Build & send RTM_NEWLINK setlink to bring ifindex up (IFF_UP).
 * No flags are cleared — only IFF_UP is set in ifi_change so the
 * existing flag bits stay intact.
 */
static int build_setlink_up(int fd, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

/*
 * Build & send RTM_NEWRULE / RTM_DELRULE for an IPv4 fib-rule
 * targeting `table` at priority `prio`.  Pass `cmd` = RTM_NEWRULE or
 * RTM_DELRULE.  NLM_F_CREATE|NLM_F_EXCL on add; bare flags on del.
 */
static int build_rule(int fd, int cmd, __u32 table, __u32 prio)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct fib_rule_hdr *frh;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = (unsigned short)cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	if (cmd == RTM_NEWRULE)
		nlh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq = next_seq();

	frh = (struct fib_rule_hdr *)NLMSG_DATA(nlh);
	frh->family = AF_INET;
	frh->action = FR_ACT_TO_TBL;
	frh->table  = (table < 256) ? (__u8)table : RT_TABLE_UNSPEC;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*frh));

	off = nla_put_u32(buf, off, sizeof(buf), FRA_TABLE, table);
	if (!off)
		return -EIO;
	off = nla_put_u32(buf, off, sizeof(buf), FRA_PRIORITY, prio);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

static int build_dellink(int fd, int ifindex)
{
	unsigned char buf[128];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv(fd, buf, off);
}

bool vrf_fib_churn(struct childdata *child)
{
	char vrf_name[IFNAMSIZ];
	int rtnl = -1;
	int udp = -1;
	int ifindex = 0;
	__u32 table;
	__u32 prio;
	bool rule_added = false;
	bool rule2_added = false;
	bool link_added = false;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.vrf_fib_churn_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_unsupported = true;
			__atomic_add_fetch(&shm->stats.vrf_fib_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	rtnl = rtnl_open();
	if (rtnl < 0) {
		__atomic_add_fetch(&shm->stats.vrf_fib_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	snprintf(vrf_name, sizeof(vrf_name), "trvrf%u",
		 (unsigned int)(rand32() & 0xffffu));
	table = VRF_TABLE_MIN + (rand32() % VRF_TABLE_RANGE);
	prio  = VRF_PRIO_MIN  + (rand32() % VRF_PRIO_RANGE);

	rc = build_vrf_link(rtnl, vrf_name, table);
	if (rc != 0)
		goto out;
	link_added = true;
	__atomic_add_fetch(&shm->stats.vrf_fib_churn_link_ok,
			   1, __ATOMIC_RELAXED);

	ifindex = (int)if_nametoindex(vrf_name);
	if (ifindex == 0)
		goto out;

	if (build_addaddr(rtnl, ifindex) == 0)
		__atomic_add_fetch(&shm->stats.vrf_fib_churn_addr_ok,
				   1, __ATOMIC_RELAXED);

	if (build_setlink_up(rtnl, ifindex) == 0)
		__atomic_add_fetch(&shm->stats.vrf_fib_churn_up_ok,
				   1, __ATOMIC_RELAXED);

	if (build_rule(rtnl, RTM_NEWRULE, table, prio) == 0) {
		rule_added = true;
		__atomic_add_fetch(&shm->stats.vrf_fib_churn_rule_added,
				   1, __ATOMIC_RELAXED);
	}

	udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (udp < 0)
		goto out;

	if (setsockopt(udp, SOL_SOCKET, SO_BINDTODEVICE,
		       vrf_name, (socklen_t)strlen(vrf_name)) == 0)
		__atomic_add_fetch(&shm->stats.vrf_fib_churn_bound,
				   1, __ATOMIC_RELAXED);

	/* Drive the bound-socket FIB lookup through l3mdev_fib_table.
	 * Destination is a random 240/4 (reserved) address so we never
	 * actually exit the host even if something escapes the netns;
	 * EHOSTUNREACH / ENETUNREACH back from the kernel is the
	 * expected outcome and means we hit the rule walker. */
	{
		struct sockaddr_in dst;
		ssize_t n;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		dst.sin_addr.s_addr = htonl(0xf0000000u |
					    (rand32() & 0x0fffffffu));
		dst.sin_port = htons(53);
		n = sendto(udp, "x", 1, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst));
		if (n >= 0)
			__atomic_add_fetch(&shm->stats.vrf_fib_churn_sendto_ok,
					   1, __ATOMIC_RELAXED);
	}

	/* Insert a HIGHER-priority rule mid-traffic.  The window between
	 * the bound socket's FIB walk and this rule insertion is the
	 * targeted replace-while-walk race. */
	if (prio > 0) {
		if (build_rule(rtnl, RTM_NEWRULE, table, prio - 1) == 0) {
			rule2_added = true;
			__atomic_add_fetch(&shm->stats.vrf_fib_churn_rule2_added,
					   1, __ATOMIC_RELAXED);
		}
	}

out:
	if (udp >= 0)
		close(udp);

	if (rtnl >= 0) {
		if (rule2_added)
			(void)build_rule(rtnl, RTM_DELRULE, table, prio - 1);
		if (rule_added) {
			if (build_rule(rtnl, RTM_DELRULE, table, prio) == 0)
				__atomic_add_fetch(&shm->stats.vrf_fib_churn_rule_removed,
						   1, __ATOMIC_RELAXED);
		}
		if (link_added && ifindex > 0) {
			if (build_dellink(rtnl, ifindex) == 0)
				__atomic_add_fetch(&shm->stats.vrf_fib_churn_link_removed,
						   1, __ATOMIC_RELAXED);
		}
		close(rtnl);
	}

	return true;
}
