/*
 * veth_asymmetric_xdp - asymmetric-queue veth pair + XDP_REDIRECT prog +
 * raw packet burst, aimed at the veth tx-queue lookup OOB shape that
 * upstream commit 08f566e8f83b ("veth: prevent NULL pointer dereference in
 * veth_xdp_rcv_one()" and the surrounding asymmetric-queue handling) was
 * about: when the receiving veth has fewer rx queues than the sending
 * veth has tx queues (or vice-versa), skb_get_tx_queue() / hash-modulo
 * selection on the rcv side can index past the per-queue array.  Random
 * isolated syscall fuzzing essentially never assembles all of (a) a veth
 * pair created with explicit IFLA_NUM_{TX,RX}_QUEUES on BOTH ends with
 * mismatched values, (b) an XDP program attached, and (c) live packet
 * traffic through the resulting pair, in a single child's lifetime.  This
 * childop drives the full sequence per outer iteration so the txq lookup
 * path actually runs against an asymmetric pair under XDP.
 *
 * Per iteration:
 *   (a) unshare(CLONE_NEWNET) once per child.  EPERM latches off.
 *   (b) RTM_NEWLINK creating veth pair with random N != M choices for
 *       primary (IFLA_NUM_TX_QUEUES=N, IFLA_NUM_RX_QUEUES=M) and the
 *       peer (NUM_TX_QUEUES=M', NUM_RX_QUEUES=N') asymmetric vs the
 *       primary so neither side has matching {tx,rx} counts.
 *   (c) RTM_NEWLINK SET IFF_UP on both ends.
 *   (d) bpf(BPF_PROG_LOAD, BPF_PROG_TYPE_XDP) for "r0 = XDP_REDIRECT;
 *       exit".  Two-insn opaque blob; no map dependency.  Loadable on
 *       any kernel that accepts unprivileged XDP load (the runtime
 *       redirect will fail without an installed map, but the program
 *       returning XDP_REDIRECT is enough to walk the kernel's
 *       xdp_do_redirect path on the rcv side).
 *   (e) Attach the prog to veth_a via RTM_NEWLINK + nested IFLA_XDP
 *       carrying IFLA_XDP_FD + IFLA_XDP_FLAGS=XDP_FLAGS_SKB_MODE.  SKB
 *       mode works without driver native-XDP support and is what veth
 *       always falls back to anyway.
 *   (f) AF_PACKET / SOCK_RAW socket bound to veth_b's ifindex, sendto
 *       a 4-16 frame burst of small ethernet+IP+UDP-shaped payloads
 *       targeting veth_a.  Hash-driven txq selection on the rcv side
 *       walks the asymmetric-queue array.
 *   (g) RTM_DELLINK veth_a (cascades to peer).  Close prog + raw fds.
 *
 * Latches:
 *   ns_unsupported_veth -- first ENOENT/EOPNOTSUPP from veth NEWLINK
 *                          (kernel module missing).
 *   ns_unsupported_xdp  -- first EPERM/EINVAL from BPF_PROG_LOAD.
 *                          Kept separate so a missing veth doesn't
 *                          disable the XDP latch and vice-versa.
 *
 * TODO: extend to vxcan/ipvlan/macvlan paired netdev types -- same
 * asymmetric-queue lookup pattern likely lurks. ~30 LOC each.
 */

#if __has_include(<linux/if_link.h>) && __has_include(<linux/bpf.h>)

#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "bpf.h"
#include "child.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#ifndef IFLA_NUM_TX_QUEUES
#define IFLA_NUM_TX_QUEUES		31
#endif
#ifndef IFLA_NUM_RX_QUEUES
#define IFLA_NUM_RX_QUEUES		32
#endif
#ifndef IFLA_VETH_INFO_PEER
#define IFLA_VETH_INFO_PEER		1
#endif
#ifndef IFLA_XDP
#define IFLA_XDP			43
#endif
#ifndef IFLA_XDP_FD
#define IFLA_XDP_FD			1
#define IFLA_XDP_FLAGS			3
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE		(1U << 1)
#endif
#ifndef BPF_PROG_TYPE_XDP
#define BPF_PROG_TYPE_XDP		6
#endif

#define VAX_BUF				512
#define VAX_BURST_MIN			4U
#define VAX_BURST_MAX			16U

static const __u8 q_choices[] = { 1, 2, 4, 8 };

static bool ns_unsupported_veth;
static bool ns_unsupported_xdp;
static bool vax_unshared;
static __u32 g_seq;
static __u32 g_iter;

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

static size_t vax_nla(unsigned char *buf, size_t off, size_t cap,
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

static size_t vax_nla_u32(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u32 v)
{
	return vax_nla(buf, off, cap, type, &v, sizeof(v));
}

static size_t vax_nla_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return vax_nla(buf, off, cap, type, s, strlen(s) + 1);
}

static int vax_rtnl_open(void)
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
	tv.tv_sec  = 1;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int vax_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[512];
	struct nlmsghdr *r;
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
	if (n < 0 || (size_t)n < NLMSG_HDRLEN)
		return -EIO;
	r = (struct nlmsghdr *)rbuf;
	if (r->nlmsg_type == NLMSG_ERROR)
		return ((struct nlmsgerr *)NLMSG_DATA(r))->error;
	return -EIO;
}

/*
 * RTM_NEWLINK creating an asymmetric-queue veth pair.  Primary side
 * gets (ntx, nrx); peer gets (ptx, prx).  Caller picks values from
 * q_choices[] such that ntx != nrx, ptx != prx, and ntx != ptx so
 * neither end matches the other and the rcv-side hash-mod-queues
 * lookup can wander.
 */
static int vax_create_pair(int fd, const char *a, const char *b,
			   __u32 ntx, __u32 nrx, __u32 ptx, __u32 prx)
{
	unsigned char buf[VAX_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi, *peer_ifi;
	struct nlattr *li, *id, *peer;
	size_t off, li_off, id_off, peer_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = ++g_seq;

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = vax_nla_str(buf, off, sizeof(buf), IFLA_IFNAME, a);
	if (!off) return -EIO;
	off = vax_nla_u32(buf, off, sizeof(buf), IFLA_NUM_TX_QUEUES, ntx);
	if (!off) return -EIO;
	off = vax_nla_u32(buf, off, sizeof(buf), IFLA_NUM_RX_QUEUES, nrx);
	if (!off) return -EIO;

	li_off = off;
	off = vax_nla(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off) return -EIO;
	off = vax_nla_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "veth");
	if (!off) return -EIO;
	id_off = off;
	off = vax_nla(buf, off, sizeof(buf), IFLA_INFO_DATA, NULL, 0);
	if (!off) return -EIO;
	peer_off = off;
	off = vax_nla(buf, off, sizeof(buf), IFLA_VETH_INFO_PEER, NULL, 0);
	if (!off) return -EIO;

	if (off + NLMSG_ALIGN(sizeof(*peer_ifi)) > sizeof(buf))
		return -EIO;
	peer_ifi = (struct ifinfomsg *)(buf + off);
	memset(peer_ifi, 0, sizeof(*peer_ifi));
	peer_ifi->ifi_family = AF_UNSPEC;
	off += NLMSG_ALIGN(sizeof(*peer_ifi));

	off = vax_nla_str(buf, off, sizeof(buf), IFLA_IFNAME, b);
	if (!off) return -EIO;
	off = vax_nla_u32(buf, off, sizeof(buf), IFLA_NUM_TX_QUEUES, ptx);
	if (!off) return -EIO;
	off = vax_nla_u32(buf, off, sizeof(buf), IFLA_NUM_RX_QUEUES, prx);
	if (!off) return -EIO;

	peer = (struct nlattr *)(buf + peer_off);
	peer->nla_len = (unsigned short)(off - peer_off);
	id = (struct nlattr *)(buf + id_off);
	id->nla_len = (unsigned short)(off - id_off);
	li = (struct nlattr *)(buf + li_off);
	li->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return vax_send_recv(fd, buf, off);
}

static int vax_setlink_up(int fd, int ifindex)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = ++g_seq;
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return vax_send_recv(fd, buf, off);
}

static int vax_dellink(int fd, int ifindex)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = ++g_seq;
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return vax_send_recv(fd, buf, off);
}

/*
 * RTM_NEWLINK SET with nested IFLA_XDP { IFLA_XDP_FD, IFLA_XDP_FLAGS=
 * XDP_FLAGS_SKB_MODE } -- attach (prog_fd >= 0) or detach (prog_fd = -1)
 * the XDP program on @ifindex.
 */
static int vax_xdp_attach(int fd, int ifindex, int prog_fd)
{
	unsigned char buf[VAX_BUF];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *xdp_nest;
	size_t off, x_off;
	__u32 flags = XDP_FLAGS_SKB_MODE;
	__s32 fdval = prog_fd;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = ++g_seq;
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	x_off = off;
	off = vax_nla(buf, off, sizeof(buf), IFLA_XDP, NULL, 0);
	if (!off) return -EIO;
	off = vax_nla(buf, off, sizeof(buf), IFLA_XDP_FD, &fdval, sizeof(fdval));
	if (!off) return -EIO;
	off = vax_nla(buf, off, sizeof(buf), IFLA_XDP_FLAGS, &flags, sizeof(flags));
	if (!off) return -EIO;
	xdp_nest = (struct nlattr *)(buf + x_off);
	xdp_nest->nla_len = (unsigned short)(off - x_off);
	nlh->nlmsg_len = (__u32)off;
	return vax_send_recv(fd, buf, off);
}

/*
 * Two-instruction XDP program: r0 = XDP_REDIRECT (3); exit.  No map,
 * no helper call -- the kernel's verifier accepts it; runtime
 * xdp_do_redirect() returns -EINVAL because no bpf_redirect_info was
 * stamped, but the rcv-side walked the XDP path before deciding to
 * drop, which is the goal.
 */
static int vax_load_xdp_prog(void)
{
	struct bpf_insn insns[] = {
		EBPF_MOV64_IMM(BPF_REG_0, 3),
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insn_cnt  = ARRAY_SIZE(insns);
	attr.insns     = (uintptr_t)insns;
	attr.license   = (uintptr_t)license;
	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static __u32 pick_q(void)
{
	return q_choices[rand32() % ARRAY_SIZE(q_choices)];
}

bool veth_asymmetric_xdp(struct childdata *child)
{
	int rtnl = -1, prog_fd = -1, raw = -1;
	int a_idx = 0, b_idx = 0;
	__u32 ntx, nrx, ptx, prx;
	unsigned int burst, i;
	char a_name[IFNAMSIZ], b_name[IFNAMSIZ];
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.veth_asym_iters, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_veth)
		return true;

	if (!vax_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			if (errno == EPERM || errno == EACCES) {
				ns_unsupported_veth = true;
				__atomic_add_fetch(&shm->stats.veth_asym_eperm,
						   1, __ATOMIC_RELAXED);
			}
			return true;
		}
		vax_unshared = true;
	}

	rtnl = vax_rtnl_open();
	if (rtnl < 0)
		goto out;

	/* Asymmetric: ntx != nrx and (ntx,nrx) != (ptx,prx).  Bounded
	 * roll loop -- q_choices has 4 entries so a few rolls suffice. */
	for (i = 0; i < 8; i++) {
		ntx = pick_q();
		nrx = pick_q();
		ptx = pick_q();
		prx = pick_q();
		if (ntx != nrx && ptx != prx && (ntx != ptx || nrx != prx))
			break;
	}

	g_iter++;
	snprintf(a_name, sizeof(a_name), "vax%ua", g_iter & 0xffffU);
	snprintf(b_name, sizeof(b_name), "vax%ub", g_iter & 0xffffU);

	rc = vax_create_pair(rtnl, a_name, b_name, ntx, nrx, ptx, prx);
	if (rc != 0) {
		if (rc == -ENOENT || rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT) {
			ns_unsupported_veth = true;
			__atomic_add_fetch(&shm->stats.veth_asym_unsupported,
					   1, __ATOMIC_RELAXED);
		} else if (rc == -EPERM) {
			__atomic_add_fetch(&shm->stats.veth_asym_eperm,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	a_idx = (int)if_nametoindex(a_name);
	b_idx = (int)if_nametoindex(b_name);
	if (a_idx <= 0 || b_idx <= 0)
		goto out;

	__atomic_add_fetch(&shm->stats.veth_asym_pair_ok, 1, __ATOMIC_RELAXED);

	(void)vax_setlink_up(rtnl, a_idx);
	(void)vax_setlink_up(rtnl, b_idx);

	if (!ns_unsupported_xdp) {
		prog_fd = vax_load_xdp_prog();
		if (prog_fd < 0) {
			if (errno == EPERM || errno == EACCES ||
			    errno == EINVAL || errno == EOPNOTSUPP) {
				ns_unsupported_xdp = true;
				__atomic_add_fetch(&shm->stats.veth_asym_unsupported,
						   1, __ATOMIC_RELAXED);
			}
		} else if (vax_xdp_attach(rtnl, a_idx, prog_fd) == 0) {
			__atomic_add_fetch(&shm->stats.veth_asym_xdp_attach_ok,
					   1, __ATOMIC_RELAXED);
		}
	}

	/* Raw send into veth_b.  Frames are eth+IPv4+UDP-shaped garbage --
	 * sufficient to drive the kernel's hash-modulo txq selection on the
	 * rcv (veth_a) side under the asymmetric-queue config. */
	raw = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
	if (raw >= 0) {
		struct sockaddr_ll sll;
		unsigned char frame[64];

		memset(&sll, 0, sizeof(sll));
		sll.sll_family   = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_IP);
		sll.sll_ifindex  = b_idx;
		sll.sll_halen    = 6;
		memset(sll.sll_addr, 0xff, 6);

		burst = VAX_BURST_MIN +
			(rand32() % (VAX_BURST_MAX - VAX_BURST_MIN + 1U));
		for (i = 0; i < burst; i++) {
			generate_rand_bytes(frame, sizeof(frame));
			frame[12] = 0x08; frame[13] = 0x00;	/* ethertype IP */
			if (sendto(raw, frame, sizeof(frame), MSG_DONTWAIT,
				   (struct sockaddr *)&sll, sizeof(sll)) > 0)
				__atomic_add_fetch(&shm->stats.veth_asym_send_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

out:
	if (raw >= 0)
		close(raw);
	if (prog_fd >= 0) {
		if (a_idx > 0 && rtnl >= 0)
			(void)vax_xdp_attach(rtnl, a_idx, -1);
		close(prog_fd);
	}
	if (a_idx > 0 && rtnl >= 0)
		(void)vax_dellink(rtnl, a_idx);
	if (rtnl >= 0)
		close(rtnl);
	return true;
}

#else  /* missing <linux/if_link.h> or <linux/bpf.h> */

#include <stdbool.h>
#include "child.h"
#include "shm.h"

bool veth_asymmetric_xdp(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.veth_asym_iters, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.veth_asym_unsupported, 1, __ATOMIC_RELAXED);
	return true;
}

#endif
