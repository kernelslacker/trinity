/*
 * tc_qdisc_churn - TC qdisc tree mutation under live traffic.
 *
 * Per-syscall fuzzing rolls a fresh netlink message every call and
 * never builds a working TCM_HANDLE / TCM_PARENT chain: the random
 * picker can't keep handle:major and parent_handle in sync across
 * iterations, so RTM_NEWTCLASS / RTM_NEWTFILTER bounce off the
 * lookup gates inside net/sched/sch_api.c and net/sched/cls_api.c
 * before any of the actually-interesting commit-time work runs.  The
 * bug class this op exists to expose is "qdisc lifetime ends while
 * an skb is still being classified through it" — that requires a
 * complete (qdisc -> class -> filter) tree, an in-flight UDP burst
 * draining through the qdisc, and a deletion racing the live
 * enqueue.  Random fuzzing assembles that set ~never.
 *
 * Sequence (per invocation):
 *   1. unshare(CLONE_NEWNET) once per child into a private net
 *      namespace so no host qdisc / class / filter table is touched.
 *      Failure latches the whole op off.
 *   2. Bring lo up inside the netns (one-time).
 *   3. RTM_NEWLINK type=dummy creating a fresh dummy device per
 *      iteration (random suffix).  Failure latches
 *      ns_unsupported_dummy — a kernel without CONFIG_DUMMY pays the
 *      EFAIL once.  dummy is preferred over lo because each
 *      iteration gets a clean qdisc target instead of stomping the
 *      shared loopback root.
 *   4. RTM_SETLINK IFF_UP on the dummy.
 *   5. RTM_NEWQDISC root, TCA_KIND rotated per iteration across the
 *      qdisc-kind table.  TCM_PARENT=TC_H_ROOT, TCM_HANDLE=major:0
 *      with a random major in [0x10,0xfff0].  Per-kind latches
 *      (ns_unsupported_kind[]) gate the kinds whose modules are
 *      absent so we don't pay the EFAIL again on every retry.  A
 *      best-effort modprobe sch_<kind> is fired the first time a
 *      kind is touched, latched so a missing /sbin/modprobe / no
 *      modules / lockdown=integrity costs the EFAIL once.
 *   6. For classful kinds (htb / hfsc / qfq / prio / ets):
 *      RTM_NEWTCLASS twice, building two classes under root with
 *      handles major:1 and major:2.  parent = TC_H_ROOT.  No
 *      TCA_OPTIONS payload — most classful qdiscs accept defaults
 *      and the lookup-side commit path runs identically either way.
 *   7. RTM_NEWTFILTER, cls kind rotated per iteration across
 *      {u32, basic, matchall, flower}.  Wired to root with priority
 *      1, protocol ETH_P_ALL.  No expression payload (matches
 *      everything for matchall, "no rules" for the others — still
 *      runs the cls_*_change / cls_*_init commit-time codepaths
 *      we care about).
 *   8. socket(AF_INET, SOCK_DGRAM); bind to dummy via
 *      SO_BINDTODEVICE; sendto a small payload to a fixed loopback
 *      port BUDGETED+JITTER times around base 5.  STORM_BUDGET_NS
 *      200 ms wall-clock cap.  Each send drives the dummy's
 *      enqueue path through the freshly-installed qdisc/class/
 *      filter tree; dummy's xmit drops the packet on the floor
 *      after dequeue, but the classification + enqueue + dequeue
 *      cycle inside __dev_xmit_skb / qdisc_enqueue / sch_direct_xmit
 *      is the codepath the CVE class lives in.
 *   9. RTM_NEWQDISC TCM_REPLACE — swap the root qdisc kind to a
 *      different rotation entry mid-flow.  This is the targeted
 *      qdisc_replace race window: the old qdisc's enqueue is still
 *      in flight when the kind swap pulls it out from under any
 *      skb mid-classify.
 *  10. RTM_DELTFILTER on the root filter, racing in-flight skb
 *      classification still draining from step 8.
 *  11. RTM_DELQDISC root — racing the same in-flight skbs.  Kernel
 *      cascades cleanup of any class survivor via qdisc_destroy.
 *  12. RTM_DELLINK dummy (cleanup; netns destroy will catch any
 *      leak).
 *
 * CVE class: CVE-2023-4623 sch_qfq UAF (qdisc lifetime vs enqueue),
 * CVE-2023-3611 sch_qfq enqueue oob, CVE-2023-31436 sch_qfq ndo,
 * CVE-2023-3776 cls_fw refcount, CVE-2024-36978 sch_netem.  This is
 * historically one of the most CVE-productive corners of the
 * networking stack.  Subsystems reached: net/sched/sch_api.c,
 * net/sched/sch_*.c (per-kind enqueue/dequeue/destroy),
 * net/sched/cls_api.c, net/sched/cls_*.c, net/core/dev.c
 * (__dev_xmit_skb), net/sched/sch_generic.c (qdisc_destroy /
 * qdisc_replace), drivers/net/dummy.c.
 *
 * Self-bounding: one full create/destroy cycle per invocation,
 * packet burst BUDGETED+JITTER around base 5 with a STORM_BUDGET_NS
 * 200 ms wall-clock cap and a 64-frame ceiling on the inner send
 * loop.  All netlink and socket I/O is MSG_DONTWAIT; SO_RCVTIMEO=1s
 * on the rtnl ack socket so an unresponsive kernel can't wedge us
 * past the SIGALRM(1s) cap inherited from child.c.  Loopback +
 * dummy only (private netns).  Per-kind latches so a kernel without
 * a given sch_* / cls_* module pays the EFAIL once and skips that
 * kind permanently.
 */

#if __has_include(<linux/pkt_sched.h>)
#include <linux/pkt_sched.h>
#endif
#if __has_include(<linux/pkt_cls.h>)
#include <linux/pkt_cls.h>
#endif

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * UAPI fallbacks.  pkt_sched.h / pkt_cls.h on stripped sysroots may
 * not have all of these; the IDs are stable in the kernel UAPI.  If
 * a header is missing entirely the __has_include gates above keep
 * compilation working and these defines fill in.
 */
#ifndef TC_H_ROOT
#define TC_H_ROOT		(0xFFFFFFFFU)
#endif
#ifndef TC_H_MAJ_MASK
#define TC_H_MAJ_MASK		(0xFFFF0000U)
#endif
#ifndef TC_H_MIN_MASK
#define TC_H_MIN_MASK		(0x0000FFFFU)
#endif

/* TCA_* attribute IDs (kernel UAPI; stable). */
#ifndef TCA_UNSPEC
#define TCA_UNSPEC		0
#define TCA_KIND		1
#define TCA_OPTIONS		2
#endif

/* RTM_* qdisc / class / filter message types (kernel UAPI; stable). */
#ifndef RTM_NEWQDISC
#define RTM_NEWQDISC		36
#define RTM_DELQDISC		37
#define RTM_NEWTCLASS		40
#define RTM_DELTCLASS		41
#define RTM_NEWTFILTER		44
#define RTM_DELTFILTER		45
#endif

#ifndef ETH_P_ALL
#define ETH_P_ALL		0x0003
#endif

/* Reasonable ceiling on a single rtnl message + payload.  The
 * NEWTFILTER message with TCA_KIND + TCA_OPTIONS (empty) is the
 * largest we emit; well under 512 B.  2 KiB leaves headroom for
 * future per-kind option blobs without resizing. */
#define RTNL_BUF_BYTES		2048
#define RTNL_RECV_TIMEO_S	1

/* Per-iteration packet burst base.  BUDGETED+JITTER scales it.
 * Sends are MSG_DONTWAIT; the inner loop also clamps to
 * STORM_BUDGET_NS wall-clock so even an unbounded burst can't stall
 * past the SIGALRM(1s) cap. */
#define TC_PACKET_BASE		5U
#define TC_PACKET_FLOOR		16U	/* always send at least this many */
#define TC_PACKET_CAP		64U	/* upper clamp on per-iter burst */
#define STORM_BUDGET_NS		200000000L	/* 200 ms */

/* UDP destination port for the loopback drive packet.  Loopback-
 * only inside a private netns — value is functionally arbitrary; a
 * fixed non-privileged port keeps any escaped packet trivially
 * identifiable in a tcpdump trace during triage. */
#define TC_INNER_PORT		34569

/* Bounded retries on EAGAIN/EBUSY for the netlink config plane.
 * The qdisc / class / filter create paths can briefly return EBUSY
 * while a sibling iteration is mid-teardown — bounded retry rides
 * through it instead of giving up the whole iteration. */
#define TC_RETRY_MAX		8

/*
 * Qdisc kind rotation.  Each entry is the kind name as the kernel
 * registers it (matches the sch_<kind> module name with the same
 * suffix used by request_module).  Mix of classless (tbf, sfb,
 * cake, fq_pie, fq_codel, pfifo_fast, netem) and classful (htb,
 * hfsc, qfq, prio, ets, taprio) so both per-iteration commit paths
 * get coverage.  CV.37 spec calls out qfq, taprio, netem, sch_*
 * generally as the high-CVE corner — listed first so the rotation
 * touches them early.
 */
struct qdisc_kind {
	const char *name;
	bool classful;
};

static const struct qdisc_kind qdisc_kinds[] = {
	{ "qfq",         true  },
	{ "taprio",      true  },
	{ "netem",       false },
	{ "sfb",         false },
	{ "cake",        false },
	{ "tbf",         false },
	{ "htb",         true  },
	{ "hfsc",        true  },
	{ "prio",        true  },
	{ "ets",         true  },
	{ "fq_pie",      false },
	{ "fq_codel",    false },
	{ "pfifo_fast",  false },
};
#define NR_QDISC_KINDS	ARRAY_SIZE(qdisc_kinds)

/*
 * Filter (cls) kind rotation.  Same shape as qdisc_kinds: name +
 * "needs payload" flag.  matchall is the only one that classifies
 * with no extra options; u32 / basic / flower / bpf accept an empty
 * TCA_OPTIONS and still run the cls_*_init / cls_*_change commit
 * paths that the CVE-2023-3776 cls_fw lineage exercises.
 */
static const char * const cls_kinds[] = {
	"matchall", "u32", "basic", "flower", "bpf",
};
#define NR_CLS_KINDS	ARRAY_SIZE(cls_kinds)

/* Per-child latched gates.  Set on the first failure of the
 * corresponding subsystem and never cleared — kernel module /
 * config presence is static for the child's lifetime, so we pay the
 * EFAIL once and skip the path on subsequent invocations. */
static bool ns_unsupported_rtnl;
static bool ns_unsupported_dummy;
static bool ns_unsupported_inet;

/* Per-kind latches: indexed by qdisc_kinds[] / cls_kinds[].  Set
 * on first NEWQDISC / NEWTFILTER rejection with EOPNOTSUPP /
 * EAFNOSUPPORT / ENOENT / ENOMODULE — the next iteration skips
 * that kind in the rotation. */
static bool ns_unsupported_qdisc_kind[NR_QDISC_KINDS];
static bool ns_unsupported_cls_kind[NR_CLS_KINDS];

/* Per-kind modprobe latch: prevents re-spawning modprobe every
 * iteration for the same kind. */
static bool modprobe_tried_qdisc[NR_QDISC_KINDS];
static bool modprobe_tried_cls[NR_CLS_KINDS];

static bool ns_unshared;
static bool ns_setup_failed;
static bool lo_brought_up;

static __u32 g_seq;

static __u32 next_seq(void)
{
	return ++g_seq;
}

static long ns_since(const struct timespec *t0)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return 0;
	return (now.tv_sec - t0->tv_sec) * 1000000000L +
	       (now.tv_nsec - t0->tv_nsec);
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

static size_t nla_put_str(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, const char *s)
{
	return nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Send via NETLINK_ROUTE and consume one ack.  Returns 0 on a
 * positive ack (nlmsgerr.error == 0), the negated kernel errno on a
 * rejection, and -EIO on local sendmsg / recv failure.
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
 * Wrap rtnl_send_recv with bounded retry on EAGAIN / EBUSY so a
 * sibling iteration mid-teardown doesn't waste this iteration's
 * config-plane work.  Other errnos pass through unchanged.
 */
static int rtnl_send_recv_retry(int fd, void *msg, size_t len)
{
	int rc = -EIO;
	int i;

	for (i = 0; i < TC_RETRY_MAX; i++) {
		rc = rtnl_send_recv(fd, msg, len);
		if (rc != -EAGAIN && rc != -EBUSY)
			return rc;
	}
	return rc;
}

/*
 * Best-effort modprobe.  fork+execvp; child redirects stdio to
 * /dev/null so any module-load chatter doesn't pollute trinity's
 * output.  Ignore the exit status — modprobe failures (no module,
 * no permission, no /sbin/modprobe, lockdown=integrity) are exactly
 * the cases the per-kind latch will catch on the subsequent
 * RTM_NEWQDISC / RTM_NEWTFILTER probe.
 */
static void try_modprobe(const char *mod)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		return;
	if (pid == 0) {
		int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
		if (devnull >= 0) {
			(void)dup2(devnull, 0);
			(void)dup2(devnull, 1);
			(void)dup2(devnull, 2);
			close(devnull);
		}
		execlp("modprobe", "modprobe", "-q", mod, (char *)NULL);
		_exit(127);
	}
	(void)waitpid(pid, &status, 0);
}

static void modprobe_qdisc(unsigned int idx)
{
	char modname[32];

	if (modprobe_tried_qdisc[idx])
		return;
	modprobe_tried_qdisc[idx] = true;
	snprintf(modname, sizeof(modname), "sch_%s", qdisc_kinds[idx].name);
	try_modprobe(modname);
}

static void modprobe_cls(unsigned int idx)
{
	char modname[32];

	if (modprobe_tried_cls[idx])
		return;
	modprobe_tried_cls[idx] = true;
	snprintf(modname, sizeof(modname), "cls_%s", cls_kinds[idx]);
	try_modprobe(modname);
}

/*
 * Bring lo up inside the private netns.  Some classifier paths
 * short-circuit on lo not being up; flip it once-per-child.
 * Failures are ignored — the rest of the sequence will fail
 * visibly if rtnl is genuinely broken.
 */
static void bring_lo_up(int rtnl)
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
	nlh->nlmsg_seq   = next_seq();

	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = lo_idx;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;

	nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi)));
	(void)rtnl_send_recv(rtnl, buf, nlh->nlmsg_len);
}

/*
 * RTM_NEWLINK type=dummy with the supplied dev name.  Each iteration
 * gets a fresh dummy device so the qdisc tree is isolated from any
 * other iteration's leftovers.  No IFLA_INFO_DATA — defaults give us
 * a working netif_tx_lock dummy that accepts UDP traffic.
 */
static int build_dummy_create(int fd, const char *name)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *linkinfo;
	size_t off, li_off;

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

	off = nla_put_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "dummy");
	if (!off)
		return -EIO;

	linkinfo = (struct nlattr *)(buf + li_off);
	linkinfo->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return rtnl_send_recv_retry(fd, buf, off);
}

static int build_setlink_up(int fd, int ifindex)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
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

/*
 * Build a tcmsg-bearing rtnl message with the given msg_type and
 * flags.  Returns the offset past the tcmsg payload header where
 * caller-supplied attributes start.
 */
static size_t tcmsg_hdr(unsigned char *buf, __u16 msg_type, __u16 extra_flags,
			int ifindex, __u32 handle, __u32 parent, __u32 info)
{
	struct nlmsghdr *nlh;
	struct tcmsg *tcm;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | extra_flags;
	nlh->nlmsg_seq   = next_seq();

	tcm = (struct tcmsg *)NLMSG_DATA(nlh);
	tcm->tcm_family  = AF_UNSPEC;
	tcm->tcm_ifindex = ifindex;
	tcm->tcm_handle  = handle;
	tcm->tcm_parent  = parent;
	tcm->tcm_info    = info;

	return NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*tcm));
}

static void tcmsg_finalize(unsigned char *buf, size_t off)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	nlh->nlmsg_len = (__u32)off;
}

/*
 * RTM_NEWQDISC root, TCA_KIND=<kind>.  TCA_OPTIONS is emitted as an
 * empty nested attribute — most qdiscs accept defaults; the few
 * that demand a parameter (taprio, ets) reject with EINVAL which
 * the per-kind latch picks up via the EOPNOTSUPP / ENOENT family
 * mapping in the caller.  Flags select between create, replace,
 * and create-or-replace as the caller requires.
 */
static int build_newqdisc(int fd, int ifindex, __u32 handle, __u32 parent,
			  const char *kind, __u16 extra_flags)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlattr *opts;
	size_t off, opts_off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(buf, RTM_NEWQDISC, extra_flags, ifindex,
			handle, parent, 0);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_put(buf, off, sizeof(buf), TCA_OPTIONS, NULL, 0);
	if (!off)
		return -EIO;
	opts = (struct nlattr *)(buf + opts_off);
	opts->nla_len = (unsigned short)(off - opts_off);

	tcmsg_finalize(buf, off);
	return rtnl_send_recv_retry(fd, buf, off);
}

static int build_delqdisc(int fd, int ifindex, __u32 handle, __u32 parent)
{
	unsigned char buf[256];
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(buf, RTM_DELQDISC, 0, ifindex, handle, parent, 0);
	tcmsg_finalize(buf, off);
	return rtnl_send_recv(fd, buf, off);
}

/*
 * RTM_NEWTCLASS under (ifindex, parent).  TCA_KIND inherits the
 * qdisc kind (htb, hfsc, etc.) — the kernel rejects with EINVAL if
 * the parent qdisc isn't classful, which the caller has already
 * gated on.  Empty TCA_OPTIONS — defaults are sufficient to install
 * the class; the lookup-side commit path is what we're after, not
 * the per-class scheduling parameters.
 */
static int build_newtclass(int fd, int ifindex, __u32 handle, __u32 parent,
			   const char *kind)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlattr *opts;
	size_t off, opts_off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(buf, RTM_NEWTCLASS, NLM_F_CREATE | NLM_F_EXCL,
			ifindex, handle, parent, 0);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_put(buf, off, sizeof(buf), TCA_OPTIONS, NULL, 0);
	if (!off)
		return -EIO;
	opts = (struct nlattr *)(buf + opts_off);
	opts->nla_len = (unsigned short)(off - opts_off);

	tcmsg_finalize(buf, off);
	return rtnl_send_recv_retry(fd, buf, off);
}

/*
 * RTM_NEWTFILTER on (ifindex, parent).  tcm_info encodes priority
 * (high 16 bits) and protocol (low 16, htons'd).  Priority 1 is
 * fine; the kernel rejects priority 0 with EINVAL.  Empty
 * TCA_OPTIONS — most cls_* kinds accept this and run their _init /
 * _change codepaths anyway; the few that demand options reject
 * with EINVAL which trips the per-kind latch.
 */
static int build_newtfilter(int fd, int ifindex, __u32 parent,
			    const char *kind)
{
	unsigned char buf[RTNL_BUF_BYTES];
	struct nlattr *opts;
	size_t off, opts_off;
	__u32 info = ((__u32)1U << 16) | (__u32)htons(ETH_P_ALL);

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(buf, RTM_NEWTFILTER, NLM_F_CREATE | NLM_F_EXCL,
			ifindex, 0, parent, info);

	off = nla_put_str(buf, off, sizeof(buf), TCA_KIND, kind);
	if (!off)
		return -EIO;

	opts_off = off;
	off = nla_put(buf, off, sizeof(buf), TCA_OPTIONS, NULL, 0);
	if (!off)
		return -EIO;
	opts = (struct nlattr *)(buf + opts_off);
	opts->nla_len = (unsigned short)(off - opts_off);

	tcmsg_finalize(buf, off);
	return rtnl_send_recv_retry(fd, buf, off);
}

/*
 * RTM_DELTFILTER on (ifindex, parent) with no TCA_KIND — kernel
 * treats this as "delete every filter on parent".  Races any
 * in-flight skb classification still draining through the qdisc.
 */
static int build_deltfilter(int fd, int ifindex, __u32 parent)
{
	unsigned char buf[256];
	__u32 info = ((__u32)1U << 16) | (__u32)htons(ETH_P_ALL);
	size_t off;

	memset(buf, 0, sizeof(buf));
	off = tcmsg_hdr(buf, RTM_DELTFILTER, 0, ifindex, 0, parent, info);
	tcmsg_finalize(buf, off);
	return rtnl_send_recv(fd, buf, off);
}

/*
 * Pick a random qdisc kind index that isn't latched-off.  Returns
 * NR_QDISC_KINDS if every kind is latched (caller bails out).
 */
static unsigned int pick_qdisc_idx(void)
{
	unsigned int start = rand32() % NR_QDISC_KINDS;
	unsigned int i;

	for (i = 0; i < NR_QDISC_KINDS; i++) {
		unsigned int idx = (start + i) % NR_QDISC_KINDS;

		if (!ns_unsupported_qdisc_kind[idx])
			return idx;
	}
	return NR_QDISC_KINDS;
}

/*
 * Pick a different qdisc kind than `avoid`, for the mid-flow
 * REPLACE.  Returns NR_QDISC_KINDS if no alternative is available.
 */
static unsigned int pick_qdisc_idx_other(unsigned int avoid)
{
	unsigned int start = rand32() % NR_QDISC_KINDS;
	unsigned int i;

	for (i = 0; i < NR_QDISC_KINDS; i++) {
		unsigned int idx = (start + i) % NR_QDISC_KINDS;

		if (idx == avoid)
			continue;
		if (!ns_unsupported_qdisc_kind[idx])
			return idx;
	}
	return NR_QDISC_KINDS;
}

static unsigned int pick_cls_idx(void)
{
	unsigned int start = rand32() % NR_CLS_KINDS;
	unsigned int i;

	for (i = 0; i < NR_CLS_KINDS; i++) {
		unsigned int idx = (start + i) % NR_CLS_KINDS;

		if (!ns_unsupported_cls_kind[idx])
			return idx;
	}
	return NR_CLS_KINDS;
}

/*
 * Map a kernel error to a "module unsupported" verdict.  EOPNOTSUPP
 * / EAFNOSUPPORT / EPROTONOSUPPORT / ENOENT are the typical
 * rejections from the kernel for an unknown qdisc / cls module
 * after request_module fails.  EINVAL is excluded — most kinds
 * reject our empty TCA_OPTIONS with EINVAL as a parameter complaint,
 * not a module-missing signal.
 */
static bool is_unsupported_err(int rc)
{
	return rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
	       rc == -EPROTONOSUPPORT || rc == -ENOENT;
}

bool tc_qdisc_churn(struct childdata *child)
{
	char dummy_name[IFNAMSIZ];
	int rtnl = -1;
	int udp = -1;
	int dummy_idx = 0;
	bool dummy_added = false;
	unsigned int qidx, qidx2, cidx;
	__u32 major, handle, class1, class2;
	struct timespec t0;
	unsigned int iters;
	unsigned int i;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.tc_qdisc_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ns_setup_failed || ns_unsupported_rtnl || ns_unsupported_dummy)
		return true;

	if (!ns_unshared) {
		if (unshare(CLONE_NEWNET) < 0) {
			ns_setup_failed = true;
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn_setup_failed,
					   1, __ATOMIC_RELAXED);
			return true;
		}
		ns_unshared = true;
	}

	rtnl = rtnl_open();
	if (rtnl < 0) {
		if (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT)
			ns_unsupported_rtnl = true;
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (!lo_brought_up) {
		bring_lo_up(rtnl);
		lo_brought_up = true;
	}

	snprintf(dummy_name, sizeof(dummy_name), "trtcd%u",
		 (unsigned int)(rand32() & 0xffffu));

	rc = build_dummy_create(rtnl, dummy_name);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_dummy = true;
		goto out;
	}
	dummy_added = true;
	__atomic_add_fetch(&shm->stats.tc_qdisc_churn_link_create_ok,
			   1, __ATOMIC_RELAXED);

	dummy_idx = (int)if_nametoindex(dummy_name);
	if (dummy_idx == 0)
		goto out;

	(void)build_setlink_up(rtnl, dummy_idx);

	qidx = pick_qdisc_idx();
	if (qidx >= NR_QDISC_KINDS)
		goto out;

	/* random major in [0x10, 0xfff0] keeps us clear of TC_H_MAJ
	 * values reserved for the kernel's own ingress / clsact / root
	 * qdiscs (0xffff* is the well-known reserved range). */
	major = (__u32)((rand32() % 0xfee0U) + 0x10U);
	handle = major << 16;
	class1 = handle | 1U;
	class2 = handle | 2U;

	modprobe_qdisc(qidx);
	rc = build_newqdisc(rtnl, dummy_idx, handle, TC_H_ROOT,
			    qdisc_kinds[qidx].name, NLM_F_CREATE | NLM_F_EXCL);
	if (rc != 0) {
		if (is_unsupported_err(rc))
			ns_unsupported_qdisc_kind[qidx] = true;
		goto out;
	}
	__atomic_add_fetch(&shm->stats.tc_qdisc_churn_qdisc_create_ok,
			   1, __ATOMIC_RELAXED);

	if (qdisc_kinds[qidx].classful) {
		if (build_newtclass(rtnl, dummy_idx, class1, TC_H_ROOT,
				    qdisc_kinds[qidx].name) == 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn_tclass_create_ok,
					   1, __ATOMIC_RELAXED);
		if (build_newtclass(rtnl, dummy_idx, class2, TC_H_ROOT,
				    qdisc_kinds[qidx].name) == 0)
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn_tclass_create_ok,
					   1, __ATOMIC_RELAXED);
	}

	cidx = pick_cls_idx();
	if (cidx < NR_CLS_KINDS) {
		modprobe_cls(cidx);
		rc = build_newtfilter(rtnl, dummy_idx, handle,
				      cls_kinds[cidx]);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn_tfilter_create_ok,
					   1, __ATOMIC_RELAXED);
		} else if (is_unsupported_err(rc)) {
			ns_unsupported_cls_kind[cidx] = true;
		}
	}

	/*
	 * Drive the dummy's xmit path with loopback UDP.  Each send
	 * walks __dev_xmit_skb / qdisc_enqueue / sch_direct_xmit
	 * through the freshly-installed qdisc -> class -> filter
	 * tree.  dummy's xmit drops on the floor after dequeue but
	 * the classification / enqueue / dequeue cycle is what the
	 * CVE class lives in.
	 */
	if (!ns_unsupported_inet) {
		udp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
		if (udp < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				ns_unsupported_inet = true;
		} else {
			(void)setsockopt(udp, SOL_SOCKET, SO_BINDTODEVICE,
					 dummy_name, strlen(dummy_name) + 1);
		}
	}

	if (udp >= 0) {
		struct sockaddr_in dst;

		memset(&dst, 0, sizeof(dst));
		dst.sin_family      = AF_INET;
		dst.sin_port        = htons(TC_INNER_PORT);
		dst.sin_addr.s_addr = htonl(0x7f000001U);	/* 127.0.0.1 */

		(void)clock_gettime(CLOCK_MONOTONIC, &t0);
		iters = BUDGETED(CHILD_OP_TC_QDISC_CHURN,
				 JITTER_RANGE(TC_PACKET_BASE));
		if (iters < TC_PACKET_FLOOR)
			iters = TC_PACKET_FLOOR;
		if (iters > TC_PACKET_CAP)
			iters = TC_PACKET_CAP;

		for (i = 0; i < iters; i++) {
			unsigned char payload[64];
			ssize_t n;

			if (ns_since(&t0) >= STORM_BUDGET_NS)
				break;

			generate_rand_bytes(payload, sizeof(payload));
			n = sendto(udp, payload, sizeof(payload),
				   MSG_DONTWAIT,
				   (struct sockaddr *)&dst, sizeof(dst));
			if (n > 0)
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn_packet_sent_ok,
						   1, __ATOMIC_RELAXED);
		}
	}

	/*
	 * Mid-flow REPLACE: swap the root qdisc kind to a different
	 * rotation entry while skbs from the send loop above are still
	 * draining.  This is the targeted qdisc_replace race window —
	 * the same shape as the CVE-2023-4623 sch_qfq UAF.
	 */
	qidx2 = pick_qdisc_idx_other(qidx);
	if (qidx2 < NR_QDISC_KINDS) {
		modprobe_qdisc(qidx2);
		rc = build_newqdisc(rtnl, dummy_idx, handle, TC_H_ROOT,
				    qdisc_kinds[qidx2].name,
				    NLM_F_CREATE | NLM_F_REPLACE);
		if (rc == 0) {
			__atomic_add_fetch(&shm->stats.tc_qdisc_churn_qdisc_replace_ok,
					   1, __ATOMIC_RELAXED);
		} else if (is_unsupported_err(rc)) {
			ns_unsupported_qdisc_kind[qidx2] = true;
		}
	}

	/*
	 * Bulk-delete every filter on root, racing in-flight skb
	 * classification still draining from the send loop.  The
	 * cls_*_destroy commit-time codepaths (CVE-2023-3776 cls_fw
	 * lineage) live here.
	 */
	if (build_deltfilter(rtnl, dummy_idx, handle) == 0)
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn_tfilter_del_ok,
				   1, __ATOMIC_RELAXED);

	/*
	 * Drop the root qdisc, racing the same in-flight skbs.
	 * Cascades cleanup of class / filter survivors via
	 * qdisc_destroy.  This is the primary teardown-vs-traffic
	 * window the op exists to open.
	 */
	if (build_delqdisc(rtnl, dummy_idx, handle, TC_H_ROOT) == 0)
		__atomic_add_fetch(&shm->stats.tc_qdisc_churn_qdisc_del_ok,
				   1, __ATOMIC_RELAXED);

out:
	if (udp >= 0)
		close(udp);

	if (rtnl >= 0) {
		if (dummy_added && dummy_idx > 0) {
			if (build_dellink(rtnl, dummy_idx) == 0)
				__atomic_add_fetch(&shm->stats.tc_qdisc_churn_link_del_ok,
						   1, __ATOMIC_RELAXED);
		}
		close(rtnl);
	}

	return true;
}
