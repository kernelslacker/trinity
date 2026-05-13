/*
 * ovs_tunnel_vport_churn - OVS tunnel vport CMD_NEW + CMD_DEL race driver.
 *
 * Open vSwitch's userspace control path lets a single netlink client
 * create a datapath, then attach tunnel vports of GENEVE / VXLAN / GRE
 * type to it.  Each successful CMD_NEW asks the OVS kernel module to
 * register the matching shared "tunnel sys" netdev (geneve_sys_<port>,
 * vxlan_sys_<port>, gre_sys_<port>) on demand, and CMD_DEL tears the
 * vport down with rtnl held while the underlying tunnel driver is
 * still wired into the OVS dispatch tables.
 *
 * Two upstream regression classes hide in that flow:
 *   1) OVS_VPORT_CMD_DEL self-deadlock on tunnel ports -- the
 *      tunnel-vport ->destroy() handler ran call_rcu(...) while the
 *      caller still held rtnl; rcu_barrier() inside the unregister
 *      path then waited for an rtnl_lock-taking callback and
 *      deadlocked the netlink writer.  Fixed upstream by reordering
 *      the ->destroy / rtnl_unlock pair (commit aa69918bd418).
 *   2) OVS_VPORT_CMD_NEW vs RTM_DELLINK / IFLA_IFNAME race on the
 *      shared geneve_sys_<port> / vxlan_sys_<port> / gre_sys_<port>
 *      netdev: a concurrent rtnetlink rename or delete of the helper
 *      netdev while OVS was still finishing its register-vport
 *      handshake left dangling pointers in ovs_net->dps[].  Fixed
 *      upstream by 83861c48ba12.
 *
 * Neither path is reachable from any existing childop: vxlan-encap
 * exercises the rtnl-only tunnel create/destroy edge but never goes
 * through OVS, and genetlink-fuzzer hits the OVS family demuxer with
 * fully random payloads that almost never assemble a structurally-valid
 * tunnel vport message.  This childop closes that gap.
 *
 * Sequence (per child, latched after first successful setup):
 *   1. try_modprobe openvswitch / geneve / vxlan / ip_gre.
 *   2. Open NETLINK_GENERIC, dump CTRL_CMD_GETFAMILY/NLM_F_DUMP and
 *      cache the resolved family ids for ovs_datapath / ovs_vport.
 *   3. OVS_DP_CMD_NEW with OVS_DP_ATTR_NAME = tcdp_<child_id>,
 *      OVS_DP_ATTR_UPCALL_PID = 0.  Datapath name is per-child so
 *      siblings don't fight over the shared name space at startup.
 *
 * Per iteration:
 *   1. Pick a tunnel kind weighted GENEVE 5 / VXLAN 4 / GRE 3, skipping
 *      kinds whose modprobe / earlier attempt latched as unsupported.
 *   2. Send OVS_VPORT_CMD_NEW on ovs_vport with TYPE = kind, NAME =
 *      tcvp_<child>_<iter> (<= IFNAMSIZ), UPCALL_PID = u32[1]{0}, and
 *      OPTIONS nested with OVS_TUNNEL_ATTR_DST_PORT (random
 *      [20000..30000]) for GENEVE / VXLAN, empty for GRE.
 *   3. With ONE_IN(2): open a separate rtnetlink socket and fire
 *      RTM_DELLINK at the underlying helper netdev (geneve_sys_<port>
 *      / vxlan_sys_<port> / gre_sys_<port>).  Best-effort, no ack
 *      processing.  This is the rename/delete-vs-CMD_NEW race window.
 *   4. Short jitter, then OVS_VPORT_CMD_DEL referencing the same
 *      vport name.  This is the CMD_DEL self-deadlock window -- once
 *      both fixes are in, the path stays warm; without them the
 *      child wedges on the netlink ack and the parent SIGALRMs us.
 *
 * Self-bounding: SO_RCVTIMEO=1s on every netlink socket so an
 * unresponsive OVS family can't wedge us past the SIGALRM(1s) cap
 * inherited from child.c.  All sends use the genl socket bound to the
 * child's pid; the per-iteration rtnl racer socket is opened fresh,
 * fired once with NLM_F_REQUEST (no ack), and closed.  Every kind
 * has its own latch so a kernel without GENEVE / VXLAN / GRE pays the
 * EFAIL once and skips that kind on subsequent invocations.
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "child.h"
#include "jitter.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

/*
 * uapi/linux/openvswitch.h is not always present on stripped sysroots.
 * Provide per-symbol fallback definitions of the OVS_* / OVS_TUNNEL_*
 * constants this childop emits.  IDs are stable in the UAPI so the
 * fallback values match what the kernel parser expects.
 */
#ifndef OVS_DATAPATH_VERSION
#define OVS_DATAPATH_VERSION	2
#endif
#ifndef OVS_VPORT_VERSION
#define OVS_VPORT_VERSION	0x1
#endif

#ifndef OVS_DP_CMD_NEW
#define OVS_DP_CMD_NEW		1
#endif

#ifndef OVS_DP_ATTR_NAME
#define OVS_DP_ATTR_NAME	1
#endif
#ifndef OVS_DP_ATTR_UPCALL_PID
#define OVS_DP_ATTR_UPCALL_PID	2
#endif

#ifndef OVS_VPORT_CMD_NEW
#define OVS_VPORT_CMD_NEW	1
#endif
#ifndef OVS_VPORT_CMD_DEL
#define OVS_VPORT_CMD_DEL	2
#endif

#ifndef OVS_VPORT_TYPE_GRE
#define OVS_VPORT_TYPE_GRE	3
#endif
#ifndef OVS_VPORT_TYPE_VXLAN
#define OVS_VPORT_TYPE_VXLAN	4
#endif
#ifndef OVS_VPORT_TYPE_GENEVE
#define OVS_VPORT_TYPE_GENEVE	5
#endif

#ifndef OVS_VPORT_ATTR_TYPE
#define OVS_VPORT_ATTR_TYPE	1
#endif
#ifndef OVS_VPORT_ATTR_NAME
#define OVS_VPORT_ATTR_NAME	2
#endif
#ifndef OVS_VPORT_ATTR_OPTIONS
#define OVS_VPORT_ATTR_OPTIONS	3
#endif
#ifndef OVS_VPORT_ATTR_UPCALL_PID
#define OVS_VPORT_ATTR_UPCALL_PID	4
#endif

#ifndef OVS_TUNNEL_ATTR_DST_PORT
#define OVS_TUNNEL_ATTR_DST_PORT	1
#endif

/* The IFLA_IFNAME-bearing rtnetlink racer is fire-and-forget; we never
 * wait for an ack so we don't need NLM_F_ACK in its flags.  The
 * one-second recv timeout still applies to the genl socket since the
 * CMD_NEW / CMD_DEL ack is what hangs in the deadlock case. */
#define OVS_RECV_TIMEO_S	1
#define OVS_NETLINK_BUF_BYTES	2048

/* DST_PORT range is intentionally narrow but well outside the well-
 * known VXLAN (4789) / GENEVE (6081) defaults so each iteration takes
 * a fresh path through the per-port hash table on the kernel side. */
#define OVS_DST_PORT_MIN	20000
#define OVS_DST_PORT_MAX	30000

/* Per-iteration jitter base for the gap between CMD_NEW + DELLINK race
 * and the trailing CMD_DEL.  BUDGETED scales it, JITTER_RANGE picks
 * the actual delay; the small base keeps us well under SIGALRM(1s). */
#define OVS_DELAY_BASE		2U

/* Latched per-child gates.  Module presence and family registration
 * are static for a child's lifetime; once the EFAIL is paid we stop
 * probing and just bump the runs counter. */
static bool ovs_setup_failed;
static bool ovs_setup_done;
static bool ovs_kind_unsupported_geneve;
static bool ovs_kind_unsupported_vxlan;
static bool ovs_kind_unsupported_gre;

static uint16_t ovs_dp_family;
static uint16_t ovs_vport_family;
static uint8_t ovs_dp_version;
static uint8_t ovs_vport_version;

static int ovs_genl_sock = -1;
static __u32 ovs_seq;
static __u32 ovs_iter_id;

enum ovs_tun_kind {
	OVS_TUN_GENEVE = 0,
	OVS_TUN_VXLAN,
	OVS_TUN_GRE,
	OVS_TUN_NR,
};

/* Pick weights mirror the spec: GENEVE 5 / VXLAN 4 / GRE 3.  Sum = 12,
 * picker rolls rand32() % 12 and walks the cumulative table.  Weights
 * are intentionally biased toward GENEVE because its sys netdev is the
 * one most often touched by the upstream regression history. */
static const unsigned int ovs_kind_weights[OVS_TUN_NR] = {
	[OVS_TUN_GENEVE] = 5,
	[OVS_TUN_VXLAN]  = 4,
	[OVS_TUN_GRE]    = 3,
};
#define OVS_KIND_WEIGHT_SUM	12U

static __u32 next_ovs_seq(void)
{
	return ++ovs_seq;
}

static __u32 next_ovs_iter_id(void)
{
	return ++ovs_iter_id;
}

static bool *ovs_kind_latch(enum ovs_tun_kind k)
{
	switch (k) {
	case OVS_TUN_GENEVE:	return &ovs_kind_unsupported_geneve;
	case OVS_TUN_VXLAN:	return &ovs_kind_unsupported_vxlan;
	case OVS_TUN_GRE:	return &ovs_kind_unsupported_gre;
	case OVS_TUN_NR:	break;
	}
	return NULL;
}

static __u32 ovs_kind_type_id(enum ovs_tun_kind k)
{
	switch (k) {
	case OVS_TUN_GENEVE:	return OVS_VPORT_TYPE_GENEVE;
	case OVS_TUN_VXLAN:	return OVS_VPORT_TYPE_VXLAN;
	case OVS_TUN_GRE:	return OVS_VPORT_TYPE_GRE;
	case OVS_TUN_NR:	break;
	}
	return 0;
}

/* Compose the helper-netdev name that the kernel registers for each
 * tunnel kind on first vport create: geneve_sys_<port> / vxlan_sys_<port>
 * / gre_sys_<port>.  GRE's helper has no port suffix in older kernels;
 * we stamp "gre_sys_0" which is the canonical fallback name and resolves
 * to the same ip_gre stub regardless. */
static void ovs_fill_helper_netdev(enum ovs_tun_kind k, __u16 port,
				   char *out, size_t cap)
{
	switch (k) {
	case OVS_TUN_GENEVE:
		(void)snprintf(out, cap, "geneve_sys_%u", (unsigned int)port);
		return;
	case OVS_TUN_VXLAN:
		(void)snprintf(out, cap, "vxlan_sys_%u", (unsigned int)port);
		return;
	case OVS_TUN_GRE:
		(void)snprintf(out, cap, "gre_sys_0");
		return;
	case OVS_TUN_NR:
		break;
	}
	if (cap > 0)
		out[0] = '\0';
}

static enum ovs_tun_kind ovs_pick_kind(void)
{
	unsigned int roll = rand32() % OVS_KIND_WEIGHT_SUM;
	unsigned int acc = 0;
	unsigned int i;
	enum ovs_tun_kind picked = OVS_TUN_NR;

	for (i = 0; i < OVS_TUN_NR; i++) {
		acc += ovs_kind_weights[i];
		if (roll < acc) {
			picked = (enum ovs_tun_kind)i;
			break;
		}
	}

	if (picked == OVS_TUN_NR)
		return OVS_TUN_NR;

	if (!*ovs_kind_latch(picked))
		return picked;

	/* Latched: scan forward looking for any non-latched kind so a
	 * single unsupported tunnel module doesn't starve the others. */
	for (i = 1; i < OVS_TUN_NR; i++) {
		enum ovs_tun_kind k =
			(enum ovs_tun_kind)((picked + i) % OVS_TUN_NR);
		if (!*ovs_kind_latch(k))
			return k;
	}
	return OVS_TUN_NR;
}

/*
 * Best-effort modprobe.  Same shape as the vxlan-encap helper: fork +
 * execvp("modprobe -q ..."), redirect stdio to /dev/null, ignore the
 * exit status -- the latch on a subsequent CMD_NEW probe is the real
 * gate.  Static linkage so the wider build doesn't trip the
 * Wmissing-prototypes check on a duplicate name.
 */
static void ovs_try_modprobe(const char *mod)
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

static size_t ovs_nla_put(unsigned char *buf, size_t off, size_t cap,
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

static size_t ovs_nla_put_u32(unsigned char *buf, size_t off, size_t cap,
			      unsigned short type, __u32 v)
{
	return ovs_nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t ovs_nla_put_u16(unsigned char *buf, size_t off, size_t cap,
			      unsigned short type, __u16 v)
{
	return ovs_nla_put(buf, off, cap, type, &v, sizeof(v));
}

static size_t ovs_nla_put_str(unsigned char *buf, size_t off, size_t cap,
			      unsigned short type, const char *s)
{
	return ovs_nla_put(buf, off, cap, type, s, strlen(s) + 1);
}

/*
 * Open the per-child genl socket, set the 1s recv timeout that bounds
 * an OVS family ack-stall, and bind so the kernel can address us.
 * Caller is responsible for closing on teardown.
 */
static int ovs_genl_open(void)
{
	struct sockaddr_nl sa;
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
	if (fd < 0)
		return -1;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		close(fd);
		return -1;
	}

	tv.tv_sec  = OVS_RECV_TIMEO_S;
	tv.tv_usec = 0;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

/*
 * Send + drain ack on the supplied genl socket.  Returns 0 if the ack
 * carried no error, the negated errno from the ack on rejection, or
 * -EIO on local send/recv failure.  Discards any non-error message
 * (CMD_NEW responses include the assigned port body which we don't
 * need; the racer trigger only cares whether the kernel accepted us).
 */
static int ovs_send_recv(int fd, void *msg, size_t len)
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
	return 0;
}

/* Walk the CTRL_ATTR_* attributes from one CTRL_CMD_NEWFAMILY response
 * and pull out the family id + version we need.  Compares the family
 * name against the supplied target; on match, stashes id/version into
 * out_id / out_ver.  Returns true if the entry matched (whether or not
 * the id was present -- caller checks). */
static bool ovs_parse_family_match(const struct nlmsghdr *nlh,
				   const char *target_name,
				   uint16_t *out_id, uint8_t *out_ver)
{
	const struct genlmsghdr *genl;
	const unsigned char *attrs;
	size_t attrs_len;
	size_t off;
	bool name_matched = false;
	uint16_t found_id = 0;
	uint8_t found_ver = 0;

	if (nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
		return false;

	genl = (const struct genlmsghdr *)NLMSG_DATA(nlh);
	found_ver = genl->version;

	attrs = (const unsigned char *)nlh + NLMSG_HDRLEN + GENL_HDRLEN;
	attrs_len = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;

	for (off = 0; off + NLA_HDRLEN <= attrs_len; ) {
		const struct nlattr *nla = (const struct nlattr *)(attrs + off);
		size_t nla_len = nla->nla_len;
		const unsigned char *payload;
		size_t payload_len;
		unsigned short type;

		if (nla_len < NLA_HDRLEN || nla_len > attrs_len - off)
			break;
		payload = (const unsigned char *)nla + NLA_HDRLEN;
		payload_len = nla_len - NLA_HDRLEN;
		type = nla->nla_type & NLA_TYPE_MASK;

		if (type == CTRL_ATTR_FAMILY_NAME) {
			size_t cmp = payload_len;
			if (cmp > 0 && payload[cmp - 1] == '\0')
				cmp--;
			if (cmp == strlen(target_name) &&
			    memcmp(payload, target_name, cmp) == 0)
				name_matched = true;
		} else if (type == CTRL_ATTR_FAMILY_ID &&
			   payload_len >= sizeof(uint16_t)) {
			memcpy(&found_id, payload, sizeof(uint16_t));
		} else if (type == CTRL_ATTR_VERSION &&
			   payload_len >= sizeof(uint32_t)) {
			uint32_t v;

			memcpy(&v, payload, sizeof(v));
			found_ver = (uint8_t)v;
		}
		off += NLA_ALIGN(nla_len);
	}

	if (!name_matched)
		return false;
	if (out_id)
		*out_id = found_id;
	if (out_ver)
		*out_ver = found_ver;
	return true;
}

/*
 * CTRL_CMD_GETFAMILY/NLM_F_DUMP, walk every NEWFAMILY response,
 * latching ovs_dp_family / ovs_vport_family on name match.  Returns
 * false on send failure or if neither name was found in the dump.
 */
static bool ovs_resolve_families(int fd)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
	} req;
	unsigned char buf[16384];
	bool found_dp = false;
	bool found_vport = false;
	ssize_t n;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type  = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.nlh.nlmsg_seq   = next_ovs_seq();
	req.nlh.nlmsg_pid   = 0;
	req.genl.cmd        = CTRL_CMD_GETFAMILY;
	req.genl.version    = 1;

	if (send(fd, &req, req.nlh.nlmsg_len, 0) < 0)
		return false;

	for (;;) {
		struct nlmsghdr *nlh;
		size_t remaining;

		n = recv(fd, buf, sizeof(buf), 0);
		if (n <= 0)
			break;

		nlh = (struct nlmsghdr *)buf;
		remaining = (size_t)n;
		while (NLMSG_OK(nlh, remaining)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				goto done;
			if (nlh->nlmsg_type == NLMSG_ERROR)
				goto done;
			if (nlh->nlmsg_type == GENL_ID_CTRL) {
				uint16_t id = 0;
				uint8_t ver = 0;

				if (!found_dp &&
				    ovs_parse_family_match(nlh, "ovs_datapath",
							   &id, &ver) && id) {
					ovs_dp_family = id;
					ovs_dp_version = ver ? ver
							     : OVS_DATAPATH_VERSION;
					found_dp = true;
				}
				if (!found_vport &&
				    ovs_parse_family_match(nlh, "ovs_vport",
							   &id, &ver) && id) {
					ovs_vport_family = id;
					ovs_vport_version = ver ? ver
								: OVS_VPORT_VERSION;
					found_vport = true;
				}
			}
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}

done:
	return found_dp && found_vport;
}

/*
 * Build + send OVS_DP_CMD_NEW for tcdp_<child>.  Required attributes
 * per uapi: OVS_DP_ATTR_NAME (string) and OVS_DP_ATTR_UPCALL_PID (u32).
 * UPCALL_PID = 0 means "drop upcalls"; we don't want the kernel to
 * spray packets at us.
 */
static int ovs_create_datapath(int fd, const char *name)
{
	unsigned char buf[OVS_NETLINK_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header {
		int dp_ifindex;
	} *ovsh;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = ovs_dp_family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_ovs_seq();

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd     = OVS_DP_CMD_NEW;
	genl->version = ovs_dp_version;
	genl->reserved = 0;

	ovsh = (struct ovs_header *)((unsigned char *)genl + GENL_HDRLEN);
	ovsh->dp_ifindex = 0;

	off = NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(sizeof(*ovsh));

	off = ovs_nla_put_str(buf, off, sizeof(buf), OVS_DP_ATTR_NAME, name);
	if (!off)
		return -EIO;
	off = ovs_nla_put_u32(buf, off, sizeof(buf), OVS_DP_ATTR_UPCALL_PID, 0);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return ovs_send_recv(fd, buf, off);
}

/*
 * Build + send OVS_VPORT_CMD_NEW for the requested kind on the cached
 * datapath.  TYPE / NAME / UPCALL_PID are mandatory; OPTIONS is a
 * nested attr carrying OVS_TUNNEL_ATTR_DST_PORT for GENEVE / VXLAN.
 * GRE has no per-port option in the OVS uapi so its OPTIONS nest is
 * left empty (and omitted entirely below to avoid emitting a zero-len
 * nested attr the kernel will reject).
 */
static int ovs_create_vport(int fd, int dp_ifindex, enum ovs_tun_kind kind,
			    const char *vname, __u16 dst_port)
{
	unsigned char buf[OVS_NETLINK_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header {
		int dp_ifindex;
	} *ovsh;
	__u32 upcall_pid = 0;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = ovs_vport_family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = next_ovs_seq();

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd     = OVS_VPORT_CMD_NEW;
	genl->version = ovs_vport_version;
	genl->reserved = 0;

	ovsh = (struct ovs_header *)((unsigned char *)genl + GENL_HDRLEN);
	ovsh->dp_ifindex = dp_ifindex;

	off = NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(sizeof(*ovsh));

	off = ovs_nla_put_u32(buf, off, sizeof(buf),
			      OVS_VPORT_ATTR_TYPE, ovs_kind_type_id(kind));
	if (!off)
		return -EIO;

	off = ovs_nla_put_str(buf, off, sizeof(buf),
			      OVS_VPORT_ATTR_NAME, vname);
	if (!off)
		return -EIO;

	/* OVS_VPORT_ATTR_UPCALL_PID is a u32[] (one entry per upcall pid).
	 * A single zero pid stamps the "discard upcalls" intent. */
	off = ovs_nla_put(buf, off, sizeof(buf),
			  OVS_VPORT_ATTR_UPCALL_PID,
			  &upcall_pid, sizeof(upcall_pid));
	if (!off)
		return -EIO;

	if (kind == OVS_TUN_GENEVE || kind == OVS_TUN_VXLAN) {
		struct nlattr *opts;
		size_t opts_off = off;

		off = ovs_nla_put(buf, off, sizeof(buf),
				  OVS_VPORT_ATTR_OPTIONS | NLA_F_NESTED,
				  NULL, 0);
		if (!off)
			return -EIO;

		off = ovs_nla_put_u16(buf, off, sizeof(buf),
				      OVS_TUNNEL_ATTR_DST_PORT,
				      htons(dst_port));
		if (!off)
			return -EIO;

		opts = (struct nlattr *)(buf + opts_off);
		opts->nla_len = (unsigned short)(off - opts_off);
	}

	nlh->nlmsg_len = (__u32)off;
	return ovs_send_recv(fd, buf, off);
}

/*
 * Build + send OVS_VPORT_CMD_DEL referencing the vport name we just
 * created.  CMD_DEL by name + dp_ifindex is the canonical untrusted-
 * caller path; the kernel resolves the vport from name within the
 * datapath and tears it down with rtnl held -- exactly the path the
 * upstream self-deadlock fix landed on.
 */
static int ovs_delete_vport(int fd, int dp_ifindex, const char *vname)
{
	unsigned char buf[OVS_NETLINK_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct genlmsghdr *genl;
	struct ovs_header {
		int dp_ifindex;
	} *ovsh;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = ovs_vport_family;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = next_ovs_seq();

	genl = (struct genlmsghdr *)NLMSG_DATA(nlh);
	genl->cmd     = OVS_VPORT_CMD_DEL;
	genl->version = ovs_vport_version;
	genl->reserved = 0;

	ovsh = (struct ovs_header *)((unsigned char *)genl + GENL_HDRLEN);
	ovsh->dp_ifindex = dp_ifindex;

	off = NLMSG_HDRLEN + GENL_HDRLEN + NLA_ALIGN(sizeof(*ovsh));

	off = ovs_nla_put_str(buf, off, sizeof(buf),
			      OVS_VPORT_ATTR_NAME, vname);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return ovs_send_recv(fd, buf, off);
}

/*
 * Bounded-deadline RTM_DELLINK racer.  Designed to run in a forked
 * helper that overlaps with the parent's still-in-flight
 * OVS_VPORT_CMD_NEW.  The kernel's CMD_NEW handler drops and reacquires
 * rtnl while registering the shared geneve_sys_<port> / vxlan_sys_<port>
 * / gre_sys_<port> helper netdev; in that window a separate rtnetlink
 * writer can race an unregister against the OVS register-vport path,
 * leaving dangling pointers in ovs_net->dps[] (the bug fixed upstream
 * by 83861c48ba12).  A post-ack racer can't reach that window because
 * the helper netdev has already been linked into ovs_net->dps[] by the
 * time CMD_NEW returns NLM_F_ACK -- the racer has to be in flight
 * during the kernel handler, not after it.
 *
 * Loop body keeps the original fresh-socket + fire-and-forget shape: a
 * missing helper / refused ifindex / send failure just costs one wasted
 * iteration.  Exit conditions: deadline reached, hard iteration cap
 * tripped, or clock_gettime failure.  sched_yield() at the tail of each
 * iteration keeps the parent (and the kernel handler) scheduled.
 */
#define OVS_RACE_DELLINK_MAX_ITERS	50U

static void ovs_race_dellink_loop(const char *helper_name,
				  unsigned int deadline_ms)
{
	struct timespec start, now;
	unsigned int iter;

	if (clock_gettime(CLOCK_MONOTONIC, &start) != 0)
		return;

	for (iter = 0; iter < OVS_RACE_DELLINK_MAX_ITERS; iter++) {
		struct sockaddr_nl sa;
		struct sockaddr_nl dst;
		unsigned char buf[256];
		struct nlmsghdr *nlh;
		struct ifinfomsg *ifi;
		struct iovec iov;
		struct msghdr mh;
		long elapsed_ms;
		int ifindex;
		int fd;

		ifindex = (int)if_nametoindex(helper_name);
		if (ifindex > 0) {
			fd = socket(AF_NETLINK,
				    SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
			if (fd >= 0) {
				memset(&sa, 0, sizeof(sa));
				sa.nl_family = AF_NETLINK;
				if (bind(fd, (struct sockaddr *)&sa,
					 sizeof(sa)) == 0) {
					memset(buf, 0, sizeof(buf));
					nlh = (struct nlmsghdr *)buf;
					nlh->nlmsg_type  = RTM_DELLINK;
					nlh->nlmsg_flags = NLM_F_REQUEST;
					nlh->nlmsg_seq   = next_ovs_seq();

					ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
					ifi->ifi_family = AF_UNSPEC;
					ifi->ifi_index  = ifindex;

					nlh->nlmsg_len = (__u32)(NLMSG_HDRLEN +
						NLMSG_ALIGN(sizeof(*ifi)));

					memset(&dst, 0, sizeof(dst));
					dst.nl_family = AF_NETLINK;

					iov.iov_base = buf;
					iov.iov_len  = nlh->nlmsg_len;

					memset(&mh, 0, sizeof(mh));
					mh.msg_name    = &dst;
					mh.msg_namelen = sizeof(dst);
					mh.msg_iov     = &iov;
					mh.msg_iovlen  = 1;

					(void)sendmsg(fd, &mh, 0);
				}
				close(fd);
			}
		}

		sched_yield();

		if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
			break;
		elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000L +
			     (now.tv_nsec - start.tv_nsec) / 1000000L;
		if (elapsed_ms >= 0 && (unsigned long)elapsed_ms >= deadline_ms)
			break;
	}
}

/*
 * One-time setup: modprobe the four kernel modules we need, open the
 * cached genl socket, resolve ovs_datapath / ovs_vport family ids, and
 * create the per-child datapath.  Latches ovs_setup_failed on any
 * fatal step so subsequent invocations short-circuit to the runs
 * counter without retrying.
 */
static bool ovs_one_time_setup(struct childdata *child)
{
	char dpname[32];
	int rc;

	if (ovs_setup_done)
		return true;
	if (ovs_setup_failed)
		return false;

	ovs_try_modprobe("openvswitch");
	ovs_try_modprobe("geneve");
	ovs_try_modprobe("vxlan");
	ovs_try_modprobe("ip_gre");

	ovs_genl_sock = ovs_genl_open();
	if (ovs_genl_sock < 0) {
		ovs_setup_failed = true;
		return false;
	}

	if (!ovs_resolve_families(ovs_genl_sock)) {
		ovs_setup_failed = true;
		close(ovs_genl_sock);
		ovs_genl_sock = -1;
		return false;
	}

	(void)snprintf(dpname, sizeof(dpname), "tcdp_%u",
		       (unsigned int)(child->num & 0xffffu));
	rc = ovs_create_datapath(ovs_genl_sock, dpname);
	if (rc != 0 && rc != -EEXIST) {
		/* EOPNOTSUPP / EPROTONOSUPPORT means the kernel is missing
		 * CONFIG_OPENVSWITCH outright; nothing more we can do. */
		ovs_setup_failed = true;
		close(ovs_genl_sock);
		ovs_genl_sock = -1;
		return false;
	}

	ovs_setup_done = true;
	return true;
}

bool ovs_tunnel_vport_churn(struct childdata *child)
{
	char vname[IFNAMSIZ];
	/* Helper netdev name can in principle exceed IFNAMSIZ for large
	 * UDP ports (kernel truncates on register).  Size the local buffer
	 * larger so snprintf doesn't lose digits at the format-truncation
	 * gate; the racer lookup just fails when the kernel-side name is
	 * truncated and that's fine (it just means we miss the window). */
	char helper[32];
	enum ovs_tun_kind kind;
	__u16 dst_port;
	__u32 iter;
	unsigned int spin;
	unsigned int i;
	pid_t racer_pid = 0;
	int rc;

	__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn_runs, 1,
			   __ATOMIC_RELAXED);

	if (ovs_setup_failed)
		return true;

	if (!ovs_one_time_setup(child)) {
		__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	kind = ovs_pick_kind();
	if (kind == OVS_TUN_NR)
		return true;

	dst_port = (__u16)RAND_RANGE(OVS_DST_PORT_MIN, OVS_DST_PORT_MAX);
	iter = next_ovs_iter_id();

	(void)snprintf(vname, sizeof(vname), "tcvp_%u_%u",
		       (unsigned int)(child->num & 0xffu),
		       (unsigned int)(iter & 0xffffu));

	/* Pre-CMD_NEW racer fork.  The kernel CMD_NEW handler for tunnel
	 * vports drops and reacquires rtnl while registering the shared
	 * helper netdev; that drop is the bug-2 (83861c48ba12) UAF window.
	 * A post-ack racer can't reach it -- by the time CMD_NEW returns,
	 * the helper netdev is already linked into ovs_net->dps[].  So
	 * fork a short-lived helper that loops RTM_DELLINK at the helper
	 * name across the kernel handler's lifetime; the helper inherits
	 * our netns automatically.  Reaped after CMD_DEL below. */
	if (ONE_IN(2)) {
		ovs_fill_helper_netdev(kind, dst_port, helper, sizeof(helper));
		if (helper[0] != '\0') {
			racer_pid = fork();
			if (racer_pid == 0) {
				ovs_race_dellink_loop(helper, 5);
				_exit(0);
			}
			if (racer_pid < 0)
				racer_pid = 0;
			else
				__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn_race_dellink_attempted,
						   1, __ATOMIC_RELAXED);
		}
	}

	rc = ovs_create_vport(ovs_genl_sock, 0, kind, vname, dst_port);
	if (rc != 0) {
		/* Module-not-loaded / type-not-registered errors latch the
		 * kind off; transient EBUSY / EEXIST / EADDRINUSE leave the
		 * latch alone so the next iteration retries with a fresh
		 * <port, name> pair. */
		if (rc == -EOPNOTSUPP || rc == -EAFNOSUPPORT ||
		    rc == -EPROTONOSUPPORT || rc == -ENOENT)
			*ovs_kind_latch(kind) = true;
		if (racer_pid > 0) {
			int wstatus;

			(void)waitpid(racer_pid, &wstatus, 0);
		}
		return true;
	}
	__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn_create_ok, 1,
			   __ATOMIC_RELAXED);

	/* Short jitter spin between CMD_NEW and the trailing CMD_DEL.
	 * BUDGETED keeps an unproductive run from melting cycles here. */
	spin = BUDGETED(CHILD_OP_OVS_TUNNEL_VPORT_CHURN,
			JITTER_RANGE(OVS_DELAY_BASE));
	for (i = 0; i < spin; i++) {
		__asm__ __volatile__("" ::: "memory");
	}

	if (ovs_delete_vport(ovs_genl_sock, 0, vname) == 0)
		__atomic_add_fetch(&shm->stats.ovs_tunnel_vport_churn_delete_ok,
				   1, __ATOMIC_RELAXED);

	if (racer_pid > 0) {
		int wstatus;

		/* Helper has a bounded ~5ms deadline + 50-iter cap, so this
		 * is fast.  Reap to avoid leaking a zombie back to child.c. */
		(void)waitpid(racer_pid, &wstatus, 0);
	}

	return true;
}
