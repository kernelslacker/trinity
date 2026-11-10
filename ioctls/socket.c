#include <string.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_bridge.h>
#include <linux/if_tunnel.h>
#include <linux/ip6_tunnel.h>
#include <linux/sockios.h>

#include "ioctls.h"
#include "net.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

/* include/net/ip.h; the uapi has none, and <netinet/ip.h> clashes with
 * the <linux/ip.h> the tunnel headers pull in. */
#ifndef IP_DF
#define IP_DF		0x4000
#endif

static int socket_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SOCKET);

	for_each_obj(head, obj, idx) {
		struct socketinfo *si = &obj->sockinfo;

		if (si->fd == fd)
			return 0;
	}

	/* The child's own: see fd_class in ioctls.h. */
	if (find_local_object_by_fd(OBJ_FD_SOCKET, fd) != NULL)
		return 0;

	return -1;
}

/*
 * The tunnel ioctls, SIOCGETTUNNEL, SIOCADDTUNNEL, SIOCDELTUNNEL and
 * SIOCCHGTUNNEL (SIOCDEVPRIVATE + 0 to 3), take an ifreq naming a tunnel
 * device, with the parm struct of its kind behind ifr_data.  Each tunnel
 * module makes a fallback device of its kind in every netns, so a request
 * names one of those or the one tunnel of that kind its add makes, and the
 * parm names that tunnel, so an add, a change and a delete meet one device.
 * dev_ioctl() wants CAP_NET_ADMIN over the netns for any SIOCDEVPRIVATE
 * cmd, which only a lane child holds, in a netns of its own.
 */
enum tunnel_parm_type { PARM_IP, PARM_IP6, PARM_IP6_2 };

static const struct tunnel_kind {
	const char *fallback;
	const char *tunnel;
	enum tunnel_parm_type parm;
	unsigned char proto;	/* one the kind's add and change take */
} tunnel_kinds[] = {
	{ "tunl0",	"trinity-ipip",		PARM_IP,	IPPROTO_IPIP },
	{ "gre0",	"trinity-gre",		PARM_IP,	IPPROTO_GRE },
	{ "ip_vti0",	"trinity-vti",		PARM_IP,	IPPROTO_IPIP },
	{ "sit0",	"trinity-sit",		PARM_IP,	IPPROTO_IPV6 },
	{ "ip6tnl0",	"trinity-ip6tnl",	PARM_IP6,	IPPROTO_IPV6 },
	{ "ip6gre0",	"trinity-ip6gre",	PARM_IP6_2,	IPPROTO_GRE },
	{ "ip6_vti0",	"trinity-vti6",		PARM_IP6_2,	IPPROTO_IPV6 },
};

union tunnel_parm {
	struct ip_tunnel_parm ip;
	struct ip6_tnl_parm ip6;
	struct ip6_tnl_parm2 ip6_2;
};

/* GRE_VERSION and GRE_ROUTING, which ipgre_tunnel_ctl() and ip6gre refuse,
 * stay out, as do the keys but for two, so a change can match an add. */
static __be16 tunnel_gre_flags(void)
{
	static const __be16 flags[] = { 0, GRE_KEY, GRE_CSUM, GRE_SEQ,
					GRE_KEY | GRE_CSUM };

	return RAND_ARRAY(flags);
}

static void fill_tunnel_addr6(struct in6_addr *addr, unsigned char last)
{
	memset(addr, 0, sizeof(*addr));
	if (RAND_BOOL()) {
		addr->s6_addr[0] = 0xfd;
		addr->s6_addr[15] = last;
	}
}

/*
 * The parm a kind's add and change take: IPv4 with a 20-byte header, no
 * fragment bits but DF and a protocol of the kind's (ipip_tunnel_ctl(),
 * ipgre_tunnel_ctl(), vti_tunnel_ctl(), __ipip6_tunnel_ioctl_validate()),
 * or for an IPv6 kind a proto of the kind's (ip6_tnl_siocdevprivate(),
 * vti6_siocdevprivate()).  The addresses are 0 or one of two, so a change
 * on a tunnel whose remote end its add set matches it half the time, and
 * a delete or a get on a fallback, which looks a tunnel up by its addresses
 * and keys, finds the one an add made.  The fields stay random one time in
 * eight.
 */
static void fill_tunnel_parm(union tunnel_parm *parm,
			     const struct tunnel_kind *kind)
{
	const char *name = ONE_IN(16) ? "" : kind->tunnel;

	generate_rand_bytes((unsigned char *) parm, sizeof(*parm));
	if (ONE_IN(8))
		return;

	memset(parm, 0, sizeof(*parm));
	switch (kind->parm) {
	case PARM_IP:
		strncpy(parm->ip.name, name, IFNAMSIZ - 1);
		parm->ip.iph.version = 4;
		parm->ip.iph.ihl = 5;
		parm->ip.iph.protocol = kind->proto;
		parm->ip.iph.ttl = RAND_BOOL() ? 64 : 0;
		parm->ip.iph.tos = rnd_modulo_u32(256);
		parm->ip.iph.frag_off = RAND_BOOL() ? htons(IP_DF) : 0;
		parm->ip.iph.saddr = RAND_BOOL() ? htonl(0x0a000001) : 0;
		parm->ip.iph.daddr = RAND_BOOL() ? htonl(0x0a000002) : 0;
		if (kind->proto == IPPROTO_GRE) {
			parm->ip.i_flags = tunnel_gre_flags();
			parm->ip.o_flags = tunnel_gre_flags();
			parm->ip.i_key = htonl(RAND_RANGE(1, 2));
			parm->ip.o_key = htonl(RAND_RANGE(1, 2));
		}
		break;
	case PARM_IP6:
		strncpy(parm->ip6.name, name, IFNAMSIZ - 1);
		parm->ip6.proto = kind->proto;
		parm->ip6.encap_limit = rnd_modulo_u32(8);
		parm->ip6.hop_limit = RAND_BOOL() ? 64 : 0;
		parm->ip6.flags = rnd_u32() & (IP6_TNL_F_IGN_ENCAP_LIMIT |
					       IP6_TNL_F_USE_ORIG_TCLASS |
					       IP6_TNL_F_USE_ORIG_FLOWLABEL |
					       IP6_TNL_F_RCV_DSCP_COPY |
					       IP6_TNL_F_ALLOW_LOCAL_REMOTE);
		fill_tunnel_addr6(&parm->ip6.laddr, 1);
		fill_tunnel_addr6(&parm->ip6.raddr, 2);
		break;
	case PARM_IP6_2:
		strncpy(parm->ip6_2.name, name, IFNAMSIZ - 1);
		parm->ip6_2.proto = kind->proto;
		parm->ip6_2.encap_limit = rnd_modulo_u32(8);
		parm->ip6_2.hop_limit = RAND_BOOL() ? 64 : 0;
		parm->ip6_2.flags = rnd_u32() & (IP6_TNL_F_IGN_ENCAP_LIMIT |
						 IP6_TNL_F_USE_ORIG_TCLASS |
						 IP6_TNL_F_USE_ORIG_FLOWLABEL |
						 IP6_TNL_F_RCV_DSCP_COPY |
						 IP6_TNL_F_ALLOW_LOCAL_REMOTE);
		fill_tunnel_addr6(&parm->ip6_2.laddr, 1);
		fill_tunnel_addr6(&parm->ip6_2.raddr, 2);
		if (kind->proto == IPPROTO_GRE) {
			parm->ip6_2.i_flags = tunnel_gre_flags();
			parm->ip6_2.o_flags = tunnel_gre_flags();
			parm->ip6_2.i_key = htonl(RAND_RANGE(1, 2));
			parm->ip6_2.o_key = htonl(RAND_RANGE(1, 2));
		}
		break;
	}
}

/*
 * The bridge the group's SIOCBRADDBR makes, which br_ioctl_stub() lets a
 * lane child do in its own netns, and that SIOCBRADDIF, SIOCBRDELIF and
 * the old bridge ioctls name.
 */
#define BRIDGE_NAME	"trinity-br"

/*
 * The args br_dev_siocdevprivate() reads behind ifr_data, through any
 * SIOCDEVPRIVATE cmd: a BRCTL_ cmd and its args.  A SET it takes ends in
 * netdev_state_change() inside dev_siocdevprivate()'s netdev_lock_ops()
 * section.  The values sit in the ranges br_set_forward_delay(),
 * br_set_hello_time() and br_set_max_age() take, in clock ticks of USER_HZ
 * (100), and a port is a small ifindex.  BRCTL_GET_BRIDGE_INFO copies the
 * bridge's state out to args[1].
 */
static void fill_bridge_args(unsigned long *args)
{
	static const struct {
		unsigned long cmd, lo, hi;
	} cmds[] = {
		{ BRCTL_SET_BRIDGE_FORWARD_DELAY,	200,	3000 },
		{ BRCTL_SET_BRIDGE_HELLO_TIME,		100,	1000 },
		{ BRCTL_SET_BRIDGE_MAX_AGE,		600,	4000 },
		{ BRCTL_SET_AGEING_TIME,		0,	100000 },
		{ BRCTL_SET_BRIDGE_STP_STATE,		0,	1 },
		{ BRCTL_SET_BRIDGE_PRIORITY,		0,	65535 },
		{ BRCTL_ADD_IF,				1,	16 },
		{ BRCTL_DEL_IF,				1,	16 },
	};
	unsigned int i = rnd_modulo_u32(ARRAY_SIZE(cmds) + 1);

	memset(args, 0, 4 * sizeof(*args));
	if (i == ARRAY_SIZE(cmds)) {
		args[0] = BRCTL_GET_BRIDGE_INFO;
		args[1] = (unsigned long)
			get_writable_struct(sizeof(struct __bridge_info));
		return;
	}
	args[0] = cmds[i].cmd;
	args[1] = RAND_RANGE(cmds[i].lo, cmds[i].hi);
}

/* A zeroed ifreq naming @name, or NULL. */
static struct ifreq *new_ifreq(const char *name)
{
	struct ifreq *ifr = (struct ifreq *) get_writable_struct(sizeof(*ifr));

	if (ifr != NULL) {
		memset(ifr, 0, sizeof(*ifr));
		strncpy(ifr->ifr_name, name, IFNAMSIZ - 1);
	}
	return ifr;
}

/*
 * A tunnel cmd's ifreq, which names the bridge one time in eight, with the
 * old bridge ioctls' args, and otherwise a fallback device or its kind's
 * tunnel, half and half, with that kind's parm.
 */
static struct ifreq *devprivate_ifreq(void)
{
	const struct tunnel_kind *kind;
	union tunnel_parm *parm;
	unsigned long *args;
	struct ifreq *ifr;

	if (ONE_IN(8)) {
		args = (unsigned long *) get_writable_struct(4 * sizeof(*args));
		ifr = new_ifreq(BRIDGE_NAME);
		if (args == NULL || ifr == NULL)
			return NULL;
		fill_bridge_args(args);
		ifr->ifr_data = (void *) args;
		return ifr;
	}

	kind = &tunnel_kinds[rnd_modulo_u32(ARRAY_SIZE(tunnel_kinds))];
	parm = (union tunnel_parm *) get_writable_struct(sizeof(*parm));
	ifr = new_ifreq(RAND_BOOL() ? kind->fallback : kind->tunnel);
	if (parm == NULL || ifr == NULL)
		return NULL;
	fill_tunnel_parm(parm, kind);
	ifr->ifr_data = (void *) parm;
	return ifr;
}

/*
 * The picker's arg for every cmd but the tunnel and bridge ones, which get
 * theirs built seven times in eight: br_ioctl_stub() reads IFNAMSIZ bytes
 * of name for SIOCBRADDBR and SIOCBRDELBR, and an ifreq naming the bridge
 * and the port's ifindex for SIOCBRADDIF and SIOCBRDELIF.
 */
static void sanitise_socket_ioctl(const struct ioctl_group *grp,
				  struct syscallrecord *rec)
{
	struct ifreq *ifr = NULL;
	char *name;

	pick_random_ioctl(grp, rec);
	switch (rec->a2) {
	case SIOCBRADDBR:
	case SIOCBRDELBR:
		if (ONE_IN(8))
			return;
		name = (char *) get_writable_address(IFNAMSIZ);
		if (name == NULL)
			return;
		memset(name, 0, IFNAMSIZ);
		strncpy(name, BRIDGE_NAME, IFNAMSIZ - 1);
		rec->a3 = (unsigned long) name;
		return;
	case SIOCBRADDIF:
	case SIOCBRDELIF:
		if (ONE_IN(8))
			return;
		ifr = new_ifreq(BRIDGE_NAME);
		if (ifr != NULL)
			ifr->ifr_ifindex = RAND_RANGE(1, 16);
		break;
	case SIOCGETTUNNEL:
	case SIOCADDTUNNEL:
	case SIOCDELTUNNEL:
	case SIOCCHGTUNNEL:
		if (ONE_IN(8))
			return;
		ifr = devprivate_ifreq();
		break;
	default:
		return;
	}
	if (ifr != NULL)
		rec->a3 = (unsigned long) ifr;
}

static const struct ioctl socket_ioctls[] = {
	{ .name = "FIOSETOWN", .request = 0x8901, },
	{ .name = "SIOCSPGRP", .request = 0x8902, },
	{ .name = "FIOGETOWN", .request = 0x8903, },
	{ .name = "SIOCGPGRP", .request = 0x8904, },
	{ .name = "SIOCATMARK", .request = 0x8905, },
	{ .name = "SIOCGSTAMP", .request = 0x8906, },
	{ .name = "SIOCGSTAMPNS", .request = 0x8907, },

	{ .name = "SIOCADDRT", .request = 0x890B, },
	{ .name = "SIOCDELRT", .request = 0x890C, },
	{ .name = "SIOCRTMSG", .request = 0x890D, },
	{ .name = "SIOCGIFNAME", .request = 0x8910, },
	{ .name = "SIOCSIFLINK", .request = 0x8911, },
	{ .name = "SIOCGIFCONF", .request = 0x8912, },
	{ .name = "SIOCGIFFLAGS", .request = 0x8913, },
	{ .name = "SIOCSIFFLAGS", .request = 0x8914, },
	{ .name = "SIOCGIFADDR", .request = 0x8915, },
	{ .name = "SIOCSIFADDR", .request = 0x8916, },
	{ .name = "SIOCGIFDSTADDR", .request = 0x8917, },
	{ .name = "SIOCSIFDSTADDR", .request = 0x8918, },
	{ .name = "SIOCGIFBRDADDR", .request = 0x8919, },
	{ .name = "SIOCSIFBRDADDR", .request = 0x891a, },
	{ .name = "SIOCGIFNETMASK", .request = 0x891b, },
	{ .name = "SIOCSIFNETMASK", .request = 0x891c, },
	{ .name = "SIOCGIFMETRIC", .request = 0x891d, },
	{ .name = "SIOCSIFMETRIC", .request = 0x891e, },
	{ .name = "SIOCGIFMEM", .request = 0x891f, },
	{ .name = "SIOCSIFMEM", .request = 0x8920, },
	{ .name = "SIOCGIFMTU", .request = 0x8921, },
	{ .name = "SIOCSIFMTU", .request = 0x8922, },
	{ .name = "SIOCSIFNAME", .request = 0x8923, },
	{ .name = "SIOCSIFHWADDR", .request = 0x8924, },
	{ .name = "SIOCGIFENCAP", .request = 0x8925, },
	{ .name = "SIOCSIFENCAP", .request = 0x8926, },
	{ .name = "SIOCGIFHWADDR", .request = 0x8927, },
	{ .name = "SIOCGIFSLAVE", .request = 0x8929, },
	{ .name = "SIOCSIFSLAVE", .request = 0x8930, },
	{ .name = "SIOCADDMULTI", .request = 0x8931, },
	{ .name = "SIOCDELMULTI", .request = 0x8932, },
	{ .name = "SIOCGIFINDEX", .request = 0x8933, },
	{ .name = "SIOCSIFPFLAGS", .request = 0x8934, },
	{ .name = "SIOCGIFPFLAGS", .request = 0x8935, },
	{ .name = "SIOCDIFADDR", .request = 0x8936, },
	{ .name = "SIOCSIFHWBROADCAST", .request = 0x8937, },
	{ .name = "SIOCGIFCOUNT", .request = 0x8938, },
	{ .name = "SIOCGIFBR", .request = 0x8940, },
	{ .name = "SIOCSIFBR", .request = 0x8941, },
	{ .name = "SIOCGIFTXQLEN", .request = 0x8942, },
	{ .name = "SIOCSIFTXQLEN", .request = 0x8943, },
	{ .name = "SIOCETHTOOL", .request = 0x8946, },
	{ .name = "SIOCGMIIPHY", .request = 0x8947, },
	{ .name = "SIOCGMIIREG", .request = 0x8948, },
	{ .name = "SIOCSMIIREG", .request = 0x8949, },
	{ .name = "SIOCWANDEV", .request = 0x894A, },
	{ .name = "SIOCDARP", .request = 0x8953, },
	{ .name = "SIOCGARP", .request = 0x8954, },
	{ .name = "SIOCSARP", .request = 0x8955, },
	{ .name = "SIOCDRARP", .request = 0x8960, },
	{ .name = "SIOCGRARP", .request = 0x8961, },
	{ .name = "SIOCSRARP", .request = 0x8962, },
	{ .name = "SIOCGIFMAP", .request = 0x8970, },
	{ .name = "SIOCSIFMAP", .request = 0x8971, },
	{ .name = "SIOCGIFVLAN", .request = 0x8982, },
	{ .name = "SIOCSIFVLAN", .request = 0x8983, },
	{ .name = "SIOCBONDENSLAVE", .request = 0x8990, },
	{ .name = "SIOCBONDRELEASE", .request = 0x8991, },
	{ .name = "SIOCBONDSETHWADDR", .request = 0x8992, },
	{ .name = "SIOCBONDSLAVEINFOQUERY", .request = 0x8993, },
	{ .name = "SIOCBONDINFOQUERY", .request = 0x8994, },
	{ .name = "SIOCBONDCHANGEACTIVE", .request = 0x8995, },
	{ .name = "SIOCBRADDBR", .request = 0x89a0, },
	{ .name = "SIOCBRDELBR", .request = 0x89a1, },
	{ .name = "SIOCBRADDIF", .request = 0x89a2, },
	{ .name = "SIOCBRDELIF", .request = 0x89a3, },
	{ .name = "SIOCSHWTSTAMP", .request = 0x89b0, },
	{ .name = "SIOCGHWTSTAMP", .request = 0x89b1, },

	{ .name = "SIOCPROTOPRIVATE1", .request = 0x89e0, },
	{ .name = "SIOCPROTOPRIVATE2", .request = 0x89e1, },
	{ .name = "SIOCPROTOPRIVATE3", .request = 0x89e2, },
	{ .name = "SIOCPROTOPRIVATE4", .request = 0x89e3, },
	{ .name = "SIOCPROTOPRIVATE5", .request = 0x89e4, },
	{ .name = "SIOCPROTOPRIVATE6", .request = 0x89e5, },
	{ .name = "SIOCPROTOPRIVATE7", .request = 0x89e6, },
	{ .name = "SIOCPROTOPRIVATE8", .request = 0x89e7, },
	{ .name = "SIOCPROTOPRIVATE9", .request = 0x89e8, },
	{ .name = "SIOCPROTOPRIVATE10", .request = 0x89e9, },
	{ .name = "SIOCPROTOPRIVATE11", .request = 0x89ea, },
	{ .name = "SIOCPROTOPRIVATE12", .request = 0x89eb, },
	{ .name = "SIOCPROTOPRIVATE13", .request = 0x89ec, },
	{ .name = "SIOCPROTOPRIVATE14", .request = 0x89ed, },
	{ .name = "SIOCPROTOPRIVATE15", .request = 0x89ee, },
	{ .name = "SIOCPROTOPRIVATE16", .request = 0x89ef, },
	{ .name = "SIOCDEVPRIVATE1", .request = 0x89f0, },
	{ .name = "SIOCDEVPRIVATE2", .request = 0x89f1, },
	{ .name = "SIOCDEVPRIVATE3", .request = 0x89f2, },
	{ .name = "SIOCDEVPRIVATE4", .request = 0x89f3, },
	{ .name = "SIOCDEVPRIVATE5", .request = 0x89f4, },
	{ .name = "SIOCDEVPRIVATE6", .request = 0x89f5, },
	{ .name = "SIOCDEVPRIVATE7", .request = 0x89f6, },
	{ .name = "SIOCDEVPRIVATE8", .request = 0x89f7, },
	{ .name = "SIOCDEVPRIVATE9", .request = 0x89f8, },
	{ .name = "SIOCDEVPRIVATE10", .request = 0x89f9, },
	{ .name = "SIOCDEVPRIVATE11", .request = 0x89fa, },
	{ .name = "SIOCDEVPRIVATE12", .request = 0x89fb, },
	{ .name = "SIOCDEVPRIVATE13", .request = 0x89fc, },
	{ .name = "SIOCDEVPRIVATE14", .request = 0x89fd, },
	{ .name = "SIOCDEVPRIVATE15", .request = 0x89fe, },
	{ .name = "SIOCDEVPRIVATE16", .request = 0x89ff, },

	{ .name = "SIOCSIWCOMMIT", .request = 0x8B00, },
	{ .name = "SIOCGIWNAME", .request = 0x8B01, },
	{ .name = "SIOCSIWNWID", .request = 0x8B02, },
	{ .name = "SIOCGIWNWID", .request = 0x8B03, },
	{ .name = "SIOCSIWFREQ", .request = 0x8B04, },
	{ .name = "SIOCGIWFREQ", .request = 0x8B05, },
	{ .name = "SIOCSIWMODE", .request = 0x8B06, },
	{ .name = "SIOCGIWMODE", .request = 0x8B07, },
	{ .name = "SIOCSIWSENS", .request = 0x8B08, },
	{ .name = "SIOCGIWSENS", .request = 0x8B09, },
	{ .name = "SIOCSIWRANGE", .request = 0x8B0A, },
	{ .name = "SIOCGIWRANGE", .request = 0x8B0B, },
	{ .name = "SIOCSIWPRIV", .request = 0x8B0C, },
	{ .name = "SIOCGIWPRIV", .request = 0x8B0D, },
	{ .name = "SIOCSIWSTATS", .request = 0x8B0E, },
	{ .name = "SIOCGIWSTATS", .request = 0x8B0F, },
	{ .name = "SIOCSIWSPY", .request = 0x8B10, },
	{ .name = "SIOCGIWSPY", .request = 0x8B11, },
	{ .name = "SIOCSIWTHRSPY", .request = 0x8B12, },
	{ .name = "SIOCGIWTHRSPY", .request = 0x8B13, },
	{ .name = "SIOCSIWAP", .request = 0x8B14, },
	{ .name = "SIOCGIWAP", .request = 0x8B15, },
	{ .name = "SIOCGIWAPLIST", .request = 0x8B17, },
	{ .name = "SIOCSIWSCAN", .request = 0x8B18, },
	{ .name = "SIOCGIWSCAN", .request = 0x8B19, },
	{ .name = "SIOCSIWESSID", .request = 0x8B1A, },
	{ .name = "SIOCGIWESSID", .request = 0x8B1B, },
	{ .name = "SIOCSIWNICKN", .request = 0x8B1C, },
	{ .name = "SIOCGIWNICKN", .request = 0x8B1D, },
	{ .name = "SIOCSIWRATE", .request = 0x8B20, },
	{ .name = "SIOCGIWRATE", .request = 0x8B21, },
	{ .name = "SIOCSIWRTS", .request = 0x8B22, },
	{ .name = "SIOCGIWRTS", .request = 0x8B23, },
	{ .name = "SIOCSIWFRAG", .request = 0x8B24, },
	{ .name = "SIOCGIWFRAG", .request = 0x8B25, },
	{ .name = "SIOCSIWTXPOW", .request = 0x8B26, },
	{ .name = "SIOCGIWTXPOW", .request = 0x8B27, },
	{ .name = "SIOCSIWRETRY", .request = 0x8B28, },
	{ .name = "SIOCGIWRETRY", .request = 0x8B29, },
	{ .name = "SIOCSIWENCODE", .request = 0x8B2A, },
	{ .name = "SIOCGIWENCODE", .request = 0x8B2B, },
	{ .name = "SIOCSIWPOWER", .request = 0x8B2C, },
	{ .name = "SIOCGIWPOWER", .request = 0x8B2D, },
	{ .name = "SIOCSIWGENIE", .request = 0x8B30, },
	{ .name = "SIOCGIWGENIE", .request = 0x8B31, },
	{ .name = "SIOCSIWMLME", .request = 0x8B16, },
	{ .name = "SIOCSIWAUTH", .request = 0x8B32, },
	{ .name = "SIOCGIWAUTH", .request = 0x8B33, },
	{ .name = "SIOCSIWENCODEEXT", .request = 0x8B34, },
	{ .name = "SIOCGIWENCODEEXT", .request = 0x8B35, },
	{ .name = "SIOCSIWPMKSA", .request = 0x8B36, },
	{ .name = "SIOCIWFIRSTPRIV", .request = 0x8BE0, },
	{ .name = "SIOCIWPRIV2", .request = 0x8BE1, },
	{ .name = "SIOCIWPRIV3", .request = 0x8BE2, },
	{ .name = "SIOCIWPRIV4", .request = 0x8BE3, },
	{ .name = "SIOCIWPRIV5", .request = 0x8BE4, },
	{ .name = "SIOCIWPRIV6", .request = 0x8BE5, },
	{ .name = "SIOCIWPRIV7", .request = 0x8BE6, },
	{ .name = "SIOCIWPRIV8", .request = 0x8BE7, },
	{ .name = "SIOCIWPRIV9", .request = 0x8BE8, },
	{ .name = "SIOCIWPRIV10", .request = 0x8BE9, },
	{ .name = "SIOCIWPRIV11", .request = 0x8BEA, },
	{ .name = "SIOCIWPRIV12", .request = 0x8BEB, },
	{ .name = "SIOCIWPRIV13", .request = 0x8BEC, },
	{ .name = "SIOCIWPRIV14", .request = 0x8BED, },
	{ .name = "SIOCIWPRIV15", .request = 0x8BEE, },
	{ .name = "SIOCIWPRIV16", .request = 0x8BEF, },
	{ .name = "SIOCIWLASTPRIV", .request = 0x8BFF, },
};

static const struct ioctl_group socket_grp = {
	.name = "[socket]",
	.fd_test = socket_fd_test,
	.fd_class = ARG_FD_SOCKET,
	.sanitise = sanitise_socket_ioctl,
	.ioctls = socket_ioctls,
	.ioctls_cnt = ARRAY_SIZE(socket_ioctls),
};

REG_IOCTL_GROUP(socket_grp)
