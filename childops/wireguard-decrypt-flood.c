/*
 * wireguard_decrypt_flood — drive the kernel's wg_packet_decrypt_worker
 * under sustained pps load with syntactically-correct but undecryptable
 * MESSAGE_DATA transport packets.  upstream CI has produced soft-lockup
 * dumps in this worker at high pps; the bug shape lives in the
 * schedule-and-bail path through wg_packet_decrypt_worker, not in the
 * crypto itself, so junk Poly1305 tags are sufficient — the kernel
 * still walks receive_data_packet, dispatches the decrypt to the
 * per-cpu crypt queue, and only then drops on tag verification.  Every
 * dropped packet still costs the worker its fair share of CPU time,
 * and 200 packets per iter at ~50us spacing is enough to keep the
 * worker pinned long enough to surface the lockup window without
 * starving cooperating syscall fuzzer siblings on the box.
 *
 * Sequence (per invocation):
 *   1. (first call only) RTM_NEWLINK kind=wireguard creates wg0 in the
 *      per-child netns child.c already established via
 *      unshare(CLONE_NEWNET).  EOPNOTSUPP / ENODEV / EAFNOSUPPORT
 *      latches ns_unsupported_wireguard_decrypt_flood for the rest of
 *      the process — same shape as the EPROTONOSUPPORT-latch in
 *      atm_vcc_churn.
 *   2. (first call only) Resolve the "wireguard" genl family id via
 *      an inline CTRL_GETFAMILY dump.  fam_id == 0 latches.
 *   3. (first call only) WG_CMD_SET_DEVICE installs an ephemeral
 *      curve25519 private key (32 random bytes — the kernel side
 *      clamps), picks our listen port, and registers one peer with a
 *      random public key, allowed-ips 192.0.2.0/24, and endpoint
 *      127.0.0.1:<peer_port>.  Both ports are derived from getpid() so
 *      concurrent siblings don't collide on bind().  The attribute
 *      tree is the same one walked by the existing genetlink fam-
 *      wireguard grammar, but built inline because we want a peer that
 *      actually parses, not a fuzzed payload.
 *   4. (first call only) RTM_SETLINK IFF_UP brings wg0 up; SOCK_DGRAM
 *      is bound to peer_port so any reply traffic terminates cleanly.
 *   5. (every call) Burst loop: build up to 200 MESSAGE_DATA packets
 *      (type=4 LE u32, random key_idx, incrementing counter, 16..1400
 *      random "ciphertext" bytes) and sendto wg0's listen port on
 *      127.0.0.1.  50us nanosleep between sends keeps pps tight.
 *
 * Self-bounding: child.c's SIGALRM(1s) wraps each iter; the burst
 * loop is hard-bounded at 200; netns teardown on child exit reaps wg0
 * and the UDP socket.  Loopback only, no live wire.
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
#include <time.h>
#include <unistd.h>

#include "child.h"
#include "shm.h"
#include "trinity.h"

#if __has_include(<linux/wireguard.h>)

#include <net/if.h>
#include <netinet/in.h>
#include <linux/genetlink.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>

#include "random.h"

#define WGDF_BUF_BYTES		2048
#define WGDF_BURST_MAX		200U
#define WGDF_GAP_NS		50000L		/* 50us between sends */
#define WGDF_PAYLOAD_MIN	16U
#define WGDF_PAYLOAD_MAX	1400U
#define WGDF_RECV_TIMEO_MS	250
#define WGDF_PORT_BASE		32768U		/* high-range, peer/listen derive from pid */
#define WGDF_LO_ADDR		0x0100007fU	/* 127.0.0.1, network order */

/* MESSAGE_DATA == 4 in drivers/net/wireguard/messages.h.  All four
 * type codes are 32-bit little-endian on the wire. */
#define WGDF_MSG_TYPE_DATA	4U

static bool ns_unsupported_wireguard_decrypt_flood;
static bool g_wgdf_setup_done;
static int g_wgdf_udp_fd = -1;
static int g_wgdf_wg_ifindex;
static __u16 g_wgdf_listen_port;
static __u16 g_wgdf_peer_port;
static unsigned short g_wgdf_fam_id;
static __u32 g_wgdf_seq;
static __u64 g_wgdf_counter;

static __u32 wgdf_next_seq(void)
{
	return ++g_wgdf_seq;
}

static void wgdf_latch_unsupported(void)
{
	ns_unsupported_wireguard_decrypt_flood = true;
	__atomic_add_fetch(&shm->stats.wgdf_unsupported_latched, 1,
			   __ATOMIC_RELAXED);
}

static bool wgdf_err_unsupported(int rc)
{
	return rc == -EOPNOTSUPP || rc == -ENODEV || rc == -EAFNOSUPPORT;
}

/* Fill @len bytes with rand32() output.  Used for the curve25519
 * privkey, the peer pubkey, and the per-packet ciphertext body — none
 * of which the kernel validates beyond length.  The privkey is clamped
 * by wg_noise_set_static_identity_private_key on install, so passing
 * raw bytes is fine. */
static void wgdf_fill_random(unsigned char *out, size_t len)
{
	size_t i;
	__u32 r;

	for (i = 0; i + sizeof(r) <= len; i += sizeof(r)) {
		r = rand32();
		memcpy(out + i, &r, sizeof(r));
	}
	if (i < len) {
		r = rand32();
		memcpy(out + i, &r, len - i);
	}
}

static int wgdf_nl_open(int proto)
{
	struct timeval tv;
	int fd;

	fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);
	if (fd < 0)
		return -1;
	tv.tv_sec  = 0;
	tv.tv_usec = WGDF_RECV_TIMEO_MS * 1000;
	(void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	return fd;
}

static int wgdf_nl_send_recv(int fd, void *msg, size_t len)
{
	struct sockaddr_nl dst;
	struct iovec iov;
	struct msghdr mh;
	unsigned char rbuf[1024];
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
	return 0;
}

static size_t wgdf_nla(unsigned char *buf, size_t off, size_t cap,
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

static size_t wgdf_nla_u8(unsigned char *buf, size_t off, size_t cap,
			  unsigned short type, __u8 v)
{
	return wgdf_nla(buf, off, cap, type, &v, sizeof(v));
}

static size_t wgdf_nla_u16(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, __u16 v)
{
	return wgdf_nla(buf, off, cap, type, &v, sizeof(v));
}

static size_t wgdf_nla_str(unsigned char *buf, size_t off, size_t cap,
			   unsigned short type, const char *s)
{
	return wgdf_nla(buf, off, cap, type, s, strlen(s) + 1);
}

/* RTM_NEWLINK with IFLA_IFNAME=wg0 + IFLA_LINKINFO/IFLA_INFO_KIND=
 * "wireguard".  The wireguard module supplies its own rtnl_link_ops
 * with .kind = "wireguard", so the kernel routes us straight to
 * wg_newlink().  No IFLA_INFO_DATA is required. */
static int wgdf_create_wg0(int rtnl, const char *ifname)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	struct nlattr *li;
	size_t off, li_off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_NEWLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK |
			   NLM_F_CREATE | NLM_F_EXCL;
	nlh->nlmsg_seq   = wgdf_next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));

	off = wgdf_nla_str(buf, off, sizeof(buf), IFLA_IFNAME, ifname);
	if (!off) return -EIO;

	li_off = off;
	off = wgdf_nla(buf, off, sizeof(buf), IFLA_LINKINFO, NULL, 0);
	if (!off) return -EIO;
	off = wgdf_nla_str(buf, off, sizeof(buf), IFLA_INFO_KIND, "wireguard");
	if (!off) return -EIO;
	li = (struct nlattr *)(buf + li_off);
	li->nla_len = (unsigned short)(off - li_off);

	nlh->nlmsg_len = (__u32)off;
	return wgdf_nl_send_recv(rtnl, buf, off);
}

/* RTM_SETLINK to flip IFF_UP on @ifindex. */
static int wgdf_link_up(int rtnl, int ifindex)
{
	unsigned char buf[64];
	struct nlmsghdr *nlh;
	struct ifinfomsg *ifi;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_SETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = wgdf_next_seq();
	ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index  = ifindex;
	ifi->ifi_flags  = IFF_UP;
	ifi->ifi_change = IFF_UP;
	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ifi));
	nlh->nlmsg_len = (__u32)off;
	return wgdf_nl_send_recv(rtnl, buf, off);
}

/* Inline CTRL_GETFAMILY/NLM_F_DUMP — same shape as
 * resolve_handshake_family() in handshake-req-abort.c.  Returns the
 * resolved id or 0 if the "wireguard" family isn't registered. */
static unsigned short wgdf_resolve_family(void)
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
			const unsigned char *attrs;
			size_t attrs_off, attrs_len;
			char name[GENL_NAMSIZ];
			unsigned short this_id = 0;
			bool name_match = false;

			if (nlh->nlmsg_type == NLMSG_DONE ||
			    nlh->nlmsg_type == NLMSG_ERROR)
				goto done;
			if (nlh->nlmsg_type != GENL_ID_CTRL ||
			    nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
				goto next;

			attrs = (const unsigned char *)nlh +
				NLMSG_HDRLEN + GENL_HDRLEN;
			attrs_len = nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN;
			memset(name, 0, sizeof(name));
			for (attrs_off = 0; attrs_off + NLA_HDRLEN <= attrs_len; ) {
				const struct nlattr *nla =
					(const struct nlattr *)(attrs + attrs_off);
				size_t nla_len = nla->nla_len;
				const unsigned char *payload;
				size_t payload_len;

				if (nla_len < NLA_HDRLEN ||
				    nla_len > attrs_len - attrs_off)
					break;
				payload = (const unsigned char *)nla + NLA_HDRLEN;
				payload_len = nla_len - NLA_HDRLEN;
				switch (nla->nla_type & NLA_TYPE_MASK) {
				case CTRL_ATTR_FAMILY_ID:
					if (payload_len >= sizeof(this_id))
						memcpy(&this_id, payload, sizeof(this_id));
					break;
				case CTRL_ATTR_FAMILY_NAME: {
					size_t copy = payload_len;

					if (copy >= sizeof(name))
						copy = sizeof(name) - 1;
					memcpy(name, payload, copy);
					name[copy] = '\0';
					name_match = (strcmp(name, WG_GENL_NAME) == 0);
					break;
				}
				default:
					break;
				}
				attrs_off += NLA_ALIGN(nla_len);
			}
			if (name_match && this_id != 0)
				id = this_id;
next:
			nlh = NLMSG_NEXT(nlh, remaining);
		}
	}
done:
	close(sock);
	return id;
}

/* Build & send WG_CMD_SET_DEVICE on @genl_fd to install our private
 * key, listen port, and a single peer with allowed-ips 192.0.2.0/24
 * and endpoint 127.0.0.1:<peer_port>.  The doubly-nested
 * WGDEVICE_A_PEERS / WGPEER_A_ALLOWEDIPS shape is the one
 * net/netlink-genl-fam-wireguard.c documents. */
static int wgdf_set_device(int genl_fd, int ifindex, __u16 listen_port,
			   __u16 peer_port)
{
	unsigned char buf[WGDF_BUF_BYTES];
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnh;
	struct nlattr *peers, *peer0, *aips, *aip0;
	struct sockaddr_in endpoint;
	unsigned char privkey[WG_KEY_LEN];
	unsigned char pubkey[WG_KEY_LEN];
	unsigned char ipaddr[4] = { 192, 0, 2, 0 };
	size_t off, peers_off, peer0_off, aips_off, aip0_off;
	__u32 ifindex_u32 = (__u32)ifindex;

	wgdf_fill_random(privkey, sizeof(privkey));
	wgdf_fill_random(pubkey, sizeof(pubkey));

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = g_wgdf_fam_id;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = wgdf_next_seq();
	gnh = (struct genlmsghdr *)NLMSG_DATA(nlh);
	gnh->cmd     = WG_CMD_SET_DEVICE;
	gnh->version = WG_GENL_VERSION;
	off = NLMSG_HDRLEN + GENL_HDRLEN;

	off = wgdf_nla(buf, off, sizeof(buf), WGDEVICE_A_IFINDEX,
		       &ifindex_u32, sizeof(ifindex_u32));
	if (!off) return -EIO;
	off = wgdf_nla(buf, off, sizeof(buf), WGDEVICE_A_PRIVATE_KEY,
		       privkey, sizeof(privkey));
	if (!off) return -EIO;
	off = wgdf_nla_u16(buf, off, sizeof(buf), WGDEVICE_A_LISTEN_PORT,
			   listen_port);
	if (!off) return -EIO;

	peers_off = off;
	off = wgdf_nla(buf, off, sizeof(buf), WGDEVICE_A_PEERS, NULL, 0);
	if (!off) return -EIO;

	peer0_off = off;
	off = wgdf_nla(buf, off, sizeof(buf), 0, NULL, 0);
	if (!off) return -EIO;
	off = wgdf_nla(buf, off, sizeof(buf), WGPEER_A_PUBLIC_KEY,
		       pubkey, sizeof(pubkey));
	if (!off) return -EIO;

	memset(&endpoint, 0, sizeof(endpoint));
	endpoint.sin_family = AF_INET;
	endpoint.sin_port   = htons(peer_port);
	endpoint.sin_addr.s_addr = WGDF_LO_ADDR;
	off = wgdf_nla(buf, off, sizeof(buf), WGPEER_A_ENDPOINT,
		       &endpoint, sizeof(endpoint));
	if (!off) return -EIO;

	aips_off = off;
	off = wgdf_nla(buf, off, sizeof(buf), WGPEER_A_ALLOWEDIPS, NULL, 0);
	if (!off) return -EIO;
	aip0_off = off;
	off = wgdf_nla(buf, off, sizeof(buf), 0, NULL, 0);
	if (!off) return -EIO;
	off = wgdf_nla_u16(buf, off, sizeof(buf), WGALLOWEDIP_A_FAMILY, AF_INET);
	if (!off) return -EIO;
	off = wgdf_nla(buf, off, sizeof(buf), WGALLOWEDIP_A_IPADDR,
		       ipaddr, sizeof(ipaddr));
	if (!off) return -EIO;
	off = wgdf_nla_u8(buf, off, sizeof(buf), WGALLOWEDIP_A_CIDR_MASK, 24);
	if (!off) return -EIO;

	aip0  = (struct nlattr *)(buf + aip0_off);
	aip0->nla_len = (unsigned short)(off - aip0_off);
	aips  = (struct nlattr *)(buf + aips_off);
	aips->nla_len = (unsigned short)(off - aips_off);
	peer0 = (struct nlattr *)(buf + peer0_off);
	peer0->nla_len = (unsigned short)(off - peer0_off);
	peers = (struct nlattr *)(buf + peers_off);
	peers->nla_len = (unsigned short)(off - peers_off);

	nlh->nlmsg_len = (__u32)off;
	return wgdf_nl_send_recv(genl_fd, buf, off);
}

/* Open SOCK_DGRAM and bind to 127.0.0.1:peer_port so wg0 reply
 * traffic terminates locally instead of triggering ICMP unreachables.
 * Returns the bound fd or -1 on failure. */
static int wgdf_open_udp(__u16 peer_port)
{
	struct sockaddr_in sin;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_port        = htons(peer_port);
	sin.sin_addr.s_addr = WGDF_LO_ADDR;
	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

/* One-time per-child setup.  All branches that fail with an
 * unsupported-shaped error latch the whole op off; everything else
 * bumps wgdf_setup_failed and returns false so the next iter retries
 * (the failure may be a bind() race against a concurrent wg0 in a
 * shared netns, etc.). */
static bool wgdf_setup(void)
{
	pid_t pid = getpid();
	int rtnl, genl_fd, rc;

	g_wgdf_listen_port = (__u16)(WGDF_PORT_BASE + ((unsigned)pid & 0x3fff));
	g_wgdf_peer_port   = (__u16)(g_wgdf_listen_port ^ 0x100);

	rtnl = wgdf_nl_open(NETLINK_ROUTE);
	if (rtnl < 0)
		return false;

	rc = wgdf_create_wg0(rtnl, "wg0");
	if (rc != 0) {
		if (wgdf_err_unsupported(rc))
			wgdf_latch_unsupported();
		close(rtnl);
		return false;
	}
	g_wgdf_wg_ifindex = (int)if_nametoindex("wg0");
	if (g_wgdf_wg_ifindex <= 0) {
		close(rtnl);
		return false;
	}

	g_wgdf_fam_id = wgdf_resolve_family();
	if (g_wgdf_fam_id == 0) {
		wgdf_latch_unsupported();
		close(rtnl);
		return false;
	}

	genl_fd = wgdf_nl_open(NETLINK_GENERIC);
	if (genl_fd < 0) {
		close(rtnl);
		return false;
	}
	rc = wgdf_set_device(genl_fd, g_wgdf_wg_ifindex,
			     g_wgdf_listen_port, g_wgdf_peer_port);
	close(genl_fd);
	if (rc != 0 && rc != -EEXIST) {
		if (wgdf_err_unsupported(rc))
			wgdf_latch_unsupported();
		close(rtnl);
		return false;
	}

	(void)wgdf_link_up(rtnl, g_wgdf_wg_ifindex);
	close(rtnl);

	g_wgdf_udp_fd = wgdf_open_udp(g_wgdf_peer_port);
	if (g_wgdf_udp_fd < 0)
		return false;

	g_wgdf_setup_done = true;
	return true;
}

/* Build one MESSAGE_DATA-shaped UDP payload in-place.  Header layout
 * mirrors drivers/net/wireguard/messages.h struct message_data:
 *   le32 header (low byte == MESSAGE_DATA, upper 3 bytes 0)
 *   le32 key_idx
 *   le64 counter
 *   u8   encrypted_data[..]
 *
 * The kernel's wg_receive_data_packet decoder strips the header,
 * looks up the receiver index against the live keypair table, and
 * dispatches to wg_packet_decrypt_worker on the per-cpu crypt queue.
 * The decrypt-then-bail path is what we're driving. */
static size_t wgdf_build_data_pkt(unsigned char *out, size_t cap)
{
	__u32 hdr = WGDF_MSG_TYPE_DATA;	/* le on x86; htole32 not in libc by default */
	__u32 key_idx;
	__u64 counter;
	size_t payload_len;
	size_t total;

	payload_len = WGDF_PAYLOAD_MIN +
		      (rand32() % (WGDF_PAYLOAD_MAX - WGDF_PAYLOAD_MIN + 1U));
	total = 16 + payload_len;
	if (total > cap)
		total = cap;
	if (total < 16)
		return 0;

	key_idx = rand32();
	counter = ++g_wgdf_counter;

	memcpy(out + 0, &hdr, sizeof(hdr));
	memcpy(out + 4, &key_idx, sizeof(key_idx));
	memcpy(out + 8, &counter, sizeof(counter));
	wgdf_fill_random(out + 16, total - 16);
	return total;
}

bool wireguard_decrypt_flood(struct childdata *child)
{
	struct sockaddr_in dst;
	struct timespec gap = { .tv_sec = 0, .tv_nsec = WGDF_GAP_NS };
	unsigned char pkt[WGDF_PAYLOAD_MAX + 16];
	unsigned int i;

	(void)child;

	__atomic_add_fetch(&shm->stats.wgdf_runs, 1, __ATOMIC_RELAXED);

	if (ns_unsupported_wireguard_decrypt_flood)
		return true;

	if (!g_wgdf_setup_done) {
		if (!wgdf_setup()) {
			__atomic_add_fetch(&shm->stats.wgdf_setup_failed, 1,
					   __ATOMIC_RELAXED);
			return true;
		}
	}

	memset(&dst, 0, sizeof(dst));
	dst.sin_family      = AF_INET;
	dst.sin_port        = htons(g_wgdf_listen_port);
	dst.sin_addr.s_addr = WGDF_LO_ADDR;

	for (i = 0; i < WGDF_BURST_MAX; i++) {
		size_t len = wgdf_build_data_pkt(pkt, sizeof(pkt));

		if (sendto(g_wgdf_udp_fd, pkt, len, MSG_DONTWAIT,
			   (struct sockaddr *)&dst, sizeof(dst)) > 0)
			__atomic_add_fetch(&shm->stats.wgdf_packets_sent, 1,
					   __ATOMIC_RELAXED);
		(void)nanosleep(&gap, NULL);
	}
	return true;
}

#else  /* !__has_include(<linux/wireguard.h>) */

bool wireguard_decrypt_flood(struct childdata *child)
{
	(void)child;
	__atomic_add_fetch(&shm->stats.wgdf_runs, 1, __ATOMIC_RELAXED);
	__atomic_add_fetch(&shm->stats.wgdf_unsupported_latched, 1,
			   __ATOMIC_RELAXED);
	return true;
}

#endif /* __has_include(<linux/wireguard.h>) */
