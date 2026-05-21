#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/llc.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "trinity.h"
#include "utils.h"
#include "compat.h"

static void llc_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

	llc = zmalloc_tracked(sizeof(struct sockaddr_llc));

	llc->sllc_family = AF_LLC;
	llc->sllc_arphrd = ARPHRD_ETHER;
	llc->sllc_test = rand();
	llc->sllc_xid = rand();
	llc->sllc_ua = rand();
	llc->sllc_sap = rand();
	for (i = 0; i < IFHWADDRLEN; i++)
		llc->sllc_mac[i] = rand();
	*addr = (struct sockaddr *) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

#ifndef USE_LLC_OPT_PKTINFO
#define LLC_OPT_PKTINFO LLC_OPT_UNKNOWN
#endif

static const unsigned int llc_opts[] = {
	LLC_OPT_RETRY, LLC_OPT_SIZE, LLC_OPT_ACK_TMR_EXP, LLC_OPT_P_TMR_EXP,
	LLC_OPT_REJ_TMR_EXP, LLC_OPT_BUSY_TMR_EXP, LLC_OPT_TX_WIN, LLC_OPT_RX_WIN,
	LLC_OPT_PKTINFO,
};

#define SOL_NETBEUI 267
#define SOL_LLC 268

static void llc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_LLC;
	so->optname = RAND_ARRAY(llc_opts);
	so->optlen = sizeof(unsigned int);
}

static void netbeui_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_NETBEUI;
	so->optname = RAND_ARRAY(llc_opts);
	so->optlen = sizeof(unsigned int);
}

static struct socket_triplet llc_triplets[] = {
	{ .family = PF_LLC, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_LLC, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_llc = {
	.name = "llc",
	.setsockopt = llc_setsockopt,
	.gen_sockaddr = llc_gen_sockaddr,
	.valid_triplets = llc_triplets,
	.nr_triplets = ARRAY_SIZE(llc_triplets),
};

static void netbeui_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_llc *llc;
	unsigned int i;

	llc = zmalloc_tracked(sizeof(struct sockaddr_llc));

	llc->sllc_family = PF_NETBEUI;
	llc->sllc_arphrd = ARPHRD_ETHER;
	llc->sllc_test = rand();
	llc->sllc_xid = rand();
	llc->sllc_ua = rand();
	llc->sllc_sap = rand();
	for (i = 0; i < IFHWADDRLEN; i++)
		llc->sllc_mac[i] = rand();
	*addr = (struct sockaddr *) llc;
	*addrlen = sizeof(struct sockaddr_llc);
}

static struct socket_triplet netbeui_triplets[] = {
	{ .family = PF_NETBEUI, .protocol = 0, .type = SOCK_DGRAM },
	{ .family = PF_NETBEUI, .protocol = 0, .type = SOCK_STREAM },
};

const struct netproto proto_netbeui = {
	.name = "netbeui",
	.setsockopt = netbeui_setsockopt,
	.gen_sockaddr = netbeui_gen_sockaddr,
	.valid_triplets = netbeui_triplets,
	.nr_triplets = ARRAY_SIZE(netbeui_triplets),
};

/*
 * grammar_llc — coherent walk for AF_LLC (IEEE 802.2 Logical Link
 * Control over an Ethernet-class device).
 *
 * Random per-syscall fuzzing essentially never assembles the full
 * sequence required to land on the LLC SAP allocation table, the LLC2
 * connection-state-machine SABME setup, or the per-socket option
 * dispatcher's bound-state arms.  Bind alone needs sllc_arphrd matched
 * against a real device's hardware type and either an exact MAC match
 * via dev_getbyhwaddr_rcu or a pre-set sk_bound_dev_if via
 * SO_BINDTODEVICE — both of which random fuzzing essentially never
 * produces.  The interesting bug surface clusters around the SAP
 * lifecycle (llc_sap_open / llc_sap_remove_socket / llc_sap_put
 * refcount window during socket teardown) and the LLC2
 * connection-establishment dispatch kicked off by llc_ui_connect.
 *
 *   socket(AF_LLC, SOCK_DGRAM | SOCK_STREAM, 0)
 *     -> configure_pre_bind sets O_NONBLOCK so accept()/connect()/recv()
 *        return EAGAIN/EINPROGRESS instead of stalling the walk, then
 *        SO_BINDTODEVICE pinning the socket to a UP non-loopback
 *        ARPHRD_ETHER device cached at can_run() time.  Without this
 *        pin, llc_ui_bind takes the dev_getbyhwaddr_rcu path with a
 *        zeroed mac and never finds a device — bind returns -ENODEV
 *        and the walk aborts cleanly via *err_burst
 *     -> walk_setsockopts cycles through the LLC option set at SOL_LLC
 *        in deterministic order: LLC_OPT_RETRY, LLC_OPT_SIZE,
 *        LLC_OPT_ACK_TMR_EXP, LLC_OPT_BUSY_TMR_EXP, LLC_OPT_TX_WIN,
 *        LLC_OPT_RX_WIN.  Values are bounded against LLC_OPT_MAX_*
 *        so the option dispatcher's range-check arm passes most of
 *        the time and the writes land on the per-socket llc_sock
 *        fields (n2 / N1 / *_timer.expire / k)
 *     -> bind() to sockaddr_llc with sllc_arphrd=ARPHRD_ETHER,
 *        all-zero sllc_mac (kernel copies dev->dev_addr in via the
 *        is_zero_ether_addr arm of llc_ui_bind), random non-zero
 *        sllc_sap.  Drives llc_sap_find / llc_sap_open against the
 *        global SAP list and, on lsap collisions,
 *        llc_lookup_established against the per-SAP established list.
 *        Setting sllc_sap=0 50% of the time also exercises
 *        llc_ui_autoport's dynamic SAP allocation across
 *        LLC_SAP_DYN_START..LLC_SAP_DYN_STOP
 *     -> configure_post_bind fires one more SOL_LLC option so the
 *        bound-state arm of llc_opt_setsockopt runs after llc->dev /
 *        llc->sap are set up — different field-write ordering than
 *        the pre-bind walk
 *     -> SOCK_STREAM: the framework default needs_listen_accept
 *        returns true → listen()+accept() runs.  listen drives
 *        llc_ui_listen and the SOCK_RCVBUF / sk_max_ack_backlog
 *        plumb; accept on a non-blocking socket with no pending
 *        connection returns -EAGAIN, leaving data_fd = parent_fd
 *     -> SOCK_DGRAM: needs_listen_accept returns false; data_fd =
 *        parent_fd directly
 *     -> data_leg
 *          STREAM arm: connect() to a synthesised peer sockaddr_llc
 *            (random non-multicast unicast mac, random sllc_sap).
 *            Drives llc_ui_connect → llc_establish_connection → LLC2
 *            SABME state-machine setup — this is the connection-
 *            oriented IEEE 802.2 dispatch the grammar exists for.
 *            With O_NONBLOCK, connect returns -EINPROGRESS after the
 *            state-machine kick; without a peer the SABME never
 *            completes but the dispatch path has already run
 *          Both arms: sendmsg() to the synthesised peer with a small
 *            random payload.  STREAM hits the not-ESTABLISHED
 *            rejection arm (llc_ui_sendmsg early-out); DGRAM hits the
 *            llc_build_and_send_ui_pkt path that emits an LLC UI
 *            (unnumbered information) frame through llc_sap_action_send_ui
 *          Non-blocking recvmsg() to drain any frames the loopback-via-
 *            self path queued back
 *     -> close() — exercises llc_ui_release with both SOCK_ZAPPED-clear
 *        (post-bind) and SOCK_ZAPPED-set (bind failed) paths, including
 *        the llc_send_disc / llc_ui_wait_for_disc disconnect window
 *        for SOCK_STREAM
 *
 * Hardware reality.  The fuzz box may have no UP non-loopback
 * ARPHRD_ETHER device (cloud / container / minimal-rootfs setup).  In
 * that case llc_iface_idx stays at 0, SO_BINDTODEVICE is skipped, and
 * bind falls into the dev_getbyhwaddr_rcu arm with a zeroed mac which
 * never matches — bind returns -ENODEV per walk and the walk aborts
 * cleanly via *err_burst.  The pre-bind option churn has already run
 * by then, which is some surface.  When an ETHER device exists the
 * full walk (bind / connect / sendmsg) lands.
 *
 * Module + config presence.  af_llc.o sits in llc2.o (CONFIG_LLC2) in
 * upstream Linux's net/llc/Makefile, so a kernel built with CONFIG_LLC=m
 * but CONFIG_LLC2 unset has no AF_LLC socket family at all —
 * socket(AF_LLC, SOCK_DGRAM, 0) returns -EAFNOSUPPORT.  can_run latches
 * llc_supported=0 in that case and the grammar is filtered out at
 * sfg_pick_random_active() time without further probing.  When
 * CONFIG_LLC2 is enabled but the module isn't loaded, the same
 * -EAFNOSUPPORT response latches the same way; the per-process cache
 * doesn't auto-clear if the module loads mid-run.
 */

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL	0x4000
#endif

/* Per-process probe cache.  -1 untested, 0 unsupported, 1 supported. */
static int llc_supported = -1;

/* Per-process iface cache.  -1 untested, 0 = no UP non-loopback
 * ARPHRD_ETHER iface found, >0 = ifindex of first such iface.
 * llc_iface_name[] holds the matching name for SO_BINDTODEVICE. */
static int llc_iface_idx = -1;
static char llc_iface_name[IFNAMSIZ];

/*
 * Walk the host's interface list looking for the first UP non-loopback
 * ARPHRD_ETHER device.  Cache the result so subsequent walks reuse it.
 * Called once per process from llc_can_run on the supported path.
 */
static void llc_probe_iface(void)
{
	struct if_nameindex *ifs, *cur;
	int probe_fd;

	llc_iface_idx = 0;
	llc_iface_name[0] = '\0';

	probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (probe_fd < 0)
		return;

	ifs = if_nameindex();
	if (ifs == NULL) {
		close(probe_fd);
		return;
	}

	for (cur = ifs; cur->if_index != 0; cur++) {
		struct ifreq ifr;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, cur->if_name, IFNAMSIZ - 1);

		if (ioctl(probe_fd, SIOCGIFFLAGS, &ifr) < 0)
			continue;
		if (!(ifr.ifr_flags & IFF_UP))
			continue;
		if (ifr.ifr_flags & IFF_LOOPBACK)
			continue;

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, cur->if_name, IFNAMSIZ - 1);
		if (ioctl(probe_fd, SIOCGIFHWADDR, &ifr) < 0)
			continue;
		if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
			continue;

		llc_iface_idx = (int) cur->if_index;
		strncpy(llc_iface_name, cur->if_name, IFNAMSIZ - 1);
		llc_iface_name[IFNAMSIZ - 1] = '\0';
		break;
	}

	if_freenameindex(ifs);
	close(probe_fd);
}

static bool llc_can_run(void)
{
	int fd;

	if (llc_supported >= 0)
		return llc_supported == 1;

	fd = socket(AF_LLC, SOCK_DGRAM, 0);
	if (fd < 0) {
		llc_supported = 0;
		return false;
	}
	close(fd);
	llc_supported = 1;

	llc_probe_iface();
	return true;
}

static void llc_pick_triplet(struct socket_triplet *out)
{
	out->family = PF_LLC;
	out->protocol = 0;
	out->type = RAND_BOOL() ? SOCK_DGRAM : SOCK_STREAM;
}

/*
 * Pre-bind: O_NONBLOCK to keep accept/connect/recv from stalling the
 * walk, then SO_BINDTODEVICE to pin the socket to a real ETHER device
 * so llc_ui_bind takes the sk_bound_dev_if arm and the zero-mac fill
 * succeeds.  Skipped silently if no suitable device was found.
 */
static void llc_configure_pre_bind(int fd, __unused__ struct socket_triplet *t)
{
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	if (llc_iface_idx > 0 && llc_iface_name[0] != '\0') {
		(void) setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				  llc_iface_name,
				  (socklen_t) strlen(llc_iface_name) + 1);
	}
}

/*
 * Coherent setsockopt walk.  Cycles through the LLC option set in a
 * deterministic order so each walk hits a fresh subset of the
 * llc_opt_setsockopt switch arms.  Values are bounded against the
 * kernel's LLC_OPT_MAX_* limits so the range-check passes most of the
 * time and the writes land on the per-socket llc_sock fields.
 */
static void llc_walk_setsockopts(int fd, __unused__ struct socket_triplet *t,
				 unsigned int n)
{
	static const unsigned int opts_seq[] = {
		LLC_OPT_RETRY,
		LLC_OPT_SIZE,
		LLC_OPT_ACK_TMR_EXP,
		LLC_OPT_P_TMR_EXP,
		LLC_OPT_REJ_TMR_EXP,
		LLC_OPT_BUSY_TMR_EXP,
		LLC_OPT_TX_WIN,
		LLC_OPT_RX_WIN,
	};
	unsigned int i;
	unsigned int v;
	unsigned int opt;

	for (i = 0; i < n; i++) {
		opt = opts_seq[i % ARRAY_SIZE(opts_seq)];
		v = (unsigned int) rand();
		switch (opt) {
		case LLC_OPT_RETRY:
			v %= LLC_OPT_MAX_RETRY + 4;
			break;
		case LLC_OPT_SIZE:
			v %= LLC_OPT_MAX_SIZE + 4;
			break;
		case LLC_OPT_ACK_TMR_EXP:
			v %= LLC_OPT_MAX_ACK_TMR_EXP + 4;
			break;
		case LLC_OPT_P_TMR_EXP:
			v %= LLC_OPT_MAX_P_TMR_EXP + 4;
			break;
		case LLC_OPT_REJ_TMR_EXP:
			v %= LLC_OPT_MAX_REJ_TMR_EXP + 4;
			break;
		case LLC_OPT_BUSY_TMR_EXP:
			v %= LLC_OPT_MAX_BUSY_TMR_EXP + 4;
			break;
		case LLC_OPT_TX_WIN:
		case LLC_OPT_RX_WIN:
			v %= LLC_OPT_MAX_WIN + 4;
			break;
		}
		(void) setsockopt(fd, SOL_LLC, (int) opt, &v, sizeof(v));
	}
}

static int llc_bind_or_connect(int fd, __unused__ struct socket_triplet *t)
{
	struct sockaddr_llc sa;

	memset(&sa, 0, sizeof(sa));
	sa.sllc_family = AF_LLC;
	sa.sllc_arphrd = ARPHRD_ETHER;
	/* Zero mac → the is_zero_ether_addr arm of llc_ui_bind copies
	 * dev->dev_addr into addr->sllc_mac when SO_BINDTODEVICE pinned
	 * a device.  Without that pin the dev_getbyhwaddr_rcu path would
	 * never match a zeroed mac and the bind fails -ENODEV. */
	/* sllc_sap = 0 half the time exercises llc_ui_autoport's dynamic
	 * allocator across LLC_SAP_DYN_START..LLC_SAP_DYN_STOP; the rest
	 * pick a non-zero SAP that may collide with an existing one and
	 * walk the llc_lookup_established arm. */
	sa.sllc_sap = RAND_BOOL() ? 0 : (__u8) (1 + (rand() & 0xff));

	if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
		return -1;
	return 0;
}

/*
 * Post-bind: one extra SOL_LLC option so the bound-state arm of
 * llc_opt_setsockopt runs after llc->dev / llc->sap are wired in.
 */
static void llc_configure_post_bind(int fd, __unused__ struct socket_triplet *t)
{
	static const unsigned int post_opts[] = {
		LLC_OPT_RETRY, LLC_OPT_BUSY_TMR_EXP, LLC_OPT_TX_WIN,
	};
	unsigned int opt = post_opts[rand() % ARRAY_SIZE(post_opts)];
	unsigned int v = 1 + (rand() & 0x7);

	(void) setsockopt(fd, SOL_LLC, (int) opt, &v, sizeof(v));
}

/*
 * Build a peer sockaddr_llc with a random unicast (non-multicast) mac
 * and a random non-zero SAP.  The peer almost certainly doesn't exist
 * on the local segment; the kernel-side dispatch (llc_ui_connect's
 * llc_establish_connection for STREAM, llc_ui_sendmsg's
 * llc_build_and_send_ui_pkt for DGRAM) has already run by the time
 * the wire transmission fails, which is the surface the walk exists
 * for.
 */
static void llc_fill_peer(struct sockaddr_llc *sa)
{
	unsigned int i;

	memset(sa, 0, sizeof(*sa));
	sa->sllc_family = AF_LLC;
	sa->sllc_arphrd = ARPHRD_ETHER;
	sa->sllc_sap = (__u8) (1 + (rand() & 0xff));
	for (i = 0; i < IFHWADDRLEN; i++)
		sa->sllc_mac[i] = (unsigned char) rand();
	/* Clear the I/G bit (LSB of byte 0) → unicast destination. */
	sa->sllc_mac[0] &= 0xfe;
}

static void llc_data_leg(int parent_fd, int data_fd,
			 struct socket_triplet *triplet)
{
	struct sockaddr_llc peer;
	struct msghdr msg, rmsg;
	struct iovec iov, riov;
	unsigned char payload[64];
	unsigned char rcvbuf[256];

	llc_fill_peer(&peer);

	if (triplet->type == SOCK_STREAM) {
		/* Drives llc_ui_connect → llc_establish_connection → LLC2
		 * SABME state-machine setup.  With O_NONBLOCK the call
		 * returns -EINPROGRESS after the dispatch; without a peer
		 * the SABME never completes but the surface has run. */
		(void) connect(parent_fd, (struct sockaddr *) &peer,
			       sizeof(peer));
	}

	generate_rand_bytes(payload, sizeof(payload));
	iov.iov_base = payload;
	iov.iov_len = sizeof(payload);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &peer;
	msg.msg_namelen = sizeof(peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	(void) sendmsg(data_fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);

	memset(&rmsg, 0, sizeof(rmsg));
	riov.iov_base = rcvbuf;
	riov.iov_len = sizeof(rcvbuf);
	rmsg.msg_iov = &riov;
	rmsg.msg_iovlen = 1;
	(void) recvmsg(data_fd, &rmsg, MSG_DONTWAIT);
}

const struct socket_family_grammar grammar_llc = {
	.family			= PF_LLC,
	.name			= "llc",
	.can_run		= llc_can_run,
	.pick_triplet		= llc_pick_triplet,
	.configure_pre_bind	= llc_configure_pre_bind,
	.bind_or_connect	= llc_bind_or_connect,
	.configure_post_bind	= llc_configure_post_bind,
	.walk_setsockopts	= llc_walk_setsockopts,
	.data_leg		= llc_data_leg,
	/* needs_listen_accept defaults: true for SOCK_STREAM,
	 * false for SOCK_DGRAM — sfg_default_needs_listen_accept fits. */
};
