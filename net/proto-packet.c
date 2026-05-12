#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "net.h"
#include "random.h"
#include "socket-family-grammar.h"
#include "compat.h"

/* Older <linux/if_packet.h> may predate the PACKET_FANOUT_FLAG_*
 * additions.  Define the bits locally so the fuzzer can name them
 * even when building against an old UAPI header. */
#ifndef PACKET_FANOUT_FLAG_ROLLOVER
#define PACKET_FANOUT_FLAG_ROLLOVER		0x1000
#endif
#ifndef PACKET_FANOUT_FLAG_UNIQUEID
#define PACKET_FANOUT_FLAG_UNIQUEID		0x2000
#endif
#ifndef PACKET_FANOUT_FLAG_IGNORE_OUTGOING
#define PACKET_FANOUT_FLAG_IGNORE_OUTGOING	0x4000
#endif
#ifndef PACKET_FANOUT_FLAG_DEFRAG
#define PACKET_FANOUT_FLAG_DEFRAG		0x8000
#endif

/* ETH_P_* values are big-endian Ethernet types; socket() for PF_PACKET
 * expects them in network byte order.  Use a compile-time byte-swap so
 * the constant can appear in a static initializer. */
#define ETH_P_ALL_NBO (((ETH_P_ALL & 0xff) << 8) | ((ETH_P_ALL >> 8) & 0xff))

static void packet_gen_sockaddr(struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_ll *ll;

	ll = zmalloc(sizeof(struct sockaddr_ll));

	ll->sll_family = PF_PACKET;

	switch (rand() % 5) {
	case 0:
		ll->sll_protocol = htons(ETH_P_ALL);
		break;
	case 1:
		ll->sll_protocol = htons(ETH_P_IP);
		break;
	case 2:
		ll->sll_protocol = htons(ETH_P_ARP);
		break;
	case 3:
		ll->sll_protocol = htons(ETH_P_8021Q);
		break;
	case 4:
		ll->sll_protocol = htons(rand());
		break;
	}

	ll->sll_ifindex = rand() % 2;	/* 0=any, 1=lo */
	ll->sll_hatype = rand() % 2 ? 1 : rand();	/* 1=ARPHRD_ETHER */
	ll->sll_pkttype = rand() % 5;	/* HOST..OTHERHOST */
	ll->sll_halen = 6;
	generate_rand_bytes(ll->sll_addr, 8);

	*addr = (struct sockaddr *) ll;
	*addrlen = sizeof(struct sockaddr_ll);
}


static const unsigned int packet_opts[] = {
	PACKET_ADD_MEMBERSHIP, PACKET_DROP_MEMBERSHIP, PACKET_RECV_OUTPUT, 4,   /* Value 4 is still used by obsolete turbo-packet. */
	PACKET_RX_RING, PACKET_STATISTICS, PACKET_COPY_THRESH, PACKET_AUXDATA,
	PACKET_ORIGDEV, PACKET_VERSION, PACKET_HDRLEN, PACKET_RESERVE,
	PACKET_TX_RING, PACKET_LOSS, PACKET_VNET_HDR, PACKET_TX_TIMESTAMP,
	PACKET_TIMESTAMP, PACKET_FANOUT,
	PACKET_TX_HAS_OFF, PACKET_QDISC_BYPASS, PACKET_ROLLOVER_STATS,
	PACKET_FANOUT_DATA, PACKET_IGNORE_OUTGOING, PACKET_VNET_HDR_SZ,
};


static void setup_tpacket_req3(struct tpacket_req3 *req)
{
	unsigned int blocksiz = 1 << 21, framesiz = 1 << 11;
	unsigned int blocknum = 1;

	memset(req, 0, sizeof(struct tpacket_req3));
	req->tp_block_size = blocksiz;
	req->tp_frame_size = framesiz;
	req->tp_block_nr = blocknum;
	req->tp_frame_nr = (blocksiz * blocknum) / framesiz;
	req->tp_retire_blk_tov = 60;
	req->tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
}

static void packet_socket_setup(int fd)
{
	int v3 = TPACKET_V3;

	// for now, we only speak v3
	// trying to mix it up goes horribly wrong, with oom kills etc.
	(void) setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v3, sizeof(v3));
}


static void set_tpacket_version3(struct sockopt *so)
{
	char *optval = (char *) so->optval;

	optval[0] = TPACKET_V3;
	so->optlen = sizeof(int);
}

static void packet_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	struct tpacket_req3 *req = (struct tpacket_req3 *) so->optval;

	so->level = SOL_PACKET;

	so->optname = RAND_ARRAY(packet_opts);

	/* Adjust length according to operation set. */
	switch (so->optname) {
	case PACKET_VERSION:
		set_tpacket_version3(so);
		break;

	case PACKET_RX_RING:
		setup_tpacket_req3(req);
		so->optlen = sizeof(struct tpacket_req3);
		break;

	case PACKET_FANOUT: {
		/* type in low 16 bits, flags in high 16 bits */
		unsigned int *optval32 = (unsigned int *) so->optval;
		unsigned int type = rand() % 7;	/* HASH..CBPF */
		unsigned int flags = 0;

		if (RAND_BOOL())
			flags |= PACKET_FANOUT_FLAG_ROLLOVER;
		if (RAND_BOOL())
			flags |= PACKET_FANOUT_FLAG_UNIQUEID;
		if (RAND_BOOL())
			flags |= PACKET_FANOUT_FLAG_IGNORE_OUTGOING;
		if (RAND_BOOL())
			flags |= PACKET_FANOUT_FLAG_DEFRAG;
		*optval32 = type | (flags << 16) | ((rand() % 256) << 8);
		so->optlen = sizeof(unsigned int);
		break;
	}

	case PACKET_ADD_MEMBERSHIP:
	case PACKET_DROP_MEMBERSHIP: {
		struct packet_mreq *mreq = (struct packet_mreq *) so->optval;

		memset(mreq, 0, sizeof(struct packet_mreq));
		mreq->mr_ifindex = rand() % 4;
		mreq->mr_type = rand() % 4 + 1;	/* MULTICAST..ALLMULTI */
		mreq->mr_alen = rand() % 9;
		generate_rand_bytes((unsigned char *) mreq->mr_address, 8);
		so->optlen = sizeof(struct packet_mreq);
		break;
	}

	default:
		break;
	}
}

static struct socket_triplet packet_triplets[] = {
	{ .family = PF_PACKET, .protocol = ETH_P_ALL_NBO, .type = SOCK_PACKET },
	{ .family = PF_PACKET, .protocol = ETH_P_ALL_NBO, .type = SOCK_RAW },
	{ .family = PF_PACKET, .protocol = ETH_P_ALL_NBO, .type = SOCK_DGRAM },
};

const struct netproto proto_packet = {
	.name = "packet",
	.socket_setup = packet_socket_setup,
	.setsockopt = packet_setsockopt,
	.gen_sockaddr = packet_gen_sockaddr,
	.valid_triplets = packet_triplets,
	.nr_triplets = ARRAY_SIZE(packet_triplets),
};

/*
 * grammar_packet — coherent walk for AF_PACKET driven by the
 * per-family grammar dispatcher (net/socket-family-grammar.c).
 *
 * walk_setsockopts fires the TPACKET ring-teardown sequence the
 * design doc calls for: PACKET_VERSION cycles V1 -> V2 -> V3,
 * PACKET_RX_RING installs a minimal-but-valid tpacket_req3,
 * PACKET_FANOUT joins a HASH | DEFRAG group, PACKET_AUXDATA and
 * PACKET_VNET_HDR enable, then PACKET_TX_RING installs again with
 * the same minimal req3, and finally PACKET_VERSION rolls back to
 * V1 to exercise the ring-teardown-on-version-change path.  Random
 * per-syscall fuzzing rolls one of these per call — landing them
 * in this exact order on the same fd is what catches the
 * sequence-dependent packet_set_ring / packet_release_ring paths.
 *
 * pick_triplet uses SOCK_RAW or SOCK_DGRAM with one of ETH_P_ALL,
 * ETH_P_IP, ETH_P_ARP, ETH_P_802_2 in network byte order.
 * bind_or_connect lands sockaddr_ll on the loopback interface so
 * the ring can attach without depending on a real netdev.
 *
 * can_run probes socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)).
 * EPERM on unprivileged hosts latches the family off cleanly via
 * the framework's sfg_unsupported gate.
 */

#ifndef PACKET_FANOUT_HASH
#define PACKET_FANOUT_HASH		0
#endif

static const int packet_grammar_protos[] = {
	ETH_P_ALL, ETH_P_IP, ETH_P_ARP, ETH_P_802_2,
};

static bool packet_grammar_can_run(void)
{
	int fd;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static void packet_grammar_pick_triplet(struct socket_triplet *out)
{
	out->family = AF_PACKET;
	out->type = RAND_BOOL() ? SOCK_RAW : SOCK_DGRAM;
	out->protocol = htons(packet_grammar_protos[
		rand() % ARRAY_SIZE(packet_grammar_protos)]);
}

static void packet_grammar_configure_pre_bind(int fd, struct socket_triplet *t)
{
	int flags;

	(void) t;
	flags = fcntl(fd, F_GETFL, 0);
	if (flags >= 0)
		(void) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int packet_grammar_bind(int fd, struct socket_triplet *t)
{
	struct sockaddr_ll ll;
	unsigned int ifindex;

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_protocol = (unsigned short) t->protocol;
	ifindex = if_nametoindex("lo");
	ll.sll_ifindex = (int) ifindex;	/* 0 falls through to "any" */

	if (bind(fd, (struct sockaddr *) &ll, sizeof(ll)) < 0)
		return -1;
	return 0;
}

static bool packet_grammar_needs_listen_accept(struct socket_triplet *t)
{
	(void) t;
	return false;
}

static void packet_grammar_setup_req3(struct tpacket_req3 *req)
{
	memset(req, 0, sizeof(*req));
	req->tp_block_size = 0x1000;
	req->tp_block_nr = 4;
	req->tp_frame_size = 0x800;
	req->tp_frame_nr = 8;
	req->tp_retire_blk_tov = 60;
	req->tp_feature_req_word = 0;
}

static void packet_grammar_set_version(int fd, int version)
{
	(void) setsockopt(fd, SOL_PACKET, PACKET_VERSION,
			  &version, sizeof(version));
}

static void packet_grammar_walk_setsockopts(int fd, struct socket_triplet *t,
					    unsigned int n)
{
	struct tpacket_req3 req;
	unsigned int step = 0;
	int one = 1;
	unsigned int fanout;

	(void) t;

	if (step++ < n)
		packet_grammar_set_version(fd, TPACKET_V1);
	if (step++ < n)
		packet_grammar_set_version(fd, TPACKET_V2);
	if (step++ < n)
		packet_grammar_set_version(fd, TPACKET_V3);

	if (step++ < n) {
		packet_grammar_setup_req3(&req);
		(void) setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
				  &req, sizeof(req));
	}

	if (step++ < n) {
		fanout = (PACKET_FANOUT_HASH |
			  ((unsigned int) PACKET_FANOUT_FLAG_DEFRAG << 16));
		(void) setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
				  &fanout, sizeof(fanout));
	}

	if (step++ < n)
		(void) setsockopt(fd, SOL_PACKET, PACKET_AUXDATA,
				  &one, sizeof(one));
	if (step++ < n)
		(void) setsockopt(fd, SOL_PACKET, PACKET_VNET_HDR,
				  &one, sizeof(one));

	if (step++ < n) {
		packet_grammar_setup_req3(&req);
		(void) setsockopt(fd, SOL_PACKET, PACKET_TX_RING,
				  &req, sizeof(req));
	}

	/* Roll the version back to V1 — kernel must tear down the
	 * V3-shaped rings before it can install a V1 view.  This is
	 * the sequence the random per-syscall fuzzer never lands. */
	if (step++ < n)
		packet_grammar_set_version(fd, TPACKET_V1);
}

const struct socket_family_grammar grammar_packet = {
	.family			= AF_PACKET,
	.name			= "packet",
	.can_run		= packet_grammar_can_run,
	.pick_triplet		= packet_grammar_pick_triplet,
	.configure_pre_bind	= packet_grammar_configure_pre_bind,
	.bind_or_connect	= packet_grammar_bind,
	.walk_setsockopts	= packet_grammar_walk_setsockopts,
	.needs_listen_accept	= packet_grammar_needs_listen_accept,
};
