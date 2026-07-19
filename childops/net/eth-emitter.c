/*
 * eth_emitter - AF_PACKET/SOCK_RAW emitter for L2 template families.
 *
 * Many L2 paths (ARP, NDP, VLAN, fragmentation, exotic EtherTypes)
 * see little fuzzer coverage today: trinity rarely assembles a
 * structurally-valid Ethernet frame end-to-end and pushes it through
 * AF_PACKET, so the kernel's frame-parse fast paths stay cold.  This
 * childop opens AF_PACKET/SOCK_RAW once per child, binds to loopback,
 * and on every call hand-crafts one frame from one of five template
 * families (ARP, IPv4-frag-zero, IPv6-NA, VLAN-Q-in-Q, malformed-
 * EtherType) and sendto()s it.  Each template carries a small set of
 * mutation knobs that vary the fields the kernel's parser actually
 * branches on.  Needs CAP_NET_RAW; without it socket() fails with
 * EPERM, we latch a disabled flag, warn once via outputerr(), and
 * noop for this child.  Frames go out on loopback only.
 */

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <string.h>

#include "child.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define ETH_FRAME_MAX	1518
#define NR_TEMPLATES	5

static int eth_fd = -1;
static int eth_ifindex;
static bool eth_disabled;
static bool warned_unsupported;

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static void rand_mac(uint8_t *dst)
{
	uint32_t r0 = rnd_u32(), r1 = rnd_u32();
	dst[0] = (uint8_t)((r0 & 0xfc) | 0x02);	/* LAA, unicast */
	dst[1] = r0 >> 8;  dst[2] = r0 >> 16;
	dst[3] = r1;       dst[4] = r1 >> 8;  dst[5] = r1 >> 16;
}

static size_t put_eth_hdr(uint8_t *buf, uint16_t ethertype)
{
	rand_mac(buf);
	rand_mac(buf + 6);
	put_be16(buf + 12, ethertype);
	return 14;
}

/* Knobs: opcode (REQ/REPLY/RREQ/RREPLY), sender MAC zero|random,
 * sender IP zero|random, target IP zero|random. */
static size_t tmpl_arp(uint8_t *buf)
{
	static const uint16_t arpops[] = {
		ARPOP_REQUEST, ARPOP_REPLY, ARPOP_RREQUEST, ARPOP_RREPLY,
	};
	size_t off = put_eth_hdr(buf, ETH_P_ARP);
	uint32_t r;

	put_be16(buf + off, 0x0001);	off += 2;
	put_be16(buf + off, ETH_P_IP);	off += 2;
	buf[off++] = 6;  buf[off++] = 4;
	put_be16(buf + off, arpops[rnd_modulo_u32(ARRAY_SIZE(arpops))]);
	off += 2;
	if (RAND_BOOL()) memset(buf + off, 0, 6); else rand_mac(buf + off);
	off += 6;
	r = RAND_BOOL() ? 0 : rnd_u32();
	memcpy(buf + off, &r, 4);	off += 4;
	memset(buf + off, 0xff, 6);	off += 6;
	r = RAND_BOOL() ? 0 : rnd_u32();
	memcpy(buf + off, &r, 4);	off += 4;
	return off;
}

/* Knobs: protocol, ihl (5 or 6 with router-alert option), frag_off
 * value (always MF=0 + non-zero offset), ttl. */
static size_t tmpl_ipv4_frag_zero(uint8_t *buf)
{
	static const uint8_t protos[] = {
		IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP, 250,
	};
	size_t off = put_eth_hdr(buf, ETH_P_IP);
	uint8_t ihl = ONE_IN(4) ? 6 : 5;
	uint16_t frag_off = 1 + rnd_modulo_u32(0x1fff);
	uint32_t lo_addr = htonl(0x7f000001);
	uint16_t id = rnd_u32();

	buf[off++] = 0x40 | ihl;  buf[off++] = 0;
	put_be16(buf + off, ihl * 4 + 8); off += 2;
	put_be16(buf + off, id);	off += 2;
	put_be16(buf + off, frag_off);	off += 2;
	buf[off++] = 1 + rnd_modulo_u32(254);
	buf[off++] = protos[rnd_modulo_u32(ARRAY_SIZE(protos))];
	put_be16(buf + off, 0);		off += 2;
	memcpy(buf + off, &lo_addr, 4); off += 4;
	memcpy(buf + off, &lo_addr, 4); off += 4;
	if (ihl == 6) {
		buf[off++] = 0x94; buf[off++] = 0x04;	/* router-alert */
		buf[off++] = 0;    buf[off++] = 0;
	}
	memset(buf + off, 0, 8);
	return off + 8;
}

/* Knobs: target address (loopback/all-nodes/random), R/S/O flags,
 * target-LLA option present|absent. */
static size_t tmpl_ipv6_na(uint8_t *buf)
{
	size_t off = put_eth_hdr(buf, ETH_P_IPV6);
	bool with_lla = RAND_BOOL();
	int i;

	buf[off++] = 0x60;  buf[off++] = 0;  buf[off++] = 0;  buf[off++] = 0;
	put_be16(buf + off, with_lla ? 32 : 24);  off += 2;
	buf[off++] = IPPROTO_ICMPV6;
	buf[off++] = 1 + rnd_modulo_u32(254);
	memset(buf + off, 0, 16);
	buf[off + 15] = ONE_IN(4) ? 0 : 0x01;	off += 16;	/* src */
	memset(buf + off, 0, 16);
	buf[off] = 0xff; buf[off + 1] = 0x02; buf[off + 15] = 0x01;
	off += 16;						/* dst */
	buf[off++] = 136; buf[off++] = 0;
	put_be16(buf + off, 0); off += 2;
	buf[off++] = rnd_u32() & 0xe0;		/* R/S/O flags */
	buf[off++] = 0; buf[off++] = 0; buf[off++] = 0;
	switch (rnd_modulo_u32(3)) {
	case 0:
		memset(buf + off, 0, 16); buf[off + 15] = 0x01; break;
	case 1:
		memset(buf + off, 0, 16);
		buf[off] = 0xff; buf[off + 1] = 0x02; buf[off + 15] = 0x01;
		break;
	default:
		for (i = 0; i < 16; i++) buf[off + i] = rnd_u32() & 0xff;
	}
	off += 16;
	if (with_lla) {
		buf[off++] = 2; buf[off++] = 1;
		rand_mac(buf + off); off += 6;
	}
	return off;
}

/* Knobs: outer TPID, outer VID, inner VID, PCP, inner EtherType. */
static size_t tmpl_vlan_qinq(uint8_t *buf)
{
	static const uint16_t outer_tpids[] = { ETH_P_8021AD, 0x9100, 0x9200 };
	static const uint16_t inner_etypes[] = {
		ETH_P_IP, ETH_P_IPV6, ETH_P_ARP, 0x0000,
	};
	uint16_t outer = outer_tpids[rnd_modulo_u32(ARRAY_SIZE(outer_tpids))];
	uint16_t inner_et = inner_etypes[rnd_modulo_u32(ARRAY_SIZE(inner_etypes))];
	uint8_t pcp = rnd_modulo_u32(8);
	uint16_t out_tci = (pcp << 13) | (rnd_modulo_u32(4096) & 0x0fff);
	uint16_t in_tci  = (pcp << 13) | (rnd_modulo_u32(4096) & 0x0fff);
	size_t off = put_eth_hdr(buf, outer);
	int i;

	put_be16(buf + off, out_tci);     off += 2;
	put_be16(buf + off, ETH_P_8021Q); off += 2;
	put_be16(buf + off, in_tci);      off += 2;
	put_be16(buf + off, inner_et);    off += 2;
	for (i = 0; i < 16; i++) buf[off + i] = rnd_u32() & 0xff;
	return off + 16;
}

/* Knobs: ethertype (reserved set or random), payload length, payload
 * content (zero or random). */
static size_t tmpl_bad_ethertype(uint8_t *buf)
{
	static const uint16_t reserved[] = {
		0x0000, 0xffff, 0x88b5, 0x88b6, 0x88cc, 0x8870,
	};
	uint16_t et = ONE_IN(4) ? (uint16_t)rnd_u32()
	                        : reserved[rnd_modulo_u32(ARRAY_SIZE(reserved))];
	size_t plen = RAND_RANGE(0, 256);
	size_t off = put_eth_hdr(buf, et);

	if (RAND_BOOL())
		memset(buf + off, 0, plen);
	else
		generate_rand_bytes(buf + off, plen);
	return off + plen;
}

typedef size_t (*tmpl_fn)(uint8_t *);

static const tmpl_fn templates[NR_TEMPLATES] = {
	tmpl_arp, tmpl_ipv4_frag_zero, tmpl_ipv6_na,
	tmpl_vlan_qinq, tmpl_bad_ethertype,
};

static bool ensure_socket(struct childdata *child)
{
	struct sockaddr_ll sll;
	unsigned int idx;
	int fd;

	if (eth_disabled)
		return false;
	if (eth_fd >= 0)
		return true;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0)
		goto disable;
	idx = if_nametoindex("lo");
	if (idx == 0)
		idx = 1;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = (int)idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		close(fd);
		goto disable;
	}
	eth_fd = fd;
	eth_ifindex = (int)idx;
	return true;
disable:
	eth_disabled = true;
	/* child->op_type lives in shared memory and can be scribbled by a
	 * poisoned-arena write from a sibling; bounds-check the snapshot
	 * before indexing the NR_CHILD_OP_TYPES-sized stats arrays, same
	 * pattern the child.c dispatch loop uses for the unguarded write
	 * that motivated this guard. */
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 (errno == EPERM || errno == EACCES) ?
						 CHILDOP_LATCH_NS_UNSUPPORTED :
						 CHILDOP_LATCH_INIT_FAILED,
					 __ATOMIC_RELAXED);
	}
	if (!warned_unsupported) {
		warned_unsupported = true;
		outputerr("eth_emitter: AF_PACKET setup failed (errno=%d), disabling\n",
		          errno);
	}
	return false;
}

bool eth_emitter(struct childdata *child)
{
	uint8_t frame[ETH_FRAME_MAX];
	struct sockaddr_ll sll;
	unsigned int pick;
	size_t len;
	ssize_t rc;

	__atomic_add_fetch(&shm->stats.eth_emitter.runs, 1, __ATOMIC_RELAXED);

	if (!ensure_socket(child)) {
		__atomic_add_fetch(&shm->stats.eth_emitter.setup_failed,
		                   1, __ATOMIC_RELAXED);
		return true;
	}

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	pick = rnd_modulo_u32(NR_TEMPLATES);
	len = templates[pick](frame);
	if (len < 14 || len > sizeof(frame)) {
		__atomic_add_fetch(&shm->stats.eth_emitter.short_frame,
		                   1, __ATOMIC_RELAXED);
		return true;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = eth_ifindex;
	sll.sll_halen = 6;
	memcpy(sll.sll_addr, frame, 6);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	rc = sendto(eth_fd, frame, len, 0,
	            (struct sockaddr *)&sll, sizeof(sll));
	if (rc > 0) {
		__atomic_add_fetch(&shm->stats.eth_emitter.sends_ok,
		                   1, __ATOMIC_RELAXED);
		__atomic_add_fetch(&shm->stats.eth_emitter.per_tmpl[pick],
		                   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.eth_emitter.sends_failed,
		                   1, __ATOMIC_RELAXED);
	}
	return true;
}
