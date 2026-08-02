/*
 * sit_proto41_rx - target ipip6_rcv() with a truncated inner IPv6
 * header so the SIT proto-41 RX decode reads past skb->tail before
 * the pull that would fault-check the inner header.
 *
 * The SIT (6-in-4) receive path inspects fields of the inner IPv6
 * header (version tag, source address) before the pskb_may_pull()
 * that guarantees a full 40-byte ipv6hdr is linearised.  A crafted
 * IPv4 frame with protocol=41 whose inner-IPv6 payload is shorter
 * than sizeof(ipv6hdr) causes the pre-pull field reads to run past
 * skb->tail; on a KASAN build that is a slab-out-of-bounds read.
 *
 * We open one AF_PACKET/SOCK_RAW socket per child, bind to loopback,
 * hand-craft an Ethernet + IPv4(proto=41) + truncated-inner frame,
 * and sendto() it.  A do-once latch at first-run modprobes the sit
 * module and brings sit0 up so ipip6_rcv() is actually registered
 * as the proto-41 handler; without that the frame is dropped in
 * ip_local_deliver() and the RX path never runs.
 *
 * Inner length is swept over {0, 4, 8, 12} bytes -- all below the
 * 40-byte ipv6hdr minimum -- so the OOB read lands at several offsets
 * past skb->tail.  Each length is burst x8 so a single hit isn't
 * swallowed by net_warn_ratelimited().  Needs CAP_NET_RAW; without it
 * socket() fails with EPERM, we latch a disabled flag, warn once via
 * outputerr(), and noop for this child.  Frames go out on loopback.
 */

#include <errno.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "child.h"
#include "childop-outcome.h"
#include "childops-util.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

#define SIT_INNER_MAX	12
#define SIT_FRAME_LEN	(14 + 20 + SIT_INNER_MAX)
#define SIT_BURST	8

static const uint8_t sit_inner_lengths[] = { 0, 4, 8, 12 };
#define SIT_NR_LENGTHS	ARRAY_SIZE(sit_inner_lengths)

static int sit_fd = -1;
static int sit_ifindex;
static bool sit_disabled;
static bool link_setup_done;

static void put_be16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v & 0xff; }

static uint16_t ip_csum(const uint8_t *hdr, size_t len)
{
	uint32_t s = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		s += ((uint32_t)hdr[i] << 8) | hdr[i + 1];
	if (i < len)
		s += (uint32_t)hdr[i] << 8;
	while (s >> 16)
		s = (s & 0xffff) + (s >> 16);
	return (uint16_t)(~s & 0xffff);
}

/* Bring sit0 up so ipip6_rcv() is registered as the proto-41 handler.
 * Best effort: on kernels without CONFIG_IPV6_SIT the interface is
 * absent and SIOCGIFFLAGS returns ENODEV; we swallow that and let the
 * emit path try anyway (proto-41 with no handler is silently dropped
 * without an OOB read, which is the safe fallback). */
static void bring_sit0_up(void)
{
	struct ifreq ifr;
	int s;

	s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (s < 0)
		return;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "sit0", IFNAMSIZ - 1);
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0 &&
	    !(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
		(void)ioctl(s, SIOCSIFFLAGS, &ifr);
	}
	close(s);
}

static void setup_sit_once(void)
{
	if (link_setup_done)
		return;
	link_setup_done = true;
	try_modprobe("sit");
	bring_sit0_up();
}

static bool ensure_socket(struct childdata *child)
{
	struct sockaddr_ll sll;
	unsigned int idx;
	int fd;
	int saved_errno;

	if (sit_disabled)
		return false;
	if (sit_fd >= 0)
		return true;

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (fd < 0) {
		saved_errno = errno;
		goto disable;
	}
	idx = if_nametoindex("lo");
	if (idx == 0)
		idx = 1;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = (int)idx;
	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		saved_errno = errno;
		close(fd);
		goto disable;
	}
	sit_fd = fd;
	sit_ifindex = (int)idx;
	return true;
disable:
	sit_disabled = true;
	{
		const enum child_op_type op = child->op_type;
		if ((int) op >= 0 && op < NR_CHILD_OP_TYPES)
			__atomic_store_n(&shm->stats.childop.latch_reason[op],
					 (saved_errno == EPERM || saved_errno == EACCES) ?
						 CHILDOP_LATCH_NS_UNSUPPORTED :
						 CHILDOP_LATCH_INIT_FAILED,
					 __ATOMIC_RELAXED);
	}
	return false;
}

/* Compose an Ethernet + IPv4(proto=41) + truncated-inner frame.
 * inner_len is one of {0,4,8,12}; when non-zero the first byte carries
 * the IPv6 version nibble (0x60) so the SIT ingress recognises the
 * frame as v6-in-v4 before the doomed field reads. */
static size_t build_frame(uint8_t *buf, uint8_t inner_len)
{
	static const uint8_t bcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint32_t lo_addr = htonl(0x7f000001);
	uint16_t tot_len = 20 + inner_len;
	uint16_t id = rnd_u32() & 0xffff;
	size_t off = 0;
	uint16_t sum;

	memcpy(buf + off, bcast_mac, 6); off += 6;
	memcpy(buf + off, bcast_mac, 6); off += 6;
	put_be16(buf + off, ETH_P_IP);   off += 2;

	buf[off + 0] = 0x45;
	buf[off + 1] = 0;
	put_be16(buf + off + 2, tot_len);
	put_be16(buf + off + 4, id);
	put_be16(buf + off + 6, 0);
	buf[off + 8] = 64;
	buf[off + 9] = 41;
	put_be16(buf + off + 10, 0);
	memcpy(buf + off + 12, &lo_addr, 4);
	memcpy(buf + off + 16, &lo_addr, 4);
	sum = ip_csum(buf + off, 20);
	put_be16(buf + off + 10, sum);
	off += 20;

	if (inner_len > 0) {
		buf[off] = 0x60;
		if (inner_len > 1)
			memset(buf + off + 1, 0, inner_len - 1);
		off += inner_len;
	}
	return off;
}

bool sit_proto41_rx(struct childdata *child)
{
	uint8_t frame[SIT_FRAME_LEN];
	struct sockaddr_ll sll;
	unsigned long direct_calls = 0;
	unsigned int i, j;

	setup_sit_once();

	if (!ensure_socket(child))
		return true;

	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = sit_ifindex;
	sll.sll_halen = 6;
	memset(sll.sll_addr, 0xff, 6);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (i = 0; i < SIT_NR_LENGTHS; i++) {
		size_t len = build_frame(frame, sit_inner_lengths[i]);
		for (j = 0; j < SIT_BURST; j++) {
			(void)sendto(sit_fd, frame, len, 0,
				     (struct sockaddr *)&sll, sizeof(sll));
			direct_calls++;
		}
	}

	if (valid_op)
		childop_direct_syscalls_add(op, direct_calls);

	return true;
}
