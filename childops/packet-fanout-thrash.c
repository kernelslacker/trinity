/*
 * packet_fanout_thrash - AF_PACKET PACKET_FANOUT join + RX/TX ring
 * mmap + fanout-group rotation, all on one socket.
 *
 * Single-syscall fuzzing can issue any one of these setsockopts, but
 * AF_PACKET's bug-rich paths require a four-step setup that flat
 * fuzzing essentially never assembles in order: socket(AF_PACKET) ->
 * setsockopt(PACKET_VERSION, TPACKET_V3) -> setsockopt(PACKET_RX_RING)
 * -> mmap the ring -> setsockopt(PACKET_FANOUT) to join a group.
 * Without a ring, packet_rcv's fast paths are never hit; without a
 * fanout group, the dispatcher logic is never exercised; without a
 * mmap, the tpacket_v3 block-walk code is never reached.
 *
 * Sequence:
 *   1. socket(AF_PACKET, SOCK_RAW, ETH_P_ALL).
 *   2. setsockopt(PACKET_VERSION, TPACKET_V3).
 *   3. setsockopt(PACKET_RX_RING) with a small tpacket_req3.
 *   4. mmap the RX ring.
 *   5. bind to ifindex=lo (loopback always exists).
 *   6. setsockopt(PACKET_FANOUT) joining group G with random
 *      type (HASH/LB/CPU/ROLLOVER/RND/QM/CBPF/EBPF) and random flags
 *      (ROLLOVER/UNIQUEID/DEFRAG).
 *   7. setsockopt(PACKET_TX_RING) with the same tpacket_req3 (driver
 *      side of the mmap ring lifecycle; this exercises the alloc path
 *      that's the historical home of CVE-2017-7308 packet_set_ring oob).
 *   8. setsockopt(PACKET_FANOUT) AGAIN with a *different* type or
 *      group_id (will frequently EALREADY -- the rejection path is
 *      itself coverage of the dispatcher's already-joined check).
 *   9. munmap; close.
 *
 * CVE class: CVE-2017-7308 packet_set_ring oob, CVE-2020-14386
 * tpacket vlan, recurring fanout-group ref bugs.
 *
 * Self-bounding: one full cycle per invocation; ring is 256 KiB
 * (4 blocks * 64 KiB) -- small enough that mass-spawning hundreds of
 * children doesn't OOM, large enough to be a real ring.  Failures at
 * every step are expected (no CAP_NET_RAW under unprivileged trinity,
 * no CONFIG_PACKET_MMAP, etc.) and treated as benign code-path
 * coverage rather than childop failure.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "child.h"
#include "compat.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef PACKET_FANOUT_FLAG_ROLLOVER
#define PACKET_FANOUT_FLAG_ROLLOVER	0x1000
#endif
#ifndef PACKET_FANOUT_FLAG_UNIQUEID
#define PACKET_FANOUT_FLAG_UNIQUEID	0x2000
#endif
#ifndef PACKET_FANOUT_FLAG_DEFRAG
#define PACKET_FANOUT_FLAG_DEFRAG	0x8000
#endif

#ifndef PACKET_FANOUT_HASH
#define PACKET_FANOUT_HASH		0
#define PACKET_FANOUT_LB		1
#define PACKET_FANOUT_CPU		2
#define PACKET_FANOUT_ROLLOVER		3
#define PACKET_FANOUT_RND		4
#define PACKET_FANOUT_QM		5
#define PACKET_FANOUT_CBPF		6
#define PACKET_FANOUT_EBPF		7
#endif

/* Modest ring: 4 blocks of 64 KiB == 256 KiB total.  Frame size of
 * 2048 yields 32 frames per block, 128 frames total -- enough for the
 * tpacket_v3 block-walker to have multiple blocks to chase, small
 * enough that hundreds of concurrent children stay well under VM
 * limits. */
#define BLOCK_SIZE	(1U << 16)
#define FRAME_SIZE	(1U << 11)
#define BLOCK_NR	4U
#define RING_BYTES	((size_t)BLOCK_SIZE * BLOCK_NR)

static unsigned int random_fanout_type(void)
{
	switch ((unsigned int)rand() % 8) {
	case 0:  return PACKET_FANOUT_HASH;
	case 1:  return PACKET_FANOUT_LB;
	case 2:  return PACKET_FANOUT_CPU;
	case 3:  return PACKET_FANOUT_ROLLOVER;
	case 4:  return PACKET_FANOUT_RND;
	case 5:  return PACKET_FANOUT_QM;
	case 6:  return PACKET_FANOUT_CBPF;
	default: return PACKET_FANOUT_EBPF;
	}
}

/* Build the packed PACKET_FANOUT arg.  Layout:
 *   bits  0..15: group_id
 *   bits 16..23: type
 *   bits 24..31: flags (ROLLOVER/UNIQUEID/DEFRAG)
 */
static int make_fanout_arg(unsigned int group, unsigned int type,
			   unsigned int flag_byte)
{
	uint32_t v;

	v = (group & 0xffffu) |
	    ((type & 0xffu) << 16) |
	    ((flag_byte & 0xffu) << 24);
	return (int)v;
}

bool packet_fanout_thrash(struct childdata *child)
{
	struct tpacket_req3 req;
	struct sockaddr_ll sll;
	void *ring = MAP_FAILED;
	int fd = -1;
	int v3 = TPACKET_V3;
	int fanout1, fanout2;
	unsigned int lo_ifindex;
	unsigned int group1, group2;
	unsigned int type1, type2;
	unsigned int flags1;
	int rc;

	(void)child;

	__atomic_add_fetch(&shm->stats.packet_fanout_runs, 1, __ATOMIC_RELAXED);

	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		/* EPERM (no CAP_NET_RAW), EAFNOSUPPORT (no CONFIG_PACKET),
		 * EPROTONOSUPPORT — all valid no-coverage early-outs. */
		__atomic_add_fetch(&shm->stats.packet_fanout_setup_failed,
				   1, __ATOMIC_RELAXED);
		return true;
	}

	if (setsockopt(fd, SOL_PACKET, PACKET_VERSION, &v3, sizeof(v3)) < 0)
		goto out;

	memset(&req, 0, sizeof(req));
	req.tp_block_size = BLOCK_SIZE;
	req.tp_frame_size = FRAME_SIZE;
	req.tp_block_nr = BLOCK_NR;
	req.tp_frame_nr = (BLOCK_SIZE * BLOCK_NR) / FRAME_SIZE;
	req.tp_retire_blk_tov = 60;
	req.tp_feature_req_word = 0;

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
		       &req, sizeof(req)) < 0) {
		__atomic_add_fetch(&shm->stats.packet_fanout_ring_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.packet_fanout_rings_installed,
			   1, __ATOMIC_RELAXED);

	ring = mmap(NULL, RING_BYTES, PROT_READ | PROT_WRITE,
		    MAP_SHARED, fd, 0);
	if (ring == MAP_FAILED) {
		__atomic_add_fetch(&shm->stats.packet_fanout_mmap_failed,
				   1, __ATOMIC_RELAXED);
		/* Setsockopt sequence still partially ran -- keep going
		 * to exercise the post-ring fanout path even without a
		 * usable userspace mapping. */
	}

	lo_ifindex = if_nametoindex("lo");
	if (lo_ifindex == 0)
		lo_ifindex = 1;	/* lo is conventionally ifindex 1 */

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = (int)lo_ifindex;
	(void)bind(fd, (struct sockaddr *)&sll, sizeof(sll));

	/* Step 6: join a fanout group with random type + flags. */
	group1 = 1 + ((unsigned int)rand() & 0xff);
	type1 = random_fanout_type();
	flags1 = 0;
	if (RAND_BOOL())
		flags1 |= (PACKET_FANOUT_FLAG_ROLLOVER >> 8);
	if (RAND_BOOL())
		flags1 |= (PACKET_FANOUT_FLAG_UNIQUEID >> 8);
	if (RAND_BOOL())
		flags1 |= (PACKET_FANOUT_FLAG_DEFRAG >> 8);

	fanout1 = make_fanout_arg(group1, type1, flags1);
	rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
			&fanout1, sizeof(fanout1));
	if (rc == 0)
		__atomic_add_fetch(&shm->stats.packet_fanout_joins,
				   1, __ATOMIC_RELAXED);

	/* Step 7: TX ring after fanout join.  This exercises the
	 * packet_set_ring path with the fanout dispatcher already
	 * armed -- a state combination flat fuzzing reaches with
	 * probability ~zero. */
	(void)setsockopt(fd, SOL_PACKET, PACKET_TX_RING,
			 &req, sizeof(req));

	/* Step 8: re-join a different fanout group OR with a different
	 * type.  The dispatcher will reject (EALREADY / EINVAL) on
	 * almost every type/group mismatch -- the rejection path is
	 * itself dispatcher coverage. */
	do {
		type2 = random_fanout_type();
		group2 = 1 + ((unsigned int)rand() & 0xff);
	} while (type2 == type1 && group2 == group1);

	fanout2 = make_fanout_arg(group2, type2, 0);
	rc = setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
			&fanout2, sizeof(fanout2));
	if (rc == 0) {
		__atomic_add_fetch(&shm->stats.packet_fanout_rejoins_ok,
				   1, __ATOMIC_RELAXED);
	} else {
		__atomic_add_fetch(&shm->stats.packet_fanout_rejoins_rejected,
				   1, __ATOMIC_RELAXED);
	}

	/* Optional: drain a PACKET_STATISTICS read to drive the
	 * ring-aware getsockopt path. */
	if (ONE_IN(4)) {
		struct tpacket_stats_v3 stats;
		socklen_t len = sizeof(stats);

		(void)getsockopt(fd, SOL_PACKET, PACKET_STATISTICS,
				 &stats, &len);
	}

out:
	if (ring != MAP_FAILED)
		(void)munmap(ring, RING_BYTES);
	if (fd >= 0)
		close(fd);
	return true;
}
