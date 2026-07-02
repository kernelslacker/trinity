#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args-internal.h"
#include "net.h"		// get_rand_socketinfo
#include "nodemask.h"		// NODEMASK_POOL_BITS
#include "random.h"		// generate_rand_bytes
#include "rnd.h"
#include "sanitise.h"		// get_writable_struct, get_argval
#include "syscall.h"
#include "trinity.h"		// cached_online_cpus

/*
 * Probe the highest NUMA node number from sysfs.  Returns 0 on a single-
 * node system (or when /sys is not available); cached after the first
 * call.  File-local until the bespoke duplicates in syscalls/migrate_pages.c
 * and syscalls/set_mempolicy.c are folded away by their conversion rows.
 */
static unsigned int nodemask_get_max_node(void)
{
	static unsigned int cached = UINT_MAX;
	FILE *fp;
	char buf[64];
	unsigned int max = 0;

	if (cached != UINT_MAX)
		return cached;

	/* check-static: slow-ok */
	fp = fopen("/sys/devices/system/node/online", "r");
	if (fp == NULL) {
		cached = 0;
		return 0;
	}

	if (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p = buf;

		while (*p != '\0') {
			char *end;
			unsigned long v = strtoul(p, &end, 10);

			if (end == p)
				break;
			if (v > max)
				max = (unsigned int) v;
			p = end;
			if (*p == '-' || *p == ',')
				p++;
		}
	}

	fclose(fp);
	cached = max;
	return max;
}

/*
 * ARG_NODEMASK: a writable pool buffer filled with a valid-ish NUMA
 * nodemask bitmap, sized to NODEMASK_POOL_BITS (128 bytes / 16 longs).
 *
 * The kernel's get_nodes() copies ceil(maxnode/8) bytes from the user
 * pointer; converted callers cap their advertised maxnode at
 * NODEMASK_POOL_BITS so that copy stays inside the pool buffer.
 *
 * Fill buckets, biased to shapes that reach the body of mbind /
 * migrate_pages / set_mempolicy rather than the early validator
 * reject:
 *   ~5%  raw random bytes  (keep the get_nodes() validator warm)
 *   95% bucketed legal / boundary shapes:
 *         node 0 only
 *         random bits within [0, max_node]
 *         all-set within nr_nodes
 *         empty / all-zero (MPOL_BIND-with-no-nodes EINVAL arm)
 *         one bit past max_node (get_nodes() reject path)
 *
 * Pool buffer (get_writable_struct), off the shared region / libc heap
 * so the blanket address scrub is a no-op.  No .cleanup needed.
 *
 * The generator owns only the buffer + fill.  The sibling maxnode
 * argument is a BIT COUNT (not a byte length), so the converted
 * caller's .sanitise keeps owning the maxnode slot -- capped at
 * NODEMASK_POOL_BITS so the kernel's copy stays in-bounds of the pool.
 */
#define NODEMASK_POOL_BYTES	((NODEMASK_POOL_BITS) / 8)
#define NODEMASK_POOL_WORDS	((NODEMASK_POOL_BYTES) / sizeof(unsigned long))

unsigned long gen_arg_nodemask(struct syscallentry *entry __unused__,
				      struct syscallrecord *rec __unused__,
				      unsigned int argnum __unused__)
{
	unsigned long *mask;
	unsigned int max_node;
	unsigned int nr_nodes;
	unsigned int cap_bits;
	unsigned int i;

	mask = (unsigned long *) get_writable_struct(NODEMASK_POOL_BYTES);
	if (mask == NULL)
		return 0;

	/* Default to empty so any bucket that only writes a few bits
	 * leaves the rest of the pool zeroed (the kernel reads up to
	 * ceil(maxnode/8) bytes, and stale bits would bleed into the
	 * caller's view of the bitmap). */
	memset(mask, 0, NODEMASK_POOL_BYTES);

	if (rnd_modulo_u32(20) == 0) {
		/* Raw random bytes -- keep the get_nodes() validator warm. */
		generate_rand_bytes((unsigned char *) mask, NODEMASK_POOL_BYTES);
		return (unsigned long) mask;
	}

	max_node = nodemask_get_max_node();
	nr_nodes = max_node + 1;
	cap_bits = NODEMASK_POOL_BITS;
	if (nr_nodes > cap_bits)
		nr_nodes = cap_bits;

	switch (rnd_modulo_u32(5)) {
	case 0:
		/* Node 0 only. */
		mask[0] = 1UL;
		break;

	case 1: {
		/* A few random bits in [0, max_node]. */
		unsigned int n_bits;
		unsigned int j;

		if (nr_nodes == 0)
			break;
		n_bits = 1 + rnd_modulo_u32(nr_nodes < 8 ? nr_nodes : 8);
		for (j = 0; j < n_bits; j++) {
			unsigned int bit = rnd_modulo_u32(nr_nodes);

			mask[bit / (sizeof(unsigned long) * 8)] |=
				1UL << (bit % (sizeof(unsigned long) * 8));
		}
		break;
	}

	case 2: {
		/* All bits set within nr_nodes. */
		unsigned int full_words = nr_nodes / (sizeof(unsigned long) * 8);
		unsigned int tail_bits = nr_nodes % (sizeof(unsigned long) * 8);

		if (full_words > NODEMASK_POOL_WORDS)
			full_words = NODEMASK_POOL_WORDS;
		for (i = 0; i < full_words; i++)
			mask[i] = ~0UL;
		if (tail_bits != 0 && full_words < NODEMASK_POOL_WORDS)
			mask[full_words] = (1UL << tail_bits) - 1UL;
		break;
	}

	case 3:
		/* Empty / all-zero -- MPOL_BIND with no nodes hits the
		 * kernel's EINVAL arm. */
		break;

	default: {
		/* One bit past max_node -- exercise the get_nodes() reject
		 * path that polices "nodemask carries a bit >= maxnode". */
		unsigned int bit = max_node + 1;

		if (bit >= NODEMASK_POOL_BITS)
			bit = NODEMASK_POOL_BITS - 1;
		mask[bit / (sizeof(unsigned long) * 8)] |=
			1UL << (bit % (sizeof(unsigned long) * 8));
		break;
	}
	}

	return (unsigned long) mask;
}

/*
 * ARG_CPUMASK: a writable pool buffer filled with a valid-ish CPU
 * affinity mask (cpu_set_t -- CPU_SETSIZE bits / 128 bytes on glibc).
 *
 * The kernel's sched_setaffinity gate rejects a mask with no bits in
 * cpu_online_mask before any of the scheduler body runs, and the raw
 * ARG_UNDEFINED fill is virtually guaranteed to land outside the
 * online range on any system with a small num_online_cpus.  Promote
 * sched_setaffinity's hand-rolled bucket distribution into a first-
 * class argtype so the affinity-mask body actually executes, and so
 * any future syscall that grows a cpumask slot picks up the same
 * valid-ish distribution by declaration.
 *
 * Fill buckets, biased toward shapes the kernel does not silently
 * reject:
 *   30%  single online CPU
 *   25%  sparse subset within [0, num_online)
 *   20%  all-online
 *   15%  offline bits set above num_online -- kernel silently strips,
 *         keeps the strip path warm
 *   10%  empty -- kernel EINVAL arm
 *
 * Pool buffer (get_writable_struct), off the shared region / libc
 * heap so the blanket address scrub is a no-op.  No .cleanup needed
 * -- mirror ARG_NODEMASK.
 *
 * The generator owns only the buffer + fill.  The sibling len
 * argument is a BYTE COUNT floored at cpumask_size(), set
 * independently per caller; the converted caller's .sanitise keeps
 * owning the len slot so the kernel's copy_from_user stays in-bounds
 * of the pool buffer.
 */
unsigned long gen_arg_cpumask(struct syscallentry *entry __unused__,
				     struct syscallrecord *rec __unused__,
				     unsigned int argnum __unused__)
{
	cpu_set_t *mask;
	unsigned int online = cached_online_cpus();
	unsigned int i, bits, idx;
	unsigned int roll;

	mask = (cpu_set_t *) get_writable_struct(sizeof(*mask));
	if (mask == NULL)
		return 0;
	CPU_ZERO(mask);

	roll = rnd_modulo_u32(100);

	if (roll < 30) {
		CPU_SET(rnd_modulo_u32(online), mask);
	} else if (roll < 55) {
		bits = 1 + rnd_modulo_u32(online);
		for (i = 0; i < bits; i++) {
			idx = rnd_modulo_u32(online);
			CPU_SET(idx, mask);
		}
	} else if (roll < 75) {
		for (i = 0; i < online; i++)
			CPU_SET(i, mask);
	} else if (roll < 90) {
		if (online < CPU_SETSIZE) {
			unsigned int span = CPU_SETSIZE - online;

			bits = 1 + rnd_modulo_u32(span);
			for (i = 0; i < bits; i++) {
				idx = online + rnd_modulo_u32(span);
				CPU_SET(idx, mask);
			}
		} else {
			CPU_SET(rnd_modulo_u32(CPU_SETSIZE), mask);
		}
	}
	/* else: empty mask -- CPU_ZERO already done above. */

	return (unsigned long) mask;
}

/* ARG_IOVECLEN / ARG_SOCKADDRLEN: the value was published into the slot
 * by the paired ARG_IOVEC / ARG_SOCKADDR generator that ran earlier in
 * this dispatch.  Just hand it back. */
unsigned long gen_arg_paired_length(struct syscallentry *entry __unused__,
					   struct syscallrecord *rec,
					   unsigned int argnum)
{
	return get_argval(rec, argnum);
}

unsigned long gen_arg_socketinfo(struct syscallentry *entry __unused__,
					struct syscallrecord *rec __unused__,
					unsigned int argnum __unused__)
{
	return (unsigned long) get_rand_socketinfo();
}
