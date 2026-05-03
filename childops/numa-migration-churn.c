/*
 * numa_migration_churn - cycle NUMA migration syscalls against a pool-drawn
 * region per invocation, with concurrent siblings holding/faulting the same
 * backing.
 *
 * Trinity's random_syscall path exercises mbind / migrate_pages / move_pages
 * / set_mempolicy with arbitrary args, but most calls bounce off range
 * validation (-EINVAL / -ENOMEM) before reaching the per-policy walker, the
 * page-migration core, or the hugepage / compaction code.  The migration
 * path also wants real cross-child contention to drive the interesting
 * behaviours: one task moves pages while a sibling holds the same region
 * pinned and a third is faulting it.  The shared mmap pool gives us that
 * for free — every alt-op child draws from the same parent-owned pool, so
 * an entry this op chooses to migrate is, with high probability, also being
 * read / written / madvised / mlocked by other concurrent children.
 *
 * Per invocation we:
 *   - Draw one writable mapping from the pool via
 *     get_map_with_prot(PROT_READ|PROT_WRITE).  PROT_NONE / read-only
 *     entries don't carry the writable VMA needed for MPOL_MF_MOVE to do
 *     work; skip them.
 *   - Loop over a curated migration-op cycle (mbind, migrate_pages,
 *     move_pages, set_mempolicy) targeting the region or the whole
 *     process.  Cycle through MPOL_BIND / MPOL_INTERLEAVE /
 *     MPOL_PREFERRED_MANY / MPOL_WEIGHTED_INTERLEAVE between mbind /
 *     set_mempolicy invocations to churn the policy state itself.
 *   - Touch a few pages at the end of each iteration to force fault-in /
 *     refault on the (potentially-migrated) backing.
 *
 * Hugepage migration and the compaction-on-migration path are particularly
 * under-pressured today; cycling MPOL_MF_MOVE / MPOL_MF_MOVE_ALL on a hot
 * region is the cheapest userspace driver for them.
 *
 * Single-node hosts: this op is meaningless.  At init we parse
 * /sys/devices/system/node/online; if only one node is present we set
 * noop_forever and every subsequent invocation bails immediately (counted
 * once for visibility).  EPERM responses from migrate_pages / move_pages
 * (need CAP_SYS_NICE) are counted as regular failures and the loop
 * continues — the kernel-side entry check still ran, which is the
 * fuzz-relevant surface.
 *
 * Recent policies (MPOL_PREFERRED_MANY in 5.15+, MPOL_WEIGHTED_INTERLEAVE
 * in 6.9+) are probed at init via a one-shot set_mempolicy attempt; if the
 * kernel rejects them we drop those modes from the per-invocation cycle.
 *
 * No private allocation: the pool entry is owned by the parent and remains
 * alive after return — this op never munmap()s it.  Same brick-risk shape
 * as the other CV.4-converted childops (madvise_cycler, mprotect_split): a
 * sibling drawing the same entry mid-migration is the test surface, not a
 * bug.
 *
 * Self-bounding:
 *   - MAX_ITERATIONS caps the inner loop (migration ops are heavyweight,
 *     each one walks ptes and may move multiple pages).
 *   - BUDGET_NS (300 ms) sits slightly above the typical thrash band
 *     because per-op cost is higher than madvise / mprotect.
 *   - alarm(1) is armed by child.c around every non-syscall op, so a
 *     wedged migration path here still trips the SIGALRM stall detector.
 */

#include <errno.h>
#include <linux/mempolicy.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "child.h"
#include "maps.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/* Recent policies that older libc / kernel headers may not define. */
#ifndef MPOL_PREFERRED_MANY
#define MPOL_PREFERRED_MANY	5
#endif
#ifndef MPOL_WEIGHTED_INTERLEAVE
#define MPOL_WEIGHTED_INTERLEAVE 6
#endif

/* Wall-clock ceiling for the inner loop.  300ms — slightly higher than
 * the typical thrash band because each migration op walks ptes and can
 * move multiple pages. */
#define BUDGET_NS	300000000L

/* Hard cap on inner-loop iterations.  Migration ops are heavyweight, so
 * 32 is plenty without risking the SIGALRM stall detector. */
#define MAX_ITERATIONS	32

/* Width of the nodemask bitmap we hand the kernel.  64 bits handles up
 * to 64 NUMA nodes; far beyond anything we'll see in practice. */
#define NODEMASK_BITS	64

/* maxnode arg to mbind/set_mempolicy is the number of bits in the mask,
 * NOT the highest node id.  See mempolicy(2). */
#define MAXNODE_ARG	(NODEMASK_BITS + 1)

/* Pages we attempt to move per move_pages() call.  Small enough that the
 * status / target arrays fit on the stack without bloat. */
#define MOVE_PAGES_BATCH	16

/* Number of pages we touch after each migration op to force fault-in. */
#define TOUCH_PAGES		4

static bool numa_inited;
static bool noop_forever;

/* Highest-numbered online node id, populated by init_numa_state().  Used
 * to cap our random node selection so we don't keep targeting offline
 * slots. */
static unsigned int max_node_id;
static unsigned int online_node_count;

/* Probed at init.  Older kernels reject these MPOL_* values with -EINVAL;
 * we drop them from the per-invocation cycle when so. */
static bool have_preferred_many;
static bool have_weighted_interleave;

static long sys_mbind(void *addr, unsigned long len, int mode,
		      const unsigned long *nodemask, unsigned long maxnode,
		      unsigned int flags)
{
	return syscall(__NR_mbind, addr, len, (unsigned long) mode,
		       nodemask, maxnode, flags);
}

static long sys_set_mempolicy(int mode, const unsigned long *nodemask,
			      unsigned long maxnode)
{
	return syscall(__NR_set_mempolicy, (unsigned long) mode,
		       nodemask, maxnode);
}

static long sys_migrate_pages(int pid, unsigned long maxnode,
			      const unsigned long *from, const unsigned long *to)
{
	return syscall(__NR_migrate_pages, (unsigned long) pid, maxnode, from, to);
}

static long sys_move_pages(int pid, unsigned long count, void **pages,
			   const int *nodes, int *status, int flags)
{
	return syscall(__NR_move_pages, (unsigned long) pid, count,
		       pages, nodes, status, (unsigned long) flags);
}

/*
 * Parse /sys/devices/system/node/online.  The file is a comma-separated
 * list of ranges, e.g. "0-1" or "0,2-3".  We just need (a) the highest
 * node id present and (b) whether more than one node is online.  Both can
 * be derived from a simple scan looking for digits and '-'.
 */
static void parse_online_nodes(void)
{
	FILE *f;
	char buf[256];
	const char *p;
	unsigned int last_high = 0;
	bool seen_any = false;

	f = fopen("/sys/devices/system/node/online", "r");
	if (f == NULL)
		return;

	if (fgets(buf, sizeof(buf), f) == NULL) {
		fclose(f);
		return;
	}
	fclose(f);

	for (p = buf; *p != '\0' && *p != '\n';) {
		unsigned int lo, hi;
		char *end;

		if (*p < '0' || *p > '9') {
			p++;
			continue;
		}

		lo = (unsigned int) strtoul(p, &end, 10);
		hi = lo;
		p = end;
		if (*p == '-') {
			p++;
			hi = (unsigned int) strtoul(p, &end, 10);
			p = end;
		}

		if (hi > last_high)
			last_high = hi;
		online_node_count += (hi - lo) + 1;
		seen_any = true;

		if (*p == ',')
			p++;
	}

	if (seen_any)
		max_node_id = last_high;
}

/*
 * Probe whether set_mempolicy() accepts MPOL_PREFERRED_MANY and
 * MPOL_WEIGHTED_INTERLEAVE on this kernel.  A one-shot call with a
 * single-node mask is enough to distinguish -EINVAL (mode unknown) from
 * success / -EPERM / etc.  We always reset to MPOL_DEFAULT afterwards so
 * we don't leave the child with a sticky policy.
 */
static void probe_recent_policies(void)
{
	unsigned long mask = 1;

	if (sys_set_mempolicy(MPOL_PREFERRED_MANY, &mask, MAXNODE_ARG) == 0 ||
	    errno != EINVAL)
		have_preferred_many = true;

	if (sys_set_mempolicy(MPOL_WEIGHTED_INTERLEAVE, &mask, MAXNODE_ARG) == 0 ||
	    errno != EINVAL)
		have_weighted_interleave = true;

	(void) sys_set_mempolicy(MPOL_DEFAULT, NULL, 0);
}

static void init_numa_state(void)
{
	numa_inited = true;

	parse_online_nodes();

	if (online_node_count < 2) {
		noop_forever = true;
		return;
	}

	probe_recent_policies();
}

/*
 * Build a single-node mask targeting node `node` in the low bits of
 * *mask.  Caller passes a unsigned long array sized at NODEMASK_BITS / 64.
 * Anything outside the first long would require a wider bitmap; we cap
 * node selection at < 64 below.
 */
static void build_single_node_mask(unsigned long *mask, unsigned int node)
{
	mask[0] = 0;
	if (node < 64)
		mask[0] = 1UL << node;
}

/*
 * Build a multi-node mask containing every online node up to max_node_id
 * (capped at 63).  Used as the to/from masks for migrate_pages so the
 * kernel actually has somewhere to migrate from and to.
 */
static void build_all_nodes_mask(unsigned long *mask)
{
	unsigned int n;

	mask[0] = 0;
	for (n = 0; n <= max_node_id && n < 64; n++)
		mask[0] |= (1UL << n);
}

/* Pick a random node id in [0, max_node_id], capped at 63. */
static unsigned int pick_node(void)
{
	unsigned int cap = max_node_id;

	if (cap > 63)
		cap = 63;
	return (unsigned int) rand() % (cap + 1);
}

/*
 * Pick a random MPOL_* mode from the set the running kernel supports.
 * MPOL_BIND / MPOL_INTERLEAVE are unconditionally available; the
 * recent-mode entries are gated by the init-time probe.
 */
static int pick_mpol_mode(void)
{
	int candidates[4];
	unsigned int n = 0;

	candidates[n++] = MPOL_BIND;
	candidates[n++] = MPOL_INTERLEAVE;
	if (have_preferred_many)
		candidates[n++] = MPOL_PREFERRED_MANY;
	if (have_weighted_interleave)
		candidates[n++] = MPOL_WEIGHTED_INTERLEAVE;

	return candidates[(unsigned int) rand() % n];
}

/*
 * Touch a handful of pages within the region to force fault-in /
 * refault on a backing the migration may have just moved out from
 * under us.  Use volatile load + occasional store so the dirty-pte
 * path also fires.
 */
static void touch_region(volatile unsigned char *base, unsigned long len)
{
	unsigned long stride = page_size;
	unsigned int touched = 0;
	unsigned long off;

	for (off = 0; off < len && touched < TOUCH_PAGES;
	     off += stride, touched++) {
		if (RAND_BOOL())
			base[off] = (unsigned char) (off & 0xff);
		else
			(void) base[off];
	}
}

static bool budget_elapsed(const struct timespec *start)
{
	struct timespec now;
	long elapsed_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	elapsed_ns = (now.tv_sec  - start->tv_sec)  * 1000000000L
		   + (now.tv_nsec - start->tv_nsec);
	return elapsed_ns >= BUDGET_NS;
}

enum migration_op {
	OP_MBIND = 0,
	OP_MIGRATE_PAGES,
	OP_MOVE_PAGES,
	OP_SET_MEMPOLICY,
	NR_MIGRATION_OPS,
};

/*
 * One iteration of the migration cycle.  Returns the number of syscalls
 * issued (for stats accounting) and *failed_out gets the number that
 * returned -1.
 */
static unsigned int do_one_op(enum migration_op op, void *region,
			      unsigned long region_len, unsigned int *failed_out)
{
	unsigned long mask[NODEMASK_BITS / (sizeof(unsigned long) * 8)];
	unsigned long from_mask[NODEMASK_BITS / (sizeof(unsigned long) * 8)];
	unsigned long to_mask[NODEMASK_BITS / (sizeof(unsigned long) * 8)];
	void *page_addrs[MOVE_PAGES_BATCH];
	int target_nodes[MOVE_PAGES_BATCH];
	int status[MOVE_PAGES_BATCH];
	unsigned int flags;
	unsigned int i, count;
	long rc;

	switch (op) {
	case OP_MBIND:
		build_single_node_mask(mask, pick_node());
		flags = MPOL_MF_MOVE;
		if ((rand() % 4) == 0)
			flags |= MPOL_MF_MOVE_ALL;
		if ((rand() % 8) == 0)
			flags |= MPOL_MF_STRICT;
		rc = sys_mbind(region, region_len, pick_mpol_mode(),
			       mask, MAXNODE_ARG, flags);
		if (rc < 0)
			(*failed_out)++;
		return 1;

	case OP_MIGRATE_PAGES:
		/* Process-wide.  Cycle source/target so successive calls
		 * actually have something to migrate. */
		build_all_nodes_mask(from_mask);
		build_single_node_mask(to_mask, pick_node());
		rc = sys_migrate_pages(0, MAXNODE_ARG, from_mask, to_mask);
		if (rc < 0)
			(*failed_out)++;
		return 1;

	case OP_MOVE_PAGES:
		/* Per-page move on a small batch from the head of the region. */
		count = (region_len / page_size < MOVE_PAGES_BATCH)
			? (unsigned int) (region_len / page_size)
			: MOVE_PAGES_BATCH;
		if (count == 0)
			return 0;
		for (i = 0; i < count; i++) {
			page_addrs[i] = (unsigned char *) region + i * page_size;
			target_nodes[i] = (int) pick_node();
			status[i] = 0;
		}
		rc = sys_move_pages(0, count, page_addrs, target_nodes,
				    status, MPOL_MF_MOVE);
		if (rc < 0)
			(*failed_out)++;
		return 1;

	case OP_SET_MEMPOLICY:
		build_single_node_mask(mask, pick_node());
		rc = sys_set_mempolicy(pick_mpol_mode(), mask, MAXNODE_ARG);
		if (rc < 0)
			(*failed_out)++;
		return 1;

	case NR_MIGRATION_OPS:
		break;
	}
	return 0;
}

bool numa_migration_churn(struct childdata *child)
{
	struct map *m;
	void *region;
	unsigned long region_len;
	struct timespec start;
	unsigned int iter;
	enum migration_op op_idx;
	unsigned int calls = 0, failed = 0;

	(void) child;

	if (!numa_inited)
		init_numa_state();

	if (noop_forever) {
		__atomic_add_fetch(&shm->stats.numa_migration_no_numa,
				   1, __ATOMIC_RELAXED);
		return false;
	}

	__atomic_add_fetch(&shm->stats.numa_migration_runs, 1, __ATOMIC_RELAXED);

	m = get_map_with_prot(PROT_READ | PROT_WRITE);
	if (m == NULL)
		return false;

	region = m->ptr;
	region_len = m->size;

	/* mbind / move_pages need at least one whole page in the range to
	 * have anything to move; reject sub-page draws up front. */
	if (region_len < page_size)
		return true;

	clock_gettime(CLOCK_MONOTONIC, &start);

	op_idx = (enum migration_op) ((unsigned int) rand() % NR_MIGRATION_OPS);

	for (iter = 0; iter < MAX_ITERATIONS; iter++) {
		calls += do_one_op(op_idx, region, region_len, &failed);
		op_idx = (enum migration_op) (((unsigned int) op_idx + 1)
					       % NR_MIGRATION_OPS);

		touch_region((volatile unsigned char *) region, region_len);

		if (budget_elapsed(&start))
			break;
	}

	if (calls)
		__atomic_add_fetch(&shm->stats.numa_migration_calls,
				   calls, __ATOMIC_RELAXED);
	if (failed)
		__atomic_add_fetch(&shm->stats.numa_migration_failed,
				   failed, __ATOMIC_RELAXED);

	/* Reset the process-wide policy so a subsequent op (in this
	 * child or the next iteration of this one) starts from a clean
	 * MPOL_DEFAULT, not whatever sticky mode we last set. */
	(void) sys_set_mempolicy(MPOL_DEFAULT, NULL, 0);

	return true;
}
