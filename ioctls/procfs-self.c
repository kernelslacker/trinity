/*
 * PROCMAP_QUERY and PAGEMAP_SCAN (do_procmap_query() and do_pagemap_scan()
 * in fs/proc/task_mmu.c), aimed at the calling child's own /proc/self/maps
 * and pagemap and never at another process's: any regular procfs file draws
 * the group, and the call goes to a file it opens.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch.h"
#include "fd.h"
#include "ioctls.h"
#include "kernel/fs.h"
#include "maps.h"
#include "owned-fd-ring.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

IOCTL_SIZE_ASSERT(PROCMAP_QUERY, struct procmap_query);
IOCTL_SIZE_ASSERT(PAGEMAP_SCAN, struct pm_scan_arg);

/*
 * The walk of /proc stops at /proc/<pid>, so the pool has no maps or pagemap
 * file, and any regular file on procfs draws the group instead.  The fd is
 * never what the call goes to (see open_own()).  procfs's device number is
 * read off this process's own maps file the first time, which leaves the
 * claim itself no syscall.
 */
static int procfs_self_fd_test(int fd __attribute__((unused)),
			       const struct stat *st)
{
	static dev_t procfs_dev;
	static bool learned;

	if (!learned) {
		struct stat self;

		learned = true;
		if (stat("/proc/self/maps", &self) == 0)
			procfs_dev = self.st_dev;
	}

	if (procfs_dev == 0 || !S_ISREG(st->st_mode))
		return -1;
	return st->st_dev == procfs_dev ? 0 : -1;
}

/*
 * The kernel binds the mm when the file is opened, so an fd names the process
 * that opened it, and the procfs pool was opened by the parent: a walk that
 * follows symlinks (-V) takes the parent's /proc/self files into it.  Each
 * call opens its own file.  The ring closes the oldest once it is full, and
 * only while its number still names the file it recorded.
 */
static struct owned_fd_ring own_fds;

/*
 * pagemap is S_IRUSR, and a task that is not dumpable owns its /proc files as
 * root (task_dump_owner()), so a child that cleared the flag, as
 * disable_coredumps() does, cannot open its own: @owner_only sets the flag for
 * the open and puts it back, as 0 if it was 2, which prctl() cannot set.
 * maps is S_IRUGO and needs none of this.
 */
static int open_own(const char *path, bool owner_only)
{
	bool toggled = owner_only && prctl(PR_GET_DUMPABLE) != 1;
	int fd;

	if (toggled)
		prctl(PR_SET_DUMPABLE, 1);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (toggled)
		prctl(PR_SET_DUMPABLE, 0);

	if (fd < 0)
		return -1;
	if (fd_is_protected(fd)) {
		close(fd);
		return -1;
	}
	owned_fd_ring_record(&own_fds, fd);
	return fd;
}

/*
 * A run of whole pages from a pool mapping, starting at one of its pages and
 * ending at its end, or the page of a stack variable when the pool has
 * none.  Returns whether the pages are a pool mapping's.
 */
static bool pick_span(unsigned long *start, unsigned long *pages)
{
	struct map *map = get_map();
	unsigned long first;

	if (map == NULL || map->ptr == NULL || map->size < page_size) {
		*start = (unsigned long) &first & PAGE_MASK;
		*pages = 1;
		return false;
	}

	first = rnd_modulo_u64(map->size / page_size);
	*start = (unsigned long) map->ptr + first * page_size;
	*pages = map->size / page_size - first;
	return true;
}

/*
 * A size and the buffer it describes go together, and the kernel answers
 * -EINVAL for one without the other: one call in 16 gets only one of them,
 * half each way.  The kernel writes up to the size, so the buffer is that
 * long.
 */
static void out_buffer(__u32 *size, __u64 *addr, unsigned int n)
{
	void *buf = get_writable_address(n);

	if (buf == NULL)
		return;

	switch (rnd_modulo_u32(32)) {
	case 0:
		*size = n;
		break;
	case 1:
		*addr = (unsigned long) buf;
		break;
	default:
		*size = n;
		*addr = (unsigned long) buf;
		break;
	}
}

/* do_procmap_query() reads at least the flags and the address. */
#define QUERY_MIN_SIZE		offsetof(struct procmap_query, vma_start)

#define QUERY_VALID_FLAGS	(PROCMAP_QUERY_VMA_READABLE | \
				 PROCMAP_QUERY_VMA_WRITABLE | \
				 PROCMAP_QUERY_VMA_EXECUTABLE | \
				 PROCMAP_QUERY_VMA_SHARED | \
				 PROCMAP_QUERY_COVERING_OR_NEXT_VMA | \
				 PROCMAP_QUERY_FILE_BACKED_VMA)

/*
 * do_procmap_query() reads the struct's own size first: under QUERY_MIN_SIZE
 * is -EINVAL, over a page -E2BIG, and one in between is read as far as it
 * goes, with the rest zero if it is shorter than the kernel's and required
 * to be zero if it is longer (copy_struct_from_user()).  The struct is
 * allocated that long and cleared, so a longer size reads a zero tail.  A
 * flag it does not know is -EINVAL, and an address no VMA that meets the
 * flags covers is -ENOENT unless the flags ask for the next VMA.  A VMA's
 * name and the build id of its file are copied out as long as the sizes
 * the call names, which the buffers are made.
 */
static void sanitise_procmap_query(struct syscallrecord *rec)
{
	static const unsigned int name_sizes[] = { PATH_MAX, 64, 256, 1 };
	static const unsigned int id_sizes[] = { 20, 32, 8, 1 };
	struct procmap_query *q;
	unsigned long start, pages;
	size_t usize = sizeof(*q), alloc;
	int fd;

	pick_span(&start, &pages);

	switch (rnd_modulo_u32(32)) {
	case 0:
	case 1:
		usize = QUERY_MIN_SIZE +
			rnd_modulo_u32(sizeof(*q) - QUERY_MIN_SIZE);
		break;
	case 2:
	case 3:
		usize = sizeof(*q) + 1 + rnd_modulo_u32(page_size - sizeof(*q));
		break;
	case 4:
		usize = RAND_BOOL() ? rnd_modulo_u32(QUERY_MIN_SIZE) :
			(size_t) page_size + 1 + rnd_modulo_u32(page_size);
		break;
	default:
		break;
	}

	alloc = (usize > sizeof(*q) && usize <= page_size) ? usize : sizeof(*q);
	q = get_writable_struct(alloc);
	if (!q)
		return;
	memset(q, 0, alloc);
	q->size = usize;

	switch (rnd_modulo_u32(16)) {
	case 6:
	case 7:
	case 8:
	case 9:
		q->query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA;
		break;
	case 10:
	case 11:
		q->query_flags = PROCMAP_QUERY_COVERING_OR_NEXT_VMA |
				 PROCMAP_QUERY_FILE_BACKED_VMA;
		break;
	case 12:
	case 13:
	case 14:
		q->query_flags = rnd_u32() & QUERY_VALID_FLAGS;
		break;
	case 15:
		q->query_flags = rnd_u64() | (1UL << 6);
		break;
	default:
		break;
	}

	/*
	 * Three in four name an address in the mapping, and one in eight one
	 * of this program's own text, whose VMA is file backed and named,
	 * and has a build id.  The rest are the end of the run, the byte
	 * before its start, 0 and ~0.
	 */
	switch (rnd_modulo_u32(32)) {
	case 24:
	case 25:
	case 26:
	case 27:
		q->query_addr = (unsigned long) sanitise_procmap_query;
		break;
	case 28:
		q->query_addr = 0;
		break;
	case 29:
		q->query_addr = ~0UL;
		break;
	case 30:
		q->query_addr = start + pages * page_size;
		break;
	case 31:
		q->query_addr = start - 1;
		break;
	default:
		q->query_addr = start + rnd_modulo_u64(pages * page_size);
		break;
	}

	if (RAND_BOOL())
		out_buffer(&q->vma_name_size, &q->vma_name_addr,
			   ONE_IN(4) ? 1 + rnd_modulo_u32(PATH_MAX) :
			   RAND_ARRAY(name_sizes));
	if (ONE_IN(4))
		out_buffer(&q->build_id_size, &q->build_id_addr,
			   RAND_ARRAY(id_sizes));

	fd = open_own("/proc/self/maps", false);
	if (fd < 0)
		return;

	rec->a1 = (unsigned long) fd;
	rec->a3 = (unsigned long) q;
}

/* The ten categories of the current kernel's PM_SCAN_CATEGORIES. */
#define SCAN_CATEGORIES		(PAGE_IS_WPALLOWED | PAGE_IS_WRITTEN | \
				 PAGE_IS_FILE | PAGE_IS_PRESENT | \
				 PAGE_IS_SWAPPED | PAGE_IS_PFNZERO | \
				 PAGE_IS_HUGE | PAGE_IS_SOFT_DIRTY | \
				 PAGE_IS_GUARD | PAGE_IS_ACCESSED)

/*
 * pagemap_scan_get_args() answers -EINVAL to a mask holding a category the
 * kernel lacks, and an older kernel lacks up to three of the ten, so a call
 * drawn from all ten is mostly turned away there.  One category in a call
 * that is valid in every other way, over an empty range, walks nothing and
 * is -EINVAL only if the kernel lacks it; any other answer keeps it, -ENOTTY
 * from a kernel with no PAGEMAP_SCAN among them.  The set is the kernel's,
 * so the first scan of a run asks and keeps it in shm for every child.  The
 * draws take a category past WPALLOWED, so a set with none is read as a
 * probe refused for another reason, and the ten stand.
 */
static unsigned long known_categories(int fd)
{
	unsigned long known = __atomic_load_n(&shm->pagemap_scan_categories,
					      __ATOMIC_RELAXED) & SCAN_CATEGORIES;
	struct pm_scan_arg probe;
	unsigned long bit;

	if (known & ~(unsigned long) PAGE_IS_WPALLOWED)
		return known;

	known = 0;
	for (bit = 1; bit & SCAN_CATEGORIES; bit <<= 1) {
		memset(&probe, 0, sizeof(probe));
		probe.size = sizeof(probe);
		probe.return_mask = bit;
		if (ioctl(fd, PAGEMAP_SCAN, &probe) >= 0 || errno != EINVAL)
			known |= bit;
	}
	if ((known & ~(unsigned long) PAGE_IS_WPALLOWED) == 0)
		known = SCAN_CATEGORIES;

	__atomic_store_n(&shm->pagemap_scan_categories, known, __ATOMIC_RELAXED);
	return known;
}

/* One category of @cats, chosen at random.  @cats is not empty. */
static unsigned long pick_category(unsigned long cats)
{
	unsigned int skip = rnd_modulo_u32(__builtin_popcountl(cats));

	while (skip--)
		cats &= cats - 1;
	return cats & -cats;
}

/* The most pages a run covers, and the most regions a call has room for. */
#define SCAN_RUN_MAX		64
#define SCAN_REGIONS_MAX	64

/*
 * pagemap_scan_get_args() answers -EINVAL for a size other than the
 * kernel's, a flag or a category it does not know, a start that is not page
 * aligned, and a length with no buffer.  An end below the start makes the
 * length wrap, which is -EFAULT.
 *
 * pagemap_scan_test_walk() skips a VMA that is not registered for userfaultfd
 * write protection in async mode when the flags ask for WP_MATCHING, and
 * fails the walk with -EPERM when they ask for CHECK_WPASYNC, so the pages of
 * an ordinary VMA are only reached with neither.  A VMA is skipped as well
 * when WPALLOWED is in category_mask and not inverted, which that kind of
 * VMA alone has, so the bit is left out of the mask most of the time.
 *
 * The masks hold the categories the running kernel has (known_categories()),
 * and one call in 32 holds a category it lacks, so that -EINVAL stays
 * exercised on a kernel that has all ten too.
 *
 * WP_MATCHING write-protects the pages of the VMAs that pass, which only a
 * child that registered one itself has, and a write fault in async mode
 * clears the protection without a signal or a wait.  It is drawn only for a
 * range inside a pool mapping, the memory a fuzzed call already acts on,
 * and never for one that runs past it or for the stack page a child with no
 * pool falls back to.  Regions are written up to vec_len, so the buffer holds
 * as many.
 */
static void sanitise_pagemap_scan(struct syscallrecord *rec)
{
	struct pm_scan_arg *a;
	unsigned long start, pages, run, known, singles;
	bool in_pool;
	int fd;

	a = get_writable_struct(sizeof(*a));
	if (!a)
		return;
	memset(a, 0, sizeof(*a));

	fd = open_own("/proc/self/pagemap", true);
	if (fd < 0)
		return;
	known = known_categories(fd);
	singles = known & ~(unsigned long) PAGE_IS_WPALLOWED;

	a->size = sizeof(*a);
	if (ONE_IN(32))
		a->size = RAND_BOOL() ? rnd_u64() :
			  RAND_BOOL() ? sizeof(*a) - 8 : sizeof(*a) + 8;

	in_pool = pick_span(&start, &pages);
	run = 1 + rnd_modulo_u64(pages < SCAN_RUN_MAX ? pages : SCAN_RUN_MAX);
	a->start = start;
	a->end = start + run * page_size;

	switch (rnd_modulo_u32(32)) {
	case 0:
		a->start += 1 + rnd_modulo_u32(page_size - 1);
		break;
	case 1:
		a->end = start - page_size;
		break;
	case 2:
	case 3:
		a->end = start + (1UL << 30);
		break;
	case 4:
		a->end = start + pages * page_size;
		break;
	default:
		break;
	}

	switch (rnd_modulo_u32(32)) {
	case 24:
	case 25:
	case 26:
	case 27:
		a->flags = PM_SCAN_WP_MATCHING;
		break;
	case 28:
		a->flags = PM_SCAN_CHECK_WPASYNC;
		break;
	case 29:
		a->flags = PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC;
		break;
	case 30:
	case 31:
		a->flags = rnd_u64() | (1UL << 2);
		break;
	default:
		break;
	}
	if (!in_pool || a->start < start || a->end <= a->start ||
	    a->end > start + pages * page_size)
		a->flags &= ~(unsigned long) PM_SCAN_WP_MATCHING;

	if (!ONE_IN(4))
		a->return_mask = rnd_u32() & known;

	switch (rnd_modulo_u32(8)) {
	case 4:
	case 5:
		a->category_mask = pick_category(singles);
		break;
	case 6:
		a->category_mask = pick_category(singles) | pick_category(singles);
		break;
	case 7:
		a->category_mask = rnd_u32() & known;
		break;
	default:
		break;
	}
	if (RAND_BOOL())
		a->category_anyof_mask = rnd_u32() & known;
	if (ONE_IN(4))
		a->category_inverted = rnd_u32() & known;

	if (ONE_IN(32)) {
		__u64 *masks[] = {
			&a->return_mask, &a->category_mask,
			&a->category_anyof_mask, &a->category_inverted,
		};

		*masks[rnd_modulo_u32(ARRAY_SIZE(masks))] |=
			(rnd_u64() & ~(__u64) known) | (1ULL << 63);
	}

	switch (rnd_modulo_u32(64)) {
	case 0:
		a->vec_len = 1 + rnd_modulo_u32(SCAN_REGIONS_MAX);
		break;
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
	case 6:
		break;
	default: {
		unsigned int n = 1 + rnd_modulo_u32(SCAN_REGIONS_MAX);
		void *vec = get_writable_address(n * sizeof(struct page_region));

		if (vec != NULL) {
			a->vec = (unsigned long) vec;
			a->vec_len = n;
		}
		break;
	}
	}
	a->max_pages = RAND_BOOL() ? 0 : 1 + rnd_modulo_u32(256);

	rec->a1 = (unsigned long) fd;
	rec->a3 = (unsigned long) a;
}

static void procfs_self_sanitise(const struct ioctl_group *grp,
				 struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	/*
	 * The fd the draw came with is left behind, and what a path that
	 * cannot open the child's own file leaves is -1, a call no file
	 * answers.
	 */
	rec->a1 = (unsigned long) -1;

	switch (rec->a2) {
	case PROCMAP_QUERY:
		sanitise_procmap_query(rec);
		break;
	case PAGEMAP_SCAN:
		sanitise_pagemap_scan(rec);
		break;
	}
}

static const struct ioctl procfs_self_ioctls[] = {
	IOCTL(PROCMAP_QUERY),
	IOCTL(PAGEMAP_SCAN),
};

static const struct ioctl_group procfs_self_grp = {
	.name = "procfs-self",
	.fd_test = procfs_self_fd_test,
	.sanitise = procfs_self_sanitise,
	.ioctls = procfs_self_ioctls,
	.ioctls_cnt = ARRAY_SIZE(procfs_self_ioctls),
};

REG_IOCTL_GROUP(procfs_self_grp)
