/*
 * PROCMAP_QUERY (do_procmap_query() in fs/proc/task_mmu.c), aimed at the
 * calling child's own /proc/self/maps and never at another process's: any
 * regular procfs file draws the group, and the call goes to a file it opens.
 */

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
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
#include "utils.h"

IOCTL_SIZE_ASSERT(PROCMAP_QUERY, struct procmap_query);

/*
 * The walk of /proc stops at /proc/<pid>, so the pool has no maps file, and
 * any regular file on procfs draws the group instead.  The fd is never what
 * the call goes to (see open_own()).  procfs's device number is read off this
 * process's own maps file the first time, which leaves the claim itself no
 * syscall.
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

static int open_own(const char *path)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);

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
 * none.
 */
static void pick_span(unsigned long *start, unsigned long *pages)
{
	struct map *map = get_map();
	unsigned long first;

	if (map == NULL || map->ptr == NULL || map->size < page_size) {
		*start = (unsigned long) &first & PAGE_MASK;
		*pages = 1;
		return;
	}

	first = rnd_modulo_u64(map->size / page_size);
	*start = (unsigned long) map->ptr + first * page_size;
	*pages = map->size / page_size - first;
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

	fd = open_own("/proc/self/maps");
	if (fd < 0)
		return;

	rec->a1 = (unsigned long) fd;
	rec->a3 = (unsigned long) q;
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

	if (rec->a2 == PROCMAP_QUERY)
		sanitise_procmap_query(rec);
}

static const struct ioctl procfs_self_ioctls[] = {
	IOCTL(PROCMAP_QUERY),
};

static const struct ioctl_group procfs_self_grp = {
	.name = "procfs-self",
	.fd_test = procfs_self_fd_test,
	.sanitise = procfs_self_sanitise,
	.ioctls = procfs_self_ioctls,
	.ioctls_cnt = ARRAY_SIZE(procfs_self_ioctls),
};

REG_IOCTL_GROUP(procfs_self_grp)
