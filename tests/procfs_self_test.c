/*
 * Self-check for the procfs-self ioctl group: the files it claims, that its
 * calls go to the process's own files and no other, and that the
 * PROCMAP_QUERY and PAGEMAP_SCAN args it builds are held to models of
 * do_procmap_query() and pagemap_scan_get_args() (fs/proc/task_mmu.c),
 * written from the kernel.  No ioctl is issued, so what the kernel under the
 * test would answer does not matter.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "arch.h"		/* page_size */
#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/fs.h"
#include "maps.h"		/* struct map */
#include "objects.h"		/* struct object */
#include "owned-fd-ring.h"	/* MAX_OWNED_FDS */
#include "sanitise.h"		/* writable pool */
#include "syscall.h"		/* struct syscallrecord */
#include "utils-macros.h"	/* ARRAY_SIZE */

extern struct map *fake_map_drawn;	/* post_oracle_test.c */

/* The ends of the image's text, which the linker script defines. */
extern char __executable_start[], etext[];

/* Calls per model check: a draw one time in 64 is seen 300 times or so. */
#define ROUNDS		20000

static const struct ioctl_group *group(void)
{
	const struct ioctl_group *grp = fake_ioctl_group("procfs-self");

	if (grp == NULL)
		BUG("procfs-self: the group is not linked");
	return grp;
}

/* A fraction of whole that part is, held to [lo, hi]. */
static void expect_fraction(unsigned int part, unsigned int whole, double lo,
			    double hi, const char *what, const char *bug)
{
	if (whole < 500 || part < whole * lo || part > whole * hi) {
		fprintf(stderr, "%s: %u of %u, want a fraction in [%.2f, %.2f]\n",
			what, part, whole, lo, hi);
		BUG(bug);
	}
}

/* Whether @fd and @path name the same inode. */
static bool names(int fd, const char *path)
{
	struct stat a, b;

	return fstat(fd, &a) == 0 && stat(path, &b) == 0 &&
	       a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

static bool have_procfs(void)
{
	return access("/proc/self/maps", R_OK) == 0;
}

/* ---------- Which files the group claims -------------------------------- */

/*
 * A regular file on procfs, where the file a call needs is, and nothing
 * else: a regular file elsewhere (the test's own image), a directory on
 * procfs, a device, a pipe and a socket belong to other groups.
 */
static void claims_only_procfs_files(void)
{
	const struct ioctl_group *grp = group();
	static const struct {
		const char *path;
		bool claimed;
	} files[] = {
		{ "/proc/self/maps", true },
		{ "/proc/self/pagemap", true },
		{ "/proc/self/status", true },
		{ "/proc/self/exe", false },
		{ "/proc/self", false },
		{ "/dev/null", false },
		{ "/", false },
	};
	unsigned int i;
	int pipefd[2], sock;
	struct stat st;

	for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
		int fd = open(files[i].path, O_RDONLY);

		if (fd < 0)
			continue;
		if (fstat(fd, &st) != 0)
			BUG("procfs-self: cannot stat a file it just opened");
		if ((grp->fd_test(fd, &st) == 0) != files[i].claimed) {
			fprintf(stderr, "%s\n", files[i].path);
			BUG("procfs-self: the claim on a file is wrong");
		}
		close(fd);
	}

	if (pipe(pipefd) != 0)
		BUG("procfs-self: no pipe");
	if (fstat(pipefd[0], &st) != 0 || grp->fd_test(pipefd[0], &st) == 0)
		BUG("procfs-self: claimed a pipe");
	close(pipefd[0]);
	close(pipefd[1]);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0 || fstat(sock, &st) != 0 || grp->fd_test(sock, &st) == 0)
		BUG("procfs-self: claimed a socket");
	close(sock);
}

/* ---------- Whose files the calls go to --------------------------------- */

/* The group's cmds, and the file of the process each one's call needs. */
static const struct {
	unsigned long request;
	const char *file;
} cmds[] = {
	{ PROCMAP_QUERY, "maps" },
	{ PAGEMAP_SCAN, "pagemap" },
};

/*
 * Whatever fd the draw came with, the call is handed a file of this process,
 * opened for it: the kernel binds the mm when the file is opened, so a pool
 * fd, which the parent opened, would query the parent.  The parent's file
 * stands in for it, or pid 1's, or any procfs file when neither opens.
 *
 * It runs for a dumpable process and for one that is not, which is what a
 * child is once disable_coredumps() has run: pagemap is S_IRUSR, and a
 * task that is not dumpable owns its /proc files as root, so a process that
 * is not root can open its own only with the flag set.  The flag has to be
 * what it was after the call.
 */
static void goes_to_own_files(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = group();
	unsigned int c, pass, i;

	for (c = 0; c < ARRAY_SIZE(cmds); c++) {
		char own[64], foreign[64];
		int held;

		snprintf(own, sizeof(own), "/proc/%d/%s", getpid(), cmds[c].file);
		snprintf(foreign, sizeof(foreign), "/proc/%d/%s", getppid(),
			 cmds[c].file);
		held = open(foreign, O_RDONLY);
		if (held < 0) {
			snprintf(foreign, sizeof(foreign), "/proc/1/%s",
				 cmds[c].file);
			held = open(foreign, O_RDONLY);
		}
		if (held < 0)
			held = open("/proc/self/status", O_RDONLY);
		if (held < 0)
			BUG("procfs-self: no procfs file to stand in for the pool's");

		for (pass = 0; pass < 2; pass++) {
			int dumpable = pass == 0 ? 1 : 0;

			prctl(PR_SET_DUMPABLE, dumpable);
			for (i = 0; i < 64; i++) {
				memset(&rec, 0, sizeof(rec));
				rec.a1 = (unsigned long) held;
				fake_ioctl_request = cmds[c].request;
				grp->sanitise(grp, &rec);

				if (rec.a2 != cmds[c].request)
					BUG("procfs-self: the cmd was changed");
				if (rec.a1 == (unsigned long) held ||
				    !names((int) rec.a1, own)) {
					fprintf(stderr, "a1 %#lx, own %s, dumpable %d\n",
						rec.a1, own, dumpable);
					BUG("procfs-self: a call was not aimed at this process's own file");
				}
			}
			if (prctl(PR_GET_DUMPABLE) != dumpable)
				BUG("procfs-self: the dumpable flag was not put back");
		}
		prctl(PR_SET_DUMPABLE, 1);
		close(held);
	}
}

/*
 * A call that cannot open the process's own file does not fall back to the
 * one the draw came with, which may be another process's: it is left with
 * an fd that names no file.  The fd limit is lowered to the lowest free
 * number to make the open fail.
 */
static void falls_back_to_no_file(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = group();
	struct rlimit old, lowered;
	unsigned int c;
	int held, spare;

	held = open("/proc/self/status", O_RDONLY);
	spare = dup(held);
	if (held < 0 || spare < 0 || getrlimit(RLIMIT_NOFILE, &old) != 0)
		BUG("procfs-self: cannot set up a full fd table");
	close(spare);

	lowered = old;
	lowered.rlim_cur = spare;
	if (setrlimit(RLIMIT_NOFILE, &lowered) != 0)
		BUG("procfs-self: cannot lower the fd limit");

	for (c = 0; c < ARRAY_SIZE(cmds); c++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) held;
		fake_ioctl_request = cmds[c].request;
		grp->sanitise(grp, &rec);

		if (rec.a1 != (unsigned long) -1) {
			fprintf(stderr, "cmd %#lx: a1 %#lx\n", cmds[c].request,
				rec.a1);
			setrlimit(RLIMIT_NOFILE, &old);
			BUG("procfs-self: a call with no file of its own went to another");
		}
	}

	if (setrlimit(RLIMIT_NOFILE, &old) != 0)
		BUG("procfs-self: cannot restore the fd limit");
	close(held);
}

/* Each call opens a file, and the group keeps at most a ring of them. */
static void keeps_a_bounded_number_of_fds(void)
{
	static struct syscallrecord rec;
	const struct ioctl_group *grp = group();
	unsigned int before = 0, after = 0, i;
	int fd;

	for (fd = 0; fd < 4096; fd++)
		before += fcntl(fd, F_GETFD) >= 0;

	for (i = 0; i < 500; i++) {
		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = cmds[i % ARRAY_SIZE(cmds)].request;
		grp->sanitise(grp, &rec);
	}

	for (fd = 0; fd < 4096; fd++)
		after += fcntl(fd, F_GETFD) >= 0;
	if (after > before + MAX_OWNED_FDS) {
		fprintf(stderr, "%u fds before, %u after\n", before, after);
		BUG("procfs-self: the files it opens for the calls are not closed");
	}
}

/* ---------- PROCMAP_QUERY ----------------------------------------------- */

/* What do_procmap_query() reads at least: the size, the flags, the address. */
#define QUERY_MIN_SIZE	24

#define VALID_FLAGS	(PROCMAP_QUERY_VMA_READABLE | \
			 PROCMAP_QUERY_VMA_WRITABLE | \
			 PROCMAP_QUERY_VMA_EXECUTABLE | \
			 PROCMAP_QUERY_VMA_SHARED | \
			 PROCMAP_QUERY_COVERING_OR_NEXT_VMA | \
			 PROCMAP_QUERY_FILE_BACKED_VMA)

/* A VMA of the address space the model answers for. */
struct model_vma {
	unsigned long start, end;
	bool file, write, exec, shared;
};

/* In address order, as a VMA tree walks them. */
static struct model_vma world[2];

/*
 * The pool mapping the draw is made from, which stands in for the process's
 * own: an address far from anything the test's image has, so that none of
 * it is mapped for real.
 */
#define POOL_MAP_BASE	0x200000000000UL
#define POOL_MAP_PAGES	64

static void build_world(void)
{
	struct model_vma text = {
		.start = (unsigned long) __executable_start,
		.end = (unsigned long) etext,
		.file = true, .exec = true,
	};
	struct model_vma pool = {
		.start = POOL_MAP_BASE,
		.end = POOL_MAP_BASE + POOL_MAP_PAGES * page_size,
		.write = true,
	};

	world[0] = text.start < pool.start ? text : pool;
	world[1] = text.start < pool.start ? pool : text;
}

static bool in_mapping(unsigned long addr)
{
	unsigned int i;

	for (i = 0; i < 2; i++)
		if (addr >= world[i].start && addr < world[i].end)
			return true;
	return false;
}

/*
 * query_matching_vma() over the model's VMAs: the first VMA that ends above
 * the address is kept if it is file backed when the flags say so and has
 * every permission they name, and answered if it covers the address or the
 * flags take the next VMA.  One that is refused ends the search, or with
 * the next-VMA flag moves it to the VMA's end.
 */
static bool finds_a_vma(unsigned long addr, unsigned long flags)
{
	for (;;) {
		const struct model_vma *vma = NULL;
		unsigned int i;

		for (i = 0; i < 2 && vma == NULL; i++)
			if (world[i].end > addr)
				vma = &world[i];
		if (vma == NULL)
			return false;

		if ((flags & PROCMAP_QUERY_FILE_BACKED_VMA) && !vma->file)
			goto skip;
		if ((flags & PROCMAP_QUERY_VMA_WRITABLE) && !vma->write)
			goto skip;
		if ((flags & PROCMAP_QUERY_VMA_EXECUTABLE) && !vma->exec)
			goto skip;
		if ((flags & PROCMAP_QUERY_VMA_SHARED) && !vma->shared)
			goto skip;
		if ((flags & PROCMAP_QUERY_COVERING_OR_NEXT_VMA) ||
		    vma->start <= addr)
			return true;
skip:
		addr = vma->end;
		if (!(flags & PROCMAP_QUERY_COVERING_OR_NEXT_VMA))
			return false;
	}
}

enum answer { ANS_E2BIG, ANS_EINVAL, ANS_ENOENT, ANS_VMA };

/*
 * do_procmap_query() up to the lookup, and the lookup in the model's world.
 * It reads the size first: a page or less (-E2BIG) and the flags and
 * address at least (-EINVAL).  copy_struct_from_user() then takes a shorter
 * struct as far as it goes with the rest of the kernel's zero, and a longer
 * one only with a zero tail (-E2BIG), so the model reads the args as the
 * kernel does.  A flag it does not know is -EINVAL, and so is a name or
 * build id size without its buffer or the reverse.
 */
static enum answer procmap_query_answer(const struct procmap_query *q)
{
	const unsigned char *raw = (const unsigned char *) q;
	struct procmap_query karg;
	unsigned long i;

	if (q->size > page_size)
		return ANS_E2BIG;
	if (q->size < QUERY_MIN_SIZE)
		return ANS_EINVAL;
	for (i = sizeof(*q); i < q->size; i++)
		if (raw[i] != 0)
			return ANS_E2BIG;

	memset(&karg, 0, sizeof(karg));
	memcpy(&karg, q, q->size < sizeof(karg) ? q->size : sizeof(karg));

	if (karg.query_flags & ~(unsigned long) VALID_FLAGS)
		return ANS_EINVAL;
	if (!!karg.vma_name_size != !!karg.vma_name_addr)
		return ANS_EINVAL;
	if (!!karg.build_id_size != !!karg.build_id_addr)
		return ANS_EINVAL;

	return finds_a_vma(karg.query_addr, karg.query_flags) ?
	       ANS_VMA : ANS_ENOENT;
}

struct procmap_tally {
	unsigned int calls;
	unsigned int exact, older, newer, too_short, too_long;	/* by size */
	unsigned int e2big, einval, enoent, vma;	/* the model's answers */
	unsigned int bad_flags;
	unsigned int name, name_mismatch, id, id_mismatch;
	unsigned int in_mapping;	/* query_addr is in a VMA of the world */
	unsigned int in_text;		/* ... in the image's text */
};

/*
 * The sanitiser's own allocations start at the pool's start after this, and
 * are poisoned unless it clears them, which is what the kernel's reads of
 * the tail would find.  The pool wraps when a call asks for all of it.
 */
static void poison_pool(void)
{
	void *base = get_writable_address(WRITABLE_POOL_BYTES);

	memset(base, 0xa5, 3 * page_size + 8192);
}

static void tally_procmap_query(struct procmap_tally *t,
				const struct syscallrecord *rec)
{
	const struct procmap_query *q = (const struct procmap_query *) rec->a3;
	unsigned long n;

	if (rec->a3 == FAKE_IOCTL_JUNK_ARG || q == NULL)
		BUG("procfs-self: PROCMAP_QUERY got no struct");

	t->calls++;
	if (q->size == sizeof(*q))
		t->exact++;
	else if (q->size < QUERY_MIN_SIZE)
		t->too_short++;
	else if (q->size < sizeof(*q))
		t->older++;
	else if (q->size <= page_size)
		t->newer++;
	else
		t->too_long++;

	switch (procmap_query_answer(q)) {
	case ANS_E2BIG:		t->e2big++; break;
	case ANS_EINVAL:	t->einval++; break;
	case ANS_ENOENT:	t->enoent++; break;
	case ANS_VMA:		t->vma++; break;
	}

	t->bad_flags += (q->query_flags & ~(unsigned long) VALID_FLAGS) != 0;
	t->name += q->vma_name_size != 0 || q->vma_name_addr != 0;
	t->name_mismatch += !!q->vma_name_size != !!q->vma_name_addr;
	t->id += q->build_id_size != 0 || q->build_id_addr != 0;
	t->id_mismatch += !!q->build_id_size != !!q->build_id_addr;
	t->in_mapping += in_mapping(q->query_addr);
	t->in_text += q->query_addr >= (unsigned long) __executable_start &&
		      q->query_addr < (unsigned long) etext;

	/*
	 * What the kernel writes: the struct back, as far as the size it read
	 * (the first 104 bytes of a longer one), a name up to the size the
	 * call gave, cut at PATH_MAX, and a build id up to its size, all of it
	 * somewhere the kernel may write.
	 */
	if (q->size >= QUERY_MIN_SIZE && q->size <= page_size) {
		n = q->size < sizeof(*q) ? q->size : sizeof(*q);
		if (!range_in_writable_pool((unsigned long) q, n))
			BUG("procfs-self: the struct is not in the writable pool");
	}
	if (q->vma_name_size != 0 && q->vma_name_addr != 0) {
		n = q->vma_name_size < PATH_MAX ? q->vma_name_size : PATH_MAX;
		if (!range_in_writable_pool(q->vma_name_addr, n))
			BUG("procfs-self: the name buffer is not in the writable pool");
	}
	if (q->build_id_size != 0 && q->build_id_addr != 0 &&
	    !range_in_writable_pool(q->build_id_addr, q->build_id_size))
		BUG("procfs-self: the build id buffer is not in the writable pool");
}

/*
 * The sanitiser sends the exact size 27 times in 32, a shorter or a longer
 * one zero tailed two times in 32 each, and one in 32 a size the kernel
 * refuses, half of them under 24 and half over a page; its flags are 0 six
 * times in 16, the next-VMA flag alone four, that with file backing two, a
 * random combination of the six three, and one in 16 a flag that is none;
 * the address is in the pool mapping 24 times in 32, in the image's text
 * four, one byte below the pool page one, and the other three are the
 * mapping's end, 0 and ~0.  A name is asked for every other call and a
 * build id every fourth, and each is sent without its buffer or the
 * reverse one time in 16.  Over 20000 calls the fractions have deviations
 * under 0.004, and the bounds are many of them out.  How many queries
 * find a VMA depends on the model's two, which have few neighbours to
 * move on to, so the bounds on that are wide.
 */
static void expect_procmap_query(const struct procmap_tally *t)
{
	expect_fraction(t->exact, t->calls, 0.80, 0.88, "PROCMAP_QUERY",
			"procfs-self: the struct size is not the kernel's most of the time");
	expect_fraction(t->older, t->calls, 0.04, 0.09, "PROCMAP_QUERY",
			"procfs-self: the older shorter struct is not drawn");
	expect_fraction(t->newer, t->calls, 0.04, 0.09, "PROCMAP_QUERY",
			"procfs-self: the newer longer struct is not drawn");
	expect_fraction(t->too_short, t->calls, 0.008, 0.026, "PROCMAP_QUERY",
			"procfs-self: a size under the kernel's minimum is not drawn");
	expect_fraction(t->too_long, t->calls, 0.008, 0.026, "PROCMAP_QUERY",
			"procfs-self: a size over a page is not drawn");

	/* The only -E2BIG is a size over a page: every tail is zero. */
	if (t->e2big != t->too_long)
		BUG("procfs-self: a longer struct has a tail the kernel reads as not zero");

	expect_fraction(t->bad_flags, t->calls, 0.04, 0.09, "PROCMAP_QUERY",
			"procfs-self: a flag the kernel does not know is not drawn");
	expect_fraction(t->name, t->calls, 0.45, 0.55, "PROCMAP_QUERY",
			"procfs-self: a name is not asked for half the time");
	expect_fraction(t->id, t->calls, 0.21, 0.29, "PROCMAP_QUERY",
			"procfs-self: a build id is not asked for a quarter of the time");
	expect_fraction(t->name_mismatch, t->name, 0.04, 0.09, "PROCMAP_QUERY",
			"procfs-self: a name size and its buffer are not apart one time in 16");
	expect_fraction(t->id_mismatch, t->id, 0.03, 0.10, "PROCMAP_QUERY",
			"procfs-self: a build id size and its buffer are not apart one time in 16");

	/* About a seventh of the calls fail the checks ahead of the lookup. */
	expect_fraction(t->einval + t->e2big, t->calls, 0.08, 0.20, "PROCMAP_QUERY",
			"procfs-self: the calls the kernel refuses are not about a seventh of them");
	expect_fraction(t->in_mapping, t->calls, 0.82, 0.93, "PROCMAP_QUERY",
			"procfs-self: the address is not in a mapping most of the time");
	expect_fraction(t->in_text, t->calls, 0.09, 0.16, "PROCMAP_QUERY",
			"procfs-self: the address is not in the image's text one time in eight");
	expect_fraction(t->vma, t->vma + t->enoent, 0.55, 0.85, "PROCMAP_QUERY",
			"procfs-self: not enough queries that pass the checks find a VMA");
	expect_fraction(t->enoent, t->calls, 0.10, 0.45, "PROCMAP_QUERY",
			"procfs-self: no query is left without a VMA");
}

static void builds_procmap_query_args_the_kernel_takes(void)
{
	static struct syscallrecord rec;
	static struct procmap_tally t;
	const struct ioctl_group *grp = group();
	unsigned int i;

	for (i = 0; i < ROUNDS; i++) {
		poison_pool();
		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = PROCMAP_QUERY;
		grp->sanitise(grp, &rec);
		tally_procmap_query(&t, &rec);
	}
	expect_procmap_query(&t);
}

/* ---------- PAGEMAP_SCAN ------------------------------------------------ */

/* The ten categories of the kernel's PM_SCAN_CATEGORIES. */
#define CATEGORIES	((1UL << 10) - 1)

#define NCATEGORIES	10

/*
 * The end of the address space as access_ok() reads it: the pool mapping is
 * far below it, and an end below the start makes the length wrap past it.
 */
#define MODEL_TASK_SIZE	(1UL << 47)

enum scan_answer { SCAN_EINVAL, SCAN_EFAULT, SCAN_WALKS };

/*
 * pagemap_scan_get_args() (fs/proc/task_mmu.c) for the struct the sanitiser
 * built: a size other than the kernel's, a flag or a category it does not
 * know, a start that is not page aligned and a length with no buffer are
 * -EINVAL, and a range whose length is more than the address space holds,
 * which an end below the start makes, is -EFAULT.  The categories are the
 * ten of the kernel under test, PAGE_IS_GUARD and PAGE_IS_ACCESSED among
 * them; one that predates either answers a mask with it -EINVAL.
 */
static enum scan_answer pagemap_scan_answer(const struct pm_scan_arg *a)
{
	unsigned long len = a->end - a->start;

	if (a->size != sizeof(*a))
		return SCAN_EINVAL;
	if (a->flags & ~(unsigned long) (PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC))
		return SCAN_EINVAL;
	if ((a->category_inverted | a->category_mask |
	     a->category_anyof_mask | a->return_mask) & ~CATEGORIES)
		return SCAN_EINVAL;
	if (a->start & (page_size - 1))
		return SCAN_EINVAL;
	if (len > MODEL_TASK_SIZE || a->start > MODEL_TASK_SIZE - len)
		return SCAN_EFAULT;
	if (!a->vec && a->vec_len)
		return SCAN_EINVAL;
	return SCAN_WALKS;
}

/*
 * Whether the walk reaches the pages of an ordinary VMA, one no userfaultfd
 * has registered for write protection in async mode.  pagemap_scan_test_walk()
 * skips it for WP_MATCHING and fails the walk with -EPERM for CHECK_WPASYNC;
 * pagemap_scan_is_interesting_vma() skips it when category_mask asks for
 * WPALLOWED, which only a VMA of that kind has, unless category_inverted
 * flips the bit.
 */
static bool walks_ordinary_vma(const struct pm_scan_arg *a)
{
	if (a->flags & (PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC))
		return false;
	return (a->category_mask & PAGE_IS_WPALLOWED & ~a->category_inverted) == 0;
}

struct scan_tally {
	unsigned int calls;
	unsigned int einval, efault, walks;	/* the model's answers */
	unsigned int bad_size, bad_flags, bad_mask;
	unsigned int misaligned, wrapped, beyond;
	unsigned int in_map;		/* [start, end) is inside the pool mapping */
	unsigned int reaches;		/* the walk reaches an ordinary VMA's pages */
	unsigned int wp;		/* the call walks and write-protects */
	unsigned int vec, vec_none, len_only;
	unsigned int wpallowed;		/* WPALLOWED in category_mask */
	unsigned int category[NCATEGORIES];	/* each one in return_mask */
};

/*
 * @pool is the mapping get_map() hands the sanitiser, NULL when it has none.
 * Whatever the kernel would answer, a call that asks to write-protect names a
 * range inside it: the memory a fuzzed call already acts on, never the
 * stack page the fallback uses, a range that runs on past the mapping or
 * the pages the kernel's own structs sit on.
 */
static void tally_pagemap_scan(struct scan_tally *t,
			       const struct syscallrecord *rec,
			       const struct map *pool)
{
	const struct pm_scan_arg *a = (const struct pm_scan_arg *) rec->a3;
	unsigned long base = pool ? (unsigned long) pool->ptr : 0;
	unsigned long end = pool ? base + pool->size : 0;
	enum scan_answer answer;
	unsigned int i;

	if (rec->a3 == FAKE_IOCTL_JUNK_ARG || a == NULL)
		BUG("procfs-self: PAGEMAP_SCAN got no struct");
	if (!range_in_writable_pool((unsigned long) a, sizeof(*a)))
		BUG("procfs-self: the struct is not in the writable pool");

	t->calls++;
	answer = pagemap_scan_answer(a);
	switch (answer) {
	case SCAN_EINVAL:	t->einval++; break;
	case SCAN_EFAULT:	t->efault++; break;
	case SCAN_WALKS:	t->walks++; break;
	}

	t->bad_size += a->size != sizeof(*a);
	t->bad_flags += (a->flags & ~3UL) != 0;
	t->bad_mask += ((a->category_inverted | a->category_mask |
			 a->category_anyof_mask | a->return_mask) & ~CATEGORIES) != 0;
	t->misaligned += (a->start & (page_size - 1)) != 0;
	t->wrapped += a->end < a->start;
	t->reaches += answer == SCAN_WALKS && walks_ordinary_vma(a);
	t->wpallowed += (a->category_mask & PAGE_IS_WPALLOWED) != 0;
	for (i = 0; i < NCATEGORIES; i++)
		t->category[i] += (a->return_mask >> i) & 1;

	if (pool != NULL) {
		bool inside = a->start >= base && a->end > a->start && a->end <= end;

		t->in_map += inside;
		t->beyond += a->end > end;
	}

	if (a->flags & PM_SCAN_WP_MATCHING) {
		if (pool == NULL || a->start < base || a->end <= a->start ||
		    a->end > end) {
			fprintf(stderr, "start %#llx end %#llx, pool %#lx-%#lx\n",
				(unsigned long long) a->start,
				(unsigned long long) a->end, base, end);
			BUG("procfs-self: a range outside the pool mapping asks to write-protect");
		}
		t->wp += answer == SCAN_WALKS;
	}

	if (a->vec != 0 && a->vec_len != 0) {
		t->vec++;
		if (!range_in_writable_pool(a->vec, a->vec_len * sizeof(struct page_region)))
			BUG("procfs-self: the region buffer is not in the writable pool");
	} else if (a->vec == 0 && a->vec_len != 0) {
		t->len_only++;
	} else if (a->vec == 0) {
		t->vec_none++;
	} else {
		BUG("procfs-self: a buffer with no length");
	}
}

/*
 * The sanitiser sends the kernel's struct size 31 times in 32, flags of the
 * two it knows 30 times in 32 (none 24 times, WP_MATCHING 4, CHECK_WPASYNC
 * and both one each) and a word with a flag it does not know twice, a
 * start that is page aligned and an end above it 30 times in 32, and the
 * masks within the ten categories 31 times in 32.  The run is inside the
 * pool mapping except when it is drawn to run past it, twice in 32, or to
 * end below its start, once, and a buffer comes with its length 57 times
 * in 64, the length alone once, and neither six times.  return_mask is
 * zero a quarter of the time and otherwise holds each of the ten
 * categories half the time; category_mask holds WPALLOWED one time in 16.
 * Over 20000 calls the fractions have deviations under 0.004 and the
 * bounds are many of them out.
 */
static void expect_pagemap_scan(const struct scan_tally *t, bool pool)
{
	unsigned int i;

	expect_fraction(t->bad_size, t->calls, 0.015, 0.05, "PAGEMAP_SCAN",
			"procfs-self: a struct size other than the kernel's is not drawn one time in 32");
	expect_fraction(t->bad_flags, t->calls, 0.04, 0.09, "PAGEMAP_SCAN",
			"procfs-self: a flag the kernel does not know is not drawn");
	expect_fraction(t->bad_mask, t->calls, 0.015, 0.05, "PAGEMAP_SCAN",
			"procfs-self: a category the kernel does not know is not drawn one time in 32");
	expect_fraction(t->misaligned, t->calls, 0.015, 0.05, "PAGEMAP_SCAN",
			"procfs-self: a start that is not page aligned is not drawn one time in 32");
	expect_fraction(t->wrapped, t->calls, 0.015, 0.05, "PAGEMAP_SCAN",
			"procfs-self: an end below the start is not drawn one time in 32");
	expect_fraction(t->len_only, t->calls, 0.005, 0.03, "PAGEMAP_SCAN",
			"procfs-self: a length with no buffer is not drawn one time in 64");
	expect_fraction(t->vec_none, t->calls, 0.07, 0.12, "PAGEMAP_SCAN",
			"procfs-self: a call with no buffer is not drawn one time in 11");
	expect_fraction(t->vec, t->calls, 0.85, 0.92, "PAGEMAP_SCAN",
			"procfs-self: most calls do not have a buffer");
	expect_fraction(t->wpallowed, t->calls, 0.02, 0.10, "PAGEMAP_SCAN",
			"procfs-self: WPALLOWED is not in category_mask one time in 16");

	/* Every category is asked for, the two newest among them. */
	for (i = 0; i < NCATEGORIES; i++)
		expect_fraction(t->category[i], t->calls, 0.30, 0.45, "PAGEMAP_SCAN",
				"procfs-self: a category is not in return_mask about 0.375 of the time");

	/* About four calls in five pass the checks ahead of the walk. */
	expect_fraction(t->walks, t->calls, 0.72, 0.88, "PAGEMAP_SCAN",
			"procfs-self: the calls the kernel takes are not four in five");
	expect_fraction(t->einval + t->efault, t->calls, 0.12, 0.28, "PAGEMAP_SCAN",
			"procfs-self: the calls the kernel refuses are not a fifth of them");
	/*
	 * Most calls reach the pages of an ordinary VMA: those with neither
	 * flag, which is 24 draws in 32, and with WP_MATCHING dropped, which
	 * a call with no pool mapping does, four more.
	 */
	expect_fraction(t->reaches, t->calls, pool ? 0.52 : 0.62, pool ? 0.70 : 0.80,
			"PAGEMAP_SCAN",
			"procfs-self: the walk does not reach an ordinary VMA's pages most of the time");

	if (!pool) {
		if (t->wp != 0)
			BUG("procfs-self: a call with no pool mapping asks to write-protect");
		return;
	}

	expect_fraction(t->in_map, t->calls, 0.85, 0.95, "PAGEMAP_SCAN",
			"procfs-self: the range is not inside the pool mapping most of the time");
	expect_fraction(t->beyond, t->calls, 0.03, 0.10, "PAGEMAP_SCAN",
			"procfs-self: a range that runs past the mapping is not drawn two times in 32");
	expect_fraction(t->wp, t->calls, 0.06, 0.20, "PAGEMAP_SCAN",
			"procfs-self: write-protecting calls that reach the walk are not about one in eight");
}

static void builds_pagemap_scan_args_the_kernel_takes(const struct map *pool)
{
	static struct syscallrecord rec;
	static struct scan_tally t;
	const struct ioctl_group *grp = group();
	unsigned int i;

	memset(&t, 0, sizeof(t));
	for (i = 0; i < ROUNDS; i++) {
		memset(&rec, 0, sizeof(rec));
		fake_ioctl_request = PAGEMAP_SCAN;
		grp->sanitise(grp, &rec);
		tally_pagemap_scan(&t, &rec, pool);
	}
	expect_pagemap_scan(&t, pool != NULL);
}

void procfs_self_self_check(void);
void procfs_self_self_check(void)
{
	static struct object map_obj;

	if (get_writable_struct(1) == NULL)
		writable_pool_init();

	if (!have_procfs()) {
		printf("(no procfs, skipping) ");
		return;
	}

	claims_only_procfs_files();
	goes_to_own_files();
	falls_back_to_no_file();
	keeps_a_bounded_number_of_fds();

	/* With no mapping to draw from, and then with one. */
	fake_map_drawn = NULL;
	builds_pagemap_scan_args_the_kernel_takes(NULL);

	build_world();
	map_obj.map.ptr = (void *) POOL_MAP_BASE;
	map_obj.map.size = POOL_MAP_PAGES * page_size;
	fake_map_drawn = &map_obj.map;
	builds_procmap_query_args_the_kernel_takes();
	builds_pagemap_scan_args_the_kernel_takes(&map_obj.map);
	fake_map_drawn = NULL;
}
