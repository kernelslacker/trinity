/*
 * SYSCALL_DEFINE6(mmap, unsigned long, addr, unsigned long, len,
	unsigned long, prot, unsigned long, flags,
	unsigned long, fd, unsigned long, offset)
 *
 * sys_mmap2 (unsigned long addr, unsigned long len, int prot, int flags, int fd, long pgoff)
 */
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "maps.h"
#include "sanitise.h"
#include "shm.h"
#include "arch.h"
#include "compat.h"
#include "hugepages.h"
#include "objects.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"

// need this to actually get MAP_UNINITIALIZED defined
#define CONFIG_MMAP_ALLOW_UNINITIALIZED

#ifndef MAP_SHARED_VALIDATE
#define MAP_SHARED_VALIDATE 0x03
#endif

#ifndef MAP_SYNC
#define MAP_SYNC 0x080000
#endif

static void do_anon(struct syscallrecord *rec)
{
	/* no fd if anonymous mapping. */
	rec->a5 = -1;
	rec->a6 = 0;
}

/*
 * Type bits live in the low 2 bits of the mmap flags word: exactly one
 * of MAP_SHARED (0x01), MAP_PRIVATE (0x02), or MAP_SHARED_VALIDATE (0x03).
 * Picking the type is mutually exclusive — never OR these together.
 */
unsigned long mmap_excl_flags[] = {
	MAP_SHARED, MAP_PRIVATE, MAP_SHARED_VALIDATE,
};

unsigned long get_rand_mmap_flags(void)
{
	unsigned long type, flags;

	const unsigned long mmap_flags[] = {
		MAP_FIXED, MAP_ANONYMOUS, MAP_GROWSDOWN, MAP_DENYWRITE,
		MAP_EXECUTABLE, MAP_LOCKED, MAP_NORESERVE, MAP_POPULATE,
		MAP_NONBLOCK, MAP_STACK, MAP_HUGETLB, MAP_UNINITIALIZED,
		MAP_FIXED_NOREPLACE, MAP_DROPPABLE,
#ifdef __x86_64__
		MAP_32BIT,
#endif
	};

	type = RAND_ARRAY(mmap_excl_flags);
	flags = type;
	if (RAND_BOOL())
		flags |= set_rand_bitmask(ARRAY_SIZE(mmap_flags), mmap_flags);

	/*
	 * MAP_SYNC is only accepted when the type bit is MAP_SHARED_VALIDATE.
	 * MAP_SHARED|MAP_SYNC returns -EOPNOTSUPP and MAP_PRIVATE|MAP_SYNC
	 * returns -EINVAL, so don't waste calls generating those paths from
	 * the modifier array — gate MAP_SYNC on the picked type.
	 */
	if (type == MAP_SHARED_VALIDATE && RAND_BOOL())
		flags |= MAP_SYNC;

	/*
	 * If MAP_HUGETLB ended up set, sometimes also encode a specific
	 * huge-page size into bits 26..31 via MAP_HUGE_SHIFT.  Without
	 * this the kernel always uses its default size, so MAP_HUGE_2MB,
	 * MAP_HUGE_1GB, etc. never get exercised through the fuzzer.
	 */
	if ((flags & MAP_HUGETLB) && RAND_BOOL())
		flags |= pick_random_huge_size_encoding();

	return flags;
}

static void sanitise_mmap(struct syscallrecord *rec)
{
	/* Don't actually set a hint right now. */
	rec->a1 = 0;

	rec->a2 = RAND_ARRAY(mapping_sizes);

	/* this over-rides the ARG_OP in the syscall struct */
	rec->a4 = get_rand_mmap_flags();

	if (rec->a4 & MAP_ANONYMOUS) {
		do_anon(rec);
	} else {
		rec->a5 = get_random_fd();
		if (rec->a5 == (unsigned long) -1)
			rec->a5 = 0;

		if (this_syscallname("mmap2") == true) {
			/* mmap2 counts in 4K units */
			rec->a6 /= 4096;
		} else {
			/* page align non-anonymous mappings. */
			rec->a6 &= PAGE_MASK;
		}
	}

	/*
	 * MAP_FIXED unmaps any existing VMA covering [addr, addr + len)
	 * before placing the new mapping there.  If that range overlaps
	 * a trinity-owned shared region — kcov trace_buf, the global
	 * stats blob, child-data, ... — the original VMA is silently
	 * replaced by a (possibly shorter) anon/file mapping.  Reads of
	 * shared bookkeeping past the new mapping's end then SIGBUS.
	 * Drop MAP_FIXED and clear the hint so the kernel picks a free
	 * slot instead.  MAP_FIXED_NOREPLACE returns -EEXIST on overlap
	 * rather than punching, so leave it alone.
	 */
	if ((rec->a4 & MAP_FIXED) &&
	    range_overlaps_shared(rec->a1, rec->a2)) {
		rec->a4 &= ~MAP_FIXED;
		rec->a1 = 0;
	}
}

static void post_mmap(struct syscallrecord *rec)
{
	char *p;
	struct object *new;
	bool is_anon;

	p = (void *) rec->retval;
	if (p == MAP_FAILED)
		return;

	/*
	 * Oracle: a successful mmap return must be page-aligned.  A
	 * misaligned address indicates the kernel handed back a value
	 * that cannot be a real VMA base — feeding it into the object
	 * pool would cache a bogus map->ptr that later munmap /
	 * mprotect / memory-pressure consumers walk into.
	 */
	if ((unsigned long) p & (page_size - 1)) {
		output(0, "mmap oracle: returned addr %p is not page-aligned (page_size=%u)\n",
		       p, page_size);
		__atomic_add_fetch(&shm->stats.mmap_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		return;
	}

	is_anon = !!(rec->a4 & MAP_ANONYMOUS);

	new = alloc_object();
	new->map.name = strdup("misc");
	if (!new->map.name) {
		free(new);
		return;
	}
	new->map.size = rec->a2;
	new->map.prot = rec->a3;
	new->map.ptr = p;

	if (is_anon) {
		new->map.fd = -1;
		new->map.type = CHILD_ANON;
		add_object(new, OBJ_LOCAL, OBJ_MMAP_ANON);
	} else {
		new->map.fd = rec->a5;
		new->map.type = MMAPED_FILE;
		add_object(new, OBJ_LOCAL, OBJ_MMAP_FILE);
	}

	/* Sometimes dirty the mapping. */
	if (RAND_BOOL())
		dirty_mapping(&new->map);

	/*
	 * Oracle: 1-in-100 chance — verify the new mapping is visible in
	 * /proc/self/maps with the expected prot bits.  A missing or
	 * mismatched entry means the kernel's VMA tree is inconsistent
	 * with what it handed back as a successful mmap return address.
	 */
	if (ONE_IN(100)) {
		if (!proc_maps_check((unsigned long) p, rec->a2, rec->a3, true)) {
			output(0, "mmap oracle: mapping at %p size %lu prot 0x%lx "
			       "not visible in /proc/self/maps with expected prot\n",
			       p, rec->a2, rec->a3);
			__atomic_add_fetch(&shm->stats.mmap_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
		}
	}
}

static char * decode_mmap(struct syscallrecord *rec, unsigned int argnum)
{
	char *buf;

	if (argnum == 3) {
		int flags = rec->a3;
		char *p;
		char *end;

		p = buf = zmalloc(80);
		end = buf + 80;
		p += snprintf(buf, end - p, "[");

		if (flags == 0) {
			snprintf(p, end - p, "PROT_NONE]");
			return buf;
		}
		if (flags & PROT_READ)
			p += snprintf(p, end - p, "PROT_READ|");
		if (flags & PROT_WRITE)
			p += snprintf(p, end - p, "PROT_WRITE|");
		if (flags & PROT_EXEC)
			p += snprintf(p, end - p, "PROT_EXEC|");
		if (flags & PROT_SEM)
			p += snprintf(p, end - p, "PROT_SEM ");
		p--;
		snprintf(p, end - p, "]");

		return buf;
	}
	return NULL;
}

static unsigned long mmap_prots[] = {
	PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM,
};

struct syscallentry syscall_mmap = {
	.name = "mmap",
	.num_args = 6,

	.sanitise = sanitise_mmap,
	.post = post_mmap,
	.decode = decode_mmap,

	.argtype = { [1] = ARG_LEN, [2] = ARG_LIST, [3] = ARG_OP, [4] = ARG_FD, [5] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len", [2] = "prot", [3] = "flags", [4] = "fd", [5] = "off" },
	.arg_params[2].list = ARGLIST(mmap_prots),
	.arg_params[3].list = ARGLIST(mmap_excl_flags),

	.group = GROUP_VM,
	.flags = NEED_ALARM,
};

struct syscallentry syscall_mmap2 = {
	.name = "mmap2",
	.num_args = 6,

	.sanitise = sanitise_mmap,
	.post = post_mmap,
	.decode = decode_mmap,

	.argtype = { [1] = ARG_LEN, [2] = ARG_LIST, [3] = ARG_OP, [4] = ARG_FD, [5] = ARG_LEN },
	.argname = { [0] = "addr", [1] = "len", [2] = "prot", [3] = "flags", [4] = "fd", [5] = "pgoff" },
	.arg_params[2].list = ARGLIST(mmap_prots),
	.arg_params[3].list = ARGLIST(mmap_excl_flags),

	.group = GROUP_VM,
	.flags = NEED_ALARM,
};
