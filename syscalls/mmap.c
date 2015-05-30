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
#include "random.h"
#include "syscall.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"	//ARRAY_SIZE

// need this to actually get MAP_UNINITIALIZED defined
#define CONFIG_MMAP_ALLOW_UNINITIALIZED

static void do_anon(struct syscallrecord *rec)
{
	/* no fd if anonymous mapping. */
	rec->a5 = -1;
	rec->a6 = 0;
}

static void sanitise_mmap(struct syscallrecord *rec)
{
	unsigned long mmap_flags[] = {
		MAP_FIXED, MAP_ANONYMOUS, MAP_GROWSDOWN, MAP_DENYWRITE,
		MAP_EXECUTABLE, MAP_LOCKED, MAP_NORESERVE, MAP_POPULATE,
		MAP_NONBLOCK, MAP_STACK, MAP_HUGETLB, MAP_UNINITIALIZED,
#ifdef __x86_64__
		MAP_32BIT,
#endif
	};
	unsigned long sizes[] = {
		-1,	/* over-written with page_size below */
		1 * MB, 2 * MB, 4 * MB, 10 * MB,
		1 * GB,
	};

	sizes[0] = page_size;

	/* Don't actually set a hint right now. */
	rec->a1 = 0;

	// set additional flags
	rec->a4 = set_rand_bitmask(ARRAY_SIZE(mmap_flags), mmap_flags);

	if (rec->a4 & MAP_ANONYMOUS) {
		rec->a2 = sizes[rand() % ARRAY_SIZE(sizes)];
		do_anon(rec);
	} else {
		if (this_syscallname("mmap2") == TRUE) {
			/* mmap2 counts in 4K units */
			rec->a6 /= 4096;
		} else {
			/* page align non-anonymous mappings. */
			rec->a6 &= PAGE_MASK;
		}

		rec->a2 = page_size;
	}
}

static void post_mmap(struct syscallrecord *rec)
{
	char *p;
	struct list_head *list;
	struct map *new;

	p = (void *) rec->retval;
	if (p == MAP_FAILED)
		return;

	new = zmalloc(sizeof(struct map));
	new->name = strdup("misc");
	new->size = rec->a2;
	new->prot = rec->a3;
//TODO: store fd if !anon
	new->ptr = p;
	new->type = TRINITY_MAP_CHILD;

	// Add this to a list for use by subsequent syscalls.
	list = &this_child->mappings->list;
	list_add_tail(&new->list, list);
	this_child->num_mappings++;

	/* Sometimes dirty the mapping. */
	if (RAND_BOOL())
		dirty_mapping(new);
}

static char * decode_mmap(struct syscallrecord *rec, unsigned int argnum)
{
	char *buf;

	if (argnum == 3) {
		int flags = rec->a3;
		char *p;

		p = buf = zmalloc(80);
		p += sprintf(buf, "[");

		if (flags == 0) {
			p += sprintf(p, "PROT_NONE]");
			return buf;
		}
		if (flags & PROT_READ)
			p += sprintf(p, "PROT_READ|");
		if (flags & PROT_WRITE)
			p += sprintf(p, "PROT_WRITE|");
		if (flags & PROT_EXEC)
			p += sprintf(p, "PROT_EXEC|");
		if (flags & PROT_SEM)
			p += sprintf(p, "PROT_SEM ");
		p--;
		sprintf(p, "]");

		return buf;
	}
	return NULL;
}

struct syscallentry syscall_mmap = {
	.name = "mmap",
	.num_args = 6,

	.sanitise = sanitise_mmap,
	.post = post_mmap,
	.decode = decode_mmap,

	.arg1name = "addr",
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 4,
		.values = { PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM },
	},
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = {
		.num = 2,
		.values = { MAP_SHARED, MAP_PRIVATE },
	},
	.arg5name = "fd",
	.arg5type = ARG_FD,
	.arg6name = "off",
	.arg6type = ARG_LEN,

	.group = GROUP_VM,
	.flags = NEED_ALARM,
};

struct syscallentry syscall_mmap2 = {
	.name = "mmap2",
	.num_args = 6,

	.sanitise = sanitise_mmap,
	.post = post_mmap,
	.decode = decode_mmap,

	.arg1name = "addr",
	.arg2name = "len",
	.arg2type = ARG_LEN,
	.arg3name = "prot",
	.arg3type = ARG_LIST,
	.arg3list = {
		.num = 4,
		.values = { PROT_READ, PROT_WRITE, PROT_EXEC, PROT_SEM },
	},
	.arg4name = "flags",
	.arg4type = ARG_OP,
	.arg4list = {
		.num = 2,
		.values = { MAP_SHARED, MAP_PRIVATE },
	},
	.arg5name = "fd",
	.arg5type = ARG_FD,
	.arg6name = "pgoff",
	.arg6type = ARG_LEN,

	.group = GROUP_VM,
	.flags = NEED_ALARM,
};
