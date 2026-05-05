#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/mman.h>	// mprotect
#include <sys/ipc.h>
#include <sys/shm.h>

#include "arch.h"	// KERNEL_ADDR etc
#include "random.h"
#include "sanitise.h"
#include "maps.h"
#include "shm.h"
#include "tables.h"
#include "utils.h"

void * get_writable_address(unsigned long size)
{
	struct map *map;
	struct object *obj;
	void *addr = NULL;
	int tries = 0;

retry:	tries++;
	if (tries == 100)
		return NULL;

	if (RAND_BOOL()) {
		map = get_map();
		if (map == NULL)
			goto retry;
		/*
		 * Sanity-guard the map pointer before deref.  Heap pointers
		 * land at >= 0x10000 and below the user/kernel VA boundary;
		 * anything else is a stale or corrupted slot from the
		 * per-child OBJ_MMAP pool and dereferencing it SIGSEGVs.
		 * Log loudly so the corruption source is visible — this
		 * branch ought to be impossible.
		 */
		if ((uintptr_t)map < 0x10000UL ||
		    (uintptr_t)map >= 0x800000000000UL) {
			outputerr("get_writable_address: bogus map pointer %p "
				  "from get_map() — pool corruption?\n", map);
			goto retry;
		}
		/*
		 * If the map struct itself sits in a tracked shared region,
		 * the prot-bookkeeping store below would either SIGSEGV
		 * (post-freeze the OBJ_GLOBAL backing heap is mprotect
		 * PROT_READ) or scribble shared bookkeeping (an OBJ_LOCAL
		 * map pointer that aliased into the shared heap is by
		 * definition a stale slot — OBJ_LOCAL maps live on the
		 * child's private heap, never inside any tracked region).
		 * Either way, retry to pick a different slot.
		 */
		if (range_overlaps_shared((unsigned long)map, sizeof(*map)))
			goto retry;
		/*
		 * Honor the prot=0 invalidation that post_munmap and
		 * post_mprotect stamp onto pool entries when a sibling
		 * syscall hole-punches or downgrades prot on the
		 * underlying VMAs.  Without this skip, a stale entry
		 * sails past every check and the caller faults on first
		 * access (SEGV_MAPERR on hole-punched pages, SEGV_ACCERR
		 * on PROT_NONE pages).  Mirrors the (m->prot & req) == req
		 * filter in get_map_with_prot(); the prot=0 case is the
		 * common ground that catches every consumer.
		 */
		if (map->prot == 0)
			goto retry;
		if (map->size < size)
			goto retry;

		addr = map->ptr;
		/*
		 * Don't update map->prot here.  The mprotect below is a
		 * sub-range upgrade (size <= map->size) so cacheing
		 * PROT_READ|PROT_WRITE for the whole mapping would lie
		 * to future get_map_with_prot() consumers about pages
		 * outside [addr, addr+size).  Worse, it would silently
		 * undo any concurrent post_munmap / post_mprotect
		 * invalidation that landed between the read of map->prot
		 * above and this write.  Leave the cached invariant
		 * owned by the post-syscall hooks.
		 */
	} else {
		obj = get_random_object(OBJ_SYSV_SHM, OBJ_GLOBAL);
		if (obj == NULL)
			goto retry;
		if (obj->sysv_shm.size < size)
			goto retry;
		/*
		 * The pool slot was valid when populated, but a sibling
		 * shmctl(IPC_RMID) may have flipped the segment to the
		 * SHM_DEST/zombie state in the meantime.  Touching the
		 * cached ptr after that SIGSEGVs/SIGBUSes the consumer.
		 * Probe the segment with IPC_STAT and retry the slot if
		 * the lookup fails or the destroy bit is set.
		 */
		{
			struct shmid_ds buf;
			if (shmctl(obj->sysv_shm.id, IPC_STAT, &buf) != 0)
				goto retry;
			if (buf.shm_perm.mode & SHM_DEST)
				goto retry;
		}
		addr = obj->sysv_shm.ptr;
	}

	if (mprotect(addr, size, PROT_READ | PROT_WRITE) != 0)
		log_mprotect_failure(addr, (size_t) size,
				     PROT_READ | PROT_WRITE,
				     __builtin_return_address(0), errno);

	return addr;
}

void * get_non_null_address(void)
{
	unsigned long size = RAND_ARRAY(mapping_sizes);

	return get_writable_address(size);
}

void * get_writable_struct(size_t size)
{
	return get_writable_address(size);
}

/*
 * Defense-in-depth for output-buffer syscall args.  A fuzzed pointer that
 * lands inside one of trinity's own alloc_shared() regions — childdata,
 * the global stats blob, fd-event rings, etc. — turns any "kernel writes
 * here" syscall (read, recv, getdents, statx, ioctl _IOR, ...) into a
 * silent corruption of trinity bookkeeping.  Symptoms include impossible
 * counter values, non-canonical pointers, and crashes far from the
 * scribbled write.  Sanitisers that hand the kernel a writable buffer
 * call this to swap the address out for a known-safe one before the
 * syscall is issued.
 */
void avoid_shared_buffer(unsigned long *addr, unsigned long len)
{
	void *replacement;

	if (addr == NULL)
		return;
	if (*addr == 0)
		return;
	if (!range_overlaps_shared(*addr, len))
		return;

	replacement = get_writable_address(len ? len : page_size);
	if (replacement == NULL)
		return;

	*addr = (unsigned long) replacement;
	if (shm != NULL)
		__atomic_add_fetch(&shm->stats.shared_buffer_redirected, 1, __ATOMIC_RELAXED);
}

void * get_address(void)
{
	if (ONE_IN(100))
		return NULL;

	return get_non_null_address();
}

static bool is_arg_address(enum argtype argtype)
{
	if (argtype == ARG_ADDRESS)
		return true;
	if (argtype == ARG_NON_NULL_ADDRESS)
		return true;
	return false;
}

unsigned long find_previous_arg_address(struct syscallrecord *rec, unsigned int argnum)
{
	struct syscallentry *entry;
	unsigned long addr = 0;
	unsigned int call;

	call = rec->nr;
	entry = get_syscall_entry(call, rec->do32bit);

	if (argnum > 1)
		if (is_arg_address(entry->argtype[0]) == true)
			addr = rec->a1;

	if (argnum > 2)
		if (is_arg_address(entry->argtype[1]) == true)
			addr = rec->a2;

	if (argnum > 3)
		if (is_arg_address(entry->argtype[2]) == true)
			addr = rec->a3;

	if (argnum > 4)
		if (is_arg_address(entry->argtype[3]) == true)
			addr = rec->a4;

	if (argnum > 5)
		if (is_arg_address(entry->argtype[4]) == true)
			addr = rec->a5;

	return addr;
}


struct iovec * alloc_iovec(unsigned int num)
{
	struct iovec *iov;
	unsigned int i;

	iov = zmalloc(num * sizeof(struct iovec));	/* freed by generic_free_arg */

	for (i = 0; i < num; i++) {
		struct map *map = get_map();
		unsigned long base;

		if (map == NULL) {
			iov[i].iov_base = NULL;
			iov[i].iov_len = 0;
			continue;
		}

		iov[i].iov_base = map->ptr;
		if (RAND_BOOL()) {
			const unsigned int lens[] = {
				0, 1, page_size - 1, page_size,
				page_size + 1, page_size * 2,
			};
			iov[i].iov_len = lens[rand() % ARRAY_SIZE(lens)];
		} else {
			iov[i].iov_len = map->size > 0 ? rand() % map->size : 0;
		}

		/*
		 * readv/preadv/preadv2/recvmsg/recvmmsg all hand each
		 * iov_base to the kernel as an output buffer.  A get_map()
		 * pointer can in principle alias one of trinity's
		 * alloc_shared() regions (children blob, fd_event_ring,
		 * shared obj/string heaps), in which case the kernel write
		 * silently scribbles bookkeeping.  Same defence the
		 * read/recv/getdents/ioctl paths already apply at the
		 * syscallrecord layer, lifted into the iovec builder so
		 * every caller is covered in one place.
		 */
		base = (unsigned long) iov[i].iov_base;
		avoid_shared_buffer(&base, iov[i].iov_len);
		iov[i].iov_base = (void *) base;
	}

	return iov;
}
