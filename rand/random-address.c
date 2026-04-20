#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <sys/mman.h>	// mprotect

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
		if (map == NULL || map->size < size)
			goto retry;

		addr = map->ptr;
		map->prot = PROT_READ | PROT_WRITE;
	} else {
		obj = get_random_object(OBJ_SYSV_SHM, OBJ_GLOBAL);
		if (obj == NULL)
			goto retry;
		if (obj->sysv_shm.size < size)
			goto retry;
		addr = obj->sysv_shm.ptr;
	}

	mprotect(addr, size, PROT_READ | PROT_WRITE);

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
		shm->stats.shared_buffer_redirected++;
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
	entry = syscalls[call].entry;

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

		if (map == NULL) {
			iov[i].iov_base = NULL;
			iov[i].iov_len = 0;
			continue;
		}

		iov[i].iov_base = map->ptr;
		if (RAND_BOOL()) {
			const unsigned int lens[] = { 0, 1, page_size };
			iov[i].iov_len = lens[rand() % 3];
		} else {
			iov[i].iov_len = map->size > 0 ? rand() % map->size : 0;
		}
	}

	return iov;
}
