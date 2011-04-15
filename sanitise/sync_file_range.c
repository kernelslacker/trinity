#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>

#include "trinity.h"
#include "sanitise.h"
#include "arch.h"

/*
 * asmlinkage long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 */

void sanitise_sync_file_range(__unused__ unsigned long *fd,
	unsigned long *offset,
	__unused__ unsigned long *nbytes,
	__unused__ unsigned long *a4,
	__unused__ unsigned long *a5,
	__unused__ unsigned long *a6)
{
	unsigned long endbyte;

retry:
	*offset = rand() & 0xfffffff;
	*nbytes = rand() & 0xfffffff;

	endbyte = *offset + *nbytes;

	if (endbyte < *offset)
		goto retry;

	if (*offset >= (0x100000000ULL << PAGE_SHIFT))
		goto retry;

}
