/*
 * Self-check for listmount's sanitiser: the request it builds is a tracked
 * heap allocation, so it must reach the record's drain even when a buffer
 * draw after it fails, or it waits for LRU eviction.
 */

#include <stdlib.h>
#include <string.h>

#include "debug.h"		/* BUG */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_listmount */

/* Draws get_writable_address() refuses before it serves again. */
static unsigned int writable_refusals;

void *__real_get_writable_address(unsigned long size);
void *__wrap_get_writable_address(unsigned long size);
void *__wrap_get_writable_address(unsigned long size)
{
	if (writable_refusals > 0) {
		writable_refusals--;
		return NULL;
	}
	return __real_get_writable_address(size);
}

void listmount_self_check(void);
void listmount_self_check(void)
{
	struct syscallrecord rec;

	/* The id buffer is the sanitiser's first pool draw. */
	memset(&rec, 0, sizeof(rec));
	writable_refusals = 1;
	syscall_listmount.sanitise(&rec);
	writable_refusals = 0;
	if (rec.owned_count != 1)
		BUG("listmount: a failed id-buffer draw strands the request");

	/* This binary's alloc-track holds nothing, so the drain would leave
	 * it. */
	while (rec.owned_count > 0)
		free(rec.owned[--rec.owned_count]);
}
