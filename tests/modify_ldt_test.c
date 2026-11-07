/*
 * Self-check for modify_ldt's sanitiser: the user_desc it builds for a
 * write func is a tracked heap allocation, so it goes to the record's
 * drain rather than waiting for LRU eviction.
 */

#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* X86 */
#include "debug.h"		/* BUG */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_modify_ldt */

#ifdef X86
#include <asm/ldt.h>		/* struct user_desc */
#endif

void modify_ldt_self_check(void);
void modify_ldt_self_check(void)
{
#ifdef X86
	struct syscallrecord rec;

	memset(&rec, 0, sizeof(rec));
	rec.a1 = 1;
	syscall_modify_ldt.sanitise(&rec);
	if (rec.a2 == 0 || rec.a3 != sizeof(struct user_desc))
		BUG("modify_ldt: write_ldt gets no user_desc");
	if (rec.owned_count != 1)
		BUG("modify_ldt: the user_desc is left to LRU eviction");

	/* This binary's alloc-track holds nothing, so the drain would leave
	 * it. */
	while (rec.owned_count > 0)
		free(rec.owned[--rec.owned_count]);
#endif
}
