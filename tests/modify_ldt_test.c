/*
 * Self-check for modify_ldt's sanitiser: func 1 and 0x11 both reach
 * write_ldt(), which reads a whole user_desc, and func 2 reaches
 * read_default_ldt(), which clears up to 128 bytes at ptr
 * (arch/x86/kernel/ldt.c).  A user_desc the sanitiser builds is a
 * tracked heap allocation, so it goes to the record's drain rather than
 * waiting for LRU eviction.
 */

#include <stdlib.h>
#include <string.h>

#include "arch.h"		/* X86 */
#include "debug.h"		/* BUG */
#include "sanitise.h"		/* range_in_writable_pool, writable_pool_init */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_modify_ldt */
#include "utils.h"		/* ARRAY_SIZE */

#ifdef X86
#include <asm/ldt.h>		/* struct user_desc */
#endif

void modify_ldt_self_check(void);
void modify_ldt_self_check(void)
{
#ifdef X86
	static const unsigned long write_funcs[] = { 1, 0x11 };
	struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(write_funcs); i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = write_funcs[i];
		syscall_modify_ldt.sanitise(&rec);
		if (rec.a2 == 0 || rec.a3 != sizeof(struct user_desc))
			BUG("modify_ldt: write_ldt gets no user_desc");
		if (rec.owned_count != 1)
			BUG("modify_ldt: the user_desc is left to LRU eviction");

		/* This binary's alloc-track holds nothing, so the drain would
		 * leave it. */
		while (rec.owned_count > 0)
			free(rec.owned[--rec.owned_count]);
	}

	if (get_writable_struct(1) == NULL)
		writable_pool_init();
	memset(&rec, 0, sizeof(rec));
	rec.a1 = 2;
	syscall_modify_ldt.sanitise(&rec);
	if (!range_in_writable_pool(rec.a2, 128))
		BUG("modify_ldt: read_default_ldt clears memory past ptr's buffer");
#endif
}
