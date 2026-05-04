#include "arch.h"

#ifdef X86
/*
 * asmlinkage int sys_modify_ldt(int func, void __user *ptr, unsigned long bytecount)
 */
#include <stdlib.h>
#include <sys/types.h>
#include <linux/types.h> /* before __ASSEMBLY__ == 1 */
#define __ASSEMBLY__ 1
#include <asm/ldt.h>
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "syscall.h"
#include "trinity.h"
#include "utils.h"

#define ALLOCSIZE LDT_ENTRIES * LDT_ENTRY_SIZE

static void sanitise_modify_ldt(struct syscallrecord *rec)
{
	//struct user_desc *desc;
	void *ldt;

	/* Clear post_state up front so the no-alloc cases below leave the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record. */
	rec->post_state = 0;

	switch (rec->a1) {
	case 0:
		/* read the ldt into the memory pointed to by ptr.
		   The number of bytes read is the smaller of bytecount and the actual size of the ldt. */
		ldt = zmalloc(ALLOCSIZE);
		rec->a2 = (unsigned long) ldt;
		rec->a3 = ALLOCSIZE;
		/* Snapshot for the post handler -- a2 may be scribbled by a
		 * sibling syscall before post_modify_ldt() runs. */
		rec->post_state = (unsigned long) ldt;
		break;

	case 1:
		rec->a2 = 0L;
		/* modify one ldt entry.
		 * ptr points to a user_desc structure
		 * bytecount must equal the size of this structure. */

	/*
	       unsigned int  entry_number;
	       unsigned long base_addr;
	       unsigned int  limit;
	       unsigned int  seg_32bit:1;
	       unsigned int  contents:2;
	       unsigned int  read_exec_only:1;
	       unsigned int  limit_in_pages:1;
	       unsigned int  seg_not_present:1;
	       unsigned int  useable:1;
	*/
		break;
	default:
		rec->a2 = 0L;
		break;
	}
}

static void post_modify_ldt(struct syscallrecord *rec)
{
	void *ldt = (void *) rec->post_state;

	if (ldt == NULL)
		return;

	if (looks_like_corrupted_ptr(ldt)) {
		outputerr("post_modify_ldt: rejected suspicious ldt=%p (pid-scribbled?)\n", ldt);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
}

static unsigned long modify_ldt_funcs[] = {
	0, 1,
};

struct syscallentry syscall_modify_ldt = {
	.name = "modify_ldt",
	.num_args = 3,
	.argtype = { [0] = ARG_OP },
	.argname = { [0] = "func", [1] = "ptr", [2] = "bytecount" },
	.arg_params[0].list = ARGLIST(modify_ldt_funcs),
	.sanitise = sanitise_modify_ldt,
	.post = post_modify_ldt,
};
#endif
