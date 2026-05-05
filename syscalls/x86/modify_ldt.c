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

/*
 * Snapshot of modify_ldt input args read by the post oracle, captured at
 * sanitise time and consumed by post_modify_ldt.  Only populated for the
 * read func (a1 == 0), which is the only path that allocates a user buffer
 * and the only path that reports a byte count back through retval.  Lives
 * in rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot smear the size bound used to validate the retval.
 */
struct modify_ldt_post_state {
	unsigned long func;
	unsigned long ldt;
	unsigned long bytecount;
};

static void sanitise_modify_ldt(struct syscallrecord *rec)
{
	//struct user_desc *desc;
	struct modify_ldt_post_state *snap;
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
		/* Snapshot for the post handler -- a1 / a2 / a3 may be
		 * scribbled by a sibling syscall before post_modify_ldt() runs. */
		snap = zmalloc(sizeof(*snap));
		snap->func = rec->a1;
		snap->ldt = (unsigned long) ldt;
		snap->bytecount = rec->a3;
		rec->post_state = (unsigned long) snap;
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
	struct modify_ldt_post_state *snap = (struct modify_ldt_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_modify_ldt: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	/*
	 * STRONG-VAL count bound for the read func (a1 == 0): the kernel
	 * copies at most bytecount bytes of the LDT into the user buffer and
	 * returns the byte count, capped at the snapshotted bytecount arg.
	 * Failure returns -1L.  Anything > snap->bytecount on a non-(-1L)
	 * return is structural ABI corruption -- a sign-extension tear in the
	 * syscall return path, a kernel-side write that spilled past the
	 * user-supplied bound, or -errno leaking through the success slot.
	 * Write funcs (a1 == 1/2) return 0/-1 only and are covered by the
	 * dispatcher-level RZS blanket validator; nothing to do here.  Fall
	 * through to the free path so the deferred ldt / snap buffers are
	 * still released.
	 */
	if (snap->func == 0 &&
	    (long) rec->retval != -1L &&
	    rec->retval > snap->bytecount) {
		outputerr("post_modify_ldt: retval %lu exceeds bytecount %lu\n",
			  rec->retval, snap->bytecount);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	rec->a2 = 0;
	deferred_freeptr(&snap->ldt);
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
