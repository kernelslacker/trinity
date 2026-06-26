#include "arch.h"

#ifdef X86
/*
 * asmlinkage int sys_modify_ldt(int func, void __user *ptr, unsigned long bytecount)
 */
#include <stdlib.h>
#include <linux/types.h> /* before __ASSEMBLY__ == 1 */
#define __ASSEMBLY__ 1
#include <asm/ldt.h>
#include "sanitise.h"
#include "deferred-free.h"
#include "random.h"
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
 *
 * Wired into the post_state ownership table by post_state_install() at
 * sanitise time; post_modify_ldt() gates the snap through
 * post_state_claim_owned() before any field deref, so a sibling stomp
 * that redirects rec->post_state at a foreign heap chunk is rejected by
 * the ownership lookup before the leading-word magic compare ever runs.
 */
#define MODIFY_LDT_POST_STATE_MAGIC	0x4D4C4454UL	/* "MLDT" */
struct modify_ldt_post_state {
	unsigned long magic;
	unsigned long func;
	unsigned long ldt;
	unsigned long bytecount;
};

static void sanitise_modify_ldt(struct syscallrecord *rec)
{
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
		ldt = zmalloc_tracked(ALLOCSIZE);
		rec->a2 = (unsigned long) ldt;
		rec->a3 = ALLOCSIZE;
		/* Hand the genuine tracked pointer to the rec owned[] carrier
		 * so the drain frees it unconditionally after post_modify_ldt()
		 * runs.  The oracle deref of snap->ldt stays valid because the
		 * drain only fires after .post returns. */
		rec_own(rec, ldt);
		/* Snapshot for the post handler -- a1 / a2 / a3 may be
		 * scribbled by a sibling syscall before post_modify_ldt() runs. */
		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic = MODIFY_LDT_POST_STATE_MAGIC;
		snap->func = rec->a1;
		snap->ldt = (unsigned long) ldt;
		snap->bytecount = rec->a3;
		post_state_install(rec, snap);
		break;

	case 1:
	{
		/* modify one ldt entry.
		 * ptr points to a user_desc structure
		 * bytecount must equal the size of this structure. */
		struct user_desc *desc = zmalloc_tracked(sizeof(*desc));

		desc->entry_number    = rnd_modulo_u32(LDT_ENTRIES);
		desc->base_addr       = rnd_u64();
		desc->limit           = rnd_u32();
		desc->seg_32bit       = RAND_BOOL();
		desc->contents        = rnd_modulo_u32(4);	/* 2 bits */
		desc->read_exec_only  = RAND_BOOL();
		desc->limit_in_pages  = RAND_BOOL();
		desc->seg_not_present = RAND_BOOL();
		desc->useable         = RAND_BOOL();

		rec->a2 = (unsigned long) desc;
		rec->a3 = sizeof(*desc);
		break;
	}
	default:
		rec->a2 = 0L;
		break;
	}
}

static void post_modify_ldt(struct syscallrecord *rec)
{
	struct modify_ldt_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;

	rec->a2 = 0;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, MODIFY_LDT_POST_STATE_MAGIC, __func__);
	if (snap == NULL)
		return;

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
	 * through to the snap free below; the ldt buffer itself is owned by
	 * the rec carrier and released by the drain after .post.
	 */
	if (snap->func == 0 &&
	    ret != -1L &&
	    retval > snap->bytecount) {
		outputerr("post_modify_ldt: retval %lu exceeds bytecount %lu\n",
			  retval, snap->bytecount);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}

	post_state_release(rec, snap);
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
	.rettype = RET_BORING,
};
#endif
