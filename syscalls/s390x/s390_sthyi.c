/*
 * int s390_sthyi(unsigned long function_code, void *resp_buffer,
 *		  uint64_t *return_code, unsigned long flags);
 */

#include <asm/sthyi.h>

#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static unsigned long syscall_s390_sthyi_arg1[] = {
	STHYI_FC_CP_IFL_CAP,
	-1
};

static u64 syscall_s390_sthyi_return_code;

/* Allocate buffer. */
static void sanitise_s390_sthyi(struct syscallrecord *rec)
{
	size_t size = RAND_RANGE(0, page_size);
	void *addr = size ? malloc(size) : NULL;

	rec->a2 = (unsigned long)addr;
	/* Snapshot for the post handler -- a2 may be scribbled by a sibling
	 * syscall before post_s390_sthyi() runs.  size==0 / malloc() failure
	 * leaves addr == NULL, which the snapshot mirrors. */
	rec->post_state = (unsigned long)addr;

	/* Use NULL, random or valid address */
	switch (rand() % 3) {
	case 0:	rec->a3 = 0;
		break;
	case 1: rec->a3 = rand();
		break;
	case 2: rec->a3 = (unsigned long)&syscall_s390_sthyi_return_code;
		break;
	}
}

static void post_s390_sthyi(struct syscallrecord *rec)
{
	void *addr = (void *) rec->post_state;

	if (addr == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, addr)) {
		outputerr("post_s390_sthyi: rejected suspicious addr=%p (pid-scribbled?)\n", addr);
		rec->a2 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a2 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_s390_sthyi = {
	.name = "s390_sthyi",
	.sanitise = sanitise_s390_sthyi,
	.post = post_s390_sthyi,
	.num_args = 4,
	.argtype = { [0] = ARG_LIST, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_RANGE },
	.argname = { [0] = "function_code", [1] = "resp_buffer", [2] = "return_code", [3] = "resp_buffer" },
	.arg_params[0].list = ARGLIST(syscall_s390_sthyi_arg1),
	.arg_params[3].range.low = 0,
	.arg_params[3].range.hi = 128
};
