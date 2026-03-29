/*
 * int s390_sthyi(unsigned long function_code, void *resp_buffer,
 *		  uint64_t *return_code, unsigned long flags);
 */

#include <asm/sthyi.h>

#include "arch.h"
#include "random.h"
#include "sanitise.h"

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

/* Free buffer, freeptr takes care of NULL */
static void post_s390_sthyi(struct syscallrecord *rec)
{
	freeptr(&rec->a2);
}

struct syscallentry syscall_s390_sthyi = {
	.name = "s390_sthyi",
	.sanitise = sanitise_s390_sthyi,
	.post = post_s390_sthyi,
	.num_args = 4,
	.argtype = { [0] = ARG_LIST, [1] = ARG_NON_NULL_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_RANGE },
	.argname = { [0] = "function_code", [1] = "resp_buffer", [2] = "return_code", [3] = "resp_buffer" },
	.arg1list = ARGLIST(syscall_s390_sthyi_arg1),
	.low4range = 0,
	.hi4range = 128
};
