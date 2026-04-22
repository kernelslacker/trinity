/*
   long sys_sigaltstack(const stack_t __user *uss, stack_t __user *uoss)
 */
#include <signal.h>
#include "arch.h"
#include "maps.h"
#include "random.h"
#include "sanitise.h"
#include "compat.h"

static void sanitise_sigaltstack(struct syscallrecord *rec)
{
	stack_t *ss;

	ss = (stack_t *) get_writable_address(sizeof(*ss));

	switch (rand() % 5) {
	case 0: /* disable the signal stack */
		ss->ss_sp = NULL;
		ss->ss_flags = SS_DISABLE;
		ss->ss_size = 0;
		break;
	case 1:	/* minimum size */
		ss->ss_sp = (void *) get_writable_address(MINSIGSTKSZ);
		ss->ss_flags = 0;
		ss->ss_size = MINSIGSTKSZ;
		break;
	case 2: /* common size (8 pages) */
		ss->ss_sp = (void *) get_writable_address(page_size * 8);
		ss->ss_flags = 0;
		ss->ss_size = page_size * 8;
		break;
	case 3: /* autodisarm */
		ss->ss_sp = (void *) get_writable_address(SIGSTKSZ);
		ss->ss_flags = SS_AUTODISARM;
		ss->ss_size = SIGSTKSZ;
		break;
	default: /* boundary: too small */
		ss->ss_sp = (void *) get_writable_address(page_size);
		ss->ss_flags = RAND_BOOL() ? SS_AUTODISARM : 0;
		ss->ss_size = rand() % MINSIGSTKSZ;
		break;
	}

	rec->a1 = (unsigned long) ss;

	/*
	 * uoss (a2) is the kernel's writeback target for the previous stack:
	 * the kernel fills its three fields when uoss is non-NULL.
	 * ARG_ADDRESS draws from the random pool, so a fuzzed pointer can
	 * land inside an alloc_shared region.
	 */
	avoid_shared_buffer(&rec->a2, sizeof(stack_t));
}

struct syscallentry syscall_sigaltstack = {
	.name = "sigaltstack",
	.group = GROUP_SIGNAL,
	.num_args = 2,
	.argtype = { [1] = ARG_ADDRESS },
	.argname = { [0] = "uss", [1] = "uoss" },
	.sanitise = sanitise_sigaltstack,
};
