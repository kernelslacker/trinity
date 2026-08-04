/*
 * SYSCALL_DEFINE1(personality, unsigned int, personality
 */
#include <stdint.h>
#include <sys/personality.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

#include "kernel/personality.h"

static const unsigned long personalities[] = {
	PER_LINUX, PER_SVR4, PER_SVR3, PER_SCOSVR3,
	PER_OSR5, PER_WYSEV386, PER_ISCR4, PER_BSD,
	PER_SUNOS,
	PER_LINUX32,
	PER_LINUX_32BIT, PER_LINUX_FDPIC, PER_XENIX, PER_LINUX32_3GB,
	PER_IRIX32, PER_IRIXN32, PER_IRIX64, PER_RISCOS,
	PER_SOLARIS, PER_UW7,
	PER_OSF4, PER_HPUX,
};

/*
 * All ten upper flag bits from include/uapi/linux/personality.h.
 * set_rand_bitmask() ORs a random non-empty subset onto the base persona,
 * exercising every combination including the three (ADDR_NO_RANDOMIZE,
 * ADDR_COMPAT_LAYOUT, READ_IMPLIES_EXEC) that never appear in any named
 * PER_* constant and therefore had 0% coverage under the old ARG_OP draw.
 */
static const unsigned long personality_flags[] = {
	ADDR_NO_RANDOMIZE,
	FDPIC_FUNCPTRS,
	MMAP_PAGE_ZERO,
	ADDR_COMPAT_LAYOUT,
	READ_IMPLIES_EXEC,
	ADDR_LIMIT_32BIT,
	SHORT_INODE,
	WHOLE_SECONDS,
	STICKY_TIMEOUTS,
	ADDR_LIMIT_3GB,
};

static void sanitise_personality(struct syscallrecord *rec)
{
	/* ~5%: emit the canonical query form personality(0xffffffff). */
	if (rnd_modulo_u32(20) == 0) {
		rec->a1 = 0xffffffffUL;
		return;
	}

	/* Base persona | random subset of upper flag bits. */
	rec->a1 = RAND_ARRAY(personalities) |
		  set_rand_bitmask(ARRAY_SIZE(personality_flags), personality_flags);
}

static void post_personality(struct syscallrecord *rec)
{
	long ret = (long) rec->retval;

	if (ret == -1L)
		return;

	/* Reject retval with high bits set — personality value is 32-bit unsigned. */
	if ((unsigned long) ret > (unsigned long) UINT32_MAX) {
		output(0, "post_personality: rejected retval 0x%lx outside [0, UINT32_MAX]\n",
		       (unsigned long) ret);
		post_handler_corrupt_ptr_bump(rec, NULL);
	}
}

struct syscallentry syscall_personality = {
	.name = "personality",
	.group = GROUP_PROCESS,
	.num_args = 1,
	.argname = { [0] = "personality" },
	.sanitise = sanitise_personality,
	.post = post_personality,
	.rettype = RET_BORING,
};
