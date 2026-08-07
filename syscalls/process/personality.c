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
 * All eleven upper flag bits from include/uapi/linux/personality.h:
 *   UNAME26 = 0x0020000, ADDR_NO_RANDOMIZE = 0x0040000, FDPIC_FUNCPTRS = 0x0080000,
 *   MMAP_PAGE_ZERO = 0x0100000, ADDR_COMPAT_LAYOUT = 0x0200000,
 *   READ_IMPLIES_EXEC = 0x0400000, ADDR_LIMIT_32BIT = 0x0800000,
 *   SHORT_INODE = 0x1000000, WHOLE_SECONDS = 0x2000000,
 *   STICKY_TIMEOUTS = 0x4000000, ADDR_LIMIT_3GB = 0x8000000.
 * UNAME26 is consumed by kernel/sys.c:override_release() and is not embedded
 * in any named PER_* constant, so it requires explicit coverage here.
 * The three (ADDR_NO_RANDOMIZE, ADDR_COMPAT_LAYOUT, READ_IMPLIES_EXEC) that
 * never appear in any named PER_* constant likewise had 0% coverage under
 * the old ARG_OP draw.
 */
static const unsigned long personality_flags[] = {
	UNAME26,
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
	unsigned int bucket = rnd_modulo_u32(20);

	/* ~5% (1/20): emit the canonical query form personality(0xffffffff). */
	if (bucket == 0) {
		rec->a1 = 0xffffffffUL;
		return;
	}

	/* ~30% (6/20): bare persona — no flag bits ORed in.
	 * This restores reachability for clean PER_LINUX, PER_LINUX32, etc.
	 * invocations, which are the most common real-world form and were
	 * reduced to 0% when set_rand_bitmask() gained its "always >= 1 bit"
	 * guard. */
	if (bucket <= 6) {
		rec->a1 = RAND_ARRAY(personalities);
		return;
	}

	/* ~65% (13/20): base persona | random non-empty subset of flag bits. */
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
	.flags = REEXEC_SANITISE_OK,
	.post = post_personality,
	.rettype = RET_BORING,
};
