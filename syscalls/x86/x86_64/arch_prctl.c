/* (x86-64 only)
 *  long sys_arch_prctl(int code, unsigned long addr)
 *
 * On success, arch_prctl() returns 0
 * On error, -1 is returned, and errno is set to indicate the error.
 */

#if defined(__i386__) || defined (__x86_64__)

#include "random.h"
#include "sanitise.h"
#include <asm/prctl.h>
#include <sys/prctl.h>

/*
 * The XCOMP / LAM / SHSTK ARCH_* codes were added across many kernel
 * versions; provide fallbacks so trinity builds against older asm/prctl.h.
 */
#ifndef ARCH_GET_CPUID
#define ARCH_GET_CPUID			0x1011
#endif
#ifndef ARCH_GET_XCOMP_SUPP
#define ARCH_GET_XCOMP_SUPP		0x1021
#endif
#ifndef ARCH_GET_XCOMP_PERM
#define ARCH_GET_XCOMP_PERM		0x1022
#endif
#ifndef ARCH_REQ_XCOMP_PERM
#define ARCH_REQ_XCOMP_PERM		0x1023
#endif
#ifndef ARCH_XCOMP_TILECFG
#define ARCH_XCOMP_TILECFG		17
#endif
#ifndef ARCH_XCOMP_TILEDATA
#define ARCH_XCOMP_TILEDATA		18
#endif
#ifndef ARCH_GET_UNTAG_MASK
#define ARCH_GET_UNTAG_MASK		0x4001
#endif
#ifndef ARCH_ENABLE_TAGGED_ADDR
#define ARCH_ENABLE_TAGGED_ADDR		0x4002
#endif
#ifndef ARCH_GET_MAX_TAG_BITS
#define ARCH_GET_MAX_TAG_BITS		0x4003
#endif
#ifndef ARCH_FORCE_TAGGED_SVA
#define ARCH_FORCE_TAGGED_SVA		0x4004
#endif
#ifndef ARCH_SHSTK_LOCK
#define ARCH_SHSTK_LOCK			0x5003
#endif
#ifndef ARCH_SHSTK_STATUS
#define ARCH_SHSTK_STATUS		0x5005
#endif

/*
 * Curated subset of ARCH_* codes that are safe to fuzz inside a child:
 * read-only getters (ARCH_GET_*, ARCH_SHSTK_STATUS) and benign feature-bit
 * setters whose effect on the child is harmless or transparent
 * (ARCH_REQ_XCOMP_PERM, ARCH_ENABLE_TAGGED_ADDR, ARCH_FORCE_TAGGED_SVA,
 * ARCH_SHSTK_LOCK).
 *
 * Deliberately excluded:
 *   ARCH_SET_FS / ARCH_SET_GS / ARCH_SET_CPUID  -- mutate segment / cpuid
 *                                                  fault state, crashes the
 *                                                  child instantly.
 *   ARCH_SHSTK_ENABLE / ARCH_SHSTK_DISABLE      -- alter shadow-stack mode
 *                                                  mid-fuzz, would break the
 *                                                  child's own returns.
 *   ARCH_MAP_VDSO_X32 / _32 / _64               -- mmap-style child VM
 *                                                  mutation.
 */
static unsigned long arch_prctl_codes[] = {
	ARCH_GET_FS, ARCH_GET_GS,
	ARCH_GET_CPUID,
	ARCH_GET_XCOMP_SUPP, ARCH_GET_XCOMP_PERM, ARCH_REQ_XCOMP_PERM,
	ARCH_GET_UNTAG_MASK, ARCH_GET_MAX_TAG_BITS,
	ARCH_ENABLE_TAGGED_ADDR, ARCH_FORCE_TAGGED_SVA,
	ARCH_SHSTK_STATUS, ARCH_SHSTK_LOCK,
};

static void sanitise_arch_prctl(struct syscallrecord *rec)
{
	switch (rec->a1) {
	case ARCH_GET_FS:
	case ARCH_GET_GS:
	case ARCH_GET_XCOMP_SUPP:
	case ARCH_GET_XCOMP_PERM:
	case ARCH_GET_UNTAG_MASK:
	case ARCH_GET_MAX_TAG_BITS:
	case ARCH_SHSTK_STATUS:
		/* Kernel writes a u64 (or smaller) to *addr -- redirect off
		 * shared / heap pages so a sibling cannot see the write. */
		avoid_shared_buffer(&rec->a2, sizeof(unsigned long));
		break;

	case ARCH_REQ_XCOMP_PERM:
		/* arg2 is the xfeature bit number; AMX TILECFG (17) and
		 * TILEDATA (18) are the only values the kernel inspects.
		 * TILEDATA sets a per-task allow-bit -- no architectural
		 * state change until the child actually executes AMX. */
		rec->a2 = RAND_BOOL() ? ARCH_XCOMP_TILECFG : ARCH_XCOMP_TILEDATA;
		break;

	case ARCH_ENABLE_TAGGED_ADDR:
		/* arg2 is nbits; LAM tags are masked transparently in user
		 * pointers, so enabling LAM_U57 does not affect the child's
		 * own pointer use. */
		rec->a2 = RAND_RANGE(0, 15);
		break;

	case ARCH_SHSTK_LOCK:
		/* arg2 is a small bitmask (SHSTK / WRSS) of features to lock
		 * against further toggles; it just ORs into a per-task mask. */
		rec->a2 = RAND_RANGE(0, 3);
		break;

	case ARCH_GET_CPUID:
	case ARCH_FORCE_TAGGED_SVA:
		/* arg2 unused -- kernel ignores it for these codes. */
		break;

	default:
		break;
	}
}

struct syscallentry syscall_arch_prctl = {
	.name = "arch_prctl",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS },
	.argname = { [0] = "code", [1] = "addr" },
	.arg_params[0].list = ARGLIST(arch_prctl_codes),
	.sanitise = sanitise_arch_prctl,
	.rettype = RET_BORING,
};
#endif
