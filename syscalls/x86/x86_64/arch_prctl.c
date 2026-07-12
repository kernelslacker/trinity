/* (x86-64 only)
 *  long sys_arch_prctl(int code, unsigned long addr)
 *
 * On success, arch_prctl() returns 0
 * On error, -1 is returned, and errno is set to indicate the error.
 */

#if defined(__i386__) || defined (__x86_64__)

#include <stdint.h>
#include "output-poison.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
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
#ifndef ARCH_GET_XCOMP_GUEST_PERM
#define ARCH_GET_XCOMP_GUEST_PERM	0x1024
#endif
#ifndef ARCH_REQ_XCOMP_GUEST_PERM
#define ARCH_REQ_XCOMP_GUEST_PERM	0x1025
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
 * (ARCH_REQ_XCOMP_PERM, ARCH_REQ_XCOMP_GUEST_PERM, ARCH_ENABLE_TAGGED_ADDR,
 * ARCH_FORCE_TAGGED_SVA, ARCH_SHSTK_LOCK).
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
	ARCH_GET_XCOMP_GUEST_PERM, ARCH_REQ_XCOMP_GUEST_PERM,
	ARCH_GET_UNTAG_MASK, ARCH_GET_MAX_TAG_BITS,
	ARCH_ENABLE_TAGGED_ADDR, ARCH_FORCE_TAGGED_SVA,
	ARCH_SHSTK_STATUS, ARCH_SHSTK_LOCK,
};

/*
 * Snapshot of the arch_prctl addr user pointer plus the fixed poison
 * pattern stamped into it, captured at sanitise time and consumed by
 * post_arch_prctl.  Lives in rec->post_state, a slot the syscall ABI
 * does not expose, so a sibling syscall scribbling rec->a2 between the
 * syscall returning and the post handler running cannot redirect the
 * poison check against an unrelated heap page whose residual bytes
 * happen to still match the fixed pattern.  A poison_seed of 0 means
 * the sanitise-time writability check refused to stamp for this call
 * (writable-pool draw no longer provably mapped after
 * avoid_shared_buffer_out) and the post handler must no-op the
 * untouched-buffer arm.  Only installed for the seven getter codes
 * that already call avoid_shared_buffer_out on a2; the setter codes
 * read a2 as an input, and ARCH_GET_CPUID / ARCH_FORCE_TAGGED_SVA
 * ignore a2 entirely, so an oracle on those paths has no writeback to
 * detect and would false-positive on every success.
 */
#define ARCH_PRCTL_POST_STATE_MAGIC	0x41504354UL	/* "APCT" */
#define ARCH_PRCTL_POISON_PATTERN	0xA5F0A5F0A5F0A5F0ULL

struct arch_prctl_post_state {
	unsigned long magic;
	unsigned long addr;
	uint64_t poison_seed;
};

static void sanitise_arch_prctl(struct syscallrecord *rec)
{
	unsigned int i;
	bool safe = false;

	/* The 1-in-16 CMP-hint bypass in handle_arg_op() (generate-args.c)
	 * can return a raw value that skips the curated arch_prctl_codes[]
	 * whitelist; ARCH_SET_FS / ARCH_SET_GS / ARCH_SET_CPUID would then
	 * scribble the child's own FS-base / GS-base / cpuid-fault state and
	 * the next libc call into TLS (%fs:...) would segfault.  Re-roll any
	 * out-of-whitelist code from the safe list. */
	for (i = 0; i < ARRAY_SIZE(arch_prctl_codes); i++) {
		if (arch_prctl_codes[i] == rec->a1) {
			safe = true;
			break;
		}
	}
	if (!safe)
		rec->a1 = arch_prctl_codes[rnd_modulo_u32(ARRAY_SIZE(arch_prctl_codes))];

	switch (rec->a1) {
	case ARCH_GET_FS:
	case ARCH_GET_GS:
	case ARCH_GET_XCOMP_SUPP:
	case ARCH_GET_XCOMP_PERM:
	case ARCH_GET_UNTAG_MASK:
	case ARCH_GET_MAX_TAG_BITS:
	case ARCH_SHSTK_STATUS: {
		struct arch_prctl_post_state *snap;
		void *buf;

		/* Kernel writes a u64 (or smaller) to *addr -- redirect off
		 * shared / heap pages so a sibling cannot see the write. */
		avoid_shared_buffer_out(&rec->a2, sizeof(unsigned long));

		/*
		 * Stamp a fixed poison pattern into the u64 the kernel is
		 * about to fill.  The post handler compares the buffer
		 * byte-for-byte against the same pattern; a match after a
		 * rec->retval == 0 return means the kernel skipped
		 * copy_to_user() entirely -- the getter codes above are
		 * contracted to write a u64 there on success.  Pattern is
		 * a fixed non-zero magic (not rnd_u64()) so the sanitise
		 * pass draws no RNG bytes on this leg: --dry-run output
		 * with a fixed seed stays byte-identical to a build
		 * without this oracle so cross-tree replays and fixed-seed
		 * corpus regeneration are unaffected.  Snapshot rec->a2
		 * into snap so a sibling scribble of the ABI slot between
		 * syscall return and post entry cannot redirect the check.
		 * Gate on range_readable_user() so a writable-pool draw
		 * that avoid_shared_buffer_out() moved to an address no
		 * longer provably mapped does not SIGSEGV the sanitiser
		 * inside poison_output_struct's byte-walk; on skip
		 * poison_seed stays 0 and the post handler no-ops the arm.
		 * Done after avoid_shared_buffer_out() so the poison lands
		 * on the final buffer the kernel will see (the relocation
		 * may have swapped rec->a2 for a fresh page).
		 */
		snap = zmalloc_tracked(sizeof(*snap));
		snap->magic       = ARCH_PRCTL_POST_STATE_MAGIC;
		snap->addr        = rec->a2;
		snap->poison_seed = 0;

		buf = (void *)(unsigned long) rec->a2;
		if (range_readable_user(buf, sizeof(unsigned long)))
			snap->poison_seed =
				poison_output_struct(buf,
						     sizeof(unsigned long),
						     ARCH_PRCTL_POISON_PATTERN);

		post_state_install(rec, snap);
		break;
	}

	case ARCH_REQ_XCOMP_GUEST_PERM:
	case ARCH_REQ_XCOMP_PERM:
		/* arg2 is the xfeature bit number; AMX TILECFG (17) and
		 * TILEDATA (18) are the only values the kernel inspects.
		 * TILEDATA sets a per-task allow-bit -- no architectural
		 * state change until the child actually executes AMX.  The
		 * GUEST variant only touches the guest-permission mask via
		 * KVM's fpu_guest_cfg, so the child's own state is unaffected. */
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

/*
 * Oracle: arch_prctl(GET_*, addr) returns 0 on success and writes an
 * unsigned long (or smaller) to *addr for the seven getter codes gated
 * in sanitise above.  A byte-identical match against the fixed poison
 * pattern after a rec->retval == 0 return means the kernel skipped
 * copy_to_user() entirely; bump the shared
 * post_handler_untouched_out_buf counter.  Non-getter codes install no
 * post_state -- setter arg2 flows in and ARCH_GET_CPUID /
 * ARCH_FORCE_TAGGED_SVA leave arg2 untouched -- so
 * post_state_claim_owned() returns NULL for them and the oracle stays
 * silent on those paths and on every error return.
 *
 * Measure-only: no re-issue, no argument mutation, no oracle output
 * beyond the counter bump.
 */
static void post_arch_prctl(struct syscallrecord *rec)
{
	struct arch_prctl_post_state *snap;

	/*
	 * Canonical shape -> ownership -> magic bracket.  The helper has
	 * already cleared rec->post_state, emitted any outputerr()
	 * diagnostic, and bumped the corruption counter on failure --
	 * callers just early-return on NULL.  This also short-circuits
	 * every non-getter code / ARCH_GET_CPUID call: sanitise did not
	 * install a snap for those, so rec->post_state is NULL and the
	 * shape gate returns immediately.
	 */
	snap = post_state_claim_owned(rec, ARCH_PRCTL_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;

	/*
	 * Untouched-buffer check: arch_prctl returned 0 but the u64 at
	 * *addr still byte-for-byte matches the fixed poison we stamped
	 * at sanitise time -- the kernel never called copy_to_user() at
	 * all.  A poison_seed of 0 is the sanitise-refused-to-stamp
	 * signal (writable-pool draw no longer provably mapped) -- skip
	 * the check so "we could not poison" is not confused with
	 * "kernel did not write".
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct_user_or_skip((void *)(unsigned long) snap->addr,
					     sizeof(unsigned long),
					     snap->poison_seed))
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_arch_prctl = {
	.name = "arch_prctl",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS },
	.argname = { [0] = "code", [1] = "addr" },
	.arg_params[0].list = ARGLIST(arch_prctl_codes),
	.sanitise = sanitise_arch_prctl,
	.post = post_arch_prctl,
	.rettype = RET_BORING,
};
#endif
