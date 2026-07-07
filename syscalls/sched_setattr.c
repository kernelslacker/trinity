/*
 * SYSCALL_DEFINE3(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr,
 *		   unsigned int, flags)
 */
#include <linux/sched/types.h>
#include "csfu.h"
#include "deferred-free.h"
#include "kernel/sched_attr.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/sched.h"
/*
 * Pre-ksize ABI floors for the csfu UNDERSIZE bucket.  The kernel
 * accepts a sched_setattr call whose sa->size matches any prior ABI
 * version and zero-pads the remainder.  build_csfu_struct() draws
 * uniformly from this pool for UNDERSIZE; the EXACT bucket already
 * covers sizeof(struct sched_attr), so the current ksize is not
 * repeated here.
 */
static const size_t sched_setattr_known_sizes[] = {
	SCHED_ATTR_SIZE_VER0,
	SCHED_ATTR_SIZE_VER1,
};

static const struct csfu_desc desc_sched_setattr = {
	.name = "sched_attr",
	.ksize = sizeof(struct sched_attr),
	.known_sizes = sched_setattr_known_sizes,
	.n_known_sizes = ARRAY_SIZE(sched_setattr_known_sizes),
};

static void sanitise_sched_setattr(struct syscallrecord *rec)
{
	struct csfu_buf buf = build_csfu_struct(&desc_sched_setattr);
	struct sched_attr *sa = buf.ptr;
	unsigned int roll;

	if (!sa)
		return;

	/*
	 * sa->size is the kernel's ABI version tag; sched_setattr has no
	 * separate usize syscall arg, so the csfu-picked usize is written
	 * here.  That is the whole point of the migration: drive the
	 * kernel's copy_struct_from_user validator across all five bucket
	 * shapes instead of always sending the current-kernel exact size.
	 */
	sa->size = buf.usize;

	/*
	 * Body fill runs across ALL csfu buckets, not just EXACT.  The
	 * kernel-side EINVAL gates (sched_copy_attr size/-E2BIG, then
	 * (int)sched_policy < 0, then ~SCHED_FLAG_ALL inside
	 * __sched_setscheduler) reject every call whose prefix carries an
	 * out-of-range policy or unknown flag bit, regardless of how the
	 * size word and tail bytes are shaped.  Restricting the structured
	 * policy/param fill to EXACT meant UNDERSIZE and OVERSIZE_ZERO --
	 * which both have valid sizes the kernel accepts -- shipped a
	 * permanent zero-body (policy=0, all zeros), so 20% of the bucket
	 * mix only ever exercised SCHED_NORMAL with default params and
	 * never the FIFO/RR/BATCH/IDLE/DEADLINE setscheduler paths.
	 * OVERSIZE_NONZERO and TAIL_MISMATCH still get -E2BIG'd by the
	 * tail-zero check independent of body content, so the body fill is
	 * harmless on those paths.
	 */

	roll = rnd_modulo_u32(100);

	if (roll < 70) {
		/* Valid shape bucket: policy + matching params. */
		switch (rnd_modulo_u32(6)) {
		case 0: /* SCHED_OTHER */
			sa->sched_policy = 0;
			sa->sched_nice = (rnd_modulo_u32(40)) - 20;	/* -20 to 19 */
			break;
		case 1: /* SCHED_FIFO */
			sa->sched_policy = 1;
			sa->sched_priority = 1 + (rnd_modulo_u32(99));
			break;
		case 2: /* SCHED_RR */
			sa->sched_policy = 2;
			sa->sched_priority = 1 + (rnd_modulo_u32(99));
			break;
		case 3: /* SCHED_BATCH */
			sa->sched_policy = 3;
			sa->sched_nice = (rnd_modulo_u32(40)) - 20;
			break;
		case 4: /* SCHED_IDLE */
			sa->sched_policy = SCHED_IDLE;
			break;
		default: /* SCHED_DEADLINE */
			sa->sched_policy = SCHED_DEADLINE;
			sa->sched_runtime  = 1000000ULL * (1 + (rnd_modulo_u32(10)));	/* 1-10ms */
			sa->sched_deadline = sa->sched_runtime * (1 + (rnd_modulo_u32(5)));
			sa->sched_period   = sa->sched_deadline * (1 + (rnd_modulo_u32(3)));
			break;
		}
	} else if (roll < 90) {
		/*
		 * Invalid-one-field bucket: real policy, one field outside
		 * legality.  Keeps the per-policy validation paths warm
		 * without the policy field itself being random garbage.
		 */
		switch (rnd_modulo_u32(6)) {
		case 0: /* SCHED_OTHER with non-zero priority */
			sa->sched_policy = 0;
			sa->sched_priority = 1 + rnd_modulo_u32(99);
			break;
		case 1: /* SCHED_FIFO with priority == 0 or > 99 */
			sa->sched_policy = 1;
			sa->sched_priority = RAND_BOOL() ? 0 :
				(100 + rnd_modulo_u32(100));
			break;
		case 2: /* SCHED_RR with priority == 0 or > 99 */
			sa->sched_policy = 2;
			sa->sched_priority = RAND_BOOL() ? 0 :
				(100 + rnd_modulo_u32(100));
			break;
		case 3: /* SCHED_BATCH with nice outside [-20, 19] */
			sa->sched_policy = 3;
			sa->sched_nice = 50;
			break;
		case 4: /* SCHED_IDLE with non-zero priority */
			sa->sched_policy = SCHED_IDLE;
			sa->sched_priority = 1 + rnd_modulo_u32(99);
			break;
		default: /* SCHED_DEADLINE with deadline < runtime */
			sa->sched_policy = SCHED_DEADLINE;
			sa->sched_runtime  = 10000000ULL;
			sa->sched_deadline = 1000000ULL;
			sa->sched_period   = 100000000ULL;
			break;
		}
	} else {
		/*
		 * 10%: fully random payload.  Hits the long-tail combinations
		 * the structured buckets above never produce.
		 */
		sa->sched_policy = rnd_u32() & 0xff;
		sa->sched_priority = rnd_u32() & 0xff;
		sa->sched_nice = (int) rnd_modulo_u32(80) - 40;
		sa->sched_runtime  = rnd_u64();
		sa->sched_deadline = rnd_u64();
		sa->sched_period   = rnd_u64();
		sa->sched_flags    = rnd_u64();
		goto submit;
	}

	/*
	 * sched_flags fuzz, scoped to the valid / one-field-invalid paths
	 * (the fully-random arm above already splatted its own rnd_u64()).
	 * __sched_setscheduler rejects unknown bits with EINVAL via the
	 * (~SCHED_FLAG_ALL) mask, so bias toward an always-safe subset:
	 * RESET_ON_FORK costs nothing per-policy, RECLAIM is only honoured
	 * for SCHED_DEADLINE but the gate doesn't reject it elsewhere.
	 * UTIL_CLAMP_MIN/MAX additionally require buf.usize >= VER1 at
	 * sched_copy_attr time, so gate them on the csfu-picked size.  A
	 * small unknown-bit roll keeps the reject path warm.
	 */
	if (rnd_modulo_u32(100) < 85) {
		if (RAND_BOOL())
			sa->sched_flags |= SCHED_FLAG_RESET_ON_FORK;
		if (sa->sched_policy == SCHED_DEADLINE && RAND_BOOL())
			sa->sched_flags |= SCHED_FLAG_RECLAIM;
		if (buf.usize >= SCHED_ATTR_SIZE_VER1 && ONE_IN(8))
			sa->sched_flags |= SCHED_FLAG_UTIL_CLAMP_MIN |
					   SCHED_FLAG_UTIL_CLAMP_MAX;
	} else {
		sa->sched_flags |= (1ULL << (rnd_modulo_u32(56) + 8));
	}

submit:
	rec->a2 = (unsigned long) sa;
	avoid_shared_buffer_inout(&rec->a2, buf.usize);
	rec->a3 = 0;	/* flags must be zero */

	/* Target self (0) most of the time.  ARG_PID overwhelmingly draws
	 * pool/random pids the kernel EPERMs without CAP_SYS_NICE, so the
	 * set never reaches the legality validator -- bias toward the one
	 * pid where the set actually lands. */
	if (rnd_modulo_u32(100) < 70)
		rec->a1 = 0;

	/*
	 * Stash the csfu buffer in rec->post_state so the unconditional
	 * .cleanup hook frees it.  sched_setattr has no .post handler, so
	 * this was the only release point; post_state is private to the
	 * cleanup path and less stomp-prone than rec->a2.
	 */
	rec->post_state = (unsigned long) sa;
}

static void cleanup_sched_setattr(struct syscallrecord *rec)
{
	cleanup_release_post_state(rec);
}

struct syscallentry syscall_sched_setattr = {
	.name = "sched_setattr",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_STRUCT_PTR_IN },
	.argname = { [0] = "pid", [1] = "uattr", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_sched_setattr,
	.cleanup = cleanup_sched_setattr,
};
