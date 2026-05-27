/*
 * SYSCALL_DEFINE3(sched_setattr, pid_t, pid, struct sched_attr __user *, uattr,
 *		   unsigned int, flags)
 */
#include <linux/sched/types.h>
#include "csfu.h"
#include "deferred-free.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "compat.h"

#ifndef SCHED_ATTR_SIZE_VER0
#define SCHED_ATTR_SIZE_VER0 48
#endif
#ifndef SCHED_ATTR_SIZE_VER1
#define SCHED_ATTR_SIZE_VER1 56
#endif

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
	 * Non-EXACT buckets only care about size -- OVERSIZE_NONZERO and
	 * TAIL_MISMATCH get rejected by the validator before any body
	 * field is inspected, and UNDERSIZE / OVERSIZE_ZERO get a
	 * zero-filled body that the per-policy logic below would just
	 * overwrite with throwaway values.  Skip the structured fill on
	 * those paths; the zmalloc_tracked() buffer is already zeroed.
	 */
	if (buf.bucket != CSFU_BUCKET_EXACT)
		goto submit;

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
	}

submit:
	rec->a2 = (unsigned long) sa;
	avoid_shared_buffer_inout(&rec->a2, sizeof(struct sched_attr));
	rec->a3 = 0;	/* flags must be zero */

	/* Target self (0) most of the time.  ARG_PID overwhelmingly draws
	 * pool/random pids the kernel EPERMs without CAP_SYS_NICE, so the
	 * set never reaches the legality validator -- bias toward the one
	 * pid where the set actually lands. */
	if (rnd_modulo_u32(100) < 70)
		rec->a1 = 0;

	/*
	 * Hand the csfu buffer to the deferred-free queue at sanitise
	 * time -- sched_setattr has no post handler, so this is the only
	 * place the zmalloc_tracked() allocation gets released.
	 */
	deferred_free_enqueue(sa);
}

struct syscallentry syscall_sched_setattr = {
	.name = "sched_setattr",
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_STRUCT_PTR_IN },
	.argname = { [0] = "pid", [1] = "uattr", [2] = "flags" },
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_sched_setattr,
};
