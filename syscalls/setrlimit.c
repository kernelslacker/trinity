/*
 * SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
 */
#include <sys/resource.h>
#include "arch.h"
#include "random.h"
#include "rlimit-safe.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

#include "kernel/resource.h"
static unsigned long rlimit_resources[] = {
	RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK,
	RLIMIT_CORE, RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE,
	RLIMIT_MEMLOCK, RLIMIT_AS, RLIMIT_LOCKS, RLIMIT_SIGPENDING,
	RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_RTPRIO,
#ifdef RLIMIT_RTTIME
	RLIMIT_RTTIME,
#endif
};

static rlim_t random_rlim(void)
{
	switch (rnd_modulo_u32(5)) {
	case 0: return RLIM_INFINITY;
	case 1: return 0;
	case 2: return 1 + (rnd_modulo_u32(1024));
	case 3: return (rlim_t) page_size * (1 + (rnd_modulo_u32(256)));
	default: return rand32();
	}
}

/* Fill struct rlimit with interesting boundary values. */
static void sanitise_setrlimit(struct syscallrecord *rec)
{
	struct rlimit *rlim;

	rlim = (struct rlimit *) get_writable_address(sizeof(*rlim));
	if (rlim == NULL)
		return;

	/*
	 * Self-poison guard.  setrlimit has no pid argument: the call
	 * always lands on the calling task, which in trinity is always
	 * a harness-owned process.  Lowering one of CPU / NOFILE / AS /
	 * DATA / STACK / RSS / MEMLOCK with the {0,0} or single-page
	 * entries the safe dictionary draws (see prlimit64.c rationale)
	 * is kernel-legal but harness-lethal: deferred_free's mprotect-RW
	 * ENOMEMs, heap_bounds_init's /proc/self/maps open hits EMFILE,
	 * and a CPU {0,0} hard cap arms update_rlimit_cpu() for an
	 * immediate posix-cpu-timer SIGKILL.  Re-roll the resource to a
	 * non-fragile one before the bucket decides cur/max, keeping the
	 * full value range against FSIZE / CORE / NPROC / LOCKS /
	 * SIGPENDING / MSGQUEUE / NICE / RTPRIO / RTTIME.  prlimit64
	 * preserves full-range fragile-resource coverage (incl. CPU) via
	 * its "random nearby pid" bucket; setrlimit has no equivalent
	 * escape hatch because the target is always us.
	 */
	if (resource_is_fragile(rec->a1))
		rec->a1 = pick_nonfragile_rlimit_resource(
				rlimit_resources,
				ARRAY_SIZE(rlimit_resources));

	/*
	 * Per-resource safe-limit bias (see prlimit64.c for the full
	 * rationale).  Bucket distribution:
	 *
	 *   ~70% safe dictionary draw against the framework-picked resource.
	 *   ~20% real resource + random values to keep the cur<=max /
	 *        privileged-max validation path warm.
	 *   ~10% pure-random resource and values for the long tail.
	 *
	 * Bucket-7/9 re-pick the resource; gate those picks through the
	 * harness-fragile filter too so a re-roll does not undo the
	 * self-poison guard above.  rand32() in bucket 9 is replaced by
	 * a non-fragile pick because, unlike prlimit64's "random nearby
	 * pid" bucket, every setrlimit call is self-targeted.
	 */
	{
		unsigned int bucket = rnd_modulo_u32(10);
		unsigned long long safe_cur, safe_max;

		if (bucket < 7 &&
		    rlimit_pick_safe_pair((unsigned int) rec->a1,
					  &safe_cur, &safe_max) == 0) {
			rlim->rlim_cur = (rlim_t) safe_cur;
			rlim->rlim_max = (rlim_t) safe_max;
		} else {
			if (bucket >= 7)
				rec->a1 = pick_nonfragile_rlimit_resource(
						rlimit_resources,
						ARRAY_SIZE(rlimit_resources));

			rlim->rlim_cur = random_rlim();
			rlim->rlim_max = random_rlim();

			/* Half the time, enforce cur <= max for valid calls. */
			if (RAND_BOOL() && rlim->rlim_cur > rlim->rlim_max)
				rlim->rlim_cur = rlim->rlim_max;
		}
	}

	rec->a2 = (unsigned long) rlim;
	avoid_shared_buffer_inout(&rec->a2, sizeof(*rlim));
}

struct syscallentry syscall_setrlimit = {
	.name = "setrlimit",
	.num_args = 2,
	.argtype = { [0] = ARG_OP, [1] = ARG_ADDRESS },
	.argname = { [0] = "resource", [1] = "rlim" },
	.arg_params[0].list = ARGLIST(rlimit_resources),
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_PROCESS,
	.sanitise = sanitise_setrlimit,
};
