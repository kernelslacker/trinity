/*
 * SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid, unsigned int, len,
	 unsigned long __user *, user_mask_ptr)
 */
#include <sched.h>
#include <unistd.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

/*
 * Online-CPU count snapshotted on first use.  The kernel rejects
 * sched_setaffinity masks with no bits in cpu_online_mask, so a
 * random CPU_SETSIZE-wide draw misses every legality test path
 * unless we constrain it to the real online range.
 */
static unsigned int cached_online_cpus(void)
{
	static unsigned int n;
	long v;

	if (n != 0)
		return n;

	v = sysconf(_SC_NPROCESSORS_ONLN);
	if (v <= 0)
		v = 1;
	if (v > CPU_SETSIZE)
		v = CPU_SETSIZE;
	n = (unsigned int) v;
	return n;
}

/*
 * Pick a setaffinity len argument biased toward the legal cpumask
 * sizes the kernel actually accepts.  ~70% land on the real
 * cpumask_size() round-up or the canonical sizeof(cpu_set_t); ~20%
 * use a generously oversized buffer (the kernel tolerates extras);
 * ~10% are deliberately too small for the validation path.
 */
static unsigned long pick_affinity_len(void)
{
	unsigned int roll = rnd_modulo_u32(100);
	unsigned int aligned;

	if (roll < 70) {
		if (RAND_BOOL())
			return sizeof(cpu_set_t);
		aligned = (cached_online_cpus() + 7) / 8;
		aligned = (aligned + sizeof(long) - 1) &
			~(sizeof(long) - 1);
		if (aligned == 0)
			aligned = sizeof(long);
		return aligned;
	}

	if (roll < 90)
		return sizeof(cpu_set_t) * 2;

	/* 10%: too-small */
	return 1 + rnd_modulo_u32(sizeof(long));
}

static void sanitise_sched_setaffinity(struct syscallrecord *rec)
{
	rec->a2 = pick_affinity_len();
}

struct syscallentry syscall_sched_setaffinity = {
	.name = "sched_setaffinity",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID, [1] = ARG_LEN, [2] = ARG_CPUMASK },
	.argname = { [0] = "pid", [1] = "len", [2] = "user_mask_ptr" },
	.sanitise = sanitise_sched_setaffinity,
};
