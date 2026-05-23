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
	cpu_set_t *mask;
	unsigned int online = cached_online_cpus();
	unsigned int i, bits, idx;
	unsigned int roll;

	mask = (cpu_set_t *) get_writable_struct(sizeof(*mask));
	if (!mask)
		return;
	CPU_ZERO(mask);

	/*
	 * Mask shape buckets, weighted toward shapes the kernel does not
	 * silently reject: 30% single online CPU, 25% sparse subset,
	 * 20% all-online, 15% offline bits set above num_online_cpus
	 * (kernel silently strips -- keeps the strip path warm), 10%
	 * empty (must EINVAL).  CPU_SETSIZE-wide random draws otherwise
	 * almost always have no bits in cpu_online_mask.
	 */
	roll = rnd_modulo_u32(100);

	if (roll < 30) {
		CPU_SET(rnd_modulo_u32(online), mask);
	} else if (roll < 55) {
		bits = 1 + rnd_modulo_u32(online);
		for (i = 0; i < bits; i++) {
			idx = rnd_modulo_u32(online);
			CPU_SET(idx, mask);
		}
	} else if (roll < 75) {
		for (i = 0; i < online; i++)
			CPU_SET(i, mask);
	} else if (roll < 90) {
		if (online < CPU_SETSIZE) {
			unsigned int span = CPU_SETSIZE - online;
			bits = 1 + rnd_modulo_u32(span);
			for (i = 0; i < bits; i++) {
				idx = online +
					rnd_modulo_u32(span);
				CPU_SET(idx, mask);
			}
		} else {
			CPU_SET(rnd_modulo_u32(CPU_SETSIZE), mask);
		}
	}
	/* else: empty mask -- CPU_ZERO already done above. */

	rec->a2 = pick_affinity_len();
	rec->a3 = (unsigned long) mask;
}

struct syscallentry syscall_sched_setaffinity = {
	.name = "sched_setaffinity",
	.rettype = RET_ZERO_SUCCESS,
	.group = GROUP_SCHED,
	.num_args = 3,
	.argtype = { [0] = ARG_PID },
	.argname = { [0] = "pid", [1] = "len", [2] = "user_mask_ptr" },
	.sanitise = sanitise_sched_setaffinity,
};
