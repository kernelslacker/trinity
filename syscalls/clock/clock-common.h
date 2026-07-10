#ifndef _TRINITY_SYSCALLS_CLOCK_COMMON_H_
#define _TRINITY_SYSCALLS_CLOCK_COMMON_H_

#include <sys/types.h>
#include <time.h>

#include "pids.h"
#include "random.h"
#include "rnd.h"
#include "utils.h"

#include "kernel/time.h"
/*
 * Local copies of the kernel's POSIX CPU clock encoding from
 * include/linux/posix-timers.h.  Not in UAPI but the encoding has been
 * stable since the syscalls landed.
 */
#ifndef CLOCKFD
#define CLOCKFD				3
#define CPUCLOCK_PERTHREAD_MASK		4
#define CPUCLOCK_PROF			0
#define CPUCLOCK_VIRT			1
#define CPUCLOCK_SCHED			2
#define MAKE_PROCESS_CPUCLOCK(pid, clk)	\
	((~(clockid_t)(pid) << 3) | (clockid_t)(clk))
#define MAKE_THREAD_CPUCLOCK(tid, clk)	\
	MAKE_PROCESS_CPUCLOCK((tid), (clk) | CPUCLOCK_PERTHREAD_MASK)
#define FD_TO_CLOCKID(fd)		\
	((~(clockid_t)(fd) << 3) | CLOCKFD)
#endif

/*
 * CLOCK_AUX is a v7.1 uapi clockid for auxiliary clocks. Older build
 * hosts' <linux/time.h> may not have it; provide a compat shim so the
 * value is always available in pick_clockid_common[] below.
 */
#ifndef CLOCK_AUX
#define CLOCK_AUX			16
#endif

static const unsigned long pick_clockid_common[] = {
	CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_TAI,
	CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE,
	CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM,
	CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
	CLOCK_AUX,
};

static const int pick_clockid_cpuwhich[] = {
	CPUCLOCK_PROF, CPUCLOCK_VIRT, CPUCLOCK_SCHED,
};

/*
 * Five-bucket clockid distribution: common (50%), process-CPU (20%),
 * self-CPU thread-or-process (10%), dynamic FD (10%), invalid (10%).
 * Random integer clockids almost never land on the CPU-clock or
 * dynamic-clock dispatch paths, so bias deliberately keeps those warm.
 */
static inline unsigned long pick_clockid(void)
{
	unsigned int roll = rnd_modulo_u32(100);
	int w;
	pid_t pid;

	if (roll < 50)
		return pick_clockid_common[rnd_modulo_u32(
			ARRAY_SIZE(pick_clockid_common))];

	w = pick_clockid_cpuwhich[rnd_modulo_u32(
		ARRAY_SIZE(pick_clockid_cpuwhich))];

	if (roll < 70)
		return MAKE_PROCESS_CPUCLOCK((pid_t) get_pid(), w);

	if (roll < 80) {
		pid = mypid();
		if (RAND_BOOL())
			return MAKE_THREAD_CPUCLOCK(pid, w);
		return MAKE_PROCESS_CPUCLOCK(pid, w);
	}

	if (roll < 90)
		return FD_TO_CLOCKID(rnd_modulo_u32(1024));

	/* invalid: large unaligned value the kernel cannot dispatch */
	return (unsigned long) (rnd_u32() | (1u << 20));
}

#endif
