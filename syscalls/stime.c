/*
 * SYSCALL_DEFINE1(stime, time_t __user *, tptr)
 */
#include <time.h>
#include "random.h"
#include "rnd.h"
#include "sanitise.h"

static void sanitise_stime(struct syscallrecord *rec)
{
	time_t *t;
	struct timespec snap;

	t = (time_t *) get_writable_address(sizeof(*t));
	if (t == NULL)
		return;

	/*
	 * Bias 70% near-now / 30% random.  Random time_t mostly EPERMs
	 * (CAP_SYS_TIME) before reaching the wall-clock writer, so the
	 * remaining draws are spread between near-now (lets the kernel's
	 * monotonic-step machinery run) and the random tail (keeps the
	 * far-future / negative validators warm).
	 */
	if (rnd_modulo_u32(100) < 70) {
		if (clock_gettime(CLOCK_REALTIME, &snap) == 0)
			*t = snap.tv_sec +
				(time_t) (rnd_modulo_u32(120)) - 60;
		else
			*t = time(NULL) +
				(time_t) (rnd_modulo_u32(120)) - 60;
	} else {
		*t = (time_t) rand32();
	}

	rec->a1 = (unsigned long) t;
}

struct syscallentry syscall_stime = {
	.name = "stime",
	.group = GROUP_TIME,
	.num_args = 1,
	.argname = { [0] = "tptr" },
	.argtype = { [0] = ARG_ADDRESS },
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_stime,
	.rettype = RET_ZERO_SUCCESS,
};
