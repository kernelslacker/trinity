/*
 * SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)
 */

#define CLOCK_REALTIME                  0
#define CLOCK_MONOTONIC                 1
#define CLOCK_PROCESS_CPUTIME_ID        2
#define CLOCK_THREAD_CPUTIME_ID         3
#define CLOCK_MONOTONIC_RAW             4
#define CLOCK_REALTIME_COARSE           5
#define CLOCK_MONOTONIC_COARSE          6
#define CLOCK_BOOTTIME                  7

#define TFD_CLOEXEC 02000000
#define TFD_NONBLOCK 04000

{
	.name = "timerfd_create",
	.num_args = 2,
	.arg1name = "clockid",
	.arg1type = ARG_LIST,
	.arg1list = {
		.num = 8,
		.values = { CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID,
				CLOCK_MONOTONIC_RAW, CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME },
	},
	.arg2name = "flags",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 2,
		.values = { TFD_NONBLOCK, TFD_CLOEXEC },
	},
},
