/*
 * SYSCALL_DEFINE3(fcntl, unsigned int, fd, unsigned int, cmd, unsigned long, arg)
 */

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ    (F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ    (F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)
#endif

#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#endif

#ifndef F_GETOWN_EX
#define F_GETOWN_EX 16
#endif

{
	.name = "fcntl",
	.num_args = 3,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "cmd",
	.arg2type = ARG_LIST,
	.arg2list = {
		.num = 23,
		.values = { F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_SETFD, F_GETFL, F_SETFL, F_GETLK, F_SETLK,
		  F_SETLKW, F_GETOWN, F_SETOWN, F_GETOWN_EX, F_SETOWN_EX, F_GETSIG, F_SETSIG, F_GETLEASE,
		  F_SETLEASE, F_NOTIFY, F_SETPIPE_SZ, F_GETPIPE_SZ, F_GETLK64, F_SETLK64, F_SETLKW64 },
	},
	.arg3name = "arg",
},
