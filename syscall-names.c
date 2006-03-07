/* Syscalls from arch/i386/kernel/entry.S as of 2.6test5 */

char *syscall_names[] = {
	"restart_syscall",	/* 0 - old "setup()" system call, used for restarting */
	"exit",
	"fork",
	"read",
	"write",
	"open",		/* 5 */
	"close",
	"waitpid",
	"creat",
	"link",
	"unlink",	/* 10 */
	"execve",
	"chdir",
	"time",
	"mknod",
	"chmod",		/* 15 */
	"lchown16",
	"ni_syscall (old break syscall holder)",
	"stat",
	"lseek",
	"getpid",	/* 20 */
	"mount",
	"oldumount",
	"setuid16",
	"getuid16",
	"stime",		/* 25 */
	"ptrace",
	"alarm",
	"fstat",
	"pause",
	"utime",		/* 30 */
	"ni_syscall (old stty syscall holder)",
	"ni_syscall (old gtty syscall holder",
	"access",
	"nice",
	"ni_syscall (old ftime syscall holder)",	/* 35 */
	"sync",
	"kill",
	"rename",
	"mkdir",
	"rmdir",		/* 40 */
	"dup",
	"pipe",
	"times",
	"ni_syscall (old prof syscall holder)",
	"brk",		/* 45 */
	"setgid16",
	"getgid16",
	"signal",
	"geteuid16",
	"getegid16",	/* 50 */
	"acct",
	"umount (recycled never used phys())",
	"ni_syscall (old lock syscall holder",
	"ioctl",
	"fcntl",		/* 55 */
	"ni_syscall (old mpx syscall holder)",
	"setpgid",
	"ni_syscall (old ulimit syscall holder)",
	"olduname",
	"umask",		/* 60 */
	"chroot",
	"ustat",
	"dup2",
	"getppid",
	"getpgrp",	/* 65 */
	"setsid",
	"sigaction",
	"sgetmask",
	"ssetmask",
	"setreuid16",	/* 70 */
	"setregid16",
	"sigsuspend",
	"sigpending",
	"sethostname",
	"setrlimit",	/* 75 */
	"old_getrlimit",
	"getrusage",
	"gettimeofday",
	"settimeofday",
	"getgroups16",	/* 80 */
	"setgroups16",
	"select",
	"symlink",
	"lstat",
	"readlink",	/* 85 */
	"uselib",
	"swapon",
	"reboot",
	"readdir",
	"mmap",		/* 90 */
	"munmap",
	"truncate",
	"ftruncate",
	"fchmod",
	"fchown16",	/* 95 */
	"getpriority",
	"setpriority",
	"ni_syscall (old profil syscall holder)",
	"statfs",
	"fstatfs",	/* 100 */
	"ioperm",
	"socketcall",
	"syslog",
	"setitimer",
	"getitimer",	/* 105 */
	"newstat",
	"newlstat",
	"newfstat",
	"uname",
	"iopl",		/* 110 */
	"vhangup",
	"ni_syscall (old 'idle' system call)",
	"vm86old",
	"wait4",
	"swapoff",	/* 115 */
	"sysinfo",
	"ipc",
	"fsync",
	"sigreturn",
	"clone",		/* 120 */
	"setdomainname",
	"newuname",
	"modify_ldt",
	"adjtimex",
	"mprotect",	/* 125 */
	"sigprocmask",
	"ni_syscall (old create_module)", 
	"init_module",
	"delete_module",
	"ni_syscall	(old get_kernel_syms)",	/* 130 */
	"quotactl",
	"getpgid",
	"fchdir",
	"bdflush",
	"sysfs",		/* 135 */
	"personality",
	"ni_syscall	(reserved for afs_syscall)",
	"setfsuid16",
	"setfsgid16",
	"llseek",	/* 140 */
	"getdents",
	"select",
	"flock",
	"msync",
	"readv",	/* 145 */
	"writev",
	"getsid",
	"fdatasync",
	"sysctl",
	"mlock",		/* 150 */
	"munlock",
	"mlockall",
	"munlockall",
	"sched_setparam",
	"sched_getparam",   /* 155 */
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_yield",
	"sched_get_priority_max",
	"sched_get_priority_min",  /* 160 */
	"sched_rr_get_interval",
	"nanosleep",
	"mremap",
	"setresuid16",
	"getresuid16",	/* 165 */
	"vm86",
	"ni_syscall (Old sys_query_module)",
	"poll",
	"nfsservctl",
	"setresgid16",	/* 170 */
	"getresgid16",
	"prctl",
	"rt_sigreturn",
	"rt_sigaction",
	"rt_sigprocmask",	/* 175 */
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"pread64",	/* 180 */
	"pwrite64",
	"chown16",
	"getcwd",
	"capget",
	"capset",	/* 185 */
	"sigaltstack",
	"sendfile",
	"ni_syscall	(reserved for streams1)",
	"ni_syscall	(reserved for streams2)",
	"vfork",		/* 190 */
	"getrlimit",
	"mmap2",
	"truncate64",
	"ftruncate64",
	"stat64",	/* 195 */
	"lstat64",
	"fstat64",
	"lchown",
	"getuid",
	"getgid",	/* 200 */
	"geteuid",
	"getegid",
	"setreuid",
	"setregid",
	"getgroups",	/* 205 */
	"setgroups",
	"fchown",
	"setresuid",
	"getresuid",
	"setresgid",	/* 210 */
	"getresgid",
	"chown",
	"setuid",
	"setgid",
	"setfsuid",	/* 215 */
	"setfsgid",
	"pivot_root",
	"mincore",
	"madvise",
	"getdents64",	/* 220 */
	"fcntl64",
	"ni_syscall	(reserved for TUX)",
	"ni_syscall (223)",
	"gettid",
	"readahead",	/* 225 */
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",
	"lgetxattr",	/* 230 */
	"fgetxattr",
	"listxattr",
	"llistxattr",
	"flistxattr",
	"removexattr",	/* 235 */
	"lremovexattr",
	"fremovexattr",
	"tkill",
	"sendfile64",
	"futex",		/* 240 */
	"sched_setaffinity",
	"sched_getaffinity",
	"set_thread_area",
	"get_thread_area",
	"io_setup",	/* 245 */
	"io_destroy",
	"io_getevents",
	"io_submit",
	"io_cancel",
	"fadvise64",	/* 250 */
	"ni_syscall (251)",
	"exit_group",
	"lookup_dcookie",
	"epoll_create",
	"epoll_ctl",	/* 255 */
	"epoll_wait",
	"remap_file_pages",
	"set_tid_address",
	"timer_create",
	"timer_settime",		/* 260 */
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",
	"clock_settime",
	"clock_gettime",		/* 265 */
	"clock_getres",
	"clock_nanosleep",
	"statfs64",
	"fstatfs64",	
	"tgkill",	/* 270 */
	"utimes",
	"fadvise64_64",
	"ni_syscall (reserved for vserver)"
};

