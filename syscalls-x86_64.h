/* Syscalls from arch/x86/include/asm/unistd_64.h as of 2.6.35 */

#include "scrashme.h"
#include "sanitise.h"

#define NR_SYSCALLS 302

struct syscalltable syscalls_x86_64[NR_SYSCALLS+1] = {
	{
		.name = "read",
		.num_args = 3,
		.sanitise = sanitise_read,
	},{
		.name = "write",
		.num_args = 3,
		.sanitise = sanitise_write,
	},{
		.name = "open",
		.num_args = 3,
	},{
		.name = "close",
		.num_args = 1,
		.sanitise = sanitise_close,
	},{
		.name = "newstat",
		.num_args = 2,
	},{
		.name = "newfstat",
		.num_args = 2,
		.sanitise = sanitise_newfstat,
	},{
		.name = "newlstat",
		.num_args = 2,
	},{
		.name = "poll",
		.num_args = 3,
	},{
		.name = "lseek",
		.num_args = 3,
		.sanitise = sanitise_lseek,
	},{
		.name = "mmap",
		.num_args = 6,
		.sanitise = sanitise_mmap,
	},{
		.name = "mprotect",
		.num_args = 3,
		.sanitise = sanitise_mprotect,
	},{
		.name = "munmap",
		.num_args = 2,
	},{
		.name = "brk",
		.num_args = 1,
	},{
		.name = "rt_sigaction",
		.num_args = 4,
		.sanitise = sanitise_rt_sigaction,
	},{
		.name = "rt_sigprocmask",
		.num_args = 4,
		.sanitise = sanitise_rt_sigprocmask,
	},{
		.name = "rt_sigreturn",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},{
		.name = "ioctl",
		.num_args = 3,
		.sanitise = sanitise_ioctl,
	},{
		.name = "pread64",
		.num_args = 4,
		.sanitise = sanitise_pread64,
	},{
		.name = "pwrite64",
		.num_args = 4,
		.sanitise = sanitise_pwrite64,
	},{
		.name = "readv",
		.num_args = 3,
		.sanitise = sanitise_readv,
	},{
		.name = "writev",
		.num_args = 3,
		.sanitise = sanitise_writev,
	},{
		.name = "access",
		.num_args = 2,
	},{
		.name = "pipe",
		.num_args = 1,
	},{
		.name = "select",
		.num_args = 5,
		.flags = AVOID_SYSCALL,
	},{
		.name = "sched_yield",
		.num_args = 0,
	},{
		.name = "mremap",
		.num_args = 5,
		.sanitise = sanitise_mremap,
	},{
		.name = "msync",
		.num_args = 3,
	},{
		.name = "mincore",
		.num_args = 3,
	},{
		.name = "madvise",
		.num_args = 3,
	},{
		.name = "shmget",
		.num_args = 3,
	},{
		.name = "shmat",
		.num_args = 3,
	},{
		.name = "shmctl",
		.num_args = 3,
	},{
		.name = "dup",
		.num_args = 1,
	},{
		.name = "dup2",
		.num_args = 2,
	},{
		.name = "pause",
		.num_args = 0,
		.flags = AVOID_SYSCALL,
	},{
		.name = "nanosleep",
		.num_args = 2,
	},{
		.name = "getitimer",
		.num_args = 2,
	},{
		.name = "alarm",
		.num_args = 1,
	},{
		.name = "setitimer",
		.num_args = 3,
	},{
		.name = "getpid",
		.num_args = 0,
	},{
		.name = "sendfile",
		.num_args = 4,
	},{
		.name = "socket",
		.num_args = 3,
	},{
		.name = "connect",
		.num_args = 3,
	},{
		.name = "accept",
		.num_args = 3,
	},{
		.name = "sendto",
		.num_args = 6,
		.sanitise = sanitise_sendto,
	},{
		.name = "recvfrom",
		.num_args = 6,
	},{
		.name = "sendmsg",
		.num_args = 3,
	},{
		.name = "recvmsg",
		.num_args = 3,
	},{
		.name = "shutdown",
		.num_args = 2,
	},{
		.name = "bind",
		.num_args = 3,
	},{
		.name = "listen",
		.num_args = 2,
	},{
		.name = "getsockname",
		.num_args = 3,
	},{
		.name = "getpeername",
		.num_args = 3,
	},{
		.name = "socketpair",
		.num_args = 4,
	},{
		.name = "setsockopt",
		.num_args = 5,
	},{
		.name = "getsockopt",
		.num_args = 5,
	},{
		.name = "clone",
		.num_args = 5,
		.flags = AVOID_SYSCALL,
	},{
		.name = "fork",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},{
		.name = "vfork",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},{
		.name = "execve",
		.num_args = 4,
	},{
		.name = "exit",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},{
		.name = "wait4",
		.num_args = 4,
	},{
		.name = "kill",
		.num_args = 2,
	},{
		.name = "uname",
		.num_args = 1,
	},{
		.name = "semget",
		.num_args = 3,
	},{
		.name = "semop",
		.num_args = 3,
	},{
		.name = "semctl",
		.num_args = 4,
	},{
		.name = "shmdt",
		.num_args = 1,
	},{
		.name = "msgget",
		.num_args = 2,
	},{
		.name = "msgsnd",
		.num_args = 4,
	},{
		.name = "msgrcv",
		.num_args = 5,
	},{
		.name = "msgctl",
		.num_args = 3,
	},{
		.name = "fcntl",
		.num_args = 3,
	},{
		.name = "flock",
		.num_args = 2,
	},{
		.name = "fsync",
		.num_args = 1,
	},{
		.name = "fdatasync",
		.num_args = 1,
	},{
		.name = "truncate",
		.num_args = 2,
	},{
		.name = "ftruncate",
		.num_args = 2,
	},{
		.name = "getdents",
		.num_args = 3,
	},{
		.name = "getcwd",
		.num_args = 2,
	},{
		.name = "chdir",
		.num_args = 1,
	},{
		.name = "fchdir",
		.num_args = 1,
	},{
		.name = "rename",
		.num_args = 2,
	},{
		.name = "mkdir",
		.num_args = 2,
	},{
		.name =	 "rmdir",
		.num_args = 1,
	},{
		.name = "creat",
		.num_args = 2,
	},{
		.name = "link",
		.num_args = 2,
	},{
		.name = "unlink",
		.num_args = 1,
	},{
		.name = "symlink",
		.num_args = 2,
	},{
		.name = "readlink",
		.num_args = 3,
	},{
		.name = "chmod",
		.num_args = 2,
	},{
		.name = "fchmod",
		.num_args = 2,
	},{
		.name = "chown",
		.num_args = 3,
	},{
		.name = "fchown",
		.num_args = 3,
	},{
		.name = "lchown",
		.num_args = 3,
	},{
		.name = "umask",
		.num_args = 1,
	},{
		.name = "gettimeofday",
		.num_args = 2,
	},{
		.name = "getrlimit",
		.num_args = 2,
	},{
		.name = "getrusage",
		.num_args = 2,
	},{
		.name = "sysinfo",
		.num_args = 1,
	},{
		.name = "times",
		.num_args = 1,
	},{
		.name = "ptrace",
		.num_args = 4,
	},{
		.name = "getuid",
		.num_args = 0,
	},{
		.name = "syslog",
		.num_args = 3,
	},{
		.name = "getgid",
		.num_args = 0,
	},{
		.name = "setuid",
		.num_args = 1,
	},{
		.name = "setgid",
		.num_args = 1,
	},{
		.name = "geteuid",
		.num_args = 0,
	},{
		.name = "getegid",
		.num_args = 0,
	},{
		.name = "setpgid",
		.num_args = 2,
	},{
		.name = "getppid",
		.num_args = 0,
	},{
		.name = "getpgrp",
		.num_args = 0,
	},{
		.name = "setsid",
		.num_args = 0,
	},{
		.name = "setreuid",
		.num_args = 2,
	},{
		.name = "setregid",
		.num_args = 2,
	},{
		.name = "getgroups",
		.num_args = 2,
	},{
		.name = "setgroups",
		.num_args = 2,
	},{
		.name = "setresuid",
		.num_args = 3,
	},{
		.name = "getresuid",
		.num_args = 3,
	},{
		.name = "setresgid",
		.num_args = 3,
	},{
		.name = "getresgid",
		.num_args = 3,
	},{
		.name = "getpgid",
		.num_args = 1,
	},{
		.name = "setfsuid",
		.num_args = 1,
	},{
		.name = "setfsgid",
		.num_args = 1,
	},{
		.name = "getsid",
		.num_args = 1,
	},{
		.name = "capget",
		.num_args = 2,
	},{
		.name = "capset",
		.num_args = 2,
	},{
		.name = "rt_sigpending",
		.num_args = 2,
	},{
		.name = "rt_sigtimedwait",
		.num_args = 4,
	},{
		.name = "rt_sigqueueinfo",
		.num_args = 3,
	},{
		.name = "rt_sigsuspend",
		.num_args = 2,
	},{
		.name = "sigaltstack",
		.num_args = 3,
	},{
		.name = "utime",
		.num_args = 2,
	},{
		.name = "mknod",
		.num_args = 3,
	},{
		.name = "ni_syscall (uselib)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "personality",
		.num_args = 1,
	},{
		.name = "ustat",
		.num_args = 2,
	},{
		.name = "statfs",
		.num_args = 2,
	},{
		.name = "fstatfs",
		.num_args = 2,
	},{
		.name = "sysfs",
		.num_args = 3,
	},{
		.name = "getpriority",
		.num_args = 2,
	},{
		.name = "setpriority",
		.num_args = 3,
	},{
		.name = "sched_setparam",
		.num_args = 2,
	},{
		.name = "sched_getparam",
		.num_args = 2,
	},{
		.name = "sched_setscheduler",
		.num_args = 3,
	},{
		.name = "sched_getscheduler",
		.num_args = 1,
	},{
		.name = "sched_get_priority_max",
		.num_args = 1,
	},{
		.name = "sched_get_priority_min",
		.num_args = 1,
	},{
		.name = "sched_rr_get_interval",
		.num_args = 2,
	},{
		.name = "mlock",
		.num_args = 2,
	},{
		.name = "munlock",
		.num_args = 2,
	},{
		.name = "mlockall",
		.num_args = 1,
	},{
		.name = "munlockall",
		.num_args = 0,
	},{
		.name = "vhangup",
		.num_args = 0,.flags = CAPABILITY_CHECK,
	},{
		.name = "modify_ldt",
		.num_args = 3,
	},{
		.name = "pivot_root",
		.num_args = 2,.flags = CAPABILITY_CHECK,
	},{
		.name = "sysctl",
		.num_args = 1,
	},{
		.name = "prctl",
		.num_args = 5,
	},{
		.name = "arch_prctl",
		.num_args = 2,
	},{
		.name = "adjtimex",
		.num_args = 1,
	},{
		.name = "setrlimit",
		.num_args = 2,
	},{
		.name = "chroot",
		.num_args = 1,
	},{
		.name = "sync",
		.num_args = 0,
	},{
		.name = "acct",
		.num_args = 1,
	},{
		.name = "settimeofday",
		.num_args = 2,
	},{
		.name = "mount",
		.num_args = 5,
	},{
		.name = "umount",
		.num_args = 2,
	},{
		.name = "swapon",
		.num_args = 2,
	},{
		.name = "swapoff",
		.num_args = 1,
	},{
		.name = "reboot",
		.num_args = 4,
		.flags = CAPABILITY_CHECK,
	},{
		.name = "sethostname",
		.num_args = 2,
		.flags = CAPABILITY_CHECK,
	},{
		.name = "setdomainname",
		.num_args = 2,
		.flags = CAPABILITY_CHECK,
	},{
		.name = "iopl",
		.num_args = 2,
	},{
		.name = "ioperm",
		.num_args = 3,
	},{
		.name = "ni_syscall (create_module)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "init_module",
		.num_args = 3,.flags = CAPABILITY_CHECK,
	},{
		.name = "delete_module",
		.num_args = 2,.flags = CAPABILITY_CHECK,
	},{
		.name = "ni_syscall (get_kernel_syms)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "ni_syscall (query_module)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "quotactl",
		.num_args = 4,
	},{
		.name = "nfsservctl",
		.num_args = 3,
	},{
		.name = "ni_syscall (getpmsg)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "ni_syscall (putpmsg)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "ni_syscall (afs)",
		.num_args = 6,
		.flags = NI_SYSCALL,
	},{
		.name = "ni_syscall (tux)",
		.num_args = 6,
		.flags = NI_SYSCALL,
	},{
		.name = "ni_syscall (security)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "gettid",
		.num_args = 0,
	},{
		.name = "readahead",
		.num_args = 3,
	},{
		.name = "setxattr",
		.num_args = 5,
	},{
		.name = "lsetxattr",
		.num_args = 5,
	},{
		.name = "fsetxattr",
		.num_args = 5,
	},{
		.name = "getxattr",
		.num_args = 4,
	},{
		.name = "lgetxattr",
		.num_args = 4,
	},{
		.name = "fgetxattr",
		.num_args = 4,
	},{
		.name = "listxattr",
		.num_args = 3,
	},{
		.name = "llistxattr",
		.num_args = 3,
	},{
		.name = "flistxattr",
		.num_args = 3,
	},{
		.name = "removexattr",
		.num_args = 2,
	},{
		.name = "lremovexattr",
		.num_args = 2,
	},{
		.name = "fremovexattr",
		.num_args = 2,
	},{
		.name = "tkill",
		.num_args = 2,
	},{
		.name = "time",
		.num_args = 1,
	},{
		.name = "futex",
		.num_args = 6,
	},{
		.name = "sched_setaffinity",
		.num_args = 3,
	},{
		.name = "sched_getaffinity",
		.num_args = 3,
	},{
		.name = "ni_syscall (set_thread_area)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "io_setup",
		.num_args = 2,
	},{
		.name = "io_destroy",
		.num_args = 1,
	},{
		.name = "io_getevents",
		.num_args = 5,
	},{
		.name = "io_submit",
		.num_args = 3,
	},{
		.name = "io_cancel",
		.num_args = 3,
	},{
		.name = "ni_syscall (get_thread_area)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "lookup_dcookie",
		.num_args = 3,.flags = CAPABILITY_CHECK,
	},{
		.name = "epoll_create",
		.num_args = 1,
	},{
		.name = "ni_syscall (epoll_ctl_old)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "ni_syscall (epoll_wait_old)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "remap_file_pages",
		.num_args = 5,
	},{
		.name = "getdents64",
		.num_args = 3,
	},{
		.name = "set_tid_address",
		.num_args = 1,
	},{
		.name = "restart_syscall",
		.num_args = 0,
	},{
		.name = "semtimedop",
		.num_args = 4,
	},{
		.name = "fadvise64",
		.num_args = 4,
	},{
		.name = "timer_create",
		.num_args = 3,
	},{
		.name = "timer_settime",
		.num_args = 4,
	},{
		.name = "timer_gettime",
		.num_args = 2,
	},{
		.name = "timer_getoverrun",
		.num_args = 1,
	},{
		.name = "timer_delete",
		.num_args = 1,
	},{
		.name = "clock_settime",
		.num_args = 2,
	},{
		.name = "clock_gettime",
		.num_args = 2,
	},{
		.name = "clock_getres",
		.num_args = 2,
	},{
		.name = "clock_nanosleep",
		.num_args = 4,
	},{
		.name = "exit_group",
		.num_args = 1,
		.flags = AVOID_SYSCALL,
	},{
		.name = "epoll_wait",
		.num_args = 4,
	},{
		.name = "epoll_ctl",
		.num_args = 4,
	},{
		.name = "tgkill",
		.num_args = 3,
	},{
		.name = "utimes",
		.num_args = 2,
	},{
		.name = "ni_syscall (vserver)",
		.num_args = 0,
		.flags = NI_SYSCALL,
	},{
		.name = "mbind",
		.num_args = 6,
	},{
		.name = "set_mempolicy",
		.num_args = 3,
	},{
		.name = "get_mempolicy",
		.num_args = 5,
	},{
		.name = "mq_open",
		.num_args = 4,
	},{
		.name = "mq_unlink",
		.num_args = 1,
	},{
		.name = "mq_timedsend",
		.num_args = 5,
	},{
		.name = "mq_timedreceive",
		.num_args = 5,
	},{
		.name = "mq_notify",
		.num_args = 2,
	},{
		.name = "mq_getsetattr",
		.num_args = 3,
	},{
		.name = "kexec_load",
		.num_args = 4,.flags = CAPABILITY_CHECK,
	},{
		.name = "waitid",
		.num_args = 5,
	},{
		.name = "add_key",
		.num_args = 5,
	},{
		.name = "request_key",
		.num_args = 4,
	},{
		.name = "keyctl",
		.num_args = 5,
	},{
		.name = "ioprio_set",
		.num_args = 3,
	},{
		.name = "ioprio_get",
		.num_args = 2,
	},{
		.name = "inotify_init",
		.num_args = 0,
	},{
		.name = "inotify_add_watch",
		.num_args = 3,
	},{
		.name = "inotify_rm_watch",
		.num_args = 2,
	},{
		.name = "migrate_pages",
		.num_args = 4,
	},{
		.name = "openat",
		.num_args = 4,
	},{
		.name = "mkdirat",
		.num_args = 3,
	},{
		.name = "mknodat",
		.num_args = 4,
	},{
		.name = "fchownat",
		.num_args = 5,
	},{
		.name = "futimesat",
		.num_args = 3,
	},{
		.name = "fstatat",
		.num_args = 4,
	},{
		.name = "unlinkat",
		.num_args = 3,
	},{
		.name = "renameat",
		.num_args = 4,
	},{
		.name = "linkat",
		.num_args = 5,
	},{
		.name = "symlinkat",
		.num_args = 3,
	},{
		.name = "readlinkat",
		.num_args = 4,
	},{
		.name = "fchmodat",
		.num_args = 3,
	},{
		.name = "faccessat",
		.num_args = 3,
	},{
		.name = "pselect6",
		.num_args = 6,
	},{
		.name = "ppoll",
		.num_args = 5,
	},{
		.name = "unshare",
		.num_args = 1,
	},{
		.name = "set_robust_list",
		.num_args = 2,
		.sanitise = sanitise_set_robust_list
	},{
		.name = "get_robust_list",
		.num_args = 3,
	},{
		.name = "splice",
		.num_args = 6,
		.sanitise = sanitise_splice
	},{
		.name = "tee",
		.num_args = 4,
		.sanitise = sanitise_tee
	},{
		.name = "sync_file_range",
		.num_args = 4,
		.sanitise = sanitise_sync_file_range
	},{
		.name = "vmsplice",
		.num_args = 4,
		.sanitise = sanitise_vmsplice
	},{
		.name = "move_pages",
		.num_args = 6,
	},{
		.name = "utimensat",
		.num_args = 4,
	},{
		.name = "epoll_pwait",
		.num_args = 6,
	},{
		.name = "signalfd",
		.num_args = 3,
	},{
		.name = "timerfd_create",
		.num_args = 2,
	},{
		.name = "eventfd",
		.num_args = 1,
	},{
		.name = "fallocate",
		.num_args = 4,
	},{
		.name = "timerfd_settime",
		.num_args = 4,
	},{
		.name = "timerfd_gettime",
		.num_args = 2,
	},{
		.name = "accept4",
		.num_args = 4,
	},{
		.name = "signalfd4",
		.num_args = 4,
	},{
		.name = "eventfd2",
		.num_args = 2,
	},{
		.name = "epoll_create1",
		.num_args = 1,
	},{
		.name = "dup3",
		.num_args = 3,
	},{
		.name = "pipe2",
		.num_args = 2,
	},{
		.name = "inotify_init1",
		.num_args = 1,
	},{
		.name = "preadv",
		.num_args = 5,
	},{
		.name = "pwritev",
		.num_args = 5,
	},{
		.name = "rt_tgsigqueueinfo",
		.num_args = 4,
	},{
		.name = "perf_event_open",
		.num_args = 5,
	},{
		.name = "recvmmsg",
		.num_args = 5,
	},{
		.name = "fanotify_init",
		.num_args = 2,
	},{
		.name = "fanotify_mark",
		.num_args = 5,
	},{
		.name = "prlimit64",
		.num_args = 4,
	},
};
