/* Syscalls from arch/ia64/kernel/entry.S as of 2.6.17rc6 */

#include "scrashme.h"
#include "sanitise.h"

#define NR_SYSCALLS 278

struct syscalltable syscalls_ia64[NR_SYSCALLS+1] = {

	{ .name = "ni_syscall", },		/* 0 - This must be sys_ni_syscall!  See ivt.S. */
	{ .name = "exit", .flags = AVOID_SYSCALL },
	{ .name = "read", .sanitise = sanitise_read },
	{ .name = "write", .sanitise = sanitise_write },
	{ .name = "open", },			/* 5 */
	{ .name = "close", .sanitise = sanitise_close },
	{ .name = "creat", },
	{ .name = "link", },
	{ .name = "unlink", },
	{ .name = "execve", },			/* 10 */
	{ .name = "chdir", },
	{ .name = "fchdir", },
	{ .name = "utimes", },
	{ .name = "mknod", },
	{ .name = "chmod", },			/* 15 */
	{ .name = "chown", },
	{ .name = "lseek", .sanitise = sanitise_lseek },
	{ .name = "getpid", },
	{ .name = "getppid", },
	{ .name = "mount", },			/* 20 */
	{ .name = "umount", },
	{ .name = "setuid", },
	{ .name = "getuid", },
	{ .name = "geteuid", },
	{ .name = "ptrace", },			/* 25 */
	{ .name = "access", },
	{ .name = "sync", },
	{ .name = "fsync", },
	{ .name = "fdatasync", },
	{ .name = "kill", },			/* 30 */
	{ .name = "rename", },
	{ .name = "mkdir", },
	{ .name = "rmdir", },
	{ .name = "dup", },
	{ .name = "pipe", },			/* 35 */
	{ .name = "times", },
	{ .name = "brk", },
	{ .name = "setgid", },
	{ .name = "getgid", },
	{ .name = "getegid", },			/* 40 */
	{ .name = "acct", },
	{ .name = "ioctl", .sanitise = sanitise_ioctl },
	{ .name = "fcntl", },
	{ .name = "umask", },
	{ .name = "chroot", },			/* 45 */
	{ .name = "ustat", },
	{ .name = "dup2", },
	{ .name = "setreuid", },
	{ .name = "setregid", },
	{ .name = "getresuid", },		/* 50 */
	{ .name = "setresuid", },
	{ .name = "getresgid", },
	{ .name = "setresgid", },
	{ .name = "getgroups", },
	{ .name = "setgroups", },		/* 55 */
	{ .name = "getpgid", },
	{ .name = "setpgid", },
	{ .name = "setsid", },
	{ .name = "getsid", },
	{ .name = "sethostname", },		/* 60 */
	{ .name = "setrlimit", },
	{ .name = "getrlimit", },
	{ .name = "getrusage", },
	{ .name = "gettimeofday", },
	{ .name = "settimeofday", },		/* 65 */
	{ .name = "select", .flags = AVOID_SYSCALL },
	{ .name = "poll", },
	{ .name = "symlink", },
	{ .name = "readlink", },
	{ .name = "uselib", },			/* 70 */
	{ .name = "swapon", },
	{ .name = "swapoff", },
	{ .name = "reboot", },
	{ .name = "truncate", },
	{ .name = "ftruncate", },		/* 75 */
	{ .name = "fchmod", },
	{ .name = "fchown", },
	{ .name = "getpriority", },
	{ .name = "setpriority", },
	{ .name = "statfs", },			/* 80 */
	{ .name = "fstatfs", },
	{ .name = "gettid", },
	{ .name = "semget", },
	{ .name = "semop", },
	{ .name = "semctl", },			/* 85 */
	{ .name = "msgget", },
	{ .name = "msgsnd", },
	{ .name = "msgrcv", },
	{ .name = "msgctl", },
	{ .name = "shmget", },			/* 90 */
	{ .name = "shmat", },
	{ .name = "shmdt", },
	{ .name = "shmctl", },
	{ .name = "syslog", },
	{ .name = "setitimer", },		/* 95 */
	{ .name = "getitimer", },
	{ .name = "tux", },
	{ .name = "ni_syscall (was ia64_oldlstat)", },	/* was: ia64_oldlstat */
	{ .name = "ni_syscall (was ia64_oldfstat)", },	/* was: ia64_oldfstat */
	{ .name = "vhangup", },			/* 100 */
	{ .name = "lchown", },
	{ .name = "remap_file_pages", },
	{ .name = "wait4", },
	{ .name = "sysinfo", },
	{ .name = "clone", .flags = AVOID_SYSCALL },			/* 105 */
	{ .name = "setdomainname", },
	{ .name = "newuname", },
	{ .name = "adjtimex", },
	{ .name = "ni_syscall (was ia64_create_module)", },	/* was: ia64_create_module */
	{ .name = "init_module", },		/* 110 */
	{ .name = "delete_module", },
	{ .name = "ni_syscall", },
	{ .name = "ni_syscall (was query_module)", },	/* was:query_module */
	{ .name = "quotactl", },
	{ .name = "bdflush", },			/* 115 */
	{ .name = "sysfs", },
	{ .name = "personality", },
	{ .name = "ni_syscall (afs_syscall)", },	/* afs_syscall */
	{ .name = "setfsuid", },
	{ .name = "setfsgid", },		/* 120 */
	{ .name = "getdents", },
	{ .name = "flock", },
	{ .name = "readv", .sanitise = sanitise_readv },
	{ .name = "writev", .sanitise = sanitise_writev },
	{ .name = "pread64", .sanitise = sanitise_pread64 },			/* 125 */
	{ .name = "pwrite64", .sanitise = sanitise_pwrite64 },
	{ .name = "sysctl", },
	{ .name = "mmap", .sanitise = sanitise_mmap },
	{ .name = "munmap", },
	{ .name = "mlock", },			/* 130 */
	{ .name = "mlockall", },
	{ .name = "mprotect", .sanitise = sanitise_mprotect },
	{ .name = "mremap", },
	{ .name = "msync", },
	{ .name = "munlock", },			/* 135 */
	{ .name = "munlockall", },
	{ .name = "sched_getparam", },
	{ .name = "sched_setparam", },
	{ .name = "sched_getscheduler", },
	{ .name = "sched_setscheduler", },	/* 140 */
	{ .name = "sched_yield", },
	{ .name = "sched_get_priority_max", },
	{ .name = "sched_get_priority_min", },
	{ .name = "sched_rr_get_interval", },
	{ .name = "nanosleep", },		/* 145 */
	{ .name = "nfsservctl", },
	{ .name = "prctl", },
	{ .name = "getpagesize", },
	{ .name = "mmap2", },
	{ .name = "pciconfig_read", },		/* 150 */
	{ .name = "pciconfig_write", },
	{ .name = "perfmonctl", },
	{ .name = "sigaltstack", },
	{ .name = "rt_sigaction", .sanitise = sanitise_rt_sigaction },
	{ .name = "rt_sigpending", },		/* 155 */
	{ .name = "rt_sigprocmask", .sanitise = sanitise_rt_sigprocmask },
	{ .name = "rt_sigqueueinfo", },
	{ .name = "rt_sigreturn", .flags = AVOID_SYSCALL },
	{ .name = "rt_sigsuspend", },
	{ .name = "rt_sigtimedwait", },		/* 160 */
	{ .name = "getcwd", },
	{ .name = "capget", },
	{ .name = "capset", },
	{ .name = "sendfile64", },
	{ .name = "ni_syscall (getpmsg)", },	/* 165 - getpmsg (STREAMS) */
	{ .name = "ni_syscall (putpmsg)", },	/* putpmsg (STREAMS) */
	{ .name = "socket", },
	{ .name = "bind", },
	{ .name = "connect", },
	{ .name = "listen", },			/* 170 */
	{ .name = "accept", },
	{ .name = "getsockname", },
	{ .name = "getpeername", },
	{ .name = "socketpair", },
	{ .name = "send", },			/* 175 */
	{ .name = "sendto", },
	{ .name = "recv", },
	{ .name = "recvfrom", },
	{ .name = "shutdown", },
	{ .name = "setsockopt", },		/* 180 */
	{ .name = "getsockopt", },
	{ .name = "sendmsg", },
	{ .name = "recvmsg", },
	{ .name = "pivot_root", },
	{ .name = "mincore", },			/* 185 */
	{ .name = "madvise", },
	{ .name = "newstat", },
	{ .name = "newlstat", },
	{ .name = "newfstat", .sanitise = sanitise_newfstat },
	{ .name = "clone2", .flags = AVOID_SYSCALL },			/* 190 */
	{ .name = "getdents64", },
	{ .name = "getunwind", },
	{ .name = "readahead", },
	{ .name = "setxattr", },
	{ .name = "lsetxattr", },		/* 195 */
	{ .name = "fsetxattr", },
	{ .name = "getxattr", },
	{ .name = "lgetxattr", },
	{ .name = "fgetxattr", },
	{ .name = "listxattr", },		/* 200 */
	{ .name = "llistxattr", },
	{ .name = "flistxattr", },
	{ .name = "removexattr", },
	{ .name = "lremovexattr", },
	{ .name = "fremovexattr", },		/* 205 */
	{ .name = "tkill", },
	{ .name = "futex", },
	{ .name = "sched_setaffinity", },
	{ .name = "sched_getaffinity", },
	{ .name = "set_tid_address", },		/* 210 */
	{ .name = "fadvise64_64", },
	{ .name = "tgkill", },
	{ .name = "exit_group", .flags = AVOID_SYSCALL },
	{ .name = "lookup_dcookie", },
	{ .name = "io_setup", },		/* 215 */
	{ .name = "io_destroy", },
	{ .name = "io_getevents", },
	{ .name = "io_submit", },
	{ .name = "io_cancel", },
	{ .name = "epoll_create", },		/* 220 */
	{ .name = "epoll_ctl", },
	{ .name = "epoll_wait", },
	{ .name = "restart_syscall", },
	{ .name = "semtimedop", },
	{ .name = "timer_create", },		/* 225 */
	{ .name = "timer_settime", },
	{ .name = "timer_gettime", },
	{ .name = "timer_getoverrun", },
	{ .name = "timer_delete", },
	{ .name = "clock_settime", },		/* 230 */
	{ .name = "clock_gettime", },
	{ .name = "clock_getres", },
	{ .name = "clock_nanosleep", },
	{ .name = "fstatfs64", },
	{ .name = "statfs64", },		/* 235 */
	{ .name = "mbind", },
	{ .name = "get_mempolicy", },
	{ .name = "set_mempolicy", },
	{ .name = "mq_open", },
	{ .name = "mq_unlink", },		/* 240 */
	{ .name = "mq_timedsend", },
	{ .name = "mq_timedreceive", },
	{ .name = "mq_notify", },
	{ .name = "mq_getsetattr", },
	{ .name = "kexec_load", .flags = CAPABILITY_CHECK },	/* 245 - reserved for kexec_load */
	{ .name = "ni_syscall (reserved for vserver)", },	/* reserved for vserver */
	{ .name = "waitid", },
	{ .name = "add_key", },
	{ .name = "request_key", },
	{ .name = "keyctl", },			/* 250 */
	{ .name = "ioprio_set", },
	{ .name = "ioprio_get", },
	{ .name = "ni_syscall", },
	{ .name = "inotify_init", },
	{ .name = "inotify_add_watch", },	/* 255 */
	{ .name = "inotify_rm_watch", },
	{ .name = "migrate_pages", },
	{ .name = "openat", },
	{ .name = "mkdirat", },
	{ .name = "mknodat", },			/* 260 */
	{ .name = "fchownat", },
	{ .name = "futimesat", },
	{ .name = "newfstatat", },
	{ .name = "unlinkat", },
	{ .name = "renameat", },		/* 265 */
	{ .name = "linkat", },
	{ .name = "symlinkat", },
	{ .name = "readlinkat", },
	{ .name = "fchmodat", },
	{ .name = "faccessat", },		/* 270 */
	{ .name = "ni_syscall (reserved for pselect)", },	/* reserved for pselect */
	{ .name = "ni_syscall", },
	{ .name = "unshare", },
	{ .name = "splice", .sanitise = sanitise_splice },
	{ .name = "set_robust_list", .sanitise = sanitise_set_robust_list },	/* 275 */
	{ .name = "get_robust_list", },
	{ .name = "sync_file_range", .sanitise = sanitise_sync_file_range },
	{ .name = "tee", .sanitise = sanitise_tee },
	{ .name = "vmsplice", .sanitise = sanitise_vmsplice },
};


