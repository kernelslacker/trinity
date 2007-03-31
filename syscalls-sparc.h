/* Syscalls from arch/sparc{,64}/kernel/systbl.S as of 2.6.17rc6 */

#include "scrashme.h"
#include "sanitise.h"

# define NR_SYSCALLS 301

struct syscalltable syscalls_sparc[NR_SYSCALLS+1] = {
	{ .name = "restart_syscall", }, /* 0 - old "setup()" system call, used for restarting */
	{ .name = "exit", .flags = AVOID_SYSCALL },
	{ .name = "fork", .flags = AVOID_SYSCALL },
	{ .name = "read", .sanitise = sanitise_read },
	{ .name = "write", .sanitise = sanitise_write },
	{ .name = "open", }, /* 5 */
	{ .name = "close", .sanitise = sanitise_close },
	{ .name = "wait4", },
	{ .name = "creat", },
	{ .name = "link", },
	{ .name = "unlink", }, /* 10 */
	{ .name = "ni_syscall (sunos_execv)", },
	{ .name = "chdir", },
	{ .name = "chown", },
	{ .name = "mknod", },
	{ .name = "chmod", }, /* 15 */
	{ .name = "lchown", },
	{ .name = "brk", },
	{ .name = "perfctr", },
	{ .name = "lseek", .sanitise = sanitise_lseek },
	{ .name = "getpid", }, /* 20 */
	{ .name = "capget", },
	{ .name = "capset", },
	{ .name = "setuid", },
	{ .name = "getuid", },
	{ .name = "vmsplice", .sanitise = sanitise_vmsplice }, /* 25 */
	{ .name = "ptrace", },
	{ .name = "alarm", },	
	{ .name = "sigaltstack", },
	{ .name = "pause", },
	{ .name = "utime", }, /* 30 */
	{ .name = "ni_syscall (old stty syscall holder)", },
	{ .name = "ni_syscall (old gtty syscall holder)", },
	{ .name = "access", },
	{ .name = "nice", },
	{ .name = "ni_syscall (old ftime syscall holder)", }, /* 35 */
	{ .name = "sync", },
	{ .name = "kill", },
	{ .name = "newstat", },
	{ .name = "sendfile64", },
	{ .name = "newlstat", }, /* 40 */
	{ .name = "dup", },
	{ .name = "pipe", },
	{ .name = "times", },
	{ .name = "ni_syscall (old prof syscall holder)", },
	{ .name = "umount", }, /* 45 */
	{ .name = "setgid", },
	{ .name = "getgid", },
	{ .name = "signal", },
	{ .name = "geteuid", },
	{ .name = "getegid", }, /* 50 */
	{ .name = "acct", },
	{ .name = "memory_ordering", },
	{ .name = "getgid", },
	{ .name = "ioctl", .sanitise = sanitise_ioctl },
	{ .name = "reboot", }, /* 55 */
	{ .name = "mmap2", },
	{ .name = "symlink", },
	{ .name = "readlink", },
	{ .name = "execve", },
	{ .name = "umask", }, /* 60 */
	{ .name = "chroot", },
	{ .name = "newfstat", .sanitise = sanitise_newfstat },
	{ .name = "fstat64", },
	{ .name = "getpagesize", },
	{ .name = "msync", }, /* 65 */
	{ .name = "vfork", .flags = AVOID_SYSCALL },
	{ .name = "pread64", .sanitise = sanitise_pread64 },
	{ .name = "pwrite64", .sanitise = sanitise_pwrite64 },
	{ .name = "geteuid", },
	{ .name = "getegid", }, /* 70 */
	{ .name = "mmap", .sanitise = sanitise_mmap }, /* 90 */
	{ .name = "setreuid", },
	{ .name = "munmap", },
	{ .name = "mprotect", .sanitise = sanitise_mprotect },
	{ .name = "madvise", }, /* 75 */
	{ .name = "vhangup", },
	{ .name = "truncate64", },
	{ .name = "mincore", },
	{ .name = "getgroups", },
	{ .name = "setgroups", }, /* 80 */
	{ .name = "getpgrp", },
	{ .name = "setgroups", },
	{ .name = "setitimer", },
	{ .name = "ftruncate64", },
	{ .name = "swapon", }, /* 85 */
	{ .name = "getitimer", },
	{ .name = "setuid", },
	{ .name = "sethostname", },
	{ .name = "setgid", },
	{ .name = "dup2", }, /* 90 */
	{ .name = "setfsuid", },
	{ .name = "fcntl", },
	{ .name = "select", },
	{ .name = "setfsgid", },
	{ .name = "fsync", }, /* 95 */
	{ .name = "setpriority", },
	{ .name = "socket", },
	{ .name = "connect", },
	{ .name = "accept", },
	{ .name = "getpriority", }, /* 100 */
	{ .name = "rt_sigreturn", .flags = AVOID_SYSCALL },
	{ .name = "rt_sigaction", .sanitise = sanitise_rt_sigaction },
	{ .name = "rt_sigprocmask", .sanitise = sanitise_rt_sigprocmask },
	{ .name = "rt_sigpending", },
	{ .name = "rt_sigtimedwait", }, /* 105 */
	{ .name = "rt_sigqueueinfo", },
	{ .name = "rt_sigsuspend", },
	{ .name = "setresuid", },
	{ .name = "getresuid", },
	{ .name = "setresgid", }, /* 110 */
	{ .name = "getresgid", },
	{ .name = "setregid", },
	{ .name = "recvmsg" },
	{ .name = "sendmsg" },
	{ .name = "getgroups" }, /* 115 */
	{ .name = "gettimeofday", },
	{ .name = "getrusage", },
	{ .name = "getsockopt" },
	{ .name = "getcwd" },
	{ .name = "readv", .sanitise = sanitise_readv }, /* 120 */
	{ .name = "writev", .sanitise = sanitise_writev },
	{ .name = "settimeofday" },
	{ .name = "fchown" },
	{ .name = "fchmod" },
	{ .name = "recvfrom" },	/* 125 */
	{ .name = "setreuid" },
	{ .name = "setregid" },
	{ .name = "rename" },
	{ .name = "truncate" },
	{ .name = "ftruncate" }, /* 130 */
	{ .name = "flock" },
	{ .name = "lstat64", },
	{ .name = "sendto" },
	{ .name = "shutdown" },
	{ .name = "socketpair" }, /* 135 */
	{ .name = "mkdir" },
	{ .name = "rmdir" },
	{ .name = "utimes" },
	{ .name = "stat64", },
	{ .name = "sendfile64", }, /* 140 */
	{ .name = "getpeername" },
	{ .name = "futex" },
	{ .name = "gettid" },
	{ .name = "getrlimit" },
	{ .name = "setrlimit", }, /* 145 */
	{ .name = "pivot_root", .flags = CAPABILITY_CHECK, },
	{ .name = "prctl" },
	{ .name = "pciconfig_read", },
	{ .name = "pciconfig_write", },
	{ .name = "getsockname" }, /* 150 */
	{ .name = "inotify_init" },
	{ .name = "inotify_add_watch" },
	{ .name = "poll" },
	{ .name = "getdents64" },
	{ .name = "fcntl64", }, /* 155 */
	{ .name = "inotify_rm_watch" },
	{ .name = "statfs" },
	{ .name = "fstatfs" },
	{ .name = "oldumount", },
	{ .name = "sched_setaffinity", }, /* 160 */
	{ .name = "sched_getaffinity", },
	{ .name = "getdomainname", },
	{ .name = "setdomainname", },
	{ .name = "utrap_install", },
	{ .name = "quotactl" }, /* 165 */
	{ .name = "set_tid_address" },
	{ .name = "mount", },
	{ .name = "ustat" },
	{ .name = "setxattr" },
	{ .name = "lsetxattr" }, /* 170 */
	{ .name = "fsetxattr" },
	{ .name = "getxattr" },
	{ .name = "lgetxattr" },
	{ .name = "getdents" },
	{ .name = "setsid" }, /* 175 */
	{ .name = "fchdir", },
	{ .name = "fgetxattr", },
	{ .name = "listxattr", },
	{ .name = "llistxattr", },
	{ .name = "flistxattr", }, /* 180 */
	{ .name = "removexattr", },
	{ .name = "lremovexattr", },
	{ .name = "sigpending", },
	{ .name = "ni_syscall", },
	{ .name = "setpgid", }, /* 185 */
	{ .name = "fremovexattr", },
	{ .name = "tkill", },
	{ .name = "exit_group", .flags = AVOID_SYSCALL },
	{ .name = "newuname", },
	{ .name = "init_module", }, /* 190 */
	{ .name = "personality", },
	{ .name = "remap_file_pages", },
	{ .name = "epoll_create", },
	{ .name = "epoll_ctl", },
	{ .name = "epoll_wait", }, /* 195 */
	{ .name = "ioprio_set", },
	{ .name = "getppid", },
	{ .name = "ni_syscall", },
	{ .name = "sgetmask", },
	{ .name = "ssetmask", }, /* 200 */
	{ .name = "sigsuspend", .flags = AVOID_SYSCALL },
	{ .name = "newlstat", },
	{ .name = "uselib", },
	{ .name = "old_readdir", },
	{ .name = "readahead", }, /* 205 */
	{ .name = "socketcall", },
	{ .name = "syslog", },
	{ .name = "lookup_dcookie", .flags = CAPABILITY_CHECK, },
	{ .name = "fadvise64", },
	{ .name = "fadvise64_64", }, /* 210 */
	{ .name = "tgkill", },
	{ .name = "waitpid", },
	{ .name = "swapoff", },
	{ .name = "sysinfo", },
	{ .name = "ipc", }, /* 215 */
	{ .name = "sigreturn", },
	{ .name = "clone", .flags = AVOID_SYSCALL },
	{ .name = "ioprio_get", },
	{ .name = "adjtimex", },
	{ .name = "sigprocmask", }, /* 220 */
	{ .name = "ni_syscall", },
	{ .name = "delete_module", },
	{ .name = "ni_syscall", },
	{ .name = "getpgid", },
	{ .name = "bdflush", }, /* 225 */
	{ .name = "sysfs", },
	{ .name = "ni_syscall", },
	{ .name = "setfsuid", },
	{ .name = "setfsgid", },
	{ .name = "select", .flags = AVOID_SYSCALL }, /* 230 */
	{ .name = "time" },
	{ .name = "splice", .sanitise = sanitise_splice },
	{ .name = "stime" },
	{ .name = "statfs64", },
	{ .name = "fstatfs64", }, /* 235 */
	{ .name = "llseek", },
	{ .name = "mlock", },
	{ .name = "munlock", },
	{ .name = "mlockall", },
	{ .name = "munlockall", }, /* 240 */
	{ .name = "sched_setparam", },
	{ .name = "sched_getparam", },
	{ .name = "sched_setscheduler", },
	{ .name = "sched_getscheduler", },
	{ .name = "sched_yield", }, /* 245 */
	{ .name = "sched_get_priority_max", },
	{ .name = "sched_get_priority_min", },
	{ .name = "sched_rr_get_interval", },
	{ .name = "nanosleep", },
	{ .name = "mremap", .sanitise = sanitise_mremap }, /* 250 */
	{ .name = "sysctl", },
	{ .name = "getsid", },
	{ .name = "fdatasync", },
	{ .name = "nfsservctl", },
	{ .name = "sync_file_range", .sanitise = sanitise_sync_file_range }, /* 255 */
	{ .name = "clock_settime", },
	{ .name = "clock_gettime", },
	{ .name = "clock_getres", },
	{ .name = "clock_nanosleep", },
	{ .name = "sched_getaffinity", }, /* 260 */
	{ .name = "sched_setaffinity", },
	{ .name = "timer_settime", },
	{ .name = "timer_gettime", },
	{ .name = "timer_getoverrun", },
	{ .name = "timer_delete", }, /* 265 */
	{ .name = "timer_create", },
	{ .name = "ni_syscall", },
	{ .name = "io_setup", },
	{ .name = "io_destroy", },
	{ .name = "io_submit", }, /* 270 */
	{ .name = "io_cancel", },
	{ .name = "io_getevents", },
	{ .name = "mq_open", },
	{ .name = "mq_unlink", },
	{ .name = "mq_timedsend", }, /* 275 */
	{ .name = "mq_timedreceive", },
	{ .name = "mq_notify", },
	{ .name = "mq_getsetattr", },
	{ .name = "waitid", },
	{ .name = "tee", .sanitise = sanitise_tee }, /* 280 */
	{ .name = "add_key", },
	{ .name = "request_key", },
	{ .name = "keyctl", },
	{ .name = "openat", },
	{ .name = "mkdirat", }, /* 285 */
	{ .name = "mknodat", },
	{ .name = "fchownat", },
	{ .name = "futimesat", },
	{ .name = "fstatat64", },
	{ .name = "unlinkat", }, /* 290 */
	{ .name = "renameat", },
	{ .name = "linkat", },
	{ .name = "symlinkat", },
	{ .name = "readlinkat", },
	{ .name = "fchmodat", }, /* 295 */
	{ .name = "faccessat", },
	{ .name = "pselect6", },
	{ .name = "ppoll", },
	{ .name = "unshare", },
	{ .name = "set_robust_list", .sanitise = sanitise_set_robust_list }, /* 300 */
	{ .name = "get_robust_list", },
};

