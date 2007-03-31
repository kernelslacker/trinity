/* Syscalls from arch/powerpc/kernel/systbl.S as of 2.6.17rc6 */

#include "scrashme.h"
#include "sanitise.h"

# define NR_SYSCALLS 300

struct syscalltable syscalls_ppc[NR_SYSCALLS+1] = {
	{ .name = "restart_syscall", }, /* 0 - old "setup()" system call, used for restarting */
	{ .name = "exit", .flags = AVOID_SYSCALL },
	{ .name = "fork", .flags = AVOID_SYSCALL },
	{ .name = "read", .sanitise = sanitise_read },
	{ .name = "write", .sanitise = sanitise_write },
	{ .name = "open", }, /* 5 */
	{ .name = "close", .sanitise = sanitise_close },
	{ .name = "waitpid", },
	{ .name = "creat", },
	{ .name = "link", },
	{ .name = "unlink", }, /* 10 */
	{ .name = "execve", },
	{ .name = "chdir", },
	{ .name = "time", },
	{ .name = "mknod", },
	{ .name = "chmod", }, /* 15 */
	{ .name = "lchown", },
	{ .name = "ni_syscall (old break syscall holder)", },
	{ .name = "stat", },
	{ .name = "lseek", .sanitise = sanitise_lseek },
	{ .name = "getpid", }, /* 20 */
	{ .name = "mount", },
	{ .name = "sys_ni_syscall,sys_oldumount,sys_oldumount", },
	{ .name = "setuid", },
	{ .name = "getuid", },
	{ .name = "stime", }, /* 25 */
	{ .name = "ptrace", },
	{ .name = "alarm", },
	{ .name = "fstat", },
	{ .name = "pause", },
	{ .name = "utime", }, /* 30 */
	{ .name = "ni_syscall (old stty syscall holder)", },
	{ .name = "ni_syscall (old gtty syscall holder)", },
	{ .name = "access", },
	{ .name = "nice", },
	{ .name = "ni_syscall (old ftime syscall holder)", }, /* 35 */
	{ .name = "sync", },
	{ .name = "kill", },
	{ .name = "rename", },
	{ .name = "mkdir", },
	{ .name = "rmdir", }, /* 40 */
	{ .name = "dup", },
	{ .name = "pipe", },
	{ .name = "times", },
	{ .name = "ni_syscall (old prof syscall holder)", },
	{ .name = "brk", }, /* 45 */
	{ .name = "setgid", },
	{ .name = "getgid", },
	{ .name = "signal", },
	{ .name = "geteuid", },
	{ .name = "getegid", }, /* 50 */
	{ .name = "acct", },
	{ .name = "umount (recycled never used phys())", },
	{ .name = "ni_syscall (old lock syscall holder)", },
	{ .name = "ioctl", .sanitise = sanitise_ioctl },
	{ .name = "fcntl", }, /* 55 */
	{ .name = "ni_syscall (old mpx syscall holder)", },
	{ .name = "setpgid", },
	{ .name = "ni_syscall (old ulimit syscall holder)", },
	{ .name = "olduname", },
	{ .name = "umask", }, /* 60 */
	{ .name = "chroot", },
	{ .name = "ustat", },
	{ .name = "dup2", },
	{ .name = "getppid", },
	{ .name = "getpgrp", }, /* 65 */
	{ .name = "setsid", },
	{ .name = "sigaction", },
	{ .name = "sgetmask", },
	{ .name = "ssetmask", },
	{ .name = "setreuid", }, /* 70 */
	{ .name = "setregid", },
	{ .name = "sigsuspend", .flags = AVOID_SYSCALL },
	{ .name = "sigpending", },
	{ .name = "sethostname", },
	{ .name = "setrlimit", }, /* 75 */
	{ .name = "old_getrlimit", },
	{ .name = "getrusage", },
	{ .name = "gettimeofday", },
	{ .name = "settimeofday", },
	{ .name = "getgroups", }, /* 80 */
	{ .name = "setgroups", },
	{ .name = "select", .flags = AVOID_SYSCALL },
	{ .name = "symlink", },
	{ .name = "lstat", },
	{ .name = "readlink", }, /* 85 */
	{ .name = "uselib", },
	{ .name = "swapon", },
	{ .name = "reboot", },
	{ .name = "readdir", },
	{ .name = "mmap", .sanitise = sanitise_mmap }, /* 90 */
	{ .name = "munmap", },
	{ .name = "truncate", },
	{ .name = "ftruncate", },
	{ .name = "fchmod", },
	{ .name = "fchown", }, /* 95 */
	{ .name = "getpriority", },
	{ .name = "setpriority", },
	{ .name = "ni_syscall (old profil syscall holder)", },
	{ .name = "statfs", },
	{ .name = "fstatfs", }, /* 100 */
	{ .name = "ni_syscall", },
	{ .name = "socketcall", },
	{ .name = "syslog", },
	{ .name = "setitimer", },
	{ .name = "getitimer", }, /* 105 */
	{ .name = "newstat", },
	{ .name = "newlstat", },
	{ .name = "newfstat", .sanitise = sanitise_newfstat },
	{ .name = "uname", },
	{ .name = "ni_syscall (105)", }, /* 110 */
	{ .name = "vhangup", },
	{ .name = "ni_syscall (old 'idle' system call?)", },
	{ .name = "ni_syscall (108)", },
	{ .name = "wait4", },
	{ .name = "swapoff", }, /* 115 */
	{ .name = "sysinfo", },
	{ .name = "ipc", },
	{ .name = "fsync", },
	{ .name = "sigreturn", .flags = AVOID_SYSCALL },
	{ .name = "clone", .flags = AVOID_SYSCALL }, /* 120 */
	{ .name = "setdomainname", },
	{ .name = "newuname", },
	{ .name = "ni_syscall", },
	{ .name = "adjtimex", },
	{ .name = "mprotect", .sanitise = sanitise_mprotect }, /* 125 */
	{ .name = "sigprocmask", },
	{ .name = "ni_syscall (old create module)", },
	{ .name = "init_module", },
	{ .name = "delete_module", },
	{ .name = "ni_syscall (old get_kernel_syms)", }, /* 130 */
	{ .name = "quotactl", },
	{ .name = "getpgid", },
	{ .name = "fchdir", },
	{ .name = "bdflush", },
	{ .name = "sysfs", }, /* 135 */
	{ .name = "personality", },
	{ .name = "ni_syscall (reserved for afs_syscall", },
	{ .name = "setfsuid", },
	{ .name = "setfsgid", },
	{ .name = "llseek", }, /* 140 */
	{ .name = "getdents", },
	{ .name = "sys_select,ppc32_select,ppc_select", },
	{ .name = "flock", },
	{ .name = "msync", },
	{ .name = "readv", .sanitise = sanitise_readv }, /* 145 */
	{ .name = "writev", .sanitise = sanitise_writev },
	{ .name = "getsid", },
	{ .name = "fdatasync", },
	{ .name = "sysctl", },
	{ .name = "mlock", }, /* 150 */
	{ .name = "munlock", },
	{ .name = "mlockall", },
	{ .name = "munlockall", },
	{ .name = "sched_setparam", },
	{ .name = "sched_getparam", }, /* 155 */
	{ .name = "sched_setscheduler", },
	{ .name = "sched_getscheduler", },
	{ .name = "sched_yield", },
	{ .name = "sched_get_priority_max", },
	{ .name = "sched_get_priority_min", }, /* 160 */
	{ .name = "sched_rr_get_interval", },
	{ .name = "nanosleep", },
	{ .name = "mremap", .sanitise = sanitise_mremap },
	{ .name = "setresuid", },
	{ .name = "getresuid", }, /* 165 */
	{ .name = "ni_syscall (Old sys_query_module)", },
	{ .name = "poll", },
	{ .name = "nfsservctl", },
	{ .name = "setresgid", },
	{ .name = "getresgid", }, /* 170 */
	{ .name = "prctl", },
	{ .name = "rt_sigreturn", .flags = AVOID_SYSCALL },
	{ .name = "rt_sigaction", .sanitise = sanitise_rt_sigaction },
	{ .name = "rt_sigprocmask", .sanitise = sanitise_rt_sigprocmask },
	{ .name = "rt_sigpending", }, /* 175 */
	{ .name = "rt_sigtimedwait", },
	{ .name = "rt_sigqueueinfo", },
	{ .name = "rt_sigsuspend", },
	{ .name = "pread64", .sanitise = sanitise_pread64 },
	{ .name = "pwrite64", .sanitise = sanitise_pwrite64 }, /* 180 */
	{ .name = "chown", },
	{ .name = "getcwd", },
	{ .name = "capget", },
	{ .name = "capset", },
	{ .name = "sigaltstack", }, /* 185 */
	{ .name = "sendfile", },
	{ .name = "ni_syscall (reserved for streams1)", },
	{ .name = "ni_syscall (reserved for streams2)", },
	{ .name = "vfork", .flags = AVOID_SYSCALL },
	{ .name = "getrlimit", }, /* 190 */
	{ .name = "readahead", },
	{ .name = "mmap2", },
	{ .name = "truncate64", },
	{ .name = "ftruncate64", },
	{ .name = "stat64", }, /* 195 */
	{ .name = "lstat64", },
	{ .name = "fstat64", },
	{ .name = "pciconfig_read", },
	{ .name = "pciconfig_write", },
	{ .name = "pciconfig_iobase", }, /* 200 */
	{ .name = "ni_syscall (201)", },
	{ .name = "getdents64", },
	{ .name = "pivot_root", },
	{ .name = "fcntl64", },
	{ .name = "madvise", }, /* 205 */
	{ .name = "mincore", },
	{ .name = "gettid", },
	{ .name = "tkill", },
	{ .name = "setxattr", },
	{ .name = "lsetxattr", }, /* 210 */
	{ .name = "fsetxattr", },
	{ .name = "getxattr", },
	{ .name = "lgetxattr", },
	{ .name = "fgetxattr", },
	{ .name = "listxattr", }, /* 215 */
	{ .name = "llistxattr", },
	{ .name = "flistxattr", },
	{ .name = "removexattr", },
	{ .name = "lremovexattr", },
	{ .name = "fremovexattr", }, /* 220 */
	{ .name = "futex", },
	{ .name = "sched_setaffinity", },
	{ .name = "sched_getaffinity", },
	{ .name = "ni_syscall", },
	{ .name = "ni_syscall", }, /* 225 */
	{ .name = "sendfile64", },
	{ .name = "io_setup", },
	{ .name = "io_destroy", },
	{ .name = "io_getevents", },
	{ .name = "io_submit", }, /* 230 */
	{ .name = "io_cancel", },
	{ .name = "set_tid_address", },
	{ .name = "fadvise64", },
	{ .name = "exit_group", .flags = AVOID_SYSCALL },
	{ .name = "lookup_dcookie", .flags = CAPABILITY_CHECK, }, /* 235 */
	{ .name = "epoll_create", },
	{ .name = "epoll_ctl", },
	{ .name = "epoll_wait", },
	{ .name = "remap_file_pages", },
	{ .name = "timer_create", }, /* 240 */
	{ .name = "timer_settime", },
	{ .name = "timer_gettime", },
	{ .name = "timer_getoverrun", },
	{ .name = "timer_delete", },
	{ .name = "clock_settime", }, /* 245 */
	{ .name = "clock_gettime", },
	{ .name = "clock_getres", },
	{ .name = "clock_nanosleep", },
	{ .name = "swapcontext", },
	{ .name = "tgkill", }, /* 250 */
	{ .name = "utimes", },
	{ .name = "statfs64", },
	{ .name = "fstatfs64", },
	{ .name = "fadvise64_64", },
	{ .name = "rtas", }, /* 255 */
	{ .name = "debug_setcontext", },
	{ .name = "ni_syscall", },
	{ .name = "ni_syscall", },
	{ .name = "mbind", },
	{ .name = "get_mempolicy", }, /* 260 */
	{ .name = "set_mempolicy", },
	{ .name = "mq_open", },
	{ .name = "mq_unlink", },
	{ .name = "mq_timedsend", },
	{ .name = "mq_timedreceive", }, /* 265 */
	{ .name = "mq_notify", },
	{ .name = "mq_getsetattr", },
	{ .name = "kexec_load", .flags = CAPABILITY_CHECK, },
	{ .name = "add_key", },
	{ .name = "request_key", }, /* 270 */
	{ .name = "keyctl", },
	{ .name = "waitid", },
	{ .name = "ioprio_set", },
	{ .name = "ioprio_get", },
	{ .name = "inotify_init", }, /* 275 */
	{ .name = "inotify_add_watch", },
	{ .name = "inotify_rm_watch", },
	{ .name = "spu_run", },
	{ .name = "spu_create", },
	{ .name = "pselect6", }, /* 280 */
	{ .name = "ppoll", },
	{ .name = "unshare", },
	{ .name = "splice", .sanitise = sanitise_splice },
	{ .name = "tee", .sanitise = sanitise_tee },
	{ .name = "vmsplice", .sanitise = sanitise_vmsplice }, /* 285 */
	{ .name = "openat", },
	{ .name = "mkdirat", },
	{ .name = "mknodat", },
	{ .name = "fchownat", },
	{ .name = "futimesat", },	/* 290 */
	{ .name = "fstatat64", },
	{ .name = "unlinkat", },
	{ .name = "renameat", },
	{ .name = "linkat", },
	{ .name = "symlinkat", },	/* 295 */
	{ .name = "readlinkat", },
	{ .name = "fchmodat", },
	{ .name = "faccessat", },
	{ .name = "get_robust_list", },
	{ .name = "set_robust_list", .sanitise = sanitise_set_robust_list }, /* 300 */
};

