/* Syscalls from include/asm-x86_64/unistd.h as of 2.6.17rc1 */

#include "scrashme.h"
#include "sanitise.h"

#define NR_SYSCALLS 278

struct syscalltable syscalls_x86_64[NR_SYSCALLS+1] = {
	{ .name = "read", .sanitise = sanitise_read },		/* 0 */
	{ .name = "write", .sanitise = sanitise_write },
	{ .name = "open" },
	{ .name = "close", .sanitise = sanitise_close },
	{ .name = "newstat" },
	{ .name = "newfstat", .sanitise = sanitise_newfstat },	/* 5 */
	{ .name = "newlstat" },
	{ .name = "poll" },
	{ .name = "lseek", .sanitise = sanitise_lseek },
	{ .name = "mmap", .sanitise = sanitise_mmap },
	{ .name = "mprotect", .sanitise = sanitise_mprotect },	/* 10 */
	{ .name = "munmap" },
	{ .name = "brk" },
	{ .name = "rt_sigaction", .sanitise = sanitise_rt_sigaction },
	{ .name = "rt_sigprocmask", .sanitise = sanitise_rt_sigprocmask },
	{ .name = "rt_sigreturn", .flags = AVOID_SYSCALL },	/* 15 */
	{ .name = "ioctl", .sanitise = sanitise_ioctl },
	{ .name = "pread64", .sanitise = sanitise_pread64 },
	{ .name = "pwrite64", .sanitise = sanitise_pwrite64 },
	{ .name = "readv", .sanitise = sanitise_readv },
	{ .name = "writev", .sanitise = sanitise_writev },	/* 20 */
	{ .name = "access" },
	{ .name = "pipe" },
	{ .name = "select", .flags = AVOID_SYSCALL },
	{ .name = "sched_yield" },
	{ .name = "mremap", .sanitise = sanitise_mremap },	/* 25 */
	{ .name = "msync" },
	{ .name = "mincore" },
	{ .name = "madvise" },
	{ .name = "shmget" },
	{ .name = "shmat" },	/* 30 */
	{ .name = "shmctl" },
	{ .name = "dup" },
	{ .name = "dup2" },
	{ .name = "pause" },
	{ .name = "nanosleep" },	/* 35 */
	{ .name = "getitimer" },
	{ .name = "alarm" },
	{ .name = "setitimer" },
	{ .name = "getpid" },
	{ .name = "sendfile" },	/* 40 */
	{ .name = "socket" },
	{ .name = "connect" },
	{ .name = "accept" },
	{ .name = "sendto" },
	{ .name = "recvfrom" },	/* 45 */
	{ .name = "sendmsg" },
	{ .name = "recvmsg" },
	{ .name = "shutdown" },
	{ .name = "bind" },
	{ .name = "listen" },	/* 50 */
	{ .name = "getsockname" },
	{ .name = "getpeername" },
	{ .name = "socketpair" },
	{ .name = "setsockopt" },
	{ .name = "getsockopt" },	/* 55 */
	{ .name = "clone", .flags = AVOID_SYSCALL },
	{ .name = "fork", .flags = AVOID_SYSCALL },
	{ .name = "vfork", .flags = AVOID_SYSCALL },
	{ .name = "execve" },
	{ .name = "exit", .flags = AVOID_SYSCALL },	/* 60 */
	{ .name = "wait4" },
	{ .name = "kill" },
	{ .name = "uname" },
	{ .name = "semget" },
	{ .name = "semop" },	/* 65 */
	{ .name = "semctl" },
	{ .name = "shmdt" },
	{ .name = "msgget" },
	{ .name = "msgsnd" },
	{ .name = "msgrcv" },	/* 70 */
	{ .name = "msgctl" },
	{ .name = "fcntl" },
	{ .name = "flock" },
	{ .name = "fsync" },
	{ .name = "fdatasync" },	/* 75 */
	{ .name = "truncate" },
	{ .name = "ftruncate" },
	{ .name = "getdents" },
	{ .name = "getcwd" },
	{ .name = "chdir" },	/* 80 */
	{ .name = "fchdir" },
	{ .name = "rename" },
	{ .name = "mkdir" },
	{ .name = "rmdir" },
	{ .name = "creat" },	/* 85 */
	{ .name = "link" },
	{ .name = "unlink" },
	{ .name = "symlink" },
	{ .name = "readlink" },
	{ .name = "chmod" },	/* 90 */
	{ .name = "fchmod" },
	{ .name = "chown" },
	{ .name = "fchown" },
	{ .name = "lchown" },
	{ .name = "umask" },	/* 95 */
	{ .name = "gettimeofday" },
	{ .name = "getrlimit" },
	{ .name = "getrusage" },
	{ .name = "sysinfo" },
	{ .name = "times" },	/* 100 */
	{ .name = "ptrace" },
	{ .name = "getuid" },
	{ .name = "syslog" },
	{ .name = "getgid" },
	{ .name = "setuid" },	/* 105 */
	{ .name = "setgid" },
	{ .name = "geteuid" },
	{ .name = "getegid" },
	{ .name = "setpgid" },
	{ .name = "getppid" },	/* 110 */
	{ .name = "getpgrp" },
	{ .name = "setsid" },
	{ .name = "setreuid" },
	{ .name = "setregid" },
	{ .name = "getgroups" },	/* 115 */
	{ .name = "setgroups" },
	{ .name = "setresuid" },
	{ .name = "getresuid" },
	{ .name = "setresgid" },
	{ .name = "getresgid" },	/* 120 */
	{ .name = "getpgid" },
	{ .name = "setfsuid" },
	{ .name = "setfsgid" },
	{ .name = "getsid" },
	{ .name = "capget" },	/* 125 */
	{ .name = "capset" },
	{ .name = "rt_sigpending" },
	{ .name = "rt_sigtimedwait" },
	{ .name = "rt_sigqueueinfo" },
	{ .name = "rt_sigsuspend" },	/* 130 */
	{ .name = "sigaltstack" },
	{ .name = "utime" },
	{ .name = "mknod" },
	{ .name = "ni_syscall (uselib)" },
	{ .name = "personality" },	/* 135 */
	{ .name = "ustat" },
	{ .name = "statfs" },
	{ .name = "fstatfs" },
	{ .name = "sysfs" },
	{ .name = "getpriority" },	/* 140 */
	{ .name = "setpriority" },
	{ .name = "sched_setparam" },
	{ .name = "sched_getparam" },
	{ .name = "sched_setscheduler" },
	{ .name = "sched_getscheduler" },	/* 145 */
	{ .name = "sched_get_priority_max" },
	{ .name = "sched_get_priority_min" },
	{ .name = "sched_rr_get_interval" },
	{ .name = "mlock", },
	{ .name = "munlock" },	/* 150 */
	{ .name = "mlockall", },
	{ .name = "munlockall" },
	{ .name = "vhangup", .flags = CAPABILITY_CHECK, },
	{ .name = "modify_ldt" },
	{ .name = "pivot_root", .flags = CAPABILITY_CHECK, },	/* 155 */
	{ .name = "sysctl" },
	{ .name = "prctl" },
	{ .name = "arch_prctl" },
	{ .name = "adjtimex", },
	{ .name = "setrlimit", },	/* 160 */
	{ .name = "chroot", },
	{ .name = "sync" },
	{ .name = "acct" },
	{ .name = "settimeofday" },
	{ .name = "mount", },	/* 165 */
	{ .name = "umount", },
	{ .name = "swapon", },
	{ .name = "swapoff", },
	{ .name = "reboot", .flags = CAPABILITY_CHECK, },
	{ .name = "sethostname", .flags = CAPABILITY_CHECK, },	/* 170 */
	{ .name = "setdomainname", .flags = CAPABILITY_CHECK, },
	{ .name = "iopl", },
	{ .name = "ioperm" },
	{ .name = "ni_syscall (create_module)" },
	{ .name = "init_module", .flags = CAPABILITY_CHECK, },	/* 175 */
	{ .name = "delete_module", .flags = CAPABILITY_CHECK, },
	{ .name = "ni_syscall (get_kernel_syms)" },
	{ .name = "ni_syscall (query_module)" },
	{ .name = "quotactl" },
	{ .name = "nfsservctl" },	/* 180 */
	{ .name = "ni_syscall (getpmsg)" },
	{ .name = "ni_syscall (putpmsg)" },
	{ .name = "ni_syscall (afs)" },
	{ .name = "ni_syscall (tux)" },
	{ .name = "ni_syscall (security)" },	/* 185 */
	{ .name = "gettid" },
	{ .name = "readahead" },
	{ .name = "setxattr" },
	{ .name = "lsetxattr" },
	{ .name = "fsetxattr" },	/* 190 */
	{ .name = "getxattr" },
	{ .name = "lgetxattr" },
	{ .name = "fgetxattr" },
	{ .name = "listxattr" },
	{ .name = "llistxattr" },	/* 195 */
	{ .name = "flistxattr" },
	{ .name = "removexattr" },
	{ .name = "lremovexattr" },
	{ .name = "fremovexattr" },
	{ .name = "tkill" },	/* 200 */
	{ .name = "time" },
	{ .name = "futex" },
	{ .name = "sched_setaffinity" },
	{ .name = "sched_getaffinity" },
	{ .name = "ni_syscall (set_thread_area)" },	/* 205 */
	{ .name = "io_setup" },
	{ .name = "io_destroy" },
	{ .name = "io_getevents" },
	{ .name = "io_submit" },
	{ .name = "io_cancel" },	/* 210 */
	{ .name = "ni_syscall (get_thread_area)" },
	{ .name = "lookup_dcookie" },
	{ .name = "epoll_create" },
	{ .name = "ni_syscall (epoll_ctl_old)" },
	{ .name = "ni_syscall (epoll_wait_old)" },	/* 215 */
	{ .name = "remap_file_pages" },
	{ .name = "getdents64" },
	{ .name = "set_tid_address" },
	{ .name = "restart_syscall" },
	{ .name = "semtimedop" },	/* 220 */
	{ .name = "fadvise64" },
	{ .name = "timer_create" },
	{ .name = "timer_settime" },
	{ .name = "timer_gettime" },
	{ .name = "timer_getoverrun" },	/* 225 */
	{ .name = "timer_delete" },
	{ .name = "clock_settime" },
	{ .name = "clock_gettime" },
	{ .name = "clock_retres" },
	{ .name = "clock_nanosleep" },	/* 230 */
	{ .name = "exit_group", .flags = AVOID_SYSCALL },
	{ .name = "epoll_wait" },
	{ .name = "epoll_ctl" },
	{ .name = "tgkill" },
	{ .name = "utimes" },	/* 235 */
	{ .name = "ni_syscall (vserver)" },
	{ .name = "mbind" },
	{ .name = "set_mempolicy" },
	{ .name = "get_mempolicy" },
	{ .name = "mq_open" },	/* 240 */
	{ .name = "mq_unlink" },
	{ .name = "mq_timedsend" },
	{ .name = "mq_timedreceive" },
	{ .name = "mq_notify" },
	{ .name = "mq_getsetattr" },	/* 245 */
	{ .name = "kexec_load", .flags = CAPABILITY_CHECK, },
	{ .name = "waitid" },
	{ .name = "add_key" },
	{ .name = "request_key" },
	{ .name = "keyctl" },	/* 250 */
	{ .name = "ioprio_set" },
	{ .name = "ioprio_get" },
	{ .name = "inotify_init" },
	{ .name = "inotify_add_watch" },
	{ .name = "inotify_rm_watch" },	/* 255 */
	{ .name = "migrate_pages" },
	{ .name = "openat" },
	{ .name = "mkdirat" },
	{ .name = "mknodat" },
	{ .name = "fchownat" },	/* 260 */
	{ .name = "futimesat" },
	{ .name = "fstatat" },
	{ .name = "unlinkat" },
	{ .name = "renameat" },
	{ .name = "linkat" },	/* 265 */
	{ .name = "symlinkat" },
	{ .name = "readlinkat" },
	{ .name = "fchmodat" },
	{ .name = "faccessat" },
	{ .name = "pselect6" },	/* 270 */
	{ .name = "ppoll" },
	{ .name = "unshare" },
	{ .name = "set_robust_list", .sanitise = sanitise_set_robust_list },
	{ .name = "get_robust_list", },
	{ .name = "splice", .sanitise = sanitise_splice },	/* 275 */
	{ .name = "tee", .sanitise = sanitise_tee },
	{ .name = "sync_file_range", .sanitise = sanitise_sync_file_range },
	{ .name = "vmsplice", .sanitise = sanitise_vmsplice },
};
