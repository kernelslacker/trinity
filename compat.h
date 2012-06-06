#ifndef _TRINITY_COMPAT_H
#define _TRINITY_COMPAT_H 1

/* fcntl.h */
#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH           0x1000
#endif

#ifndef O_PATH
#define O_PATH        010000000 /* Resolve pathname but do not open file.  */
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC       02000000
#endif

#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

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


/* linux/perf_event.h */
#ifndef PERF_COUNT_HW_STALLED_CYCLES_FRONTEND
#define PERF_COUNT_HW_STALLED_CYCLES_FRONTEND 7
#endif
#ifndef PERF_COUNT_HW_STALLED_CYCLES_BACKEND
#define PERF_COUNT_HW_STALLED_CYCLES_BACKEND 8
#endif
#ifndef PERF_COUNT_HW_REF_CPU_CYCLES
#define PERF_COUNT_HW_REF_CPU_CYCLES 9
#endif

#ifndef PERF_FLAG_FD_NO_GROUP
#define PERF_FLAG_FD_NO_GROUP   (1U << 0)
#endif
#ifndef PERF_FLAG_FD_OUTPUT
#define PERF_FLAG_FD_OUTPUT     (1U << 1)
#endif
#ifndef PERF_FLAG_PID_CGROUP
#define PERF_FLAG_PID_CGROUP    (1U << 2) /* pid=cgroup id, per-cpu mode only */
#endif


/* asm-generic/mman-common.h */

#ifndef MAP_UNINITIALIZED
#define MAP_UNINITIALIZED 0x4000000
#endif
#ifndef PROT_SEM
#define PROT_SEM 0x8
#endif
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif
#ifndef MAP_STACK
#define MAP_STACK 0x20000
#endif


/* bits/socket.h */
#ifndef AF_NFC
#define AF_NFC		39
#endif

#endif	/* _TRINITY_COMPAT_H */
