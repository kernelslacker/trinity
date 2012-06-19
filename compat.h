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

#ifndef PERF_COUNT_SW_ALIGNMENT_FAULTS
#define PERF_COUNT_SW_ALIGNMENT_FAULTS 7
#endif
#ifndef PERF_COUNT_SW_EMULATION_FAULTS
#define PERF_COUNT_SW_EMULATION_FAULTS 8
#endif

#ifndef PERF_TYPE_BREAKPOINT
#define PERF_TYPE_BREAKPOINT 5
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

#ifndef MADV_HUGEPAGE
#define MADV_HUGEPAGE 14
#endif
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif


/* bits/socket.h */
#ifndef AF_NFC
#define AF_NFC		39
#endif

#ifndef NFC_SOCKPROTO_RAW
#define NFC_SOCKPROTO_RAW	0
#endif
#ifndef NFC_SOCKPROTO_LLCP
#define NFC_SOCKPROTO_LLCP	1
#endif

#ifndef MSG_WAITFORONE
#define MSG_WAITFORONE	0x10000
#endif


/* linux/net.h */
#ifndef SYS_RECVMMSG
#define SYS_RECVMMSG 19
#endif
#ifndef SYS_SENDMMSG
#define SYS_SENDMMSG 20
#endif

/* asm/ptrace-abi.h */
#ifndef PTRACE_SYSEMU
#define PTRACE_SYSEMU		  31
#endif
#ifndef PTRACE_SYSEMU_SINGLESTEP
#define PTRACE_SYSEMU_SINGLESTEP  32
#endif

/* sys/timerfd.h */
#ifndef TFD_CLOEXEC
#define TFD_CLOEXEC 02000000
#endif
#ifndef TFD_NONBLOCK
#define TFD_NONBLOCK 04000
#endif

/* linux/keyctl.h */
#ifndef KEYCTL_GET_KEYRING_ID
#define KEYCTL_GET_KEYRING_ID		0	/* ask for a keyring's ID */
#define KEYCTL_JOIN_SESSION_KEYRING	1	/* join or start named session keyring */
#define KEYCTL_UPDATE			2	/* update a key */
#define KEYCTL_REVOKE			3	/* revoke a key */
#define KEYCTL_CHOWN			4	/* set ownership of a key */
#define KEYCTL_SETPERM			5	/* set perms on a key */
#define KEYCTL_DESCRIBE			6	/* describe a key */
#define KEYCTL_CLEAR			7	/* clear contents of a keyring */
#define KEYCTL_LINK			8	/* link a key into a keyring */
#define KEYCTL_UNLINK			9	/* unlink a key from a keyring */
#define KEYCTL_SEARCH			10	/* search for a key in a keyring */
#define KEYCTL_READ			11	/* read a key or keyring's contents */
#define KEYCTL_INSTANTIATE		12	/* instantiate a partially constructed key */
#define KEYCTL_NEGATE			13	/* negate a partially constructed key */
#define KEYCTL_SET_REQKEY_KEYRING	14	/* set default request-key keyring */
#define KEYCTL_SET_TIMEOUT		15	/* set key timeout */
#define KEYCTL_ASSUME_AUTHORITY		16	/* assume request_key() authorisation */
#define KEYCTL_GET_SECURITY		17	/* get key security label */
#define KEYCTL_SESSION_TO_PARENT	18	/* apply session keyring to parent process */
#define KEYCTL_REJECT			19	/* reject a partially constructed key */
#define KEYCTL_INSTANTIATE_IOV		20	/* instantiate a partially constructed key */
#endif

#ifndef KCMP_TYPES
enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,

	KCMP_TYPES,
};
#endif

#endif	/* _TRINITY_COMPAT_H */
