#pragma once

#include <sys/socket.h>
#include <netinet/in.h>		/* IPPROTO_*, IP_*, IPV6_* enum members */
#include <linux/types.h>
#if __has_include(<linux/fs.h>)
#include <linux/fs.h>
#endif

#include "kernel/mempolicy.h"

#include "kernel/gtp.h"

#include "kernel/macsec.h"

#include "kernel/veth.h"

/* sys/epoll.h */
#ifndef EPOLLWAKEUP
#define EPOLLWAKEUP (1u << 29)
#endif

/* time.h */
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 4
#endif
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif
#ifndef CLOCK_REALTIME_ALARM
#define CLOCK_REALTIME_ALARM 8
#endif
#ifndef CLOCK_BOOTTIME_ALARM
#define CLOCK_BOOTTIME_ALARM 9
#endif
#ifndef CLOCK_TAI
#define CLOCK_TAI 11
#endif

/* asm-generic/poll.h */
#ifndef POLLFREE
#define POLLFREE 0x4000
#endif
#ifndef POLL_BUSY_LOOP
#define POLL_BUSY_LOOP 0x8000
#endif

/* linux/nvme_ioctl.h */
#ifndef NVME_IOCTL_RESET
#define NVME_IOCTL_RESET _IO('N', 0x44)
#endif

/* linux/sem.h */
#ifndef SEMVMX
/* Maximum value semval may take; <= 32767 per uapi linux/sem.h. */
#define SEMVMX			32767
#endif

/* linux/shm.h */
#ifndef SHM_HUGE_SHIFT
#define SHM_HUGE_SHIFT  26
#endif
#ifndef SHM_HUGE_2MB
#define SHM_HUGE_2MB	(21 << SHM_HUGE_SHIFT)
#define SHM_HUGE_1GB	(30 << SHM_HUGE_SHIFT)
#endif

/* bits/shm.h */
#ifndef SHM_NORESERVE
# define SHM_NORESERVE 010000
#endif

/* linux/mount.h */
#ifndef MOVE_MOUNT_F_SYMLINKS
#define MOVE_MOUNT_F_SYMLINKS           0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS         0x00000002 /* Follow automounts on from path */
#define MOVE_MOUNT_F_EMPTY_PATH         0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS           0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS         0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH         0x00000040 /* Empty to path permitted */
#endif
#ifndef MOVE_MOUNT_SET_GROUP
#define MOVE_MOUNT_SET_GROUP		0x00000100
#endif
#ifndef MOVE_MOUNT_BENEATH
#define MOVE_MOUNT_BENEATH		0x00000200
#endif
#ifndef MOUNT_ATTR_RDONLY
#define MOUNT_ATTR_RDONLY	0x00000001
#define MOUNT_ATTR_NOSUID	0x00000002
#define MOUNT_ATTR_NODEV	0x00000004
#define MOUNT_ATTR_NOEXEC	0x00000008
#define MOUNT_ATTR__ATIME	0x00000070
#define MOUNT_ATTR_RELATIME	0x00000000
#define MOUNT_ATTR_NOATIME	0x00000010
#define MOUNT_ATTR_STRICTATIME	0x00000020
#define MOUNT_ATTR_NODIRATIME	0x00000080
#define MOUNT_ATTR_IDMAP	0x00100000
#define MOUNT_ATTR_NOSYMFOLLOW	0x00200000
#endif

/* asm/unistd.h */
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter	426
#endif
