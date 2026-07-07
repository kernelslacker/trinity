#pragma once

#include <sys/socket.h>
#include <netinet/in.h>		/* IPPROTO_*, IP_*, IPV6_* enum members */
#include <linux/types.h>
#if __has_include(<linux/fs.h>)
#include <linux/fs.h>
#endif

#include "kernel/mempolicy.h"


#include "kernel/socket.h"
#include "kernel/sched.h"
#include "kernel/swap.h"
/* linux/if_packet.h */
#ifndef PACKET_VNET_HDR
#define PACKET_VNET_HDR		15
#endif

#ifndef PACKET_TX_TIMESTAMP
#define PACKET_TX_TIMESTAMP	16
#endif

#ifndef PACKET_TIMESTAMP
#define PACKET_TIMESTAMP	17
#endif

#ifndef PACKET_FANOUT
#define PACKET_FANOUT		18
#endif

#ifndef PACKET_FANOUT_FLAG_ROLLOVER
#define PACKET_FANOUT_FLAG_ROLLOVER	0x1000
#endif
#ifndef PACKET_FANOUT_FLAG_UNIQUEID
#define PACKET_FANOUT_FLAG_UNIQUEID	0x2000
#endif
#ifndef PACKET_FANOUT_FLAG_DEFRAG
#define PACKET_FANOUT_FLAG_DEFRAG	0x8000
#endif

#ifndef UDPLITE_RECV_CSCOV
#define UDPLITE_RECV_CSCOV   11 /* receiver partial coverage (threshold ) */
#endif

#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL		36
#endif

#ifndef MSG_COPY
#define MSG_COPY        040000
#endif

#ifndef MS_NOSEC
#define MS_NOSEC        (1<<28)
#endif

#ifndef MS_BORN
#define MS_BORN		(1<<29)
#endif

#ifndef ETH_P_BATMAN
#define ETH_P_BATMAN	0x4305
#endif
#ifndef ETH_P_LINK_CTL
#define ETH_P_LINK_CTL	0x886c
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD	0x88A8
#endif
#ifndef ETH_P_802_EX1
#define ETH_P_802_EX1	0x88B5
#endif
#ifndef ETH_P_8021AH
#define ETH_P_8021AH	0x88E7
#endif
#ifndef ETH_P_MVRP
#define ETH_P_MVRP	0x88F5
#endif
#ifndef ETH_P_PRP
#define ETH_P_PRP	0x88FB
#endif
#ifndef ETH_P_TDLS
#define ETH_P_TDLS	0x890D
#endif
#ifndef ETH_P_QINQ1
#define ETH_P_QINQ1	0x9100
#endif
#ifndef ETH_P_QINQ2
#define ETH_P_QINQ2	0x9200
#endif
#ifndef ETH_P_QINQ3
#define ETH_P_QINQ3	0x9300
#endif
#ifndef ETH_P_AF_IUCV
#define ETH_P_AF_IUCV	0xFBFB
#endif

#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif

/* sys/swap.h */
#ifndef SWAP_FLAG_DISCARD
#define SWAP_FLAG_DISCARD 0x10000
#endif

/* linux/fs.h */
#ifndef SEEK_DATA
#define SEEK_DATA 3
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE 4
#endif
#ifndef RWF_HIPRI
#define RWF_HIPRI 0x00000001 /* high priority request, poll if possible */
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC 0x00000002 /* per-IO O_DSYNC */
#define RWF_SYNC  0x00000004 /* per-IO O_SYNC */
#endif
#ifndef RWF_NOWAIT
#define RWF_NOWAIT 0x00000008 /* per-IO, return -EAGAIN if blocking would happen */
#endif
#ifndef RWF_APPEND
#define RWF_APPEND 0x00000010 /* per-IO O_APPEND */
#endif
#ifndef RWF_NOAPPEND
#define RWF_NOAPPEND 0x00000020 /* per-IO negation of O_APPEND */
#endif
#ifndef RWF_ATOMIC
#define RWF_ATOMIC 0x00000040 /* per-IO atomic write */
#endif
#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE 0x00000080 /* buffered IO that drops the cache after use */
#endif
#ifndef RWF_NOSIGNAL
#define RWF_NOSIGNAL 0x00000100 /* do not raise SIGPIPE on pipe write */
#endif

/*
 * file_getattr()/file_setattr() (Linux 6.13+) uAPI.  Older system
 * headers ship neither the struct nor the trailing FS_XFLAG bit; the
 * syscall itself may still be present on the running kernel and the
 * sanitiser/oracle code wants the layout regardless.  Guard on the
 * size constant that lands in the same uapi block so we don't redefine
 * when the headers are recent enough.
 */
#ifndef FILE_ATTR_SIZE_VER0
struct file_attr {
	__u64 fa_xflags;	/* xflags field value (get/set) */
	__u32 fa_extsize;	/* extsize field value (get/set) */
	__u32 fa_nextents;	/* nextents field value (get) */
	__u32 fa_projid;	/* project identifier (get/set) */
	__u32 fa_cowextsize;	/* CoW extsize field value (get/set) */
};
#define FILE_ATTR_SIZE_VER0	24
#define FILE_ATTR_SIZE_LATEST	FILE_ATTR_SIZE_VER0
#endif

#ifndef FS_XFLAG_HASATTR
#define FS_XFLAG_HASATTR	0x80000000
#endif

/* linux/wait.h -- GNU-extension wait options, used by wait4/waitpid/waitid */
#ifndef __WNOTHREAD
#define __WNOTHREAD 0x20000000
#endif
#ifndef __WALL
#define __WALL      0x40000000
#endif
#ifndef __WCLONE
#define __WCLONE    0x80000000
#endif

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
