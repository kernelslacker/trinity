#pragma once

#include <sys/socket.h>
#include <netinet/in.h>		/* IPPROTO_*, IP_*, IPV6_* enum members */
#include <linux/types.h>
#if __has_include(<linux/fs.h>)
#include <linux/fs.h>
#endif

#include "kernel/mempolicy.h"


#include "kernel/socket.h"
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

/* asm/resource.h */
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME		15
#endif

/* sctp/user.h */
#ifndef SCTP_RTOINFO
#define SCTP_RTOINFO    0
#define SCTP_ASSOCINFO  1
#define SCTP_INITMSG    2
#define SCTP_NODELAY    3               /* Get/set nodelay option. */
#define SCTP_AUTOCLOSE  4
#define SCTP_SET_PEER_PRIMARY_ADDR 5
#define SCTP_PRIMARY_ADDR       6
#define SCTP_ADAPTATION_LAYER   7
#define SCTP_DISABLE_FRAGMENTS  8
#define SCTP_PEER_ADDR_PARAMS   9
#define SCTP_DEFAULT_SEND_PARAM 10
#define SCTP_EVENTS     11
#define SCTP_I_WANT_MAPPED_V4_ADDR 12   /* Turn on/off mapped v4 addresses  */
#define SCTP_MAXSEG     13              /* Get/set maximum fragment. */
#define SCTP_STATUS     14
#define SCTP_GET_PEER_ADDR_INFO 15
#define SCTP_DELAYED_ACK_TIME   16
#define SCTP_CONTEXT    17
#define SCTP_FRAGMENT_INTERLEAVE        18
#define SCTP_PARTIAL_DELIVERY_POINT     19 /* Set/Get partial delivery point */
#define SCTP_MAX_BURST  20              /* Set/Get max burst */
#define SCTP_AUTH_CHUNK 21      /* Set only: add a chunk type to authenticate */
#define SCTP_HMAC_IDENT 22
#define SCTP_AUTH_KEY   23
#define SCTP_AUTH_ACTIVE_KEY    24
#define SCTP_AUTH_DELETE_KEY    25
#define SCTP_PEER_AUTH_CHUNKS   26      /* Read only */
#define SCTP_LOCAL_AUTH_CHUNKS  27      /* Read only */
#define SCTP_GET_ASSOC_NUMBER   28      /* Read only */
#define SCTP_GET_ASSOC_ID_LIST  29      /* Read only */
#define SCTP_AUTO_ASCONF       30
#define SCTP_PEER_ADDR_THLDS    31
#ifndef SCTP_RECVRCVINFO
#define SCTP_RECVRCVINFO	32
#define SCTP_RECVNXTINFO	33
#define SCTP_DEFAULT_SNDINFO	34
#define SCTP_AUTH_DEACTIVATE_KEY	35
#define SCTP_REUSE_PORT		36
#define SCTP_PEER_ADDR_THLDS_V2	37
#endif
#endif

#ifndef SCTP_SOCKOPT_BINDX_ADD
#define SCTP_SOCKOPT_BINDX_ADD  100     /* BINDX requests for adding addrs */
#define SCTP_SOCKOPT_BINDX_REM  101     /* BINDX requests for removing addrs. */
#define SCTP_SOCKOPT_PEELOFF    102     /* peel off association. */
#define SCTP_SOCKOPT_CONNECTX_OLD       107     /* CONNECTX old requests. */
#define SCTP_GET_PEER_ADDRS     108             /* Get all peer address. */
#define SCTP_GET_LOCAL_ADDRS    109             /* Get all local address. */
#define SCTP_SOCKOPT_CONNECTX   110             /* CONNECTX requests. */
#define SCTP_SOCKOPT_CONNECTX3  111     /* CONNECTX requests (updated) */
#define SCTP_GET_ASSOC_STATS    112	/* Read only */
#ifndef SCTP_PR_SUPPORTED
#define SCTP_PR_SUPPORTED		113
#define SCTP_DEFAULT_PRINFO		114
#define SCTP_PR_ASSOC_STATUS		115
#define SCTP_PR_STREAM_STATUS		116
#define SCTP_RECONFIG_SUPPORTED		117
#define SCTP_ENABLE_STREAM_RESET	118
#define SCTP_RESET_STREAMS		119
#define SCTP_RESET_ASSOC		120
#define SCTP_ADD_STREAMS		121
#define SCTP_SOCKOPT_PEELOFF_FLAGS	122
#define SCTP_STREAM_SCHEDULER		123
#define SCTP_STREAM_SCHEDULER_VALUE	124
#define SCTP_INTERLEAVING_SUPPORTED	125
#define SCTP_SENDMSG_CONNECT		126
#define SCTP_EVENT			127
#define SCTP_ASCONF_SUPPORTED		128
#define SCTP_AUTH_SUPPORTED		129
#define SCTP_ECN_SUPPORTED		130
#define SCTP_EXPOSE_POTENTIALLY_FAILED_STATE	131
#define SCTP_REMOTE_UDP_ENCAPS_PORT	132
#define SCTP_PLPMTUD_PROBE_INTERVAL	133
#endif
#endif

/* net/bluetooth/bluetooth.h */
#ifndef BT_SECURITY
#define BT_SECURITY     4
#define BT_DEFER_SETUP  7
#define BT_FLUSHABLE    8
#define BT_POWER        9
#define BT_CHANNEL_POLICY       10

#define SOL_HCI         0
#define SOL_L2CAP       6
#define SOL_SCO         17
#define SOL_RFCOMM      18
#endif

/* linux/mptcp.h - SOL_MPTCP optnames (getsockopt only in current kernels;
 * setsockopt at SOL_MPTCP returns -EOPNOTSUPP, but the dispatch path still
 * runs, and getsockopt re-uses do_setsockopt to populate level/optname).
 */
#ifndef MPTCP_INFO
#define MPTCP_INFO		1
#define MPTCP_TCPINFO		2
#define MPTCP_SUBFLOW_ADDRS	3
#define MPTCP_FULL_INFO		4
#endif

/* linux/udp.h -- UDP_SEGMENT is the SOL_UDP setsockopt/cmsg knob that
 * configures UDP GSO segment size on a sending socket.  Older kernel-
 * headers packages predate the constant; the UAPI value (103) is fixed
 * since UDP GSO landed in 4.18. */
#ifndef UDP_SEGMENT
#define UDP_SEGMENT		103
#endif

/* net/bluetooth/hci.h */
#ifndef HCI_DATA_DIR
#define HCI_DATA_DIR    1
#define HCI_FILTER      2
#define HCI_TIME_STAMP  3
#endif

/* net/bluetooth/l2cap.h */
#ifndef L2CAP_OPTIONS
#define L2CAP_OPTIONS   0x01
#define L2CAP_LM        0x03
#endif

/* net/bluetooth/rfcomm.h */
#ifndef RFCOMM_LM
#define RFCOMM_LM       0x03
#endif

/* net/iucv/af_iucv.h */
#ifndef SO_IPRMDATA_MSG
#define SO_IPRMDATA_MSG 0x0080          /* send/recv IPRM_DATA msgs */
#define SO_MSGLIMIT     0x1000          /* get/set IUCV MSGLIMIT */
#define SO_MSGSIZE      0x0800          /* get maximum msgsize */
#endif

/* linux/inotify.h */
#ifndef IN_EXCL_UNLINK
#define IN_EXCL_UNLINK	0x04000000	/* exclude events on unlinked objects */
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

/* linux/kvm.h */
#ifndef KVMIO
#define KVMIO 0xAE
#endif
#ifndef KVM_GET_REG_LIST
struct kvm_reg_list {
        __u64 n; /* number of regs */
        __u64 reg[0];
};
#define KVM_GET_REG_LIST          _IOWR(KVMIO, 0xb0, struct kvm_reg_list)
#endif

#ifndef KVM_S390_UCAS_MAP
struct kvm_s390_ucas_mapping {
        __u64 user_addr;
        __u64 vcpu_addr;
        __u64 length;
};
#define KVM_S390_UCAS_MAP         _IOW(KVMIO, 0x50, struct kvm_s390_ucas_mapping)
#endif

#ifndef KVM_S390_UCAS_UNMAP
#define KVM_S390_UCAS_UNMAP       _IOW(KVMIO, 0x51, struct kvm_s390_ucas_mapping)
#endif

#ifndef KVM_S390_VCPU_FAULT
#define KVM_S390_VCPU_FAULT       _IOW(KVMIO, 0x52, unsigned long)
#endif

#ifndef KVM_XEN_HVM_CONFIG
struct kvm_xen_hvm_config {
	__u32 flags;
	__u32 msr;
	__u64 blob_addr_32;
	__u64 blob_addr_64;
	__u8 blob_size_32;
	__u8 blob_size_64;
	__u8 pad2[30];
};
#define KVM_XEN_HVM_CONFIG        _IOW(KVMIO,  0x7a, struct kvm_xen_hvm_config)
#endif

#ifndef KVM_PPC_GET_PVINFO
struct kvm_ppc_pvinfo {
	/* out */
	__u32 flags;
	__u32 hcall[4];
	__u8  pad[108];
};
#define KVM_PPC_GET_PVINFO        _IOW(KVMIO,  0xa1, struct kvm_ppc_pvinfo)
#endif

#ifndef KVM_SET_TSC_KHZ
#define KVM_SET_TSC_KHZ           _IO(KVMIO,  0xa2)
#endif

#ifndef KVM_GET_TSC_KHZ
#define KVM_GET_TSC_KHZ           _IO(KVMIO,  0xa3)
#endif

#ifndef KVM_GET_DEBUGREGS
struct kvm_debugregs {
	__u64 db[4];
	__u64 dr6;
	__u64 dr7;
	__u64 flags;
	__u64 reserved[9];
};
#define KVM_GET_DEBUGREGS         _IOR(KVMIO,  0xa1, struct kvm_debugregs)
#define KVM_SET_DEBUGREGS         _IOW(KVMIO,  0xa2, struct kvm_debugregs)
#endif

#ifndef KVM_ENABLE_CAP
struct kvm_enable_cap {
	/* in */
	__u32 cap;
	__u32 flags;
	__u64 args[4];
	__u8  pad[64];
};
#define KVM_ENABLE_CAP            _IOW(KVMIO,  0xa3, struct kvm_enable_cap)
#endif

#ifndef KVM_GET_XSAVE
struct kvm_xsave {
	__u32 region[1024];
};
#define KVM_GET_XSAVE             _IOR(KVMIO,  0xa4, struct kvm_xsave)
#define KVM_SET_XSAVE             _IOW(KVMIO,  0xa5, struct kvm_xsave)
#endif

#ifndef KVM_GET_XCRS
#define KVM_MAX_XCRS    16
struct kvm_xcr {
	__u32 xcr;
	__u32 reserved;
	__u64 value;
};

struct kvm_xcrs {
	__u32 nr_xcrs;
	__u32 flags;
	struct kvm_xcr xcrs[KVM_MAX_XCRS];
	__u64 padding[16];
};
#define KVM_GET_XCRS              _IOR(KVMIO,  0xa6, struct kvm_xcrs)
#define KVM_SET_XCRS              _IOW(KVMIO,  0xa7, struct kvm_xcrs)
#endif

#ifndef KVM_SIGNAL_MSI
struct kvm_msi {
        __u32 address_lo;
        __u32 address_hi;
        __u32 data;
        __u32 flags;
        __u32 devid;
        __u8  pad[12];
};
#define KVM_SIGNAL_MSI            _IOW(KVMIO,  0xa5, struct kvm_msi)
#endif

#ifndef KVM_DIRTY_TLB
struct kvm_dirty_tlb {
        __u64 bitmap;
        __u32 num_dirty;
};
#define KVM_DIRTY_TLB             _IOW(KVMIO,  0xaa, struct kvm_dirty_tlb)
#endif

#ifndef KVM_GET_ONE_REG
struct kvm_one_reg {
        __u64 id;
        __u64 addr;
};
#define KVM_GET_ONE_REG           _IOW(KVMIO,  0xab, struct kvm_one_reg)
#endif

#ifndef KVM_SET_ONE_REG
#define KVM_SET_ONE_REG           _IOW(KVMIO,  0xac, struct kvm_one_reg)
#endif

#ifndef KVM_KVMCLOCK_CTRL
#define KVM_KVMCLOCK_CTRL         _IO(KVMIO,   0xad)
#endif

#ifndef KVM_PPC_GET_SMMU_INFO
#define KVM_PPC_PAGE_SIZES_MAX_SZ	8

struct kvm_ppc_one_page_size {
	__u32 page_shift;	/* Page shift (or 0) */
	__u32 pte_enc;		/* Encoding in the HPTE (>>12) */
};

struct kvm_ppc_one_seg_page_size {
	__u32 page_shift;	/* Base page shift of segment (or 0) */
	__u32 slb_enc;		/* SLB encoding for BookS */
	struct kvm_ppc_one_page_size enc[KVM_PPC_PAGE_SIZES_MAX_SZ];
};

struct kvm_ppc_smmu_info {
	__u64 flags;
	__u32 slb_size;
	__u16 data_keys;
	__u16 instr_keys;
	struct kvm_ppc_one_seg_page_size sps[KVM_PPC_PAGE_SIZES_MAX_SZ];
};
#define KVM_PPC_GET_SMMU_INFO	  _IOR(KVMIO,  0xa6, struct kvm_ppc_smmu_info)
#endif

#ifndef KVM_PPC_ALLOCATE_HTAB
#define KVM_PPC_ALLOCATE_HTAB	  _IOWR(KVMIO, 0xa7, __u32)
#endif

#ifndef KVM_PPC_GET_HTAB_FD
struct kvm_get_htab_fd {
	__u64	flags;
	__u64	start_index;
	__u64	reserved[2];
};
#define KVM_PPC_GET_HTAB_FD	  _IOW(KVMIO,  0xaa, struct kvm_get_htab_fd)
#endif

/* linux/mroute.h */
#ifndef MRT_TABLE
#define MRT_TABLE		(MRT_BASE+9)
#endif
#ifndef MRT_ADD_MFC_PROXY
#define MRT_ADD_MFC_PROXY	(MRT_BASE+10)
#endif
#ifndef MRT_DEL_MFC_PROXY
#define MRT_DEL_MFC_PROXY	(MRT_BASE+11)
#endif

/* sys/mount.h */
#ifndef MNT_DETACH
#define MNT_DETACH		2
#endif

#ifndef MNT_EXPIRE
#define MNT_EXPIRE		4
#endif

#ifndef UMOUNT_NOFOLLOW
#define UMOUNT_NOFOLLOW		8
#endif

/* if_ether.h */
#ifndef ETH_P_CANFD
#define ETH_P_CANFD	0x000D
#endif
#ifndef ETH_P_CAIF
#define ETH_P_CAIF	0x00F7
#endif
#ifndef ETH_P_802_3_MIN
#define ETH_P_802_3_MIN	0x0600
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

/* sched.h */
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif

/* linux/sched.h — CLONE_NEWCGROUP selects the cgroup namespace for
 * clone(2)/clone3(2)/unshare(2)/setns(2)/listns(2).  Older kernel-headers
 * packages predate the constant; the UAPI value (0x02000000) is fixed
 * since the cgroup namespace landed in 4.6. */
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP 0x02000000
#endif

/* linux/sched.h — CLONE_NEWTIME selects the time namespace for
 * clone(2)/clone3(2)/unshare(2)/setns(2)/listns(2).  Older kernel-headers
 * packages predate the constant; the UAPI value (0x00000080) has been
 * fixed since the time namespace landed in 5.6. */
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

/* signal.h */
#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
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
