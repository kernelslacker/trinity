#pragma once

#include <sys/socket.h>
#include <linux/socket.h>
#include <asm/socket.h>

/* bits/socket.h */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC	02000000
#endif

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK	04000
#endif

#ifndef PF_RDS
#define PF_RDS		21
#endif
#ifndef AF_RDS
#define AF_RDS		PF_RDS
#endif

#ifndef PF_LLC
#define PF_LLC		26
#endif
#ifndef AF_LLC
#define AF_LLC		PF_LLC
#endif

#ifndef AF_IB
#define AF_IB		27
#endif
#ifndef PF_IB
#define PF_IB          AF_IB
#endif

#ifndef PF_MPLS
#define PF_MPLS		28
#endif
#ifndef AF_MPLS
#define AF_MPLS		PF_MPLS
#endif

#ifndef PF_CAN
#define PF_CAN		29
#endif
#ifndef AF_CAN
#define AF_CAN		PF_CAN
#endif

#ifndef PF_TIPC
#define PF_TIPC		30
#endif
#ifndef AF_TIPC
#define AF_TIPC		PF_TIPC
#endif

#ifndef PF_PHONET
#define PF_PHONET	35
#endif
#ifndef AF_PHONET
#define AF_PHONET	PF_PHONET
#endif

#ifndef PF_IEEE802154
#define PF_IEEE802154	36
#endif
#ifndef AF_IEEE802154
#define AF_IEEE802154	PF_IEEE802154
#endif

#ifndef PF_CAIF
#define PF_CAIF		37
#endif
#ifndef AF_CAIF
#define AF_CAIF		PF_CAIF
#endif

#ifndef PF_ALG
#define PF_ALG		38
#endif
#ifndef AF_ALG
#define AF_ALG		PF_ALG
#endif
#ifndef ALG_SET_KEY
#define ALG_SET_KEY	1
#endif

#ifndef PF_NFC
#define PF_NFC		39
#endif
#ifndef AF_NFC
#define AF_NFC		PF_NFC
#endif

#ifndef PF_VSOCK
#define PF_VSOCK        40
#endif
#ifndef AF_VSOCK
#define AF_VSOCK PF_VSOCK
#endif

#ifndef PF_KCM
#define PF_KCM		41
#endif
#ifndef AF_KCM
#define AF_KCM		PF_KCM
#endif

#ifndef PF_QIPCRTR
#define PF_QIPCRTR	42
#endif
#ifndef AF_QIPCRTR
#define AF_QIPCRTR	PF_QIPCRTR
#endif

#ifndef PF_SMC
#define PF_SMC		43
#endif
#ifndef AF_SMC
#define AF_SMC		PF_SMC
#endif

#ifndef PF_XDP
#define PF_XDP		44
#endif
#ifndef AF_XDP
#define AF_XDP		PF_XDP
#endif

#ifndef PF_MCTP
#define PF_MCTP		45
#endif
#ifndef AF_MCTP
#define AF_MCTP		PF_MCTP
#endif

#ifndef MSG_WAITFORONE
#define MSG_WAITFORONE	0x10000
#endif

#ifndef MSG_BATCH
#define MSG_BATCH 0x40000
#endif

#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY	0x4000000
#endif

#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC	0x40000000
#endif

/* linux/socket.h */
#ifndef MSG_PROBE
#define MSG_PROBE 0x10
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif
#ifndef MSG_CMSG_COMPAT
#define MSG_CMSG_COMPAT 0x80000000
#endif

#include "kernel/gtp.h"

#include "kernel/macsec.h"

#include "kernel/veth.h"

#include "kernel/futex.h"
#include "kernel/ptrace.h"
#include "kernel/timerfd.h"
#include "kernel/mptcp.h"
#ifndef FUTEX2_SIZE_U16
#define FUTEX2_SIZE_U16		0x01
#endif
#ifndef FUTEX2_SIZE_U32
#define FUTEX2_SIZE_U32		0x02
#endif
#ifndef FUTEX2_SIZE_U64
#define FUTEX2_SIZE_U64		0x03
#endif
#ifndef FUTEX2_NUMA
#define FUTEX2_NUMA		0x04
#endif
#ifndef FUTEX2_MPOL
#define FUTEX2_MPOL		0x08
#endif
#ifndef FUTEX2_PRIVATE
#define FUTEX2_PRIVATE		0x80
#endif

/* asm/socket.h */
#ifndef SO_BSDCOMPAT
#define SO_BSDCOMPAT		14
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT		15
#endif

#ifndef SO_RXQ_OVFL
#define SO_RXQ_OVFL		40
#endif

#ifndef SO_WIFI_STATUS
#define SO_WIFI_STATUS		41
#endif

#ifndef SO_PEEK_OFF
#define SO_PEEK_OFF		42
#endif

#ifndef SO_NOFCS
#define SO_NOFCS		43
#endif

#ifndef SO_LOCK_FILTER
#define SO_LOCK_FILTER		44
#endif

#ifndef SO_SELECT_ERR_QUEUE
#define SO_SELECT_ERR_QUEUE	45
#endif

#ifndef SO_BUSY_POLL
#define SO_BUSY_POLL		46
#endif

#ifndef SO_MAX_PACING_RATE
#define SO_MAX_PACING_RATE	47
#endif

#ifndef SO_BPF_EXTENSIONS
#define SO_BPF_EXTENSIONS       48
#endif

#ifndef SO_INCOMING_CPU
#define SO_INCOMING_CPU		49
#endif

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF		50
#endif

#ifndef SO_ATTACH_REUSEPORT_CBPF
#define SO_ATTACH_REUSEPORT_CBPF 51
#define SO_ATTACH_REUSEPORT_EBPF 52
#endif

#ifndef SO_CNX_ADVICE
#define SO_CNX_ADVICE 53
#endif

#ifndef SCM_TIMESTAMPING_OPT_STATS
#define SCM_TIMESTAMPING_OPT_STATS      54
#endif

#ifndef SO_MEMINFO
#define SO_MEMINFO              55
#endif

#ifndef SO_INCOMING_NAPI_ID
#define SO_INCOMING_NAPI_ID     56
#endif

#ifndef SO_COOKIE
#define SO_COOKIE               57
#endif

#ifndef SCM_TIMESTAMPING_PKTINFO
#define SCM_TIMESTAMPING_PKTINFO        58
#endif

#ifndef SO_PEERGROUPS
#define SO_PEERGROUPS           59
#endif

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY	60
#endif

#ifndef SO_TXTIME
#define SO_TXTIME               61
#endif
#ifndef SO_BINDTOIFINDEX
#define SO_BINDTOIFINDEX        62
#endif
#ifndef SO_TIMESTAMP_NEW
#define SO_TIMESTAMP_NEW        63
#endif
#ifndef SO_TIMESTAMPNS_NEW
#define SO_TIMESTAMPNS_NEW      64
#endif
#ifndef SO_TIMESTAMPING_NEW
#define SO_TIMESTAMPING_NEW     65
#endif
#ifndef SO_RCVTIMEO_NEW
#define SO_RCVTIMEO_NEW         66
#endif
#ifndef SO_SNDTIMEO_NEW
#define SO_SNDTIMEO_NEW         67
#endif

#ifndef SO_DETACH_REUSEPORT_BPF
#define SO_DETACH_REUSEPORT_BPF 68
#endif

#ifndef SO_PREFER_BUSY_POLL
#define SO_PREFER_BUSY_POLL     69
#endif

#ifndef SO_BUSY_POLL_BUDGET
#define SO_BUSY_POLL_BUDGET     70
#endif

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE		71
#endif

#ifndef SO_BUF_LOCK
#define SO_BUF_LOCK		72
#endif

#ifndef SO_RESERVE_MEM
#define SO_RESERVE_MEM		73
#endif

#ifndef SO_TXREHASH
#define SO_TXREHASH		74
#endif

#ifndef SO_RCVMARK
#define SO_RCVMARK		75
#endif

#ifndef SO_PASSPIDFD
#define SO_PASSPIDFD		76
#endif

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD		77
#endif

#ifndef SO_DEVMEM_LINEAR
#define SO_DEVMEM_LINEAR	78
#endif

#ifndef SO_DEVMEM_DMABUF
#define SO_DEVMEM_DMABUF	79
#endif

#ifndef SO_DEVMEM_DONTNEED
#define SO_DEVMEM_DONTNEED	80
#endif

#ifndef SO_RCVPRIORITY
#define SO_RCVPRIORITY		82
#endif

#ifndef SO_PASSRIGHTS
#define SO_PASSRIGHTS		83
#endif

#ifndef SO_INQ
#define SO_INQ			84
#endif

#ifndef TCP_THIN_LINEAR_TIMEOUTS
#define TCP_THIN_LINEAR_TIMEOUTS 16
#endif

#ifndef TCP_THIN_DUPACK
#define TCP_THIN_DUPACK		17
#endif

#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT	18
#endif

#ifndef TCP_REPAIR
#define TCP_REPAIR		19
#endif

#ifndef TCP_REPAIR_QUEUE
#define TCP_REPAIR_QUEUE	20
#endif

#ifndef TCP_QUEUE_SEQ
#define TCP_QUEUE_SEQ		21
#endif

#ifndef TCP_REPAIR_OPTIONS
#define TCP_REPAIR_OPTIONS	22
#endif

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN		23
#endif

#ifndef TCP_TIMESTAMP
#define TCP_TIMESTAMP		24
#endif

#ifndef TCP_NOTSENT_LOWAT
#define TCP_NOTSENT_LOWAT	25
#endif

#ifndef TCP_CC_INFO
#define TCP_CC_INFO		26
#endif

#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN		27
#define TCP_SAVED_SYN		28
#endif

#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW	29
#endif

#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT	30
#endif

#ifndef TCP_ULP
#define TCP_ULP			31
#endif

#ifndef TCP_MD5SIG_EXT
#define TCP_MD5SIG_EXT		32
#endif

#ifndef TCP_FASTOPEN_KEY
#define TCP_FASTOPEN_KEY        33      /* Set the key for Fast Open (cookie) */
#endif

#ifndef TCP_FASTOPEN_NO_COOKIE
#define TCP_FASTOPEN_NO_COOKIE  34      /* Enable TFO without a TFO cookie */
#endif

#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE    35
#endif

#ifndef TCP_INQ
#define TCP_INQ                 36      /* Notify bytes available to read as a cmsg on read */
#endif

#ifndef TCP_TX_DELAY
#define TCP_TX_DELAY	37
#endif

#ifndef TCP_AO_ADD_KEY
#define TCP_AO_ADD_KEY		38
#define TCP_AO_DEL_KEY		39
#define TCP_AO_INFO		40
#define TCP_AO_GET_KEYS		41
#define TCP_AO_REPAIR		42
#endif

#ifndef TCP_IS_MPTCP
#define TCP_IS_MPTCP		43
#endif

#ifndef TCP_RTO_MAX_MS
#define TCP_RTO_MAX_MS		44
#endif

#ifndef TCP_RTO_MIN_US
#define TCP_RTO_MIN_US		45
#endif

#ifndef TCP_DELACK_MAX_US
#define TCP_DELACK_MAX_US	46
#endif

/* linux/socket.h -- SOL_ALG carries setsockopt/cmsg ops (ALG_SET_KEY,
 * ALG_SET_IV, ALG_SET_AEAD_AUTHSIZE, ...) for AF_ALG sockets.  Older
 * kernel-headers packages predate the constant; the UAPI value (279)
 * is fixed since the AF_ALG protocol family landed in 2.6.38. */
#ifndef SOL_ALG
#define SOL_ALG		279
#endif

#ifndef SOL_TLS
#define SOL_TLS		282
#endif

#ifndef SOL_MPTCP
#define SOL_MPTCP	284
#endif

#ifndef SOL_UDP
#define SOL_UDP		17
#endif

/* linux/socket.h */
#ifndef MSG_SPLICE_PAGES
#define MSG_SPLICE_PAGES		0x8000000
#endif

