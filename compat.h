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

#ifndef PF_NFC
#define PF_NFC		39
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

/* linux/socket.h */
#ifndef MSG_PROBE
#define MSG_PROBE 0x10
#endif
#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif
#ifndef MSG_CMSG_COMPAT
#define MSG_CMSG_COMPAT 0x80000000
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

/* asm/socket.h */
#ifndef SO_BSDCOMPAT
#define SO_BSDCOMPAT		14
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

/* linux/tcp.h */
#ifndef TCP_COOKIE_TRANSACTIONS
#define TCP_COOKIE_TRANSACTIONS	15
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

/* linux/dccp.h */
#ifndef DCCP_SOCKOPT_QPOLICY_ID
#define DCCP_SOCKOPT_QPOLICY_ID	16
#endif

#ifndef DCCP_SOCKOPT_QPOLICY_TXQLEN
#define DCCP_SOCKOPT_QPOLICY_TXQLEN 17
#endif

/* net/udplite.h */
#ifndef UDPLITE_SEND_CSCOV
#define UDPLITE_SEND_CSCOV   10 /* sender partial coverage (as sent)      */
#endif
#ifndef UDPLITE_RECV_CSCOV
#define UDPLITE_RECV_CSCOV   11 /* receiver partial coverage (threshold ) */
#endif

/* linux/in.h */
#ifndef IP_MTU
#define IP_MTU			14
#endif

#ifndef IP_FREEBIND
#define IP_FREEBIND		15
#endif

#ifndef IP_IPSEC_POLICY
#define IP_IPSEC_POLICY		16
#endif

#ifndef IP_XFRM_POLICY
#define IP_XFRM_POLICY		17
#endif

#ifndef IP_PASSSEC
#define IP_PASSSEC		18
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT		19
#endif

/* linux/in6.h */
#ifndef IPV6_FLOWINFO
#define IPV6_FLOWINFO 11
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
#endif

/* linux/rxrpc.h */
#ifndef RXRPC_USER_CALL_ID
#define RXRPC_USER_CALL_ID      1       /* user call ID specifier */
#define RXRPC_ABORT             2       /* abort request / notification [terminal] */
#define RXRPC_ACK               3       /* [Server] RPC op final ACK received [terminal] */
#define RXRPC_NET_ERROR         5       /* network error received [terminal] */
#define RXRPC_BUSY              6       /* server busy received [terminal] */
#define RXRPC_LOCAL_ERROR       7       /* local error generated [terminal] */
#define RXRPC_NEW_CALL          8       /* [Server] new incoming call notification */
#define RXRPC_ACCEPT            9       /* [Server] accept request */
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

/* linux/nfc.h */
#ifndef sockaddr_nfc
#include <bits/sockaddr.h>
#include <linux/types.h>

struct sockaddr_nfc {
	sa_family_t sa_family;
	__u32 dev_idx;
	__u32 target_idx;
	__u32 nfc_protocol;
};
#endif

#endif	/* _TRINITY_COMPAT_H */
