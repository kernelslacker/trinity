/*
 * Struct catalog and offset mapping for CMP-guided struct filling.
 *
 * Provides a static catalog of known struct types (with per-field offset
 * and size), a table mapping syscall args to those struct types, and a
 * fast nr-indexed lookup built at init time.
 *
 * The field-for-CMP heuristic uses value magnitude to narrow which field
 * a kernel CMP constant was most likely comparing against.
 */

#include <stddef.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sched.h>
#include <utime.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/tipc.h>
#include <linux/capability.h>
#include <linux/netfilter.h>
#include <linux/futex.h>
#include <linux/rseq.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/io_uring.h>
#include <linux/kexec.h>
#include <linux/landlock.h>
#include <linux/mman.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/quota.h>
#include <linux/dqblk_xfs.h>
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "config.h"
/*
 * linux/if_pppox.h pulls in linux/l2tp.h, whose enum declares
 * L2TP_ATTR_IP6_SADDR / RX_COOKIE_DISCARDS / ... as identifiers.
 * compat.h defines those same names as fallback numeric macros for
 * older kernel-headers packages, so the include must precede compat.h;
 * otherwise the macro expansion turns the enum members into integer
 * literals and -Werror trips.
 */
#ifdef USE_PPPOX
#include <linux/if_pppox.h>
#endif
#include "compat.h"
#ifdef USE_BPF
#include <linux/bpf.h>
#endif
#ifdef USE_VSOCK
#include <linux/vm_sockets.h>
#endif
#ifdef USE_CAIF
#include <linux/caif/caif_socket.h>
#endif
#ifdef USE_CAN
#include <linux/can.h>
#endif
#ifdef USE_RXRPC
#include <linux/rxrpc.h>
#endif
#ifdef USE_X25
#include <linux/x25.h>
#endif
#ifdef USE_PHONET
#include <linux/phonet.h>
#endif
#ifdef USE_AX25
#include <linux/ax25.h>
#endif
#ifdef USE_ROSE
#include <linux/rose.h>
#endif
#ifdef USE_ATALK
#include <linux/atalk.h>
#endif
#ifdef USE_ATM
#include <linux/atm.h>
#endif
#ifdef USE_LLC
#include <linux/llc.h>
#endif
#ifdef USE_MCTP
#include <linux/mctp.h>
#endif
#ifdef USE_IF_ALG
#include <linux/if_alg.h>
#endif
#ifdef USE_XDP
#include <linux/if_xdp.h>
/*
 * XDP_USE_NEED_WAKEUP landed in 5.4 (commit 77cd0d7b3f25); older
 * toolchain headers won't carry it even when the rest of the
 * sockaddr_xdp definitions are present.  Fall back to the upstream
 * bit value so the FT_FLAGS mask stays the same on either side.
 */
#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP	(1 << 3)
#endif
#endif
#ifdef USE_XATTR_ARGS
#include <linux/xattr.h>
#endif
#ifdef USE_SCTP
#include <linux/sctp.h>
#endif
#ifdef USE_TCP_REPAIR_OPT
#include <linux/tcp.h>
#endif

#include "argtype-ops.h"
#include "struct_catalog.h"
#include "struct_catalog-internal.h"
#include "arch.h"
#ifdef X86
#include <asm/ldt.h>		/* struct user_desc -- modify_ldt arg2 */
#endif
#include "debug.h"
#include "perf.h"		/* random_tracepoint_config -- FT_PICKER for TRACEPOINT.config */
#include "perf_event.h"
#include "random.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"

/* FIELD / FIELDX initialiser macros live in struct_catalog-internal.h
 * so the per-family leaf TUs under struct_catalog/ can reuse them. */

/*
 * struct open_how / RESOLVE_* may not be present in every host's
 * <linux/openat2.h>.  The field table lives in struct_catalog/fcntl.c,
 * but the spine's struct_catalog[] entry takes sizeof(struct open_how),
 * so the type definition must also be visible here.  The ifndef guard
 * hands off to the host header when it is present; both TUs land on a
 * layout-identical definition either way.
 */
#ifndef RESOLVE_NO_XDEV
struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};
#define RESOLVE_NO_XDEV		0x01
#define RESOLVE_NO_MAGICLINKS	0x02
#define RESOLVE_NO_SYMLINKS	0x04
#define RESOLVE_BENEATH		0x08
#define RESOLVE_IN_ROOT		0x10
#define RESOLVE_CACHED		0x20
#endif

/* ------------------------------------------------------------------ */
/* struct ns_id_req (listns)                                           */
/* ------------------------------------------------------------------ */

/*
 * struct ns_id_req from include/uapi/linux/nsfs.h.  Defined locally
 * under the same #ifndef guard the listns sanitiser uses so the
 * translation unit builds against kernel headers that predate the
 * struct.  The shape MUST match the one in syscalls/listns.c and the
 * matching shim in struct_catalog/mount.c -- the spine needs the type
 * visible for sizeof(struct ns_id_req) on its catalog entry, the leaf
 * TU needs it for the FIELD() offsetof / sizeof initialisers.  A
 * future header bump that grows the struct needs all copies updated.
 */
#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 ns_type;
	__u64 ns_id;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	24
#endif

/*
 * struct lsm_ctx from include/uapi/linux/lsm.h may not be present in
 * every host's kernel headers.  The field table lives in
 * struct_catalog/lsm.c, but the spine's struct_catalog[] entry takes
 * sizeof(struct lsm_ctx), so the type definition must also be visible
 * here.  The ifndef guard hands off to the host header when it is
 * present; both TUs land on a layout-identical definition either way.
 * A future uapi bump that grows the fixed head needs both copies
 * updated.  The flexible ctx[] tail is intentionally omitted: only
 * the fixed 4-u64 head is cataloged.
 */
#ifndef _LINUX_LSM_H
struct lsm_ctx {
	__u64 id;
	__u64 flags;
	__u64 len;
	__u64 ctx_len;
};
#endif

/* ------------------------------------------------------------------ */
/* The catalog itself                                                   */
/* ------------------------------------------------------------------ */

const struct struct_desc struct_catalog[] = {
	/* Slot order is immaterial -- refs use SC_X. */
	[SC_TIMEX] = {
		.name		= "timex",
		.struct_size	= sizeof(struct timex),
		.fields		= timex_fields,
		.num_fields	= ARRAY_SIZE(timex_fields),
	},
	[SC_SCHED_ATTR] = {
		.name		= "sched_attr",
		.struct_size	= sizeof(struct sched_attr),
		.fields		= sched_attr_fields,
		.num_fields	= ARRAY_SIZE(sched_attr_fields),
	},
	[SC_CLONE_ARGS] = {
		.name		= "clone_args",
		.struct_size	= sizeof(struct clone_args),
		.fields		= clone_args_fields,
		.num_fields	= ARRAY_SIZE(clone_args_fields),
	},
	[SC_IO_URING_PARAMS] = {
		.name		= "io_uring_params",
		.struct_size	= sizeof(struct io_uring_params),
		.fields		= io_uring_params_fields,
		.num_fields	= ARRAY_SIZE(io_uring_params_fields),
	},
	[SC_RLIMIT] = {
		.name		= "rlimit",
		.struct_size	= sizeof(struct rlimit),
		.fields		= rlimit_fields,
		.num_fields	= ARRAY_SIZE(rlimit_fields),
	},
	[SC_ITIMERSPEC] = {
		.name		= "itimerspec",
		.struct_size	= sizeof(struct itimerspec),
		.fields		= itimerspec_fields,
		.num_fields	= ARRAY_SIZE(itimerspec_fields),
	},
	[SC_EPOLL_EVENT] = {
		.name		= "epoll_event",
		.struct_size	= sizeof(struct epoll_event),
		.fields		= epoll_event_fields,
		.num_fields	= ARRAY_SIZE(epoll_event_fields),
	},
	[SC_PERF_EVENT_ATTR] = {
		.name			= "perf_event_attr",
		.struct_size		= sizeof(struct perf_event_attr),
		.fields			= perf_event_attr_fields,
		.num_fields		= ARRAY_SIZE(perf_event_attr_fields),
		.variants		= perf_event_attr_variants,
		.num_variants		= ARRAY_SIZE(perf_event_attr_variants),
		.buffer_discrim_offset	= offsetof(struct perf_event_attr, type),
		.buffer_discrim_size	= sizeof(((struct perf_event_attr *) 0)->
						 type),
	},
	[SC_SIGACTION] = {
		.name		= "sigaction",
		.struct_size	= sizeof(struct sigaction),
		.fields		= sigaction_fields,
		.num_fields	= ARRAY_SIZE(sigaction_fields),
	},
	[SC_MSGHDR] = {
		.name		= "msghdr",
		.struct_size	= sizeof(struct msghdr),
		.fields		= msghdr_fields,
		.num_fields	= ARRAY_SIZE(msghdr_fields),
	},
	[SC_SOCKADDR_STORAGE] = {
		.name			= "sockaddr_storage",
		.struct_size		= sizeof(struct sockaddr_storage),
		.fields			= sockaddr_storage_fields,
		.num_fields		= ARRAY_SIZE(sockaddr_storage_fields),
		.variants		= sockaddr_storage_variants,
		.num_variants		= ARRAY_SIZE(sockaddr_storage_variants),
		.buffer_discrim_offset	= offsetof(struct sockaddr_storage,
						   ss_family),
		.buffer_discrim_size	= sizeof(((struct sockaddr_storage *) 0)->
						 ss_family),
	},
	[SC_LANDLOCK_RULESET_ATTR] = {
		.name		= "landlock_ruleset_attr",
		.struct_size	= sizeof(struct landlock_ruleset_attr),
		.fields		= landlock_ruleset_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_ruleset_attr_fields),
	},
	[SC_MNT_ID_REQ] = {
		.name		= "mnt_id_req",
		.struct_size	= sizeof(struct mnt_id_req),
		.fields		= mnt_id_req_fields,
		.num_fields	= ARRAY_SIZE(mnt_id_req_fields),
	},
	[SC_USER_CAP_HEADER] = {
		.name		= "user_cap_header",
		.struct_size	= sizeof(struct __user_cap_header_struct),
		.fields		= user_cap_header_fields,
		.num_fields	= ARRAY_SIZE(user_cap_header_fields),
	},
	[SC_USER_CAP_DATA] = {
		.name		= "user_cap_data",
		.struct_size	= sizeof(struct __user_cap_data_struct),
		.fields		= user_cap_data_fields,
		.num_fields	= ARRAY_SIZE(user_cap_data_fields),
	},
	[SC_FUTEX_WAITV] = {
		.name		= "futex_waitv",
		.struct_size	= sizeof(struct futex_waitv),
		.fields		= futex_waitv_fields,
		.num_fields	= ARRAY_SIZE(futex_waitv_fields),
	},
	[SC_STACK_T] = {
		.name		= "stack_t",
		.struct_size	= sizeof(stack_t),
		.fields		= stack_t_fields,
		.num_fields	= ARRAY_SIZE(stack_t_fields),
	},
	[SC_SIGINFO_T] = {
		.name			= "siginfo_t",
		.struct_size		= sizeof(siginfo_t),
		.fields			= siginfo_t_fields,
		.num_fields		= ARRAY_SIZE(siginfo_t_fields),
		.variants		= siginfo_t_variants,
		.num_variants		= ARRAY_SIZE(siginfo_t_variants),
		.buffer_discrim_offset	= offsetof(siginfo_t, si_code),
		.buffer_discrim_size	= sizeof(((siginfo_t *) 0)->si_code),
	},
	[SC_MQ_ATTR] = {
		.name		= "mq_attr",
		.struct_size	= sizeof(struct mq_attr),
		.fields		= mq_attr_fields,
		.num_fields	= ARRAY_SIZE(mq_attr_fields),
	},
	[SC_MSQID_DS] = {
		.name		= "msqid_ds",
		.struct_size	= sizeof(struct msqid_ds),
		.fields		= msqid_ds_fields,
		.num_fields	= ARRAY_SIZE(msqid_ds_fields),
	},
	[SC_SCHED_PARAM] = {
		.name		= "sched_param",
		.struct_size	= sizeof(struct sched_param),
		.fields		= sched_param_fields,
		.num_fields	= ARRAY_SIZE(sched_param_fields),
	},
	/*
	 * io_uring_register tagged-union infra entry.  Each opcode (in
	 * rec->a2) presents a different per-cmd struct shape at *rec->a3;
	 * the variant table dispatches by opcode.  Shared prefix is empty:
	 * register opcodes are fully self-contained per-cmd structs with
	 * no truly-common fields.  Variants are populated per-opcode; not
	 * all opcodes are covered yet.
	 *
	 * struct_size is set to the largest projected variant
	 * (io_uring_sync_cancel_reg @ 64 bytes) so the buffer fed to the
	 * fill path is never too small for any single-struct opcode.
	 *
	 * No live consumer wires this entry today: io_uring_register's
	 * arg slot is ARG_ADDRESS (not ARG_STRUCT_PTR_*) and the existing
	 * sanitise_io_uring_register hand-rolls every opcode's payload.
	 * The entry is forward infra for opcode-scoped CMP attribution
	 * (struct_field_for_cmp pending a cmp_hints caller) and a future
	 * ARG_ADDRESS-mapped fill consumer.  The bpf catalog landed the
	 * same way: variant data first, sanitise caller after.
	 */
	[SC_IO_URING_REGISTER_ARGS] = {
		.name			= "io_uring_register_args",
		.struct_size		= 64,
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 2,	/* opcode in rec->a2 */
		.variants		= io_uring_register_variants,
		.num_variants		= ARRAY_SIZE(io_uring_register_variants),
	},
#ifdef USE_BPF
	[SC_BPF_ATTR] = {
		.name			= "bpf_attr",
		.struct_size		= sizeof(union bpf_attr),
		/*
		 * Shared prefix is empty: every bpf cmd lives in its own
		 * anonymous union arm with no truly-common fields.  The
		 * tagged-union path takes over via discrim_arg_idx == 1
		 * (bpf cmd lives in rec->a1).
		 */
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 1,
		.variants		= bpf_attr_variants,
		.num_variants		= ARRAY_SIZE(bpf_attr_variants),
	},
	/*
	 * bpf_insn registered for name lookup only -- kept as a CMP-
	 * attribution shape (code / off / imm) so KCOV-compare learned
	 * constants can be attributed to the right field.  No
	 * syscall_struct_args entry; PROG_LOAD's insns now flows through
	 * FT_BPF_PROGRAM rather than FT_PTR_ARRAY.elem_struct.
	 */
	[SC_BPF_INSN] = {
		.name		= "bpf_insn",
		.struct_size	= sizeof(struct bpf_insn),
		.fields		= bpf_insn_fields,
		.num_fields	= ARRAY_SIZE(bpf_insn_fields),
	},
#endif
	/*
	 * iovec: referenced by msghdr.msg_iov's FT_PTR_ARRAY.elem_struct
	 * so the pointer pass can resolve sizeof(struct iovec) for
	 * allocation, and also named at the iovec-array slot of the
	 * readv / writev / preadv{,2} / pwritev{,2} / vmsplice /
	 * process_madvise / process_vm_{readv,writev} syscalls via
	 * syscall_struct_args[] below.  Those slots are ARG_IOVEC /
	 * ARG_IOVEC_IN (not ARG_STRUCT_PTR_*), so the schema-aware fill
	 * path never runs against them -- the bespoke alloc_iovec()
	 * generator owns the live (iov_base, iov_len) layout.  The
	 * mapping is attribution-only: it lets struct_field_for_cmp()
	 * steer CMP-learned constants at the named iov_base / iov_len
	 * slots rather than at a coincidentally-same-width slot.
	 */
	[SC_IOVEC] = {
		.name		= "iovec",
		.struct_size	= sizeof(struct iovec),
		.fields		= iovec_fields,
		.num_fields	= ARRAY_SIZE(iovec_fields),
	},
	[SC_TIMESPEC] = {
		.name		= "timespec",
		.struct_size	= sizeof(struct timespec),
		.fields		= timespec_fields,
		.num_fields	= ARRAY_SIZE(timespec_fields),
	},
	[SC_CACHESTAT_RANGE] = {
		.name		= "cachestat_range",
		.struct_size	= sizeof(struct cachestat_range),
		.fields		= cachestat_range_fields,
		.num_fields	= ARRAY_SIZE(cachestat_range_fields),
	},
	[SC_MOUNT_ATTR] = {
		.name		= "mount_attr",
		.struct_size	= sizeof(struct mount_attr),
		.fields		= mount_attr_fields,
		.num_fields	= ARRAY_SIZE(mount_attr_fields),
	},
	[SC_SEMBUF] = {
		.name		= "sembuf",
		.struct_size	= sizeof(struct sembuf),
		.fields		= sembuf_fields,
		.num_fields	= ARRAY_SIZE(sembuf_fields),
	},
	[SC_POLLFD] = {
		.name		= "pollfd",
		.struct_size	= sizeof(struct pollfd),
		.fields		= pollfd_fields,
		.num_fields	= ARRAY_SIZE(pollfd_fields),
	},
	[SC_OPEN_HOW] = {
		.name		= "open_how",
		.struct_size	= sizeof(struct open_how),
		.fields		= open_how_fields,
		.num_fields	= ARRAY_SIZE(open_how_fields),
	},
	[SC_SIGEVENT] = {
		.name		= "sigevent",
		.struct_size	= sizeof(struct sigevent),
		.fields		= sigevent_fields,
		.num_fields	= ARRAY_SIZE(sigevent_fields),
	},
	[SC_ROBUST_LIST_HEAD] = {
		.name		= "robust_list_head",
		.struct_size	= sizeof(struct robust_list_head),
		.fields		= robust_list_head_fields,
		.num_fields	= ARRAY_SIZE(robust_list_head_fields),
	},
	[SC_RSEQ] = {
		.name		= "rseq",
		.struct_size	= sizeof(struct rseq),
		.fields		= rseq_fields,
		.num_fields	= ARRAY_SIZE(rseq_fields),
	},
	[SC_ITIMERVAL] = {
		.name		= "itimerval",
		.struct_size	= sizeof(struct itimerval),
		.fields		= itimerval_fields,
		.num_fields	= ARRAY_SIZE(itimerval_fields),
	},
	[SC_UTIMBUF] = {
		.name		= "utimbuf",
		.struct_size	= sizeof(struct utimbuf),
		.fields		= utimbuf_fields,
		.num_fields	= ARRAY_SIZE(utimbuf_fields),
	},
	[SC_FLOCK] = {
		.name		= "flock",
		.struct_size	= sizeof(struct flock),
		.fields		= flock_fields,
		.num_fields	= ARRAY_SIZE(flock_fields),
	},
	[SC_TIMEVAL] = {
		.name		= "timeval",
		.struct_size	= sizeof(struct timeval),
		.fields		= timeval_fields,
		.num_fields	= ARRAY_SIZE(timeval_fields),
	},
	[SC_TIMEZONE] = {
		.name		= "timezone",
		.struct_size	= sizeof(struct timezone),
		.fields		= timezone_fields,
		.num_fields	= ARRAY_SIZE(timezone_fields),
	},
	[SC_NS_ID_REQ] = {
		.name		= "ns_id_req",
		.struct_size	= sizeof(struct ns_id_req),
		.fields		= ns_id_req_fields,
		.num_fields	= ARRAY_SIZE(ns_id_req_fields),
	},
#ifdef USE_XATTR_ARGS
	[SC_XATTR_ARGS] = {
		.name		= "xattr_args",
		.struct_size	= sizeof(struct xattr_args),
		.fields		= xattr_args_fields,
		.num_fields	= ARRAY_SIZE(xattr_args_fields),
	},
#endif
	[SC_FILE_ATTR] = {
		.name		= "file_attr",
		.struct_size	= sizeof(struct file_attr),
		.fields		= file_attr_fields,
		.num_fields	= ARRAY_SIZE(file_attr_fields),
	},
	[SC_LANDLOCK_PATH_BENEATH_ATTR] = {
		.name		= "landlock_path_beneath_attr",
		.struct_size	= sizeof(struct landlock_path_beneath_attr),
		.fields		= landlock_path_beneath_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_path_beneath_attr_fields),
	},
	[SC_F_OWNER_EX] = {
		.name		= "f_owner_ex",
		.struct_size	= sizeof(struct f_owner_ex),
		.fields		= f_owner_ex_fields,
		.num_fields	= ARRAY_SIZE(f_owner_ex_fields),
	},
	[SC_LANDLOCK_NET_PORT_ATTR] = {
		.name		= "landlock_net_port_attr",
		.struct_size	= sizeof(struct landlock_net_port_attr),
		.fields		= landlock_net_port_attr_fields,
		.num_fields	= ARRAY_SIZE(landlock_net_port_attr_fields),
	},
	[SC_IF_DQBLK] = {
		.name		= "if_dqblk",
		.struct_size	= sizeof(struct if_dqblk),
		.fields		= if_dqblk_fields,
		.num_fields	= ARRAY_SIZE(if_dqblk_fields),
	},
	[SC_IF_DQINFO] = {
		.name		= "if_dqinfo",
		.struct_size	= sizeof(struct if_dqinfo),
		.fields		= if_dqinfo_fields,
		.num_fields	= ARRAY_SIZE(if_dqinfo_fields),
	},
#ifdef X86
	[SC_USER_DESC] = {
		.name		= "user_desc",
		.struct_size	= sizeof(struct user_desc),
		.fields		= user_desc_fields,
		.num_fields	= ARRAY_SIZE(user_desc_fields),
	},
#endif
	[SC_SOCK_FILTER] = {
		.name		= "sock_filter",
		.struct_size	= sizeof(struct sock_filter),
		.fields		= sock_filter_fields,
		.num_fields	= ARRAY_SIZE(sock_filter_fields),
	},
	[SC_SOCK_FPROG] = {
		.name		= "sock_fprog",
		.struct_size	= sizeof(struct sock_fprog),
		.fields		= sock_fprog_fields,
		.num_fields	= ARRAY_SIZE(sock_fprog_fields),
	},
	[SC_SHMID_DS] = {
		.name		= "shmid_ds",
		.struct_size	= sizeof(struct shmid_ds),
		.fields		= shmid_ds_fields,
		.num_fields	= ARRAY_SIZE(shmid_ds_fields),
	},
	[SC_IOCB] = {
		.name		= "iocb",
		.struct_size	= sizeof(struct iocb),
		.fields		= iocb_fields,
		.num_fields	= ARRAY_SIZE(iocb_fields),
	},
	[SC_LINGER] = {
		.name		= "linger",
		.struct_size	= sizeof(struct linger),
		.fields		= linger_fields,
		.num_fields	= ARRAY_SIZE(linger_fields),
	},
	[SC_IP_MREQN] = {
		.name		= "ip_mreqn",
		.struct_size	= sizeof(struct ip_mreqn),
		.fields		= ip_mreqn_fields,
		.num_fields	= ARRAY_SIZE(ip_mreqn_fields),
	},
	[SC_IPV6_MREQ] = {
		.name		= "ipv6_mreq",
		.struct_size	= sizeof(struct ipv6_mreq),
		.fields		= ipv6_mreq_fields,
		.num_fields	= ARRAY_SIZE(ipv6_mreq_fields),
	},
	[SC_PACKET_MREQ] = {
		.name		= "packet_mreq",
		.struct_size	= sizeof(struct packet_mreq),
		.fields		= packet_mreq_fields,
		.num_fields	= ARRAY_SIZE(packet_mreq_fields),
	},
	[SC_GROUP_REQ] = {
		.name		= "group_req",
		.struct_size	= sizeof(struct group_req),
		.fields		= group_req_fields,
		.num_fields	= ARRAY_SIZE(group_req_fields),
	},
	[SC_GROUP_SOURCE_REQ] = {
		.name		= "group_source_req",
		.struct_size	= sizeof(struct group_source_req),
		.fields		= group_source_req_fields,
		.num_fields	= ARRAY_SIZE(group_source_req_fields),
	},
	[SC_IP_MREQ_SOURCE] = {
		.name		= "ip_mreq_source",
		.struct_size	= sizeof(struct ip_mreq_source),
		.fields		= ip_mreq_source_fields,
		.num_fields	= ARRAY_SIZE(ip_mreq_source_fields),
	},
	[SC_MSGBUF] = {
		.name		= "msgbuf",
		.struct_size	= sizeof(struct msgbuf),
		.fields		= msgbuf_fields,
		.num_fields	= ARRAY_SIZE(msgbuf_fields),
	},
	[SC_SIGSET_T] = {
		.name		= "sigset_t",
		.struct_size	= sizeof(sigset_t),
		.fields		= sigset_t_fields,
		.num_fields	= ARRAY_SIZE(sigset_t_fields),
	},
	[SC_LSM_CTX] = {
		.name		= "lsm_ctx",
		.struct_size	= sizeof(struct lsm_ctx),
		.fields		= lsm_ctx_fields,
		.num_fields	= ARRAY_SIZE(lsm_ctx_fields),
	},
#ifdef USE_TCP_REPAIR_OPT
	[SC_TCP_REPAIR_OPT] = {
		.name		= "tcp_repair_opt",
		.struct_size	= sizeof(struct tcp_repair_opt),
		.fields		= tcp_repair_opt_fields,
		.num_fields	= ARRAY_SIZE(tcp_repair_opt_fields),
	},
#endif
#ifdef USE_SCTP
	[SC_SCTP_INITMSG] = {
		.name		= "sctp_initmsg",
		.struct_size	= sizeof(struct sctp_initmsg),
		.fields		= sctp_initmsg_fields,
		.num_fields	= ARRAY_SIZE(sctp_initmsg_fields),
	},
	[SC_SCTP_RTOINFO] = {
		.name		= "sctp_rtoinfo",
		.struct_size	= sizeof(struct sctp_rtoinfo),
		.fields		= sctp_rtoinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_rtoinfo_fields),
	},
	[SC_SCTP_ASSOCPARAMS] = {
		.name		= "sctp_assocparams",
		.struct_size	= sizeof(struct sctp_assocparams),
		.fields		= sctp_assocparams_fields,
		.num_fields	= ARRAY_SIZE(sctp_assocparams_fields),
	},
	[SC_SCTP_SETADAPTATION] = {
		.name		= "sctp_setadaptation",
		.struct_size	= sizeof(struct sctp_setadaptation),
		.fields		= sctp_setadaptation_fields,
		.num_fields	= ARRAY_SIZE(sctp_setadaptation_fields),
	},
	[SC_SCTP_ASSOC_VALUE] = {
		.name		= "sctp_assoc_value",
		.struct_size	= sizeof(struct sctp_assoc_value),
		.fields		= sctp_assoc_value_fields,
		.num_fields	= ARRAY_SIZE(sctp_assoc_value_fields),
	},
	[SC_SCTP_SNDINFO] = {
		.name		= "sctp_sndinfo",
		.struct_size	= sizeof(struct sctp_sndinfo),
		.fields		= sctp_sndinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_sndinfo_fields),
	},
	[SC_SCTP_SNDRCVINFO] = {
		.name		= "sctp_sndrcvinfo",
		.struct_size	= sizeof(struct sctp_sndrcvinfo),
		.fields		= sctp_sndrcvinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_sndrcvinfo_fields),
	},
	[SC_SCTP_EVENT_SUBSCRIBE] = {
		.name		= "sctp_event_subscribe",
		.struct_size	= sizeof(struct sctp_event_subscribe),
		.fields		= sctp_event_subscribe_fields,
		.num_fields	= ARRAY_SIZE(sctp_event_subscribe_fields),
	},
	[SC_SCTP_AUTHCHUNK] = {
		.name		= "sctp_authchunk",
		.struct_size	= sizeof(struct sctp_authchunk),
		.fields		= sctp_authchunk_fields,
		.num_fields	= ARRAY_SIZE(sctp_authchunk_fields),
	},
	[SC_SCTP_SACK_INFO] = {
		.name		= "sctp_sack_info",
		.struct_size	= sizeof(struct sctp_sack_info),
		.fields		= sctp_sack_info_fields,
		.num_fields	= ARRAY_SIZE(sctp_sack_info_fields),
	},
	[SC_SCTP_AUTHKEYID] = {
		.name		= "sctp_authkeyid",
		.struct_size	= sizeof(struct sctp_authkeyid),
		.fields		= sctp_authkeyid_fields,
		.num_fields	= ARRAY_SIZE(sctp_authkeyid_fields),
	},
	[SC_SCTP_DEFAULT_PRINFO] = {
		.name		= "sctp_default_prinfo",
		.struct_size	= sizeof(struct sctp_default_prinfo),
		.fields		= sctp_default_prinfo_fields,
		.num_fields	= ARRAY_SIZE(sctp_default_prinfo_fields),
	},
	[SC_SCTP_ADD_STREAMS] = {
		.name		= "sctp_add_streams",
		.struct_size	= sizeof(struct sctp_add_streams),
		.fields		= sctp_add_streams_fields,
		.num_fields	= ARRAY_SIZE(sctp_add_streams_fields),
	},
	[SC_SCTP_STREAM_VALUE] = {
		.name		= "sctp_stream_value",
		.struct_size	= sizeof(struct sctp_stream_value),
		.fields		= sctp_stream_value_fields,
		.num_fields	= ARRAY_SIZE(sctp_stream_value_fields),
	},
	[SC_SCTP_EVENT] = {
		.name		= "sctp_event",
		.struct_size	= sizeof(struct sctp_event),
		.fields		= sctp_event_fields,
		.num_fields	= ARRAY_SIZE(sctp_event_fields),
	},
	[SC_SCTP_PADDRTHLDS] = {
		.name		= "sctp_paddrthlds",
		.struct_size	= sizeof(struct sctp_paddrthlds),
		.fields		= sctp_paddrthlds_fields,
		.num_fields	= ARRAY_SIZE(sctp_paddrthlds_fields),
	},
	[SC_SCTP_PADDRTHLDS_V2] = {
		.name		= "sctp_paddrthlds_v2",
		.struct_size	= sizeof(struct sctp_paddrthlds_v2),
		.fields		= sctp_paddrthlds_v2_fields,
		.num_fields	= ARRAY_SIZE(sctp_paddrthlds_v2_fields),
	},
	[SC_SCTP_UDPENCAPS] = {
		.name		= "sctp_udpencaps",
		.struct_size	= sizeof(struct sctp_udpencaps),
		.fields		= sctp_udpencaps_fields,
		.num_fields	= ARRAY_SIZE(sctp_udpencaps_fields),
	},
	[SC_SCTP_PADDRPARAMS] = {
		.name		= "sctp_paddrparams",
		.struct_size	= sizeof(struct sctp_paddrparams),
		.fields		= sctp_paddrparams_fields,
		.num_fields	= ARRAY_SIZE(sctp_paddrparams_fields),
	},
	[SC_SCTP_PROBEINTERVAL] = {
		.name		= "sctp_probeinterval",
		.struct_size	= sizeof(struct sctp_probeinterval),
		.fields		= sctp_probeinterval_fields,
		.num_fields	= ARRAY_SIZE(sctp_probeinterval_fields),
	},
	[SC_SCTP_PRIM] = {
		.name		= "sctp_prim",
		.struct_size	= sizeof(struct sctp_prim),
		.fields		= sctp_prim_fields,
		.num_fields	= ARRAY_SIZE(sctp_prim_fields),
	},
#endif
	[SC_FILE_HANDLE] = {
		.name		= "file_handle",
		.struct_size	= sizeof(struct file_handle),
		.fields		= file_handle_fields,
		.num_fields	= ARRAY_SIZE(file_handle_fields),
	},
	[SC_FS_DISK_QUOTA] = {
		.name		= "fs_disk_quota",
		.struct_size	= sizeof(struct fs_disk_quota),
		.fields		= fs_disk_quota_fields,
		.num_fields	= ARRAY_SIZE(fs_disk_quota_fields),
	},
	[SC_MMSGHDR] = {
		.name		= "mmsghdr",
		.struct_size	= sizeof(struct mmsghdr),
		.fields		= mmsghdr_fields,
		.num_fields	= ARRAY_SIZE(mmsghdr_fields),
	},
	[SC_KEXEC_SEGMENT] = {
		.name		= "kexec_segment",
		.struct_size	= sizeof(struct kexec_segment),
		.fields		= kexec_segment_fields,
		.num_fields	= ARRAY_SIZE(kexec_segment_fields),
	},
};

/*
 * Lock the enum and the array in lockstep at compile time.  A missing
 * [SC_X] = {...} slot would let ARRAY_SIZE diverge from SC_NR_ENTRIES;
 * catching it here is sharper than the runtime hole-check below.
 */
_Static_assert(ARRAY_SIZE(struct_catalog) == SC_NR_ENTRIES,
	       "struct_catalog[] and enum struct_catalog_idx must stay in lockstep");

/* ------------------------------------------------------------------ */
/* Discriminator value lists                                            */
/* ------------------------------------------------------------------ */

/*
 * fcntl arg3 cmd discriminator pools.  Sibling arg a2 (cmd) selects
 * which struct backs the a3 pointer; the discriminator-aware lookup
 * resolves these lists against rec->a2 to pick the right descriptor.
 *
 * fcntl_flock_cmds: every cmd where the kernel reads a struct flock
 * at a3 -- POSIX (F_GETLK / F_SETLK / F_SETLKW), OFD (F_OFD_*) and
 * F_CANCELLK.  The LK64 variants are folded in via the
 * F_GETLK64 != F_GETLK preprocessor gate so 64-bit-clean toolchains
 * (where the LK64 cmd values collapse onto their non-LK64 siblings)
 * don't waste a duplicate-match slot.
 *
 * fcntl_f_owner_ex_cmds: the two cmds where a3 is a struct
 * f_owner_ex pointer.
 */
static const unsigned long fcntl_flock_cmds[] = {
	F_GETLK, F_SETLK, F_SETLKW,
	F_OFD_GETLK, F_OFD_SETLK, F_OFD_SETLKW,
	F_CANCELLK,
#if F_GETLK64 != F_GETLK
	F_GETLK64, F_SETLK64, F_SETLKW64,
#endif
};

static const unsigned long fcntl_f_owner_ex_cmds[] = {
	F_GETOWN_EX, F_SETOWN_EX,
};

/*
 * landlock_add_rule arg3 rule_type discriminator pools.  Sibling arg
 * a2 (rule_type) selects which struct backs the a3 pointer; the
 * discriminator-aware lookup resolves these lists against rec->a2 to
 * pick the right descriptor.
 *
 * landlock_add_rule_path_beneath_rule_types: just
 * LANDLOCK_RULE_PATH_BENEATH (a3 is a struct landlock_path_beneath_attr).
 *
 * landlock_add_rule_net_port_rule_types: just LANDLOCK_RULE_NET_PORT
 * (a3 is a struct landlock_net_port_attr).
 *
 * One-element pools so the registration shape matches the fcntl
 * cmd-discriminator above; new landlock rule_types will land here as
 * additional entries with their own descriptor + pool.
 */
static const unsigned long landlock_add_rule_path_beneath_rule_types[] = {
	LANDLOCK_RULE_PATH_BENEATH,
};

static const unsigned long landlock_add_rule_net_port_rule_types[] = {
	LANDLOCK_RULE_NET_PORT,
};

/*
 * quotactl / quotactl_fd cmd discriminator pools.  Both syscalls pack
 * the cmd into a single arg as QCMD(subcmd, type) (subcmd in the high
 * bits, USRQUOTA / GRPQUOTA / PRJQUOTA / ... type in the low byte),
 * so the discriminator-aware lookup unpacks via the (shift, mask)
 * extension: discrim_shift = SUBCMDSHIFT strips the type byte and
 * leaves the raw subcmd that the kernel switches on, which is what
 * Q_SETQUOTA / Q_SETINFO actually equal.
 *
 * quotactl_if_dqblk_subcmds: just Q_SETQUOTA (a4 / a3 is a struct
 * if_dqblk pointer the kernel reads on dispatch).  Q_GETQUOTA /
 * Q_GETNEXTQUOTA also use if_dqblk at the same slot but they're
 * output-only -- registering them would attribute CMP-learned
 * constants against bytes the kernel wrote rather than bytes we
 * stamped.
 */
static const unsigned long quotactl_if_dqblk_subcmds[] = {
	Q_SETQUOTA,
};

/*
 * quotactl_if_dqinfo_subcmds: just Q_SETINFO (a4 / a3 is a struct
 * if_dqinfo pointer the kernel reads on dispatch).  Q_GETINFO also
 * uses if_dqinfo at the same slot but is output-only -- registering
 * it would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_if_dqinfo_subcmds[] = {
	Q_SETINFO,
};

/*
 * quotactl_fs_disk_quota_subcmds: just Q_XSETQLIM (a4 is a struct
 * fs_disk_quota pointer the kernel reads on dispatch under the XFS
 * quota set-limit command).  Q_XGETQUOTA / Q_XGETNEXTQUOTA also use
 * fs_disk_quota at the same slot but they're output-only -- registering
 * them would attribute CMP-learned constants against bytes the kernel
 * wrote rather than bytes we stamped.
 */
static const unsigned long quotactl_fs_disk_quota_subcmds[] = {
	Q_XSETQLIM,
};

/*
 * seccomp(op, flags, args) op-discriminator pool.  Sibling arg a1 (op)
 * selects which struct backs the a3 pointer; the discriminator-aware
 * lookup resolves this list against rec->a1 to pick the right descriptor.
 *
 * seccomp_set_mode_filter_ops: just SECCOMP_SET_MODE_FILTER (a3 is a
 * struct sock_fprog pointer the kernel reads for cBPF install).  The
 * other three ops (SECCOMP_SET_MODE_STRICT, SECCOMP_GET_ACTION_AVAIL,
 * SECCOMP_GET_NOTIF_SIZES) point a3 at a different shape (or NULL) and
 * are not registered -- attributing CMP-learned constants against
 * sock_fprog fields on those dispatches would steer them at bytes the
 * kernel never reads as filter program.
 */
static const unsigned long seccomp_set_mode_filter_ops[] = {
	SECCOMP_SET_MODE_FILTER,
};

/*
 * setsockopt (level, optname) discriminator vocab -- proof batch for
 * the two-key extension.  Each list enumerates the optnames inside a
 * single level that share an optval struct shape, so one
 * syscall_struct_args[] row covers every (level, this-vocab) tuple
 * without cloning the entry.  Same pattern as cgroup link_create's
 * 20-attach-type discrim_values list.
 *
 * Symbol comes from setsockopt.c's sockopt_table[] vocabulary; the
 * lookup matches on the raw integer value, not the symbolic name.
 */
static const unsigned long setsockopt_timeval_optnames[] = {
	SO_RCVTIMEO,
	SO_SNDTIMEO,
};

static const unsigned long setsockopt_ip_mreqn_optnames[] = {
	IP_ADD_MEMBERSHIP,
	IP_DROP_MEMBERSHIP,
	IP_MULTICAST_IF,
};

static const unsigned long setsockopt_ip_mreq_source_optnames[] = {
	IP_ADD_SOURCE_MEMBERSHIP,
	IP_DROP_SOURCE_MEMBERSHIP,
	IP_BLOCK_SOURCE,
	IP_UNBLOCK_SOURCE,
};

static const unsigned long setsockopt_ipv6_mreq_optnames[] = {
	IPV6_ADD_MEMBERSHIP,
	IPV6_DROP_MEMBERSHIP,
};

static const unsigned long setsockopt_packet_mreq_optnames[] = {
	PACKET_ADD_MEMBERSHIP,
	PACKET_DROP_MEMBERSHIP,
};

/*
 * Protocol-independent MCAST_* setsockopt family: the same optname
 * payload is accepted under both IPPROTO_IP and IPPROTO_IPV6.  The
 * two-key map entry uses both lists so one row covers the full
 * (level, optname) cross product without cloning the entry.
 */
static const unsigned long setsockopt_mcast_levels[] = {
	IPPROTO_IP,
	IPPROTO_IPV6,
};

static const unsigned long setsockopt_mcast_join_optnames[] = {
	MCAST_JOIN_GROUP,
	MCAST_LEAVE_GROUP,
};

/*
 * Source-filter optnames in the same protocol-independent MCAST_*
 * family, sharing setsockopt_mcast_levels[] with the join/leave row.
 * Sibling list for the group_source_req payload shape.
 */
static const unsigned long setsockopt_mcast_source_optnames[] = {
	MCAST_JOIN_SOURCE_GROUP,
	MCAST_LEAVE_SOURCE_GROUP,
	MCAST_BLOCK_SOURCE,
	MCAST_UNBLOCK_SOURCE,
};

#ifdef USE_SCTP
static const unsigned long setsockopt_sctp_assoc_value_optnames[] = {
	SCTP_CONTEXT,
	SCTP_MAXSEG,
	SCTP_MAX_BURST,
	SCTP_STREAM_SCHEDULER,
};

static const unsigned long setsockopt_sctp_authkeyid_optnames[] = {
	SCTP_AUTH_ACTIVE_KEY,
	SCTP_AUTH_DELETE_KEY,
	SCTP_AUTH_DEACTIVATE_KEY,
};

static const unsigned long setsockopt_sctp_prim_optnames[] = {
	SCTP_PRIMARY_ADDR,
	SCTP_SET_PEER_PRIMARY_ADDR,
};
#endif

/*
 * futex_timeout_ops: the op subset where a4 (utime) is a struct
 * timespec pointer rather than the val2 integer overload.  Mirrors
 * the kernel's futex_cmd_has_timeout() switch (kernel/futex/syscalls.c).
 * Matched against rec->a2 masked by FUTEX_CMD_MASK so the PRIVATE /
 * CLOCK_REALTIME / ROBUST flag bits don't perturb the dispatch.
 */
static const unsigned long futex_timeout_ops[] = {
	FUTEX_WAIT,
	FUTEX_LOCK_PI,
	FUTEX_WAIT_BITSET,
	FUTEX_WAIT_REQUEUE_PI,
	FUTEX_LOCK_PI2,
};

/* ------------------------------------------------------------------ */
/* Syscall -> struct arg mapping                                        */
/* ------------------------------------------------------------------ */

/*
 * Maps (syscall name, 1-based arg index) to the struct type passed at
 * that argument.  Only covers args that are struct pointers filled by
 * a custom sanitise callback.  Terminated by .syscall_name == NULL.
 */
const struct syscall_struct_arg syscall_struct_args[] = {
	/* adjtimex(struct timex *) */
	{ "adjtimex",		1, &struct_catalog[SC_TIMEX] },
	/* clock_adjtime(clockid_t, struct timex *) */
	{ "clock_adjtime",	2, &struct_catalog[SC_TIMEX] },
	/* sched_setattr(pid_t, struct sched_attr *, unsigned int) */
	{ "sched_setattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* sched_getattr(pid_t, struct sched_attr *, unsigned int, unsigned int) */
	{ "sched_getattr",	2, &struct_catalog[SC_SCHED_ATTR] },
	/* clone3(struct clone_args *, size_t) */
	{ "clone3",		1, &struct_catalog[SC_CLONE_ARGS] },
	/* io_uring_setup(u32, struct io_uring_params *) */
	{ "io_uring_setup",	2, &struct_catalog[SC_IO_URING_PARAMS] },
	/* setrlimit(unsigned int, struct rlimit *) */
	{ "setrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* getrlimit(unsigned int, struct rlimit *) */
	{ "getrlimit",		2, &struct_catalog[SC_RLIMIT] },
	/* prlimit64(pid_t, unsigned int, struct rlimit *, struct rlimit *) */
	{ "prlimit64",		3, &struct_catalog[SC_RLIMIT] },
	{ "prlimit64",		4, &struct_catalog[SC_RLIMIT] },
	/* timer_settime(timer_t, int, struct itimerspec *, struct itimerspec *) */
	{ "timer_settime",	3, &struct_catalog[SC_ITIMERSPEC] },
	/* timerfd_settime(int, int, struct itimerspec *, struct itimerspec *) */
	{ "timerfd_settime",	3, &struct_catalog[SC_ITIMERSPEC] },
	/* epoll_ctl(int, int, int, struct epoll_event *) */
	{ "epoll_ctl",		4, &struct_catalog[SC_EPOLL_EVENT] },
	/* perf_event_open(struct perf_event_attr *, pid_t, int, int, ulong) */
	{ "perf_event_open",	1, &struct_catalog[SC_PERF_EVENT_ATTR] },
	/* rt_sigaction(int, const struct sigaction *, struct sigaction *, size_t) */
	{ "rt_sigaction",	2, &struct_catalog[SC_SIGACTION] },
	{ "rt_sigaction",	3, &struct_catalog[SC_SIGACTION] },
	/* sigaction(int, const struct old_sigaction *, struct old_sigaction *) */
	{ "sigaction",		2, &struct_catalog[SC_SIGACTION] },
	{ "sigaction",		3, &struct_catalog[SC_SIGACTION] },
	/* sendmsg(int, const struct msghdr *, int) */
	{ "sendmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* recvmsg(int, struct msghdr *, int) */
	{ "recvmsg",		2, &struct_catalog[SC_MSGHDR] },
	/* sendmmsg(int, struct mmsghdr *, unsigned int, unsigned int) */
	{ "sendmmsg",		2, &struct_catalog[SC_MMSGHDR] },
	/* recvmmsg(int, struct mmsghdr *, unsigned int, unsigned int, struct timespec *) */
	{ "recvmmsg",		2, &struct_catalog[SC_MMSGHDR] },
	/* bind(int, struct sockaddr *, socklen_t) */
	{ "bind",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* connect(int, struct sockaddr *, socklen_t) */
	{ "connect",		2, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* sendto(int, const void *, size_t, int, struct sockaddr *, socklen_t) */
	{ "sendto",		5, &struct_catalog[SC_SOCKADDR_STORAGE] },
	/* landlock_create_ruleset(const struct landlock_ruleset_attr *, size_t, u32) */
	{ "landlock_create_ruleset",	1, &struct_catalog[SC_LANDLOCK_RULESET_ATTR] },
	/* statmount(const struct mnt_id_req *, struct statmount *, size_t, u32) */
	{ "statmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* listmount(const struct mnt_id_req *, u64 *, size_t, u32) */
	{ "listmount",		1, &struct_catalog[SC_MNT_ID_REQ] },
	/* capset(cap_user_header_t hdr, const cap_user_data_t data) */
	{ "capset",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	{ "capset",		2, &struct_catalog[SC_USER_CAP_DATA] },
	/* capget(cap_user_header_t hdr, cap_user_data_t data) */
	{ "capget",		1, &struct_catalog[SC_USER_CAP_HEADER] },
	/* futex_waitv(struct futex_waitv *waiters, unsigned int nr, unsigned int flags, struct timespec *timo, clockid_t clockid) */
	{ "futex_waitv",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* futex_requeue(struct futex_waitv *waiters, unsigned int flags, int nr_wake, int nr_requeue) */
	{ "futex_requeue",	1, &struct_catalog[SC_FUTEX_WAITV] },
	/* sigaltstack(const stack_t *ss, stack_t *old_ss) */
	{ "sigaltstack",	1, &struct_catalog[SC_STACK_T] },
	/*
	 * rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo)
	 * rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig,
	 *                   siginfo_t __user *uinfo)
	 *
	 * Attribution-only registration -- argtype[*] for the siginfo
	 * slot is not ARG_STRUCT_PTR_*, so the schema-aware fill never
	 * runs against rec->a3 (rt_sigqueueinfo) / rec->a4
	 * (rt_tgsigqueueinfo).  The bespoke sanitisers keep owning the
	 * live fill (fill_siginfo_by_class on rt_sigqueueinfo, a fixed
	 * SI_QUEUE shape on rt_tgsigqueueinfo), and this entry lets
	 * struct_field_for_cmp() steer CMP-learned constants at the
	 * named si_signo / si_code / si_pid / si_uid / si_value slots
	 * rather than at coincidentally-same-width slots.  Variants in
	 * the descriptor scope the candidate field pool to the live
	 * _kill / _rt arm whenever struct_desc_resolve_variant is
	 * called with the post-fill buf (CMP-time callers that pass
	 * buf == NULL fall through to the shared head).
	 *
	 * Not mapped here on purpose: waitid's a3 is a kernel-written
	 * OUTPUT (mirrors the gettimeofday / get_robust_list /
	 * cachestat-output skips above) and registering it would
	 * attribute CMP-learned constants against bytes the kernel
	 * wrote rather than bytes we stamped.  pidfd_send_signal's a3
	 * IS mapped (attribution-only, same as rt_sigqueueinfo /
	 * rt_tgsigqueueinfo — the bespoke sanitisers keep owning the
	 * live fill).
	 */
	{ "rt_sigqueueinfo",	3, &struct_catalog[SC_SIGINFO_T] },
	{ "rt_tgsigqueueinfo",	4, &struct_catalog[SC_SIGINFO_T] },
	{ "pidfd_send_signal",	3, &struct_catalog[SC_SIGINFO_T] },
	/* mq_open(const char *, int, mode_t, struct mq_attr *) */
	{ "mq_open",		4, &struct_catalog[SC_MQ_ATTR] },
	/* mq_getsetattr(mqd_t, const struct mq_attr *, struct mq_attr *) */
	{ "mq_getsetattr",	2, &struct_catalog[SC_MQ_ATTR] },
	{ "mq_getsetattr",	3, &struct_catalog[SC_MQ_ATTR] },
	/* msgctl(int msqid, int cmd, struct msqid_ds *buf) — IPC_SET path */
	{ "msgctl",		3, &struct_catalog[SC_MSQID_DS] },
	/* shmctl(int shmid, int cmd, struct shmid_ds *buf) — IPC_SET path */
	{ "shmctl",		3, &struct_catalog[SC_SHMID_DS] },
	/* sched_setparam(pid_t, struct sched_param *) */
	{ "sched_setparam",	2, &struct_catalog[SC_SCHED_PARAM] },
	/* sched_setscheduler(pid_t, int, struct sched_param *) */
	{ "sched_setscheduler",	3, &struct_catalog[SC_SCHED_PARAM] },
	/* io_uring_register(int fd, unsigned op, void *arg, unsigned nr_args) */
	{ "io_uring_register",	3, &struct_catalog[SC_IO_URING_REGISTER_ARGS] },
#ifdef USE_BPF
	/* bpf(int, union bpf_attr *, unsigned int) */
	{ "bpf",		2, &struct_catalog[SC_BPF_ATTR] },
#endif
	/* clock_nanosleep(clockid_t, int, struct timespec *, struct timespec *) */
	{ "clock_nanosleep",	3, &struct_catalog[SC_TIMESPEC] },
	/* nanosleep(struct timespec *, struct timespec *) */
	{ "nanosleep",		1, &struct_catalog[SC_TIMESPEC] },
	/*
	 * utimensat(int, const char *, struct timespec[2], int)
	 * utimensat's `utimes` arg is a 2-element timespec array -- the
	 * mapping table has no array semantics, so the entry below names
	 * the single-struct desc and the existing sanitise_utimensat
	 * callback continues to own the 2-element layout.
	 */
	{ "utimensat",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * ppoll(struct pollfd *, nfds_t, struct timespec *tsp, const sigset_t *, size_t)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_ppoll / ppoll_post_state in syscalls/poll.c continues to
	 * own the live fill; this row only lets schema-aware CMP attribution
	 * name the tv_sec / tv_nsec fields.  ppoll's a1 (pollfd array) is
	 * mapped to SC_POLLFD above and is unaffected.
	 */
	{ "ppoll",		3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo,
	 *                 const struct timespec *uts, size_t sigsetsize)
	 * a3 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitiser (build_timeout stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (uthese,
	 * sigset_t) and a2 (uinfo, siginfo_t) are not timespecs and are
	 * intentionally unregistered here.
	 */
	{ "rt_sigtimedwait",	3, &struct_catalog[SC_TIMESPEC] },
	/*
	 * pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp,
	 *          struct timespec *tsp, void *sig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_pselect6 (allocs the timespec via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a6 (sig, a
	 * packed { sigset_t *, size_t } pointer) is not a timespec and is
	 * intentionally unregistered here.
	 */
	{ "pselect6",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * semtimedop(int semid, struct sembuf *sops, unsigned nsops,
	 *            const struct timespec *timeout)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_semtimedop (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a2 (sops, the
	 * sembuf array) is mapped to SC_SEMBUF below and is unaffected.
	 */
	{ "semtimedop",		4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * clock_settime(clockid_t which_clock, const struct timespec *tp)
	 * a2 is the INPUT timespec.  Attribution-only: the bespoke
	 * sanitise_clock_settime (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "clock_settime",	2, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedsend(mqd_t mqdes, const char *msg_ptr, size_t msg_len,
	 *              unsigned int msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedsend (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedsend",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * mq_timedreceive(mqd_t mqdes, char *msg_ptr, size_t msg_len,
	 *                 unsigned int *msg_prio, const struct timespec *abs_timeout)
	 * a5 is the INPUT abs_timeout timespec.  Attribution-only: the bespoke
	 * sanitise_mq_timedreceive (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "mq_timedreceive",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_getevents(aio_context_t ctx_id, long min_nr, long nr,
	 *              struct io_event *events, struct timespec *timeout)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_getevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_getevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex_wait(void *uaddr, unsigned long val, unsigned long mask,
	 *            unsigned int flags, struct timespec *timeout,
	 *            clockid_t clockid)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_wait (stamps the slot via get_writable_struct)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "futex_wait",		5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * futex(u32 *uaddr, int op, u32 val, struct timespec *utime,
	 *       u32 *uaddr2, u32 val3)
	 * a4 (utime) is a struct timespec pointer only for the WAIT-family
	 * and LOCK_PI / LOCK_PI2 ops (kernel: futex_cmd_has_timeout); for
	 * every other cmd it carries the val2 integer overload instead.
	 * Discriminate on a2 masked by FUTEX_CMD_MASK so the row matches
	 * only the timeout-taking ops, mirroring the kernel's own
	 * `cmd = op & FUTEX_CMD_MASK` dispatch.  Attribution-only: the
	 * bespoke sanitise_futex still owns the a4 fill via &utime_clamp;
	 * this row only lets schema-aware CMP attribution name the
	 * tv_sec / tv_nsec fields for the matching ops.
	 */
	{
		"futex", 4, &struct_catalog[SC_TIMESPEC],
		.discrim_arg_idx	= 2,
		.discrim_mask		= FUTEX_CMD_MASK,
		.discrim_values		= futex_timeout_ops,
		.num_discrim_values	= ARRAY_SIZE(futex_timeout_ops),
	},
	/*
	 * futex_waitv(struct futex_waitv *waiters, unsigned int nr_futexes,
	 *             unsigned int flags, struct timespec *timeout,
	 *             clockid_t clockid)
	 * a4 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_futex_waitv (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.  a1 (waiters)
	 * is mapped to SC_FUTEX_WAITV above and is unaffected.
	 */
	{ "futex_waitv",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
	 *              struct timespec *timeout, const sigset_t *sigmask,
	 *              size_t sigsetsize)
	 * a4 is the INPUT timeout timespec (epoll_pwait2 takes a timespec*
	 * where epoll_pwait took an int ms).  Attribution-only: the bespoke
	 * sanitise_epoll_pwait2 / pick_timespec (stamps the slot via
	 * get_writable_struct) continues to own the live fill; this row only
	 * lets schema-aware CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "epoll_pwait2",	4, &struct_catalog[SC_TIMESPEC] },
	/*
	 * io_pgetevents(aio_context_t ctx_id, long min_nr, long nr,
	 *               struct io_event *events, struct timespec *timeout,
	 *               const struct __aio_sigset *usig)
	 * a5 is the INPUT timeout timespec.  Attribution-only: the bespoke
	 * sanitise_io_pgetevents (stamps the slot via get_writable_address)
	 * continues to own the live fill; this row only lets schema-aware
	 * CMP attribution name the tv_sec / tv_nsec fields.
	 */
	{ "io_pgetevents",	5, &struct_catalog[SC_TIMESPEC] },
	/*
	 * cachestat(unsigned int fd, struct cachestat_range *cstat_range,
	 *           struct cachestat *cstat, unsigned int flags)
	 * Maps the INPUT cstat_range arg only; cstat is the kernel-written
	 * output and is intentionally not registered.  Attribution-only:
	 * sanitise_cachestat / pick_range continues to own the live fill.
	 */
	{ "cachestat",		2, &struct_catalog[SC_CACHESTAT_RANGE] },
	/*
	 * mount_setattr(int dfd, const char *path, unsigned int flags,
	 *               struct mount_attr *uattr, size_t usize)
	 * open_tree_attr(int dfd, const char *filename, unsigned int flags,
	 *                struct mount_attr *uattr, size_t usize)
	 * Both a4 slots are ARG_STRUCT_PTR_IN, but the bespoke sanitisers
	 * (build_mount_attr / sanitise_mount_setattr) overwrite rec->a4
	 * after the schema-aware fill -- attribution-only registration so
	 * struct_field_for_cmp can steer CMP-learned constants at the
	 * named fields.  The curated bespoke fill stays live.
	 */
	{ "mount_setattr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	{ "open_tree_attr",	4, &struct_catalog[SC_MOUNT_ATTR] },
	/*
	 * sembuf is an array slot on ARG_ADDRESS at a2 of both semop and
	 * semtimedop; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * fill_sembuf_array() owns the live (nsops, sem_*) layout.
	 */
	{ "semop",		2, &struct_catalog[SC_SEMBUF] },
	{ "semtimedop",		2, &struct_catalog[SC_SEMBUF] },
	/*
	 * pollfd is an array slot on ARG_ADDRESS at a1 of both poll and
	 * ppoll; the per-element type is named here so future schema
	 * consumers and struct_field_for_cmp can resolve it.  The bespoke
	 * alloc_pollfds() owns the live (nfds, fd, events) layout.
	 */
	{ "poll",		1, &struct_catalog[SC_POLLFD] },
	{ "ppoll",		1, &struct_catalog[SC_POLLFD] },
	/*
	 * openat2(int dfd, const char *filename, struct open_how *how,
	 *         size_t usize)
	 * a3 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_openat2 / build_csfu_struct path keeps owning the
	 * live (flags, mode, resolve) layout and the usize bucket
	 * distribution.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * flags / resolve slot.
	 */
	{ "openat2",		3, &struct_catalog[SC_OPEN_HOW] },
	/*
	 * open_by_handle_at(int mountdirfd, struct file_handle *handle, int flags)
	 * a2 (1-indexed) is the file_handle.  Schema-fill produces a coherent
	 * (handle_bytes, handle_type) pair and exercises the kernel's
	 * handle_bytes bounds check when fuzzed past the sized buffer.
	 */
	{ "open_by_handle_at",	2, &struct_catalog[SC_FILE_HANDLE] },
	/*
	 * timer_create(clockid_t, struct sigevent *, timer_t *)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * timer_create_sanitise() keeps owning the live (sigev_value,
	 * sigev_signo, sigev_notify, _sigev_un._tid) layout and the
	 * SIGEV_* notify-mode distribution.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at sigev_notify / sigev_signo rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "timer_create",	2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * mq_notify(mqd_t, const struct sigevent *)
	 * a2 carries the same struct sigevent that timer_create's a2
	 * carries; the bespoke sanitise_mq_notify() keeps owning the
	 * live fill (NULL-deregister half the time, otherwise SIGEV_NONE
	 * / SIGEV_SIGNAL / SIGEV_THREAD with sigev_signo populated).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at sigev_notify / sigev_signo rather
	 * than at a coincidentally-same-width slot.
	 */
	{ "mq_notify",		2, &struct_catalog[SC_SIGEVENT] },
	/*
	 * set_robust_list(struct robust_list_head __user *head, size_t len)
	 * a1 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_set_robust_list() keeps owning the live (list.next,
	 * futex_offset, list_op_pending) layout.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned constants
	 * at the named fields.  get_robust_list's robust_list_head is an
	 * output (a2 is a double pointer the kernel writes), so only
	 * set_robust_list's a1 is mapped.
	 */
	{ "set_robust_list",	1, &struct_catalog[SC_ROBUST_LIST_HEAD] },
	/*
	 * rseq(struct rseq __user *rseq, u32 rseq_len, int flags, u32 sig)
	 * a1 is the INPUT struct rseq pointer; the bespoke sanitise_rseq()
	 * keeps owning the live fill (32-byte-aligned allocation, zero-
	 * init, a2 length-bucket distribution, a4 signature pin).
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * CMP-learned constants at the named fields rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "rseq",		1, &struct_catalog[SC_RSEQ] },
	/*
	 * setitimer(int which, const struct itimerval __user *value,
	 *           struct itimerval __user *ovalue)
	 * a2 is the INPUT struct itimerval pointer; the bespoke
	 * sanitise_setitimer() keeps owning the live fill (writable
	 * allocation, per-timeval bucket distribution via fill_timeval(),
	 * half-the-time disarm of it_value, a3 routed through
	 * avoid_shared_buffer_out()).  a3 (ovalue) is a kernel-written
	 * output and is intentionally not mapped; getitimer's a2 is
	 * likewise an output and is not mapped either.  Attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at the named tv_sec / tv_usec slots rather than at a
	 * coincidentally-same-width slot.
	 */
	{ "setitimer",		2, &struct_catalog[SC_ITIMERVAL] },
	/*
	 * utime(const char *filename, const struct utimbuf __user *times)
	 * a2 is the INPUT struct utimbuf pointer.  utime has no bespoke
	 * .sanitise -- the slot previously fell through ARG_ADDRESS with no
	 * schema-aware fill.  argtype[1] is now ARG_STRUCT_PTR_IN so the
	 * times buffer lands on a dedicated sized buffer; the catalog entry
	 * also lets struct_field_for_cmp steer CMP-learned constants at the
	 * named actime / modtime slots rather than at a coincidentally-
	 * same-width slot.
	 */
	{ "utime",		2, &struct_catalog[SC_UTIMBUF] },
	/*
	 * fcntl(int fd, int cmd, ... arg)
	 * a3's type depends on the cmd in a2 -- the first proof of the
	 * discriminator-aware syscall_struct_args[] mechanism.  Two
	 * variants, both attribution-only (the bespoke sanitise_fcntl()
	 * keeps owning the live fill):
	 *
	 *   - struct flock for F_GETLK / F_SETLK / F_SETLKW, the F_OFD_*
	 *     variants, F_CANCELLK (and the LK64 variants on archs where
	 *     F_GETLK64 != F_GETLK).  build_flock() picks an l_type /
	 *     l_whence vocab member, a bounded l_start and l_len, and
	 *     zeroes l_pid.  struct_field_for_cmp() steers CMP-learned
	 *     constants at the named l_type / l_whence slots.
	 *
	 *   - struct f_owner_ex for F_GETOWN_EX / F_SETOWN_EX.  The
	 *     bespoke arm picks type from {F_OWNER_TID, F_OWNER_PID,
	 *     F_OWNER_PGRP} and stamps get_pid() into pid;
	 *     struct_field_for_cmp() steers CMP-learned constants at the
	 *     named type slot.
	 *
	 * cmds that don't carry a struct at a3 (F_DUPFD, F_GETFD,
	 * F_SETFL, F_*OWN, F_*SIG, F_*LEASE, F_*PIPE_SZ, F_ADD_SEALS,
	 * F_NOTIFY, F_DUPFD_QUERY, ...) match no variant and resolve to
	 * NULL -- gen_arg_struct_ptr_inout falls through to a zeroed
	 * fallback buffer that sanitise_fcntl overwrites with an fd or
	 * integer flag word, same as before.
	 */
	{
		"fcntl", 3, &struct_catalog[SC_FLOCK],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_flock_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_flock_cmds),
	},
	{
		"fcntl", 3, &struct_catalog[SC_F_OWNER_EX],
		.discrim_arg_idx	= 2,
		.discrim_values		= fcntl_f_owner_ex_cmds,
		.num_discrim_values	= ARRAY_SIZE(fcntl_f_owner_ex_cmds),
	},
	/*
	 * settimeofday(struct timeval __user *tv, struct timezone __user *tz)
	 * a1 is the INPUT struct timeval pointer.  The bespoke
	 * sanitise_settimeofday() keeps owning the live fill (70% near-now
	 * via clock_gettime() + bounded tv_usec, 30% random with an
	 * explicit invalid-tv_usec leg).  Attribution-only registration
	 * lets struct_field_for_cmp steer CMP-learned constants at the
	 * named tv_sec / tv_usec slots rather than at a coincidentally-
	 * same-width slot.
	 *
	 * select(int n, fd_set *, fd_set *, fd_set *, struct timeval *tvp)
	 * a5 is the INOUT timeout pointer.  sanitise_select() stamps a
	 * deterministic {0, 10us} short timeout in the writable buffer it
	 * allocates; the kernel may write back the remaining time, so the
	 * slot is INOUT.  Attribution-only registration again -- the
	 * bespoke fill remains the sole writer; the catalog entry just
	 * lets CMP-learned constants attribute at tv_sec / tv_usec rather
	 * than at a coincidentally-same-width slot.
	 *
	 * futimesat(int dfd, const char __user *filename,
	 *           struct timeval __user *utimes)
	 * a3 is the INPUT struct timeval[2] pointer.  The bespoke
	 * sanitise_futimesat() owns the live fill via a bucketed picker
	 * (NULL leg, near-now / far-past / far-future valid, deliberately
	 * invalid tv_usec, mixed, fully random) writing both array
	 * elements into a get_writable_address(sizeof(*tv) * 2) slab.
	 * Attribution-only registration describes utimes[0] only -- the
	 * single-struct descriptor cannot span the [2] array, but covering
	 * the first element is enough to let struct_field_for_cmp steer
	 * CMP-learned constants at the named tv_sec / tv_usec slots
	 * rather than at a coincidentally-same-width slot.  The bespoke
	 * fill remains the sole writer of both elements.
	 *
	 * utimes(char __user *filename, struct __kernel_old_timeval __user *utimes)
	 * a2 is the INPUT struct timeval[2] pointer.  Attribution-only
	 * registration describes utimes[0] only -- the single-struct
	 * descriptor cannot span the [2] array, but covering the first
	 * element is enough to let struct_field_for_cmp steer CMP-learned
	 * constants at the named tv_sec / tv_usec slots rather than at a
	 * coincidentally-same-width slot.  The live fill remains the sole
	 * writer of both elements.
	 *
	 * Not mapped here on purpose: gettimeofday's a1 is a kernel-written
	 * OUTPUT buffer with no input fill to attribute against.
	 */
	{ "settimeofday",	1, &struct_catalog[SC_TIMEVAL] },
	{ "select",		5, &struct_catalog[SC_TIMEVAL] },
	{ "futimesat",		3, &struct_catalog[SC_TIMEVAL] },
	{ "utimes",		2, &struct_catalog[SC_TIMEVAL] },
	/*
	 * settimeofday(struct timeval __user *tv, struct timezone __user *tz)
	 * a2 is the INPUT struct timezone pointer.  The bespoke
	 * sanitise_settimeofday() keeps owning the live fill via a
	 * RAND_BOOL() gate over get_writable_address(): a 50/50 zero-leg vs
	 * random-leg producing tz_minuteswest in [-780, +780] and tz_dsttime
	 * in [0, 3].  Attribution-only registration lets struct_field_for_cmp
	 * steer CMP-learned constants at the named tz_minuteswest /
	 * tz_dsttime slots rather than at a coincidentally-same-width slot.
	 *
	 * Not mapped here on purpose: gettimeofday's a2 is a kernel-written
	 * OUTPUT buffer with no input fill to attribute against.
	 */
	{ "settimeofday",	2, &struct_catalog[SC_TIMEZONE] },
	/*
	 * listns(const struct ns_id_req __user *req, u64 __user *ns_ids,
	 *        size_t nr_ns_ids, unsigned int flags)
	 * a1 is the INPUT struct ns_id_req pointer.  sanitise_listns()
	 * keeps owning the live fill via build_csfu_struct(&desc_listns)
	 * -- the csfu path stamps the versioned size word and the
	 * subsequent ns_type / ns_id / user_ns_id pickers populate the
	 * remaining slots.  Attribution-only registration lets
	 * struct_field_for_cmp steer CMP-learned constants at the named
	 * size / ns_type / ns_id / user_ns_id slots, with ns_type masked
	 * to the eight defined CLONE_NEW* selector bits.
	 */
	{ "listns",		1, &struct_catalog[SC_NS_ID_REQ] },
#ifdef USE_XATTR_ARGS
	/*
	 * setxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            const struct xattr_args __user *uargs, size_t usize)
	 * getxattrat(int dfd, const char __user *pathname,
	 *            unsigned int at_flags, const char __user *name,
	 *            struct xattr_args __user *uargs, size_t usize)
	 * a5 is the INPUT struct xattr_args pointer in both cases (the
	 * kernel reads value / size / flags before any sub-buffer access
	 * even for getxattrat).  sanitise_{set,get}xattrat() keep owning
	 * the live fill via build_csfu_struct(&desc_{set,get}xattrat) and
	 * the in-line value/size/flags picker; attribution-only
	 * registration lets struct_field_for_cmp steer CMP-learned
	 * constants at the named value / size / flags slots, with flags
	 * masked to XATTR_CREATE | XATTR_REPLACE.
	 */
	{ "setxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
	{ "getxattrat",		5, &struct_catalog[SC_XATTR_ARGS] },
#endif
	/*
	 * file_setattr(int dfd, const char __user *filename,
	 *              struct file_attr __user *ufattr, size_t usize,
	 *              unsigned int at_flags)
	 * a3 is the INPUT struct file_attr pointer.  The bespoke
	 * sanitise_file_setattr() keeps owning the live fill via
	 * build_csfu_struct(&desc_file_setattr) and the curated
	 * FS_XFLAG_* pool picker; this registration is attribution-only
	 * so struct_field_for_cmp can steer CMP-learned constants at
	 * the named fa_xflags / fa_extsize / fa_nextents / fa_projid /
	 * fa_cowextsize slots rather than at a coincidentally-same-
	 * width slot.
	 *
	 * Not mapped here on purpose: file_getattr's a2 buffer is a
	 * kernel-written OUTPUT and has no input fill to attribute
	 * against.
	 */
	{ "file_setattr",	3, &struct_catalog[SC_FILE_ATTR] },
	/*
	 * landlock_add_rule(int ruleset_fd, enum landlock_rule_type rule_type,
	 *                   const void __user *rule_attr, __u32 flags)
	 * a3's type depends on the rule_type in a2, mirroring fcntl's
	 * cmd-discriminated a3 above.  Two variants, both attribution-only
	 * (the bespoke sanitise_landlock_add_rule() keeps owning the live
	 * fill -- argtype[2] is not declared, so the schema-aware fill
	 * path never runs against rec->a3):
	 *
	 *   - struct landlock_path_beneath_attr for
	 *     LANDLOCK_RULE_PATH_BENEATH.  The bespoke arm masks
	 *     allowed_access to the low 16 bits (LANDLOCK_ACCESS_FS_*) and
	 *     stamps get_random_fd() into parent_fd;
	 *     struct_field_for_cmp() steers CMP-learned constants at the
	 *     named allowed_access / parent_fd slots.
	 *
	 *   - struct landlock_net_port_attr for LANDLOCK_RULE_NET_PORT.
	 *     The bespoke arm picks allowed_access from the 2-bit
	 *     LANDLOCK_ACCESS_NET_* pool and stratifies port across
	 *     ephemeral / well-known / privileged / unprivileged ranges;
	 *     struct_field_for_cmp() steers CMP-learned constants at the
	 *     named allowed_access / port slots.
	 *
	 * rule_types outside both lists match no variant and resolve to
	 * NULL -- gen_arg_struct_ptr_inout falls through to a zeroed
	 * fallback buffer that sanitise_landlock_add_rule's switch
	 * default leaves untouched (rec->a3 keeps whatever the generic
	 * arg-gen wrote), same as before.
	 *
	 * Pre-discriminator the catalog could map only one descriptor per
	 * (syscall, arg), so a3 resolved to landlock_path_beneath_attr
	 * for every rule_type and struct_field_for_cmp() was attributing
	 * CMP-learned constants at allowed_access / parent_fd even on
	 * NET_PORT dispatches where the kernel was reading a wholly
	 * different struct.
	 */
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_PATH_BENEATH_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_path_beneath_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_path_beneath_rule_types),
	},
	{
		"landlock_add_rule", 3,
		&struct_catalog[SC_LANDLOCK_NET_PORT_ATTR],
		.discrim_arg_idx	= 2,
		.discrim_values		= landlock_add_rule_net_port_rule_types,
		.num_discrim_values	= ARRAY_SIZE(landlock_add_rule_net_port_rule_types),
	},
	/*
	 * quotactl(unsigned int cmd, const char *special, qid_t id,
	 *          void *addr)
	 * quotactl_fd(unsigned int fd, unsigned int cmd, qid_t id,
	 *             void *addr)
	 * The addr slot (quotactl a4 / quotactl_fd a4) is a struct
	 * if_dqblk pointer under Q_SETQUOTA -- the SET path is the
	 * input arm where the bytes we stamp actually reach the
	 * kernel's quota lookup.  Both sanitisers keep owning the live
	 * fill (writable allocation, dqb_*hardlimit / dqb_*softlimit
	 * pickers, routed through avoid_shared_buffer_inout()); this
	 * registration is attribution-only so struct_field_for_cmp()
	 * can steer CMP-learned constants at the named limit / time /
	 * valid slots rather than at a coincidentally-same-width slot.
	 *
	 * The cmd discriminator is packed: rec->a1 (quotactl) /
	 * rec->a2 (quotactl_fd) is QCMD(subcmd, type) ==
	 * (subcmd << SUBCMDSHIFT) | (type & SUBCMDMASK), so the
	 * pre-extension exact-match discriminator could never resolve
	 * (Q_SETQUOTA would have had to land in the low byte to
	 * compare equal to the raw arg).  discrim_shift = SUBCMDSHIFT
	 * strips the type byte before the match; discrim_mask defaults
	 * to zero (i.e. ~0UL, all bits after the shift), which suffices
	 * because the kernel-side subcmd values are disjoint scalars.
	 *
	 * Q_GETQUOTA / Q_GETNEXTQUOTA also use if_dqblk at the same
	 * slot but they're output-only -- registering them would
	 * attribute CMP-learned constants against bytes the kernel
	 * wrote rather than bytes we stamped.  Subcmds outside the
	 * Q_SETQUOTA pool match no variant and resolve to NULL --
	 * gen_arg_struct_ptr_inout falls through to a zeroed fallback
	 * buffer that the bespoke sanitiser overwrites for the
	 * remaining cmds, same as before.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQBLK],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqblk_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqblk_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * if_dqinfo sibling of the if_dqblk registration above: the same
	 * addr slot (quotactl a4 / quotactl_fd a4) is a struct if_dqinfo
	 * pointer under Q_SETINFO.  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk pair -- the bespoke sanitisers own the live
	 * dqi_bgrace / dqi_igrace fill; this entry only steers
	 * struct_field_for_cmp().  Q_GETINFO uses if_dqinfo at the same
	 * slot but is output-only, so the pool stays at just Q_SETINFO.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_IF_DQINFO],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_if_dqinfo_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_if_dqinfo_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	/*
	 * fs_disk_quota sibling of the if_dqblk / if_dqinfo registrations
	 * above: the same addr slot (quotactl a4 / quotactl_fd a4) is a
	 * struct fs_disk_quota pointer under Q_XSETQLIM (the XFS quota
	 * set-limit command).  Same packed-discriminator extraction
	 * (discrim_shift = SUBCMDSHIFT) and same attribution-only shape
	 * as the if_dqblk / if_dqinfo pairs -- the bespoke sanitisers
	 * own the live fill; this entry only steers
	 * struct_field_for_cmp().  Q_XGETQUOTA / Q_XGETNEXTQUOTA use
	 * fs_disk_quota at the same slot but are output-only, so the
	 * pool stays at just Q_XSETQLIM.
	 */
	{
		"quotactl", 4, &struct_catalog[SC_FS_DISK_QUOTA],
		.discrim_arg_idx	= 1,
		.discrim_values		= quotactl_fs_disk_quota_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_fs_disk_quota_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
	{
		"quotactl_fd", 4, &struct_catalog[SC_FS_DISK_QUOTA],
		.discrim_arg_idx	= 2,
		.discrim_values		= quotactl_fs_disk_quota_subcmds,
		.num_discrim_values	= ARRAY_SIZE(quotactl_fs_disk_quota_subcmds),
		.discrim_shift		= SUBCMDSHIFT,
	},
#ifdef X86
	/*
	 * modify_ldt(int func, void __user *ptr, unsigned long bytecount)
	 * a2 is a struct user_desc pointer only on the write_ldt arm
	 * (func == 1); the read arm (func == 0) hands the kernel a
	 * plain user buffer to splat the live LDT into.  The bespoke
	 * sanitise_modify_ldt() arm keeps owning the live fill (per-bit
	 * RAND_BOOL pickers for the seg_32bit / contents / read_exec_only
	 * / limit_in_pages / seg_not_present / useable / lm bitfields,
	 * rec->a3 pinned to sizeof(struct user_desc));  attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named entry_number / base_addr / limit slots
	 * rather than at a coincidentally-same-width slot.
	 *
	 * Discriminator pool is the single value {1}; func == 0 / 2 fall
	 * through to NULL and the bespoke arm continues to own them.
	 */
	{
		"modify_ldt", 2, &struct_catalog[SC_USER_DESC],
		.discrim_arg_idx	= 1,
		.discrim_value		= 1,
	},
#endif
	/*
	 * seccomp(unsigned int op, unsigned int flags, void __user *args)
	 * a3 is a struct sock_fprog pointer only on SECCOMP_SET_MODE_FILTER
	 * (the cBPF install arm); the other ops point a3 at different
	 * shapes (uint32_t * for SECCOMP_GET_ACTION_AVAIL, a seccomp_notif_
	 * sizes-sized scratch buffer for SECCOMP_GET_NOTIF_SIZES) or leave
	 * it unused (SECCOMP_SET_MODE_STRICT).  The bespoke sanitise_seccomp()
	 * keeps owning the live fill via bpf_gen_seccomp(), which builds a
	 * Markov-chain cBPF program the kernel verifier will load; an
	 * FT_RAW splat across sock_filter[] insn words could not.
	 * Attribution-only registration so struct_field_for_cmp() can steer
	 * CMP-learned constants at the named len / filter slots (and at
	 * the cataloged sock_filter elem_struct's code / jt / jf / k
	 * slots) rather than at a coincidentally-same-width slot.
	 *
	 * argtype[2] is ARG_ADDRESS, not ARG_STRUCT_PTR_*, so the schema-
	 * aware fill path never overwrites rec->a3 -- the bespoke fill
	 * stays the sole writer.  Ops outside the SET_MODE_FILTER pool
	 * match no variant and resolve to NULL, matching the iovec /
	 * sembuf / pollfd attribution-only pattern.
	 *
	 * prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, sock_fprog *, ...)
	 * shares the cBPF install shape and is registered as a two-key row
	 * immediately below (option at a1 == PR_SET_SECCOMP, mode at a2 ==
	 * SECCOMP_MODE_FILTER, sock_fprog pointer at a3).
	 *
	 * setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, ...) is the
	 * SO_ATTACH_FILTER arm of the (level, optname) two-key family the
	 * proof batch below exercises -- it stays bespoke because the BPF
	 * arm REPLACES the optval allocation wholesale rather than fills
	 * it (see socket_setsockopt() SO_ATTACH_FILTER branch), so a
	 * schema-fill row would race the bpf_gen_filter() replacement.
	 */
	{
		"seccomp", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_values		= seccomp_set_mode_filter_ops,
		.num_discrim_values	= ARRAY_SIZE(seccomp_set_mode_filter_ops),
	},
	/*
	 * prctl(option, arg2, arg3, arg4, arg5) cBPF install arm:
	 * option == PR_SET_SECCOMP with arg2 == SECCOMP_MODE_FILTER points
	 * arg3 at a struct sock_fprog the kernel reads to load the classic
	 * BPF program (the cBPF arm; PR_SET_SECCOMP with arg2 ==
	 * SECCOMP_MODE_STRICT ignores arg3, and other option values do not
	 * touch a sock_fprog at all -- those dispatches match no variant
	 * and resolve to NULL).  sanitise_prctl()'s PR_SET_SECCOMP arm
	 * owns the live fill via bpf_gen_seccomp() and stays the sole
	 * writer of rec->a3; the syscallentry leaves argtype[2] at the
	 * default ARG_UNDEFINED, so the schema-aware fill path (gated on
	 * ARG_STRUCT_PTR_*) never resolves this slot and cannot race the
	 * heap sock_fprog.  Attribution-only registration so
	 * struct_field_for_cmp() can steer CMP-learned constants at the
	 * named len / filter slots (and at the cataloged sock_filter
	 * elem_struct's code / jt / jf / k slots) rather than at a
	 * coincidentally-same-width slot.
	 */
	{
		"prctl", 3, &struct_catalog[SC_SOCK_FPROG],
		.discrim_arg_idx	= 1,
		.discrim_value		= PR_SET_SECCOMP,
		.discrim2_arg_idx	= 2,
		.discrim2_value		= SECCOMP_MODE_FILTER,
	},
	/*
	 * ----------------------------------------------------------------
	 * setsockopt(fd, level, optname, optval, optlen) optval -- a4.
	 *
	 * Two-key proof batch: five (level, optname) shapes already owned
	 * by bespoke build_*() functions in syscalls/setsockopt.c, now
	 * resolved through struct_arg_lookup_two_key() from
	 * apply_sockopt_entry().  discrim_arg_idx=2 is level (a2) and
	 * discrim2_arg_idx=3 is optname (a3); the explicit-key consumer
	 * passes them directly off the picked sockopt_table[] row so the
	 * lookup runs against the authoritative picked values, not the
	 * post-mangle rec->a2/a3 the kernel would see.
	 *
	 * argtype[3] is not ARG_STRUCT_PTR_*, so the rec-based
	 * struct_arg_lookup() never resolves these rows -- which is the
	 * point: the bespoke driver owns selection / optlen / BPF-arm
	 * replacement / per-fd pairing, and routes only the fill through
	 * the catalog when a row matches.  Bespoke builders remain in
	 * code as the miss-fallback for the int / bool / string scalar
	 * sockopt_table[] entries (no struct shape, no row to register)
	 * and for the higher-leverage shapes (sctp / mptcp / tcp_repair /
	 * can_filter[] etc.) that follow this proof.
	 * ----------------------------------------------------------------
	 */
	{
		"setsockopt", 4, &struct_catalog[SC_LINGER],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SO_LINGER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_TIMEVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_SOCKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_timeval_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_timeval_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQN],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreqn_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreqn_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IP_MREQ_SOURCE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ip_mreq_source_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ip_mreq_source_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_IPV6_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_IPV6,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_ipv6_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_ipv6_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_PACKET_MREQ],
		.discrim_arg_idx	= 2,
		.discrim_value		= SOL_PACKET,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_packet_mreq_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_packet_mreq_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_GROUP_REQ],
		.discrim_arg_idx	= 2,
		.discrim_values		= setsockopt_mcast_levels,
		.num_discrim_values	= ARRAY_SIZE(setsockopt_mcast_levels),
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_mcast_join_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_mcast_join_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_GROUP_SOURCE_REQ],
		.discrim_arg_idx	= 2,
		.discrim_values		= setsockopt_mcast_levels,
		.num_discrim_values	= ARRAY_SIZE(setsockopt_mcast_levels),
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_mcast_source_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_mcast_source_optnames),
	},
#ifdef USE_TCP_REPAIR_OPT
	{
		"setsockopt", 4, &struct_catalog[SC_TCP_REPAIR_OPT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_TCP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= TCP_REPAIR_OPTIONS,
	},
#endif
#ifdef USE_SCTP
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_INITMSG],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_INITMSG,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_RTOINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_RTOINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOCPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ASSOCINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SETADAPTATION],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADAPTATION_LAYER,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ASSOC_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_assoc_value_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_assoc_value_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SNDINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SNDRCVINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_SEND_PARAM,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT_SUBSCRIBE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENTS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHCHUNK],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_AUTH_CHUNK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_SACK_INFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DELAYED_SACK,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_AUTHKEYID],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_authkeyid_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_authkeyid_optnames),
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_DEFAULT_PRINFO],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_DEFAULT_PRINFO,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_ADD_STREAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_ADD_STREAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_STREAM_VALUE],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_STREAM_SCHEDULER_VALUE,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_EVENT],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_EVENT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRTHLDS_V2],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_THLDS_V2,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_UDPENCAPS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_REMOTE_UDP_ENCAPS_PORT,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PADDRPARAMS],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PEER_ADDR_PARAMS,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PROBEINTERVAL],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_value		= SCTP_PLPMTUD_PROBE_INTERVAL,
	},
	{
		"setsockopt", 4, &struct_catalog[SC_SCTP_PRIM],
		.discrim_arg_idx	= 2,
		.discrim_value		= IPPROTO_SCTP,
		.discrim2_arg_idx	= 3,
		.discrim2_values	= setsockopt_sctp_prim_optnames,
		.num_discrim2_values	= ARRAY_SIZE(setsockopt_sctp_prim_optnames),
	},
#endif
	/*
	 * io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
	 *           struct io_event __user *result)
	 * a2 is the INPUT struct iocb pointer.  sanitise_io_cancel() owns
	 * the live fill (memset, opcode = IOCB_CMD_PREAD, fd from
	 * get_random_fd(), aio_buf via get_writable_address, optional pool
	 * pin from OBJ_AIO_IOCB) and overwrites rec->a2 wholesale.
	 * Attribution-only registration lets struct_field_for_cmp steer
	 * KCOV-CMP learned constants at the named opcode / flags / fd
	 * slots rather than at a coincidentally-same-width slot.
	 *
	 * Not registered here on purpose: io_submit's a3 is
	 * `struct iocb __user * __user *` -- an array-of-pointers, the
	 * wrong indirection for a flat single-struct descriptor.  The
	 * io_cancel a2 slot is the real `struct iocb *`.
	 */
	{ "io_cancel",		2, &struct_catalog[SC_IOCB] },
	/*
	 * iovec is an array slot on ARG_IOVEC / ARG_IOVEC_IN at the
	 * vec / iov argument of every iovec-shaped syscall; the per-
	 * element type is named here so future schema consumers and
	 * struct_field_for_cmp() can resolve it.  The bespoke
	 * alloc_iovec() generator owns the live (iov_base, iov_len)
	 * layout, so all rows below are attribution-only.
	 *
	 * readv(int fd, const struct iovec *vec, int vlen)
	 * writev(int fd, const struct iovec *vec, int vlen)
	 * preadv(unsigned long fd, const struct iovec *vec,
	 *        unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * preadv2(..., int flags)
	 * pwritev(unsigned long fd, const struct iovec *vec,
	 *         unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
	 * pwritev2(..., int flags)
	 * vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs,
	 *          unsigned int flags)
	 * process_madvise(int pidfd, const struct iovec *vec, size_t vlen,
	 *                 int behavior, unsigned int flags)
	 */
	{ "readv",		2, &struct_catalog[SC_IOVEC] },
	{ "writev",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv",		2, &struct_catalog[SC_IOVEC] },
	{ "preadv2",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev",		2, &struct_catalog[SC_IOVEC] },
	{ "pwritev2",		2, &struct_catalog[SC_IOVEC] },
	{ "vmsplice",		2, &struct_catalog[SC_IOVEC] },
	{ "process_madvise",	2, &struct_catalog[SC_IOVEC] },
	/*
	 * process_vm_readv(pid_t pid, const struct iovec *lvec,
	 *                  unsigned long liovcnt, const struct iovec *rvec,
	 *                  unsigned long riovcnt, unsigned long flags)
	 * process_vm_writev(pid_t pid, const struct iovec *lvec,
	 *                   unsigned long liovcnt, const struct iovec *rvec,
	 *                   unsigned long riovcnt, unsigned long flags)
	 * Both lvec (a2) and rvec (a4) are iovec arrays; map each
	 * separately so attribution covers both slots.
	 */
	{ "process_vm_readv",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_readv",	4, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	2, &struct_catalog[SC_IOVEC] },
	{ "process_vm_writev",	4, &struct_catalog[SC_IOVEC] },
	/*
	 * msgsnd(int msqid, const struct msgbuf __user *msgp, size_t msgsz,
	 *        int msgflg)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_msgsnd() keeps owning the live fill: a zmalloc'd
	 * sizeof(struct msgbuf) + msgsz buffer with mtype in [1, 255] and
	 * the variable mtext[] tail covered by the bespoke sizing.
	 * Attribution-only registration lets struct_field_for_cmp() steer
	 * CMP-learned constants at the named mtype slot rather than at a
	 * coincidentally-same-width slot.  msgrcv's a2 is a kernel-written
	 * output buffer and is intentionally not mapped.
	 */
	{ "msgsnd",		2, &struct_catalog[SC_MSGBUF] },
	/*
	 * signalfd(int ufd, const sigset_t __user *user_mask, size_t sizemask)
	 * signalfd4(int ufd, const sigset_t __user *user_mask, size_t sizemask,
	 *           int flags)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_signalfd() / sanitise_signalfd4() keep owning the live
	 * fill: a four-way bucketed sigset_t (empty / single RT signal /
	 * classic standard-signal mix / sigfillset minus SIGKILL+SIGSTOP).
	 * Attribution-only registration lets struct_field_for_cmp() steer
	 * CMP-learned constants at the named __val slot rather than at a
	 * coincidentally-same-width neighbour.  SC_SIGSET_T is shared infra
	 * future sigset_t-taking syscalls (e.g. rt_sigsuspend) can reuse.
	 */
	{ "signalfd",		2, &struct_catalog[SC_SIGSET_T] },
	{ "signalfd4",		2, &struct_catalog[SC_SIGSET_T] },
	{ "rt_sigsuspend",	1, &struct_catalog[SC_SIGSET_T] },
	{ "rt_sigtimedwait",	1, &struct_catalog[SC_SIGSET_T] },
	{ "ppoll",		4, &struct_catalog[SC_SIGSET_T] },
	{ "epoll_pwait",	5, &struct_catalog[SC_SIGSET_T] },
	/*
	 * epoll_pwait2(int epfd, struct epoll_event __user *events,
	 *              int maxevents, const struct timespec __user *timeout,
	 *              const sigset_t __user *sigmask, size_t sigsetsize)
	 * a5 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_epoll_pwait2() keeps owning the live fill via
	 * pick_sigmask().  Attribution-only registration lets
	 * struct_field_for_cmp() steer CMP-learned constants at the named
	 * sigset_t __val slot rather than at a coincidentally-same-width
	 * neighbour.  a4 (timeout) is mapped to SC_TIMESPEC above and is
	 * unaffected.
	 */
	{ "epoll_pwait2",	5, &struct_catalog[SC_SIGSET_T] },
	/*
	 * lsm_set_self_attr(unsigned int attr, struct lsm_ctx __user *ctx,
	 *                   u32 size, u32 flags)
	 * a2 is ARG_ADDRESS (not ARG_STRUCT_PTR_*), so the bespoke
	 * sanitise_lsm_set_self_attr() keeps owning the live fill: a
	 * page_size+64 buffer with id drawn from {SELINUX, SMACK, APPARMOR,
	 * LANDLOCK} and size bucketed across the kernel's
	 * security_setselfattr() validation arms.  Attribution-only
	 * registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named id / flags / len / ctx_len slots rather
	 * than at coincidentally-same-width neighbours; id is the prime
	 * dispatch target (the kernel selects a single LSM hook from it).
	 * lsm_get_self_attr's lsm_ctx a1 is a kernel-written output buffer
	 * and is intentionally not mapped.
	 */
	{ "lsm_set_self_attr",	2, &struct_catalog[SC_LSM_CTX] },
	/*
	 * kexec_load(unsigned long entry, unsigned long nr_segments,
	 *            struct kexec_segment __user *segments,
	 *            unsigned long flags)
	 * a3 is the segments array; argtype[2] is ARG_ADDRESS (not
	 * ARG_STRUCT_PTR_*), so sanitise_kexec_load() in
	 * syscalls/kexec_load.c keeps owning the live fill.  Attribution-
	 * only registration lets struct_field_for_cmp() steer CMP-learned
	 * constants at the named buf / bufsz / mem / memsz slots rather
	 * than at coincidentally-same-width neighbours.  See
	 * SC_KEXEC_SEGMENT above.
	 */
	{ "kexec_load",		3, &struct_catalog[SC_KEXEC_SEGMENT] },
	/* sentinel */
	{ NULL, 0, NULL },
};

/* ------------------------------------------------------------------ */
/* Fast nr -> desc lookup table                                         */
/* ------------------------------------------------------------------ */

/*
 * desc_by_nr_64[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * desc_by_nr_32[syscall_nr][arg_idx - 1] -> slot_binding* or NULL.
 * Populated at init time by scanning the active syscall table.
 * Split to avoid collisions when biarch builds have different syscall
 * numbers for 32-bit and 64-bit that happen to overlap.
 *
 * Each non-NULL cell points into slot_pool[] and groups every
 * registration for that (nr, arg_idx): one optional default entry plus
 * any discriminator variants.  struct_arg_lookup() walks the variants
 * (rec required) first and falls back to the default; a slot with
 * neither a default nor a matching variant returns NULL.
 */
/*
 * Per-slot discriminated variant cap.  Bumped 8 -> 32 ahead of the
 * setsockopt (level, optname) two-key rows: arg4 will accrete one
 * binding per cataloged optval shape, and even the proof batch
 * (linger / timeval / ip_mreqn / ipv6_mreq / packet_mreq) consumes
 * five slots before any of the higher-leverage shapes (sctp / mptcp /
 * tcp_repair) land.  Init BUG()s on overflow, so the cap MUST be raised
 * before any setsockopt rows -- a deferred bump turns the first
 * registration past 8 into a hard boot failure.
 */
#define DISCRIM_VARIANTS_PER_SLOT_MAX	32

struct slot_binding {
	const struct struct_desc	*default_desc;
	const struct syscall_struct_arg	*discrim[DISCRIM_VARIANTS_PER_SLOT_MAX];
	unsigned int			 num_discrim;
};

/*
 * Slot-binding pool.  Sized for every registered (nr, arg) cell across
 * both arch tables -- syscall_struct_args[] is ~60 entries today, so 256
 * leaves growth headroom and stays comfortably under any reasonable
 * static budget.  struct_catalog_init() BUG()s if a registration
 * overflows either the pool or the per-slot variant cap rather than
 * silently dropping mappings.
 */
#define SLOT_POOL_MAX			256

static struct slot_binding slot_pool[SLOT_POOL_MAX];
static unsigned int slot_pool_used;

static const struct slot_binding *desc_by_nr_64[MAX_NR_SYSCALL][6];
static const struct slot_binding *desc_by_nr_32[MAX_NR_SYSCALL][6];

/* ------------------------------------------------------------------ */
/* API                                                                  */
/* ------------------------------------------------------------------ */

const struct struct_desc *struct_catalog_lookup(const char *name)
{
	unsigned int i;

	if (name == NULL)
		return NULL;

	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (strcmp(struct_catalog[i].name, name) == 0)
			return &struct_catalog[i];
	}
	return NULL;
}

const struct struct_desc *struct_arg_lookup(unsigned int nr,
					    unsigned int arg_idx,
					    bool do32bit,
					    struct syscallrecord *rec)
{
	const struct slot_binding *b;
	unsigned int i;

	if (nr >= MAX_NR_SYSCALL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	b = do32bit ? desc_by_nr_32[nr][arg_idx - 1]
		    : desc_by_nr_64[nr][arg_idx - 1];
	if (b == NULL)
		return NULL;

	/*
	 * Discriminated variants are consulted only when the caller has a
	 * live syscall record to read sibling args off.  No rec, or no
	 * discriminated entries registered, falls straight through to the
	 * default desc -- the byte-identical pre-discriminator path.
	 */
	if (rec != NULL && b->num_discrim != 0) {
		for (i = 0; i < b->num_discrim; i++) {
			const struct syscall_struct_arg *sa = b->discrim[i];
			unsigned long raw;

			if (!read_rec_arg(rec, sa->discrim_arg_idx, &raw))
				continue;
			if (!discrim_key_matches(raw, sa->discrim_shift,
						 sa->discrim_mask,
						 sa->discrim_value,
						 sa->discrim_values,
						 sa->num_discrim_values))
				continue;
			/*
			 * Key2 only participates when the entry declares one
			 * (discrim2_arg_idx != 0); single-key rows leave
			 * key2 a no-op and stay byte-identical to the
			 * pre-extension path.  Both keys must match.
			 */
			if (!discrim_key2_matches(sa, rec))
				continue;
			return sa->desc;
		}
	}
	return b->default_desc;
}

const struct struct_desc *struct_arg_lookup_two_key(const char *name,
						    unsigned int arg_idx,
						    unsigned long k1,
						    unsigned long k2)
{
	const struct syscall_struct_arg *sa;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;

	/*
	 * Linear scan keeps the cost identical to struct_arg_lookup_by_name
	 * and avoids a second nr-indexed table just for explicit-key
	 * callers.  syscall_struct_args[] is small (~70 entries today); the
	 * scan runs once per apply_sockopt_entry call which already does
	 * O(table) work picking a random row.
	 *
	 * Skip rows with no second key registered: this entry point is for
	 * genuine two-key resolution -- a single-key row would resolve to
	 * different semantics on its own and a caller wanting that should
	 * use struct_arg_lookup() (rec-path) or struct_arg_lookup_by_name
	 * (discriminator-blind) instead.
	 */
	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (sa->discrim_arg_idx == 0 || sa->discrim2_arg_idx == 0)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (!discrim_key_matches(k1, sa->discrim_shift, sa->discrim_mask,
					 sa->discrim_value, sa->discrim_values,
					 sa->num_discrim_values))
			continue;
		if (!discrim_key_matches(k2, sa->discrim2_shift,
					 sa->discrim2_mask,
					 sa->discrim2_value,
					 sa->discrim2_values,
					 sa->num_discrim2_values))
			continue;
		return sa->desc;
	}
	return NULL;
}

const struct struct_desc *struct_arg_lookup_by_name(const char *name,
						    unsigned int arg_idx)
{
	const struct syscall_struct_arg *sa;
	const struct struct_desc *first = NULL;

	if (name == NULL || arg_idx < 1 || arg_idx > 6)
		return NULL;
	/*
	 * Prefer the slot's default (non-discriminated) entry; fall back to
	 * the first discriminated variant when no default is registered.
	 * Callers that need OR-across-all-variants semantics (e.g. the
	 * nested-address-scrub mask) use struct_arg_any_has_address_field()
	 * below -- single-desc returns can't represent that question.
	 */
	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx != arg_idx)
			continue;
		if (strcmp(sa->syscall_name, name) != 0)
			continue;
		if (sa->discrim_arg_idx == 0)
			return sa->desc;
		if (first == NULL)
			first = sa->desc;
	}
	return first;
}

/*
 * Allocate (or fetch) the slot_binding cell at table[nr][arg_idx-1].
 * Pool growth is bounded by SLOT_POOL_MAX; running out is a hard
 * configuration error (caller forgot to bump the cap when extending
 * the registration table), not a runtime degradation, so BUG() rather
 * than silently dropping mappings.
 */
static struct slot_binding *
slot_binding_get(const struct slot_binding *table[MAX_NR_SYSCALL][6],
		 unsigned int nr, unsigned int arg_idx)
{
	struct slot_binding *b;

	if (table[nr][arg_idx - 1] != NULL)
		return (struct slot_binding *) table[nr][arg_idx - 1];

	if (slot_pool_used >= SLOT_POOL_MAX) {
		output(0, "struct_catalog: SLOT_POOL_MAX (%u) exhausted at "
		       "(nr=%u, arg=%u) -- raise SLOT_POOL_MAX or trim "
		       "syscall_struct_args[]\n",
		       (unsigned int) SLOT_POOL_MAX, nr, arg_idx);
		BUG("struct_catalog: SLOT_POOL_MAX exhausted");
	}
	b = &slot_pool[slot_pool_used++];
	b->default_desc = NULL;
	b->num_discrim = 0;
	table[nr][arg_idx - 1] = b;
	return b;
}

/*
 * Attach one syscall_struct_args[] entry to its (nr, arg_idx) binding.
 * Default entries write through to slot_binding::default_desc;
 * discriminated entries push into the variant list in registration
 * order so the lookup walk's first-match semantic matches the source
 * declaration order.  Multiple defaults for the same slot are a
 * registration bug; BUG() so the conflict surfaces at init rather than
 * silently leaking the later-registered desc into the lookup.
 */
static void slot_binding_attach(const struct slot_binding *table[MAX_NR_SYSCALL][6],
				unsigned int nr,
				const struct syscall_struct_arg *sa)
{
	struct slot_binding *b = slot_binding_get(table, nr, sa->arg_idx);

	if (sa->discrim_arg_idx == 0) {
		if (b->default_desc != NULL) {
			output(0, "struct_catalog: duplicate default "
			       "registration for (%s, arg %u)\n",
			       sa->syscall_name, sa->arg_idx);
			BUG("struct_catalog: duplicate default registration");
		}
		b->default_desc = sa->desc;
		return;
	}
	if (b->num_discrim >= DISCRIM_VARIANTS_PER_SLOT_MAX) {
		output(0, "struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX (%u) "
		       "exhausted for (%s, arg %u) -- raise the cap or "
		       "collapse variants\n",
		       (unsigned int) DISCRIM_VARIANTS_PER_SLOT_MAX,
		       sa->syscall_name, sa->arg_idx);
		BUG("struct_catalog: DISCRIM_VARIANTS_PER_SLOT_MAX exhausted");
	}
	b->discrim[b->num_discrim++] = sa;
}

/*
 * Slot-shape guard for syscall_struct_args[] rows.
 *
 * argtype[] is 0-indexed; syscall_struct_args::arg_idx is 1-indexed.  The
 * off-by-one was caught in the 2026-06-11 audit when six of eight new rows
 * were silently mapping their struct_desc onto the wrong slot -- the
 * dispatcher tolerates the mismatch (the desc fires against whatever
 * argtype actually sits at argidx-1, typically ARG_PATHNAME or a scalar
 * length / fd) so nothing aborted at build or runtime.  This guard turns
 * that silent mis-map into an init-time BUG by demanding that the slot
 * named by (argidx - 1) is a pointer-bearing argtype that can plausibly
 * carry the registered struct:
 *
 *   - ARG_STRUCT_PTR_IN / OUT / INOUT  (schema-aware fill, primary user)
 *   - ARG_ADDRESS / ARG_NON_NULL_ADDRESS  (bespoke .sanitise owns the
 *     live fill, attribution-only catalog row for CMP steering)
 *   - ARG_IOVEC / ARG_IOVEC_IN  (alloc_iovec() owns the live fill;
 *     catalog row is attribution-only for the iov_base / iov_len CMP
 *     names, see the SC_IOVEC comment above the catalog slot)
 *   - ARG_SOCKADDR  (bespoke sockaddr generator owns the live fill;
 *     attribution-only catalog row for sa_family / port CMP names)
 *   - ARG_TIMESPEC / ARG_ITIMERSPEC / ARG_TIMEVAL / ARG_ITIMERVAL
 *     (time-shaped pointer slots; catalog row carries the named
 *     tv_sec / tv_nsec / tv_usec CMP attributions while the per-argtype
 *     filler owns the live struct contents)
 *   - ARG_UNDEFINED  (the syscall has not fully classified its
 *     argtypes -- the bespoke .sanitise owns the fill regardless;
 *     this case is permissive on purpose so the guard does not block
 *     the long tail of legacy syscallentries that still leave argtype
 *     unset.  Migrating those to concrete argtypes tightens the guard
 *     for free.)
 *
 * The rejected set is what the off-by-one bug actually lands on:
 * ARG_PATHNAME (filename slot), ARG_LEN, ARG_FD and all typed-fd
 * argtypes, ARG_MODE_T, ARG_PID, ARG_KEY_SERIAL, ARG_RANGE, ARG_OP,
 * ARG_LIST, ARG_CPU, ARG_NUMA_NODE, ARG_MMAP, ARG_SOCKETINFO, the
 * paired-length helpers (ARG_IOVECLEN, ARG_SOCKADDRLEN, ARG_STRUCT_SIZE),
 * etc. -- every scalar or string slot whose contents are not a struct
 * the kernel will dereference as the desc named here.
 */
static bool is_struct_slot_argtype(enum argtype t)
{
	switch (t) {
	case ARG_ADDRESS:
	case ARG_NON_NULL_ADDRESS:
	case ARG_STRUCT_PTR_IN:
	case ARG_STRUCT_PTR_OUT:
	case ARG_STRUCT_PTR_INOUT:
	case ARG_IOVEC:
	case ARG_IOVEC_IN:
	case ARG_SOCKADDR:
	case ARG_TIMESPEC:
	case ARG_ITIMERVAL:
	case ARG_ITIMERSPEC:
	case ARG_TIMEVAL:
	case ARG_UNDEFINED:
		return true;
	default:
		return false;
	}
}

static const char *argtype_name(enum argtype t)
{
	if ((unsigned int) t < argtype_table_size && argtype_table[t].name != NULL)
		return argtype_table[t].name;
	return "<unknown>";
}

static void validate_one_against_table(const struct syscalltable *table,
				       unsigned int nr_syscalls,
				       const char *tablename,
				       const struct syscall_struct_arg *sa,
				       unsigned int *violations)
{
	struct syscallentry *entry;
	enum argtype t;
	int nr;

	nr = search_syscall_table(table, nr_syscalls, sa->syscall_name);
	if (nr < 0)
		return;		/* not present on this arch table -- not an error */
	if ((unsigned int) nr >= MAX_NR_SYSCALL)
		return;
	entry = table[nr].entry;
	if (entry == NULL)
		return;

	if (sa->arg_idx < 1 || sa->arg_idx > entry->num_args) {
		outputerr("struct_catalog: %s arg_idx %u out of range for "
			  "syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, entry->name,
			  entry->num_args, tablename);
		(*violations)++;
		return;
	}

	t = entry->argtype[sa->arg_idx - 1];
	if (!is_struct_slot_argtype(t)) {
		outputerr("struct_catalog: %s arg %u maps struct_desc \"%s\" "
			  "onto non-struct slot (argtype[%u]=%s, num_args=%u) "
			  "in %s -- argidx is 1-based, argtype[] is 0-based; "
			  "off-by-one?\n",
			  sa->syscall_name, sa->arg_idx,
			  sa->desc != NULL ? sa->desc->name : "<null>",
			  sa->arg_idx - 1, argtype_name(t),
			  entry->num_args, tablename);
		(*violations)++;
	}

	if (sa->discrim_arg_idx != 0 &&
	    (sa->discrim_arg_idx < 1 || sa->discrim_arg_idx > entry->num_args)) {
		outputerr("struct_catalog: %s arg %u discrim_arg_idx %u out of "
			  "range for syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, sa->discrim_arg_idx,
			  entry->name, entry->num_args, tablename);
		(*violations)++;
	}

	if (sa->discrim2_arg_idx != 0 &&
	    (sa->discrim2_arg_idx < 1 || sa->discrim2_arg_idx > entry->num_args)) {
		outputerr("struct_catalog: %s arg %u discrim2_arg_idx %u out of "
			  "range for syscall %s (num_args=%u) in %s\n",
			  sa->syscall_name, sa->arg_idx, sa->discrim2_arg_idx,
			  entry->name, entry->num_args, tablename);
		(*violations)++;
	}
}

static void validate_syscall_struct_args(void)
{
	const struct syscall_struct_arg *sa;
	unsigned int violations = 0;

	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (biarch) {
			validate_one_against_table(syscalls_64bit,
						   max_nr_64bit_syscalls,
						   "64bit table", sa,
						   &violations);
			validate_one_against_table(syscalls_32bit,
						   max_nr_32bit_syscalls,
						   "32bit table", sa,
						   &violations);
		} else {
			validate_one_against_table(syscalls,
						   max_nr_syscalls,
						   "syscall table", sa,
						   &violations);
		}
	}

	if (violations != 0) {
		outputerr("struct_catalog: %u syscall_struct_args[] entr%s "
			  "failed slot-shape validation -- see lines above\n",
			  violations, violations == 1 ? "y" : "ies");
		BUG("struct_catalog: syscall_struct_args[] slot-shape violation");
	}
}

void struct_catalog_init(void)
{
	const struct syscall_struct_arg *sa;
	unsigned int i;
	int nr;

	/*
	 * Holes are zero-init struct_desc slots with .name == NULL --
	 * a sign of a typo'd [SC_X] designator above the slot, or of an
	 * SC_X enum constant added without a matching catalog entry.
	 * Catch it on first init rather than letting the dispatch path
	 * deref a half-zeroed struct_desc.
	 */
	for (i = 0; i < SC_NR_ENTRIES; i++) {
		if (struct_catalog[i].name == NULL) {
			outputerr("struct_catalog: hole at slot %u "
				  "(missing [SC_X] designator)\n", i);
			BUG("struct_catalog: hole in catalog array");
		}
	}

	validate_syscall_struct_args();

	memset(desc_by_nr_64, 0, sizeof(desc_by_nr_64));
	memset(desc_by_nr_32, 0, sizeof(desc_by_nr_32));
	slot_pool_used = 0;

	for (sa = syscall_struct_args; sa->syscall_name != NULL; sa++) {
		if (sa->arg_idx < 1 || sa->arg_idx > 6)
			continue;

		/* Search the active syscall table(s) for this name. */
		if (biarch) {
			nr = search_syscall_table(syscalls_64bit,
						  max_nr_64bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);

			nr = search_syscall_table(syscalls_32bit,
						  max_nr_32bit_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL)
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
		} else {
			nr = search_syscall_table(syscalls,
						  max_nr_syscalls,
						  sa->syscall_name);
			if (nr >= 0 && (unsigned int) nr < MAX_NR_SYSCALL) {
				slot_binding_attach(desc_by_nr_64,
						    (unsigned int) nr, sa);
				slot_binding_attach(desc_by_nr_32,
						    (unsigned int) nr, sa);
			}
		}
	}

	for (i = 0; i < SC_NR_ENTRIES; i++)
		output(0, "struct catalog: registered %s (%u fields, %u bytes)\n",
		       struct_catalog[i].name,
		       struct_catalog[i].num_fields,
		       struct_catalog[i].struct_size);
}
