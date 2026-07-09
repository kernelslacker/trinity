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
#include <linux/userfaultfd.h>
#include <mqueue.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>

#include "config.h"
/*
 * linux/if_pppox.h pulls in linux/l2tp.h, whose enum declares
 * L2TP_ATTR_IP6_SADDR / RX_COOKIE_DISCARDS / ... as identifiers.
 * include/kernel headers define those same names as fallback numeric macros for
 * older kernel-headers packages, so the include must precede the kernel fallback header;
 * otherwise the macro expansion turns the enum members into integer
 * literals and -Werror trips.
 */
#ifdef USE_PPPOX
#include <linux/if_pppox.h>
#endif
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

#include "kernel/keyctl.h"
#include "kernel/l2tp.h"
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
#else
/*
 * Host <linux/openat2.h> supplied the struct.  Assert its size matches
 * the 3-u64 fallback above so a future uapi bump that grows the struct
 * trips at compile time rather than silently diverging from the shim
 * in struct_catalog/fcntl.c.
 */
_Static_assert(sizeof(struct open_how) == 3 * sizeof(__u64),
	       "struct open_how head drifted from trinity fallback; update both fallback copies");
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
#else
/*
 * Host <linux/nsfs.h> supplied the struct.  Assert its size matches
 * NS_ID_REQ_SIZE_VER0 so a future uapi bump that grows the head trips
 * at compile time rather than silently diverging from the shim in
 * struct_catalog/mount.c.
 */
_Static_assert(sizeof(struct ns_id_req) == NS_ID_REQ_SIZE_VER0,
	       "struct ns_id_req head drifted from trinity fallback; update both fallback copies");
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
#else
/*
 * Host <linux/lsm.h> supplied the struct.  Assert the fixed head is
 * the 4-u64 layout the fallback declares so a future uapi bump that
 * grows the head trips at compile time rather than silently diverging
 * from the shim in struct_catalog/lsm.c.  Only the fixed head is
 * cataloged; the flexible ctx[] tail is intentionally not covered.
 */
_Static_assert(sizeof(struct lsm_ctx) == 4 * sizeof(__u64),
	       "struct lsm_ctx head drifted from trinity fallback; update both fallback copies");
#endif

/*
 * struct keyctl_pkey_params / keyctl_dh_params may not be present in
 * every host's <linux/keyctl.h>.  The field tables live in
 * struct_catalog/keyctl.c, but the spine's struct_catalog[] entry
 * takes sizeof(struct keyctl_pkey_params), so the type definition must
 * also be visible here.  The ifndef guard hands off to the host header
 * when it is present; both TUs land on a layout-identical definition
 * either way.  A future uapi bump that grows either struct needs both
 * copies updated.
 */
#ifndef KEYCTL_SUPPORTS_ENCRYPT
struct keyctl_dh_params {
	__s32 priv;
	__s32 prime;
	__s32 base;
};

struct keyctl_pkey_params {
	__s32 key_id;
	__u32 in_len;
	__u32 out_len;
	__u32 __spare[7];
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
	/*
	 * userfaultfd ioctl argument structs.  Attribution-only: ioctls
	 * do not resolve through syscall_struct_args[] and the bespoke
	 * sanitisers in ioctls/userfaultfd.c own every live fill.  These
	 * entries let struct_field_for_cmp() name the specific u64 slot
	 * (dst / src / len / mode / features / ...) a KCOV-CMP-learned
	 * constant fell out of.  Consumers reach the descriptors via
	 * struct_catalog_lookup() on the struct name.
	 */
	[SC_UFFDIO_RANGE] = {
		.name		= "uffdio_range",
		.struct_size	= sizeof(struct uffdio_range),
		.fields		= uffdio_range_fields,
		.num_fields	= ARRAY_SIZE(uffdio_range_fields),
	},
	[SC_UFFDIO_API] = {
		.name		= "uffdio_api",
		.struct_size	= sizeof(struct uffdio_api),
		.fields		= uffdio_api_fields,
		.num_fields	= ARRAY_SIZE(uffdio_api_fields),
	},
	[SC_UFFDIO_REGISTER] = {
		.name		= "uffdio_register",
		.struct_size	= sizeof(struct uffdio_register),
		.fields		= uffdio_register_fields,
		.num_fields	= ARRAY_SIZE(uffdio_register_fields),
	},
	[SC_UFFDIO_COPY] = {
		.name		= "uffdio_copy",
		.struct_size	= sizeof(struct uffdio_copy),
		.fields		= uffdio_copy_fields,
		.num_fields	= ARRAY_SIZE(uffdio_copy_fields),
	},
	[SC_UFFDIO_ZEROPAGE] = {
		.name		= "uffdio_zeropage",
		.struct_size	= sizeof(struct uffdio_zeropage),
		.fields		= uffdio_zeropage_fields,
		.num_fields	= ARRAY_SIZE(uffdio_zeropage_fields),
	},
#ifdef USE_IF_ALG
	/*
	 * struct af_alg_iv: sendmsg(SOL_ALG, ALG_SET_IV) ancillary payload.
	 * Attribution-only -- AF_ALG IV cmsgs are built by the bespoke
	 * childops/net af-alg walker rather than the schema-aware fill, so
	 * consumers reach the descriptor via struct_catalog_lookup() on the
	 * struct name and struct_field_for_cmp() names the ivlen slot on a
	 * KCOV-CMP-learned constant instead of guessing off width alone.
	 * struct_size covers only the fixed __u32 head; the iv[] flexible
	 * tail is intentionally uncataloged (same shape as file_handle).
	 */
	[SC_AF_ALG_IV] = {
		.name		= "af_alg_iv",
		.struct_size	= sizeof(struct af_alg_iv),
		.fields		= af_alg_iv_fields,
		.num_fields	= ARRAY_SIZE(af_alg_iv_fields),
	},
#endif
	[SC_KEYCTL_PAYLOAD] = {
		.name			= "keyctl_payload",
		/*
		 * a2 carries the widest per-cmd struct (keyctl_pkey_params
		 * at 40 bytes) across the cataloged variants; DH_COMPUTE's
		 * 12-byte keyctl_dh_params fits inside.  Attribution-only
		 * (keyctl's argtype[1] is ARG_UNDEFINED so the schema-aware
		 * fill never allocates against this size), so the value is
		 * a bound for struct_field_for_cmp()'s per-variant walk
		 * rather than a live-fill allocation size.
		 */
		.struct_size		= sizeof(struct keyctl_pkey_params),
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 1,
		.variants		= keyctl_payload_variants,
		.num_variants		= ARRAY_SIZE(keyctl_payload_variants),
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


