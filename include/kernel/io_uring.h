#pragma once

/*
 * Wrapper around <linux/io_uring.h> that ships:
 *   - #ifndef-guarded fallbacks for IORING_REGISTER_* / IORING_OP_* /
 *     IORING_RSRC_* values added after our installed uapi header.
 *   - Trinity-private mirrors for the IORING_REGISTER_* opcode arg
 *     structs.  The kernel copies sizeof(its-own-struct) bytes from the
 *     user pointer, so layout is the only thing that matters at the
 *     syscall boundary; mirroring keeps the file building against any
 *     uapi header vintage trinity supports.
 *   - UAPI-interface-shaped selector values (TRINITY_IO_URING_QUERY_*,
 *     TRINITY_ZCRX_CTRL_*, TRINITY_IO_URING_BPF_CMD_*) for fields inside
 *     the mirrored structs whose system-header enums lack per-value
 *     sentinel #defines testable via #ifndef.
 *
 * Purely handler-local policy values (e.g. flex-array allocation caps)
 * stay with their handler in the .c.
 */
#include <linux/io_uring.h>

/* Opcodes added after our system headers — guard with #ifndef. */
#ifndef IORING_REGISTER_PBUF_STATUS
#define IORING_REGISTER_PBUF_STATUS	26
#endif
#ifndef IORING_REGISTER_NAPI
#define IORING_REGISTER_NAPI		27
#endif
#ifndef IORING_UNREGISTER_NAPI
#define IORING_UNREGISTER_NAPI		28
#endif
#ifndef IORING_REGISTER_CLOCK
#define IORING_REGISTER_CLOCK		29
#endif
#ifndef IORING_REGISTER_CLONE_BUFFERS
#define IORING_REGISTER_CLONE_BUFFERS	30
#endif
#ifndef IORING_REGISTER_SEND_MSG_RING
#define IORING_REGISTER_SEND_MSG_RING	31
#endif
#ifndef IORING_REGISTER_ZCRX_IFQ
#define IORING_REGISTER_ZCRX_IFQ	32
#endif
#ifndef IORING_REGISTER_RESIZE_RINGS
#define IORING_REGISTER_RESIZE_RINGS	33
#endif
#ifndef IORING_REGISTER_MEM_REGION
#define IORING_REGISTER_MEM_REGION	34
#endif
#ifndef IORING_REGISTER_QUERY
#define IORING_REGISTER_QUERY		35
#endif
#ifndef IORING_REGISTER_ZCRX_CTRL
#define IORING_REGISTER_ZCRX_CTRL	36
#endif
#ifndef IORING_REGISTER_BPF_FILTER
#define IORING_REGISTER_BPF_FILTER	37
#endif
#ifndef IORING_REGISTER_USE_REGISTERED_RING
#define IORING_REGISTER_USE_REGISTERED_RING	(1U << 31)
#endif
#ifndef IORING_OP_MSG_RING
#define IORING_OP_MSG_RING			40
#endif
#ifndef IORING_RSRC_REGISTER_SPARSE
#define IORING_RSRC_REGISTER_SPARSE		(1U << 0)
#endif

/*
 * IO_URING_QUERY_* selectors inside struct io_uring_query_hdr's query_op
 * field, and ZCRX_CTRL_* selectors inside struct zcrx_ctrl's op field.
 * No per-value sentinel #define exists in <linux/io_uring/query.h> or
 * <linux/io_uring/zcrx.h> (both are enums) -- mirror the values here.
 */
#define TRINITY_IO_URING_QUERY_OPCODES		0
#define TRINITY_IO_URING_QUERY_ZCRX		1
#define TRINITY_IO_URING_QUERY_SCQ		2
#define TRINITY_IO_URING_QUERY_LAST		3

#define TRINITY_ZCRX_CTRL_FLUSH_RQ		0
#define TRINITY_ZCRX_CTRL_EXPORT		1
#define TRINITY_ZCRX_CTRL_LAST			2

/*
 * IO_URING_BPF_CMD_FILTER: cmd_type selector inside struct io_uring_bpf.
 * No system-header sentinel #define; mirror the value here.
 */
#define TRINITY_IO_URING_BPF_CMD_FILTER	1

/*
 * Local mirrors of the FILE_ALLOC_RANGE / CLOCK opcode argument structs.
 * <linux/io_uring.h> declares io_uring_file_index_range and
 * io_uring_clock_register as enums-or-structs depending on the kernel
 * vintage, with no stable #define companion to detect via #ifndef.
 * Use trinity-private struct names with identical layout: the kernel
 * copies sizeof(its-own-struct) bytes from the user pointer, so layout
 * is the only thing that matters at the syscall boundary.  This keeps
 * the file building against any header vintage without redefinition.
 */
struct trinity_io_uring_file_index_range {
	__u32	off;
	__u32	len;
	__u64	resv;
};

struct trinity_io_uring_clock_register {
	__u32	clockid;
	__u32	__resv[3];
};

/*
 * Trinity-private mirrors for the IORING_REGISTER_* opcode arg structs added
 * in 6.4..6.14.  Same rationale as the file_index_range / clock_register
 * mirrors above: the kernel copies sizeof(its-own-struct) bytes from the user
 * pointer, so layout is the only thing that matters at the syscall boundary,
 * and there is no per-struct sentinel #define to test via #ifndef.  Mirroring
 * keeps the file building against any uapi header vintage trinity supports.
 */
struct trinity_io_uring_buf_reg {
	__u64	ring_addr;
	__u32	ring_entries;
	__u16	bgid;
	__u16	flags;
	__u64	resv[3];
};

struct trinity_io_uring_buf_status {
	__u32	buf_group;
	__u32	head;
	__u32	resv[8];
};

struct trinity_io_uring_napi {
	__u32	busy_poll_to;
	__u8	prefer_busy_poll;
	__u8	opcode;
	__u8	pad[2];
	__u32	op_param;
	__u32	resv;
};

struct trinity_io_uring_zcrx_offsets {
	__u32	head;
	__u32	tail;
	__u32	rqes;
	__u32	__resv2;
	__u64	__resv[2];
};

struct trinity_io_uring_zcrx_ifq_reg {
	__u32	if_idx;
	__u32	if_rxq;
	__u32	rq_entries;
	__u32	flags;
	__u64	area_ptr;
	__u64	region_ptr;
	struct trinity_io_uring_zcrx_offsets offsets;
	__u32	zcrx_id;
	__u32	__resv2;
	__u64	__resv[3];
};

struct trinity_io_uring_mem_region_reg {
	__u64	region_uptr;
	__u64	flags;
	__u64	__resv[2];
};

struct trinity_io_uring_clone_buffers {
	__u32	src_fd;
	__u32	flags;
	__u32	src_off;
	__u32	dst_off;
	__u32	nr;
	__u32	pad[3];
};

/*
 * Trinity-private mirrors for the blind-fd register opcode arg structs:
 * io_uring_restriction / io_uring_task_restriction (RESTRICTIONS task path)
 * and io_uring_bpf / io_uring_bpf_filter (BPF_FILTER task path).  Same
 * rationale as the other private mirrors here -- no per-struct sentinel
 * #define exists to test via #ifndef, so layout-only mirrors keep the
 * file building against any uapi header vintage trinity supports.
 */
struct trinity_io_uring_restriction {
	__u16	opcode;
	__u8	op;
	__u8	resv;
	__u32	resv2[3];
};

struct trinity_io_uring_task_restriction {
	__u16	flags;
	__u16	nr_res;
	__u32	resv[3];
	struct trinity_io_uring_restriction restrictions[];
};

struct trinity_io_uring_bpf_filter {
	__u32	opcode;
	__u32	flags;
	__u32	filter_len;
	__u8	pdu_size;
	__u8	resv[3];
	__u64	filter_ptr;
	__u64	resv2[5];
};

struct trinity_io_uring_bpf {
	__u16	cmd_type;
	__u16	cmd_flags;
	__u32	resv;
	union {
		struct trinity_io_uring_bpf_filter filter;
	};
};

/*
 * __kernel_timespec embedded by value -- inline its layout to avoid pulling
 * in <linux/time_types.h> and to insulate against any future ABI churn.
 */
struct trinity_io_uring_sync_cancel_reg {
	__u64	addr;
	__s32	fd;
	__u32	flags;
	__s64	timeout_tv_sec;
	__s64	timeout_tv_nsec;
	__u8	opcode;
	__u8	pad[7];
	__u64	pad2[3];
};

/*
 * Trinity-private mirror for struct io_uring_query_hdr, defined in
 * <linux/io_uring/query.h> (shipped 6.16).  Same rationale as the other
 * mirrors here: that header isn't pulled in by <linux/io_uring.h> and no
 * per-struct sentinel #define exists to test via #ifndef.  The kernel
 * copies sizeof(its-own-struct) bytes from the user pointer, so layout
 * is the only thing that matters at the syscall boundary.
 */
struct trinity_io_uring_query_hdr {
	__u64	next_entry;
	__u64	query_data;
	__u32	query_op;
	__u32	size;
	__s32	result;
	__u32	__resv[3];
};

/*
 * Trinity-private mirror for struct zcrx_ctrl from
 * <linux/io_uring/zcrx.h> (shipped post-6.16).  Anonymous union body sized
 * to 48 bytes -- both arms (zc_export = 4 + 11*4 = 48; zc_flush = 6*8 = 48)
 * are the same length and the kernel decodes the body off ->op.
 */
struct trinity_io_uring_zcrx_ctrl_export {
	__u32	zcrx_fd;
	__u32	__resv1[11];
};

struct trinity_io_uring_zcrx_ctrl_flush {
	__u64	__resv[6];
};

struct trinity_io_uring_zcrx_ctrl {
	__u32	zcrx_id;
	__u32	op;
	__u64	__resv[2];
	union {
		struct trinity_io_uring_zcrx_ctrl_export	zc_export;
		struct trinity_io_uring_zcrx_ctrl_flush		zc_flush;
	} body;
};

#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES		0x10000000ULL
#endif

#ifndef IORING_OP_READ_MULTISHOT
#define IORING_OP_READ_MULTISHOT	49
#endif
#ifndef IORING_OP_WAITID
#define IORING_OP_WAITID		50
#endif
#ifndef IORING_OP_FUTEX_WAIT
#define IORING_OP_FUTEX_WAIT		51
#define IORING_OP_FUTEX_WAKE		52
#define TRINITY_COMPAT_BACKFILLED_FUTEX_WAIT_WAKE
#endif
#ifndef IORING_OP_FUTEX_WAITV
#define IORING_OP_FUTEX_WAITV		53
#endif
#ifndef IORING_OP_FIXED_FD_INSTALL
#define IORING_OP_FIXED_FD_INSTALL	54
#endif
#ifndef IORING_OP_FTRUNCATE
#define IORING_OP_FTRUNCATE		55
#endif
#ifndef IORING_OP_BIND
#define IORING_OP_BIND			56
#define TRINITY_COMPAT_BACKFILLED_BIND
#endif
#ifndef IORING_OP_LISTEN
#define IORING_OP_LISTEN		57
#endif
#ifndef IORING_OP_RECV_ZC
#define IORING_OP_RECV_ZC		58
#endif
#ifndef IORING_OP_EPOLL_WAIT
#define IORING_OP_EPOLL_WAIT		59
#endif

#ifndef SOCKET_URING_OP_SIOCINQ
#define SOCKET_URING_OP_SIOCINQ		0
#define SOCKET_URING_OP_SIOCOUTQ	1
#define SOCKET_URING_OP_GETSOCKOPT	2
#define SOCKET_URING_OP_SETSOCKOPT	3
#define TRINITY_COMPAT_BACKFILLED_SOCKET_URING_OP
#endif

