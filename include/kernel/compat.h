#pragma once

/*
 * 32-bit compat layouts the kernel reads for compat readv/writev, compat
 * recvmsg/sendmsg/recvmmsg/sendmmsg and the time32 calls, from
 * include/net/compat.h, include/linux/compat.h and include/vdso/time32.h,
 * which no uapi header ships.  All fields are 32-bit: a compat call reads
 * the array header and every entry at 32-bit width, so handing it the
 * native 64-bit layouts misreads every second field.
 */
#include <linux/types.h>

struct compat_iovec {
	__u32 iov_base;
	__u32 iov_len;
};

struct compat_msghdr {
	__u32 msg_name;
	__s32 msg_namelen;
	__u32 msg_iov;
	__u32 msg_iovlen;
	__u32 msg_control;
	__u32 msg_controllen;
	__u32 msg_flags;
};

/* From include/net/compat.h: a compat mmsghdr is the compat msghdr
 * plus the 32-bit received/sent length the kernel writes back. */
struct compat_mmsghdr {
	struct compat_msghdr msg_hdr;
	__u32 msg_len;
};

/*
 * The y2038 calls sit at 403 (clock_gettime64) to 423 on every 32-bit
 * ABI, and every call numbered past them takes 64-bit time, so a compat
 * call numbered below 403 reads its time structs as old_timespec32.
 */
#define NR_COMPAT_TIME64_FIRST	403

struct old_timespec32 {
	__s32 tv_sec;
	__s32 tv_nsec;
};

_Static_assert(sizeof(struct compat_iovec) == 8,
	       "compat_iovec must be two 32-bit words");
_Static_assert(sizeof(struct compat_msghdr) == 28,
	       "compat_msghdr must be seven 32-bit words");
_Static_assert(sizeof(struct compat_mmsghdr) == 32,
	       "compat_mmsghdr must be a compat msghdr plus one 32-bit word");
_Static_assert(sizeof(struct old_timespec32) == 8,
	       "old_timespec32 must be two 32-bit words");
