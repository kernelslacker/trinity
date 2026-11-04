#pragma once

/*
 * 32-bit compat layouts the kernel reads for compat readv/writev and
 * compat recvmsg/sendmsg/recvmmsg/sendmmsg, from include/net/compat.h and
 * include/linux/compat.h, which no uapi header ships.  All fields
 * are 32-bit: a compat call reads the array header and every entry
 * at 32-bit width, so handing it the native 64-bit layouts misreads
 * every second field.
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

_Static_assert(sizeof(struct compat_iovec) == 8,
	       "compat_iovec must be two 32-bit words");
_Static_assert(sizeof(struct compat_msghdr) == 28,
	       "compat_msghdr must be seven 32-bit words");
_Static_assert(sizeof(struct compat_mmsghdr) == 32,
	       "compat_mmsghdr must be a compat msghdr plus one 32-bit word");
