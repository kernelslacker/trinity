#pragma once

/*
 * 32-bit compat layouts the kernel reads for compat readv/writev, compat
 * recvmsg/sendmsg/recvmmsg/sendmmsg, compat pselect6 and the time32
 * calls, from include/net/compat.h, include/linux/compat.h, fs/select.c,
 * include/vdso/time32.h and include/linux/time32.h, which no uapi header
 * ships.  All fields are 32-bit: a compat call reads the array header and
 * every entry at 32-bit width, so handing it the native 64-bit layouts
 * misreads every second field.
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

/* From fs/select.c: pselect6's sixth argument, the sigmask pointer and
 * the mask's length. */
struct compat_sigset_argpack {
	__u32 p;
	__u32 size;
};

/* Also from fs/select.c: the block i386's select at 82, old_select(),
 * reads its five arguments from. */
struct compat_sel_arg_struct {
	__u32 n;
	__u32 inp;
	__u32 outp;
	__u32 exp;
	__u32 tvp;
};

/*
 * The y2038 calls sit at 403 (clock_gettime64) to 423 on every 32-bit
 * ABI, and every call numbered past them takes 64-bit time, so a compat
 * call numbered below 403 reads its time structs as old_timespec32,
 * old_timeval32 and the itimer pairs of them.
 */
#define NR_COMPAT_TIME64_FIRST	403

struct old_timespec32 {
	__s32 tv_sec;
	__s32 tv_nsec;
};

struct old_itimerspec32 {
	struct old_timespec32 it_interval;
	struct old_timespec32 it_value;
};

struct old_timeval32 {
	__s32 tv_sec;
	__s32 tv_usec;
};

struct old_itimerval32 {
	struct old_timeval32 it_interval;
	struct old_timeval32 it_value;
};

/* struct timex as a time32 call reads it: with every field 32-bit, each
 * sits at its own offset, not only a narrower one. */
struct old_timex32 {
	__u32 modes;
	__s32 offset;
	__s32 freq;
	__s32 maxerror;
	__s32 esterror;
	__s32 status;
	__s32 constant;
	__s32 precision;
	__s32 tolerance;
	struct old_timeval32 time;
	__s32 tick;
	__s32 ppsfreq;
	__s32 jitter;
	__s32 shift;
	__s32 stabil;
	__s32 jitcnt;
	__s32 calcnt;
	__s32 errcnt;
	__s32 stbcnt;
	__s32 tai;
	__s32 reserved[11];
};

_Static_assert(sizeof(struct compat_iovec) == 8,
	       "compat_iovec must be two 32-bit words");
_Static_assert(sizeof(struct compat_msghdr) == 28,
	       "compat_msghdr must be seven 32-bit words");
_Static_assert(sizeof(struct compat_mmsghdr) == 32,
	       "compat_mmsghdr must be a compat msghdr plus one 32-bit word");
_Static_assert(sizeof(struct compat_sigset_argpack) == 8,
	       "compat_sigset_argpack must be two 32-bit words");
_Static_assert(sizeof(struct compat_sel_arg_struct) == 20,
	       "compat_sel_arg_struct must be five 32-bit words");
_Static_assert(sizeof(struct old_timespec32) == 8,
	       "old_timespec32 must be two 32-bit words");
_Static_assert(sizeof(struct old_itimerspec32) == 16,
	       "old_itimerspec32 must be two old_timespec32s");
_Static_assert(sizeof(struct old_timeval32) == 8,
	       "old_timeval32 must be two 32-bit words");
_Static_assert(sizeof(struct old_itimerval32) == 16,
	       "old_itimerval32 must be two old_timeval32s");
_Static_assert(sizeof(struct old_timex32) == 128,
	       "old_timex32 must be 32 32-bit words");
