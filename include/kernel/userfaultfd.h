#pragma once

/*
 * Wrapper around <linux/userfaultfd.h> that ships #ifndef-guarded
 * fallbacks for constants and structs that may be missing on older
 * installed uapi headers.  The syscall itself is available on every
 * kernel trinity targets.
 *
 * Everything here is an upstream #define or struct, never an enum
 * member, so the #ifndef guards mean what they say -- an older header
 * genuinely lacks the name rather than declaring it somewhere a
 * preprocessor test cannot see.
 */
#include <linux/userfaultfd.h>

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif

/*
 * RWP -- read-write protection tracking, Linux 7.3.  The largest
 * functional addition to uffd in that window: a second protection mode
 * alongside WP that makes pages inaccessible rather than read-only, a
 * runtime feature toggle, and an async variant that resolves faults
 * in-kernel with no message to the handler.
 *
 * Three things make it worth carrying rather than waiting for the
 * distro headers: uffd is the classic race-widening primitive, RWP_ASYNC
 * introduces an in-kernel PTE-mutation path that never talks to
 * userspace, and UFFDIO_SET_MODE is a hand-written mutual-exclusion
 * check ("setting a bit in both enable and disable is invalid") on a
 * live toggle -- a validation-bug shape.
 */
#ifndef UFFD_FEATURE_RWP
#define UFFD_FEATURE_RWP		(1<<17)
#endif
#ifndef UFFD_FEATURE_RWP_ASYNC
#define UFFD_FEATURE_RWP_ASYNC		(1<<18)
#endif
#ifndef UFFDIO_REGISTER_MODE_RWP
#define UFFDIO_REGISTER_MODE_RWP	((__u64)1<<3)
#endif
#ifndef UFFD_PAGEFAULT_FLAG_RWP
#define UFFD_PAGEFAULT_FLAG_RWP		(1<<3)
#endif

#ifndef _UFFDIO_RWPROTECT
#define _UFFDIO_RWPROTECT		(0x09)
struct uffdio_rwprotect {
	struct uffdio_range range;
	__u64 mode;
};
#define UFFDIO_RWPROTECT_MODE_RWP	((__u64)1<<0)
#define UFFDIO_RWPROTECT_MODE_DONTWAKE	((__u64)1<<1)
#define UFFDIO_RWPROTECT		_IOWR(UFFDIO, _UFFDIO_RWPROTECT, \
					      struct uffdio_rwprotect)
#endif

#ifndef _UFFDIO_SET_MODE
#define _UFFDIO_SET_MODE		(0x0A)
struct uffdio_set_mode {
	__u64 enable;
	__u64 disable;
};
#define UFFDIO_SET_MODE			_IOW(UFFDIO, _UFFDIO_SET_MODE, \
					     struct uffdio_set_mode)
#endif
