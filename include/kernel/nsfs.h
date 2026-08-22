#pragma once

/*
 * Wrapper around <linux/nsfs.h> that ships #ifndef-guarded fallbacks
 * for the listns UAPI (struct ns_id_req, NS_ID_REQ_SIZE_VER0, and
 * LISTNS_CURRENT_USER).  Defined locally so trinity builds against
 * older kernel headers that predate the listns syscall.
 *
 * This is the ONLY definition of struct ns_id_req in the tree: the
 * listns sanitiser, the struct-catalog spine and the mount/namespace
 * leaf table all include this header.  Upstream declares the second
 * half inside an anonymous struct; the members and the layout are
 * identical, so the flat form below is ABI-equivalent.
 */
#include <linux/nsfs.h>

#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 spare;
	__u64 ns_id;
	__u32 ns_type;
	__u32 spare2;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	32
#else
/*
 * Host <linux/nsfs.h> supplied the struct.  Assert its size matches
 * NS_ID_REQ_SIZE_VER0 so a uapi bump that grows the head trips at
 * compile time rather than silently diverging from the fallback.
 */
_Static_assert(sizeof(struct ns_id_req) == NS_ID_REQ_SIZE_VER0,
	       "struct ns_id_req head drifted from trinity fallback; update the fallback in include/kernel/nsfs.h");
#endif

#ifndef LISTNS_CURRENT_USER
#define LISTNS_CURRENT_USER	0xffffffffffffffffULL
#endif
