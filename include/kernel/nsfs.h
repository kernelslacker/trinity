#pragma once

/*
 * Wrapper around <linux/nsfs.h> that ships #ifndef-guarded fallbacks
 * for the listns UAPI (struct ns_id_req, NS_ID_REQ_SIZE_VER0, and
 * LISTNS_CURRENT_USER).  Defined locally so trinity builds against
 * older kernel headers that predate the listns syscall.
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
#endif

#ifndef LISTNS_CURRENT_USER
#define LISTNS_CURRENT_USER	0xffffffffffffffffULL
#endif
