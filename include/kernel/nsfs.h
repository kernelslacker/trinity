#pragma once

/*
 * Wrapper around <linux/nsfs.h> that ships #ifndef-guarded fallbacks
 * for the listns UAPI (struct ns_id_req, NS_ID_REQ_SIZE_VER0, and
 * LISTNS_CURRENT_USER) and for the ioctls of an nsfs file.  Defined
 * locally so trinity builds against older kernel headers that predate
 * them.
 *
 * This is the ONLY definition of struct ns_id_req in the tree, and the
 * listns sanitiser includes it.  Upstream declares the second half
 * inside an anonymous struct; the members and the layout are
 * identical, so the flat form below is ABI-equivalent.
 */
#include <linux/ioctl.h>
#include <linux/nsfs.h>
#include <linux/types.h>

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

/*
 * The ioctls of an nsfs file, each guarded alone, as they arrived over
 * the years.  struct mnt_ns_info and its size come with the first of the
 * three mount namespace requests, which arrived together.
 */
#ifndef NSIO
#define NSIO			0xb7
#endif

#ifndef NS_GET_USERNS
#define NS_GET_USERNS		_IO(NSIO, 0x1)
#endif
#ifndef NS_GET_PARENT
#define NS_GET_PARENT		_IO(NSIO, 0x2)
#endif
#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE		_IO(NSIO, 0x3)
#endif
#ifndef NS_GET_OWNER_UID
#define NS_GET_OWNER_UID	_IO(NSIO, 0x4)
#endif
#ifndef NS_GET_MNTNS_ID
#define NS_GET_MNTNS_ID		_IOR(NSIO, 0x5, __u64)
#endif
#ifndef NS_GET_PID_FROM_PIDNS
#define NS_GET_PID_FROM_PIDNS	_IOR(NSIO, 0x6, int)
#endif
#ifndef NS_GET_TGID_FROM_PIDNS
#define NS_GET_TGID_FROM_PIDNS	_IOR(NSIO, 0x7, int)
#endif
#ifndef NS_GET_PID_IN_PIDNS
#define NS_GET_PID_IN_PIDNS	_IOR(NSIO, 0x8, int)
#endif
#ifndef NS_GET_TGID_IN_PIDNS
#define NS_GET_TGID_IN_PIDNS	_IOR(NSIO, 0x9, int)
#endif

#ifndef NS_MNT_GET_INFO
struct mnt_ns_info {
	__u32 size;
	__u32 nr_mounts;
	__u64 mnt_ns_id;
};
#define MNT_NS_INFO_SIZE_VER0	16
#define NS_MNT_GET_INFO		_IOR(NSIO, 10, struct mnt_ns_info)
#endif
#ifndef NS_MNT_GET_NEXT
#define NS_MNT_GET_NEXT		_IOR(NSIO, 11, struct mnt_ns_info)
#endif
#ifndef NS_MNT_GET_PREV
#define NS_MNT_GET_PREV		_IOR(NSIO, 12, struct mnt_ns_info)
#endif

#ifndef NS_GET_ID
#define NS_GET_ID		_IOR(NSIO, 13, __u64)
#endif
