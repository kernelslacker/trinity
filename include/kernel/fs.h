#pragma once

#if __has_include(<linux/fs.h>)
#include <linux/fs.h>
#endif

#ifndef SEEK_DATA
#define SEEK_DATA 3
#endif
#ifndef SEEK_HOLE
#define SEEK_HOLE 4
#endif
#ifndef RWF_HIPRI
#define RWF_HIPRI 0x00000001
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC 0x00000002
#define RWF_SYNC  0x00000004
#endif
#ifndef RWF_NOWAIT
#define RWF_NOWAIT 0x00000008
#endif
#ifndef RWF_APPEND
#define RWF_APPEND 0x00000010
#endif
#ifndef RWF_NOAPPEND
#define RWF_NOAPPEND 0x00000020
#endif
#ifndef RWF_ATOMIC
#define RWF_ATOMIC 0x00000040
#endif
#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE 0x00000080
#endif
#ifndef RWF_NOSIGNAL
#define RWF_NOSIGNAL 0x00000100
#endif

#ifndef FILE_ATTR_SIZE_VER0
struct file_attr {
	__u64 fa_xflags;
	__u32 fa_extsize;
	__u32 fa_nextents;
	__u32 fa_projid;
	__u32 fa_cowextsize;
};
#define FILE_ATTR_SIZE_VER0	24
#define FILE_ATTR_SIZE_LATEST	FILE_ATTR_SIZE_VER0
#endif

#ifndef FS_XFLAG_HASATTR
#define FS_XFLAG_HASATTR	0x80000000
#endif
