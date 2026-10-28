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

#ifndef FS_XFLAG_VERITY
#define FS_XFLAG_VERITY		0x00020000
#endif
#ifndef FS_XFLAG_CASEFOLD
#define FS_XFLAG_CASEFOLD	0x00040000
#endif
#ifndef FS_XFLAG_CASENONPRESERVING
#define FS_XFLAG_CASENONPRESERVING 0x00080000
#endif
#ifndef FS_XFLAG_HASATTR
#define FS_XFLAG_HASATTR	0x80000000
#endif

#ifndef PROCFS_IOCTL_MAGIC
#define PROCFS_IOCTL_MAGIC	'f'
#endif

#ifndef PAGEMAP_SCAN
#define PAGEMAP_SCAN	_IOWR(PROCFS_IOCTL_MAGIC, 16, struct pm_scan_arg)

/* What a scan reports in struct page_region and takes in its masks. */
#define PAGE_IS_WPALLOWED	(1 << 0)
#define PAGE_IS_WRITTEN		(1 << 1)
#define PAGE_IS_FILE		(1 << 2)
#define PAGE_IS_PRESENT		(1 << 3)
#define PAGE_IS_SWAPPED		(1 << 4)
#define PAGE_IS_PFNZERO		(1 << 5)
#define PAGE_IS_HUGE		(1 << 6)
#define PAGE_IS_SOFT_DIRTY	(1 << 7)

struct page_region {
	__u64 start;
	__u64 end;
	__u64 categories;
};

#define PM_SCAN_WP_MATCHING	(1 << 0)
#define PM_SCAN_CHECK_WPASYNC	(1 << 1)

struct pm_scan_arg {
	__u64 size;
	__u64 flags;
	__u64 start;
	__u64 end;
	__u64 walk_end;
	__u64 vec;
	__u64 vec_len;
	__u64 max_pages;
	__u64 category_inverted;
	__u64 category_mask;
	__u64 category_anyof_mask;
	__u64 return_mask;
};
#endif
#ifndef PAGE_IS_GUARD
#define PAGE_IS_GUARD		(1 << 8)
#endif
#ifndef PAGE_IS_ACCESSED
#define PAGE_IS_ACCESSED	(1 << 9)
#endif

#ifndef PROCMAP_QUERY
#define PROCMAP_QUERY	_IOWR(PROCFS_IOCTL_MAGIC, 17, struct procmap_query)

enum procmap_query_flags {
	PROCMAP_QUERY_VMA_READABLE		= 0x01,
	PROCMAP_QUERY_VMA_WRITABLE		= 0x02,
	PROCMAP_QUERY_VMA_EXECUTABLE		= 0x04,
	PROCMAP_QUERY_VMA_SHARED		= 0x08,
	PROCMAP_QUERY_COVERING_OR_NEXT_VMA	= 0x10,
	PROCMAP_QUERY_FILE_BACKED_VMA		= 0x20,
};

struct procmap_query {
	__u64 size;
	__u64 query_flags;		/* in */
	__u64 query_addr;		/* in */
	__u64 vma_start;		/* out */
	__u64 vma_end;			/* out */
	__u64 vma_flags;		/* out */
	__u64 vma_page_size;		/* out */
	__u64 vma_offset;		/* out */
	__u64 inode;			/* out */
	__u32 dev_major;		/* out */
	__u32 dev_minor;		/* out */
	__u32 vma_name_size;		/* in/out */
	__u32 build_id_size;		/* in/out */
	__u64 vma_name_addr;		/* in */
	__u64 build_id_addr;		/* in */
};
#endif
