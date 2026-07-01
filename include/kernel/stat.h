#pragma once

#include <linux/stat.h>

#ifndef STATX_TYPE
#define STATX_TYPE		0x00000001
#define STATX_MODE		0x00000002
#define STATX_NLINK		0x00000004
#define STATX_UID		0x00000008
#define STATX_GID		0x00000010
#define STATX_ATIME		0x00000020
#define STATX_MTIME		0x00000040
#define STATX_CTIME		0x00000080
#define STATX_INO		0x00000100
#define STATX_SIZE		0x00000200
#define STATX_BLOCKS		0x00000400
#define STATX_BTIME		0x00000800
#define STATX_MNT_ID		0x00001000
#define STATX_DIOALIGN		0x00002000
#define STATX_MNT_ID_UNIQUE	0x00004000
#define STATX_SUBVOL		0x00008000
#endif

/*
 * Per-bit guards: STATX_WRITE_ATOMIC landed in 6.11 and STATX_DIO_READ_ALIGN
 * in 6.13, after the umbrella STATX_TYPE block above was last refreshed.  A
 * uapi snapshot from 6.10..6.12 defines STATX_TYPE (skipping the block above)
 * but is missing one or both of these.  Guarding individually fills the gap
 * without redefining bits the host header already provides.
 */
#ifndef STATX_WRITE_ATOMIC
#define STATX_WRITE_ATOMIC	0x00010000
#endif
#ifndef STATX_DIO_READ_ALIGN
#define STATX_DIO_READ_ALIGN	0x00020000
#endif

#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS	0x000007ffU
#endif
#ifndef STATX_ALL
#define STATX_ALL		0x00000fffU
#endif
