#pragma once

/*
 * Wrapper around <linux/fanotify.h> that ships the #ifndef-guarded
 * fallbacks for FAN_* event/modifier/class bits added after the
 * installed uapi header.  A .c that includes "kernel/fanotify.h" gets
 * the real uapi defines plus the fallback shims for bits the installed
 * header is too old to know.
 *
 * Purely handler-local trinity helper masks (e.g. FAN_MARK_OBJTYPE_MASK,
 * FAN_CLASS_MASK) stay with their handler in the .c.
 */
#include <linux/fanotify.h>

/* Event mask bits added in newer kernels; guard for older toolchains. */
#ifndef FAN_ATTRIB
#define FAN_ATTRIB		0x00000004
#endif
#ifndef FAN_DELETE_SELF
#define FAN_DELETE_SELF		0x00000400
#endif
#ifndef FAN_MOVE_SELF
#define FAN_MOVE_SELF		0x00000800
#endif
#ifndef FAN_OPEN_EXEC
#define FAN_OPEN_EXEC		0x00001000
#endif
#ifndef FAN_OPEN_EXEC_PERM
#define FAN_OPEN_EXEC_PERM	0x00040000
#endif
#ifndef FAN_RENAME
#define FAN_RENAME		0x10000000
#endif
#ifndef FAN_ONDIR
#define FAN_ONDIR		0x40000000
#endif
#ifndef FAN_FS_ERROR
#define FAN_FS_ERROR		0x00008000
#endif
#ifndef FAN_PRE_ACCESS
#define FAN_PRE_ACCESS		0x00100000
#endif
#ifndef FAN_MNT_ATTACH
#define FAN_MNT_ATTACH		0x01000000
#endif
#ifndef FAN_MNT_DETACH
#define FAN_MNT_DETACH		0x02000000
#endif

/* Modifier flag bits added in newer kernels. */
#ifndef FAN_MARK_FILESYSTEM
#define FAN_MARK_FILESYSTEM	0x00000100
#endif
#ifndef FAN_MARK_EVICTABLE
#define FAN_MARK_EVICTABLE	0x00000200
#endif
#ifndef FAN_MARK_IGNORE
#define FAN_MARK_IGNORE		0x00000400
#endif
#ifndef FAN_MARK_INODE
#define FAN_MARK_INODE		0x00000000
#endif
#ifndef FAN_MARK_MNTNS
#define FAN_MARK_MNTNS		0x00000110
#endif

#ifndef FAN_REPORT_FID
#define FAN_REPORT_FID		0x00000200
#endif
#ifndef FAN_CLASS_NOTIF
#define FAN_CLASS_NOTIF		0x00000000
#endif
#ifndef FAN_CLASS_CONTENT
#define FAN_CLASS_CONTENT	0x00000004
#endif
#ifndef FAN_CLASS_PRE_CONTENT
#define FAN_CLASS_PRE_CONTENT	0x00000008
#endif
