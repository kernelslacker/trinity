#ifndef _TRINITY_STATS_SUBSYS_FS_LIFECYCLE_H
#define _TRINITY_STATS_SUBSYS_FS_LIFECYCLE_H

struct fs_lifecycle_stats {
	/* fs_lifecycle childop counters */
	unsigned long tmpfs;	/* plain tmpfs variant */
	unsigned long ramfs;	/* ramfs variant */
	unsigned long rdonly;	/* read-only proc/sysfs traversal */
	unsigned long overlay;	/* overlayfs variant */
	unsigned long quota;	/* tmpfs size= / ENOSPC variant */
	unsigned long bind;	/* bind-mount teardown variant */
	unsigned long unsupported;	/* CLONE_NEWUSER refused (helper -EPERM) */
};

#endif /* _TRINITY_STATS_SUBSYS_FS_LIFECYCLE_H */
