#ifndef _TRINITY_STATS_SUBSYS_PROCFS_WRITER_H
#define _TRINITY_STATS_SUBSYS_PROCFS_WRITER_H

/* procfs_writer childop: per-tree write counts, split by outcome.
 * Discovery happens in the parent under root privileges (access(W_OK)
 * succeeds), but writes happen in privilege-dropped children, so a
 * large fraction of open() / write() calls fail.  Counting only
 * "open succeeded" hides this; split into open-fail / write-fail /
 * write-ok so the dump shows real reach into each tree. */
struct procfs_writer_stats {
	unsigned long procfs_open_fail;
	unsigned long procfs_write_fail;
	unsigned long procfs_write_ok;
	unsigned long sysfs_open_fail;
	unsigned long sysfs_write_fail;
	unsigned long sysfs_write_ok;
	unsigned long debugfs_open_fail;
	unsigned long debugfs_write_fail;
	unsigned long debugfs_write_ok;
};

#endif /* _TRINITY_STATS_SUBSYS_PROCFS_WRITER_H */
