/*
 * When an unchanged ctime says an unchanged inode: the rule the oracles that
 * look an inode up twice and take a held ctime as a held inode judge by.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "ctime-rule.h"
#include "kernel/mount.h"
#include "kernel/stat.h"
#include "kernel/unistd.h"
#include "utils.h"

/*
 * The filesystems the rule judges on, and the release whose file_system_type
 * first set FS_MGTIME (0 for none).  A getattr that reads the ctime of an
 * inode on a multigrain filesystem marks it queried (fill_mg_cmtime()), and
 * the next change stamps a fine-grained time past it
 * (inode_set_ctime_current()).  Anywhere else a change stamps the coarse
 * clock cut to the filesystem's grain, so a second change inside one grain
 * leaves the ctime the first left.  ext2 and ext3 are served by drivers
 * without FS_MGTIME yet report ext4's magic to statfs(), so the type goes by
 * name.  Each one listed stamps from the local clock, which the fallback in
 * ctime_rule_holds() leans on: a network filesystem's server clock owes it
 * nothing, so no type that is not listed is judged.
 */
static const struct ctime_fs {
	const char *name;
	unsigned int mgtime_since;
} ctime_fs[] = {
	{ "btrfs",	KERNEL_RELEASE(6, 13) },
	{ "ext2",	0 },
	{ "ext3",	0 },
	{ "ext4",	KERNEL_RELEASE(6, 13) },
	{ "f2fs",	KERNEL_RELEASE(7, 4) },
	{ "tmpfs",	KERNEL_RELEASE(6, 13) },
	{ "xfs",	KERNEL_RELEASE(6, 13) },
};

/*
 * How much older than the reference reading a ctime has to be for the coarse
 * clock to have left its grain behind: the coarsest of the filesystems listed
 * keep whole seconds (ext2, and ext3 and ext4 with 128-byte inodes, whose
 * s_time_gran is NSEC_PER_SEC), and a second more covers the coarse tick.
 */
#define CTIME_GRAIN_MARGIN_SEC	2

bool ctime_rule_holds(const char *fs_type, unsigned int release,
		      const struct timespec *ctime, const struct timespec *before)
{
	const struct ctime_fs *fs = NULL;
	unsigned int i;

	if (fs_type == NULL)
		return false;
	for (i = 0; i < ARRAY_SIZE(ctime_fs); i++) {
		if (strcmp(fs_type, ctime_fs[i].name) == 0) {
			fs = &ctime_fs[i];
			break;
		}
	}
	if (fs == NULL)
		return false;

	/*
	 * A whole-second grain truncates a fine-grained stamp too, and leaves
	 * tv_nsec 0: a nonzero one says the filesystem keeps nanoseconds.
	 */
	if (fs->mgtime_since != 0 && release >= fs->mgtime_since &&
	    ctime->tv_nsec != 0)
		return true;

	/*
	 * Otherwise a change after the reference reading stamps a time no
	 * earlier than it, so a ctime a grain older cannot come back.  Past
	 * 2038 a filesystem without wide timestamps clamps every stamp to the
	 * one value (timestamp_truncate()), which this cannot see.
	 */
	return before->tv_sec < INT32_MAX &&
	       ctime->tv_sec < before->tv_sec - CTIME_GRAIN_MARGIN_SEC;
}

/* The running kernel's release, or 0 when uname() cannot say. */
static unsigned int running_release(void)
{
	static unsigned int release;
	static bool asked;
	unsigned int major, minor;
	struct utsname u;

	if (!asked) {
		asked = true;
		if (uname(&u) == 0 &&
		    sscanf(u.release, "%u.%u", &major, &minor) == 2)
			release = KERNEL_RELEASE(major, minor);
	}
	return release;
}

#ifdef SYS_statmount
/*
 * The type names of the last few mounts asked about, by unique id.  An id is
 * never reused and a mount never changes type, so an entry cannot go stale.
 */
#define MNT_TYPE_CACHE	8

static struct {
	unsigned long long mnt_id;
	char type[8];		/* longer than any type listed: "" */
} mnt_types[MNT_TYPE_CACHE];
static unsigned int mnt_types_next;

/* The type name of the mount @mnt_id, or NULL when statmount() cannot say. */
static const char *mount_fs_type(unsigned long long mnt_id)
{
	struct mnt_id_req req = {
		.size = MNT_ID_REQ_SIZE_VER0,
		.mnt_id = mnt_id,
		.param = STATMOUNT_FS_TYPE,
	};
	uint64_t buf[(sizeof(struct statmount) + 64) / sizeof(uint64_t)];
	struct statmount *sm = (struct statmount *) buf;
	size_t room = sizeof(buf) - sizeof(*sm);
	const char *name;
	unsigned int i, slot;

	if (mnt_id == 0)
		return NULL;
	for (i = 0; i < MNT_TYPE_CACHE; i++) {
		if (mnt_types[i].mnt_id == mnt_id)
			return mnt_types[i].type;
	}

	if (syscall(SYS_statmount, &req, sm, sizeof(buf), 0) != 0 ||
	    !(sm->mask & STATMOUNT_FS_TYPE) || sm->fs_type >= room)
		return NULL;
	name = sm->str + sm->fs_type;
	if (memchr(name, '\0', room - sm->fs_type) == NULL)
		return NULL;

	slot = mnt_types_next++ % MNT_TYPE_CACHE;
	mnt_types[slot].mnt_id = mnt_id;
	if (strlen(name) < sizeof(mnt_types[slot].type))
		strcpy(mnt_types[slot].type, name);
	else
		mnt_types[slot].type[0] = '\0';
	return mnt_types[slot].type;
}
#else
static const char *mount_fs_type(unsigned long long mnt_id)
{
	(void) mnt_id;
	return NULL;
}
#endif

bool ctime_marks_change(unsigned long long mnt_id, const struct timespec *ctime,
			const struct timespec *before)
{
	return ctime_rule_holds(mount_fs_type(mnt_id), running_release(),
				ctime, before);
}

unsigned long long stat_mnt_id(int dfd, const char *path, int flags,
			       dev_t dev, ino_t ino)
{
	struct statx stx;

	if (syscall(SYS_statx, dfd, path, flags,
		    STATX_INO | STATX_MNT_ID_UNIQUE, &stx) != 0 ||
	    !(stx.stx_mask & STATX_INO) ||
	    !(stx.stx_mask & STATX_MNT_ID_UNIQUE) ||
	    makedev(stx.stx_dev_major, stx.stx_dev_minor) != dev ||
	    stx.stx_ino != ino)
		return 0;
	return stx.stx_mnt_id;
}
