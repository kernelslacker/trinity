/*
 * Self-check for the rule the re-lookup oracles take a held ctime as a held
 * inode by (syscalls/fs/ctime-rule.c): the filesystems and kernels whose
 * ctime marks every later change, and the coarse-clock fallback elsewhere.
 * It also holds the seams the oracles' own tests use, so that they run the
 * same on any host.
 */

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "ctime-rule.h"
#include "debug.h"		/* BUG */

/*
 * The seams: ctime_marks_change() answers as armed, refusing any ctime no
 * newer than fake_ctime_refuse_upto first when that is set, and stat_mnt_id()
 * answers no mount at all, or, where the kernel has no unique ids (before
 * v6.8), a stand-in for each filesystem.  Unarmed, each goes on to the real
 * function.
 */
enum fake_ctime_rule { FAKE_CTIME_REAL, FAKE_CTIME_HOLDS, FAKE_CTIME_FAILS };

enum fake_ctime_rule fake_ctime_rule;
struct timespec fake_ctime_refuse_upto;
bool fake_mnt_ids;
bool fake_no_mnt_id;

bool __real_ctime_marks_change(unsigned long long mnt_id,
			       const struct timespec *ctime,
			       const struct timespec *before);
bool __wrap_ctime_marks_change(unsigned long long mnt_id,
			       const struct timespec *ctime,
			       const struct timespec *before);
unsigned long long __real_stat_mnt_id(int dfd, const char *path, int flags,
				      dev_t dev, ino_t ino);
unsigned long long __wrap_stat_mnt_id(int dfd, const char *path, int flags,
				      dev_t dev, ino_t ino);

bool __wrap_ctime_marks_change(unsigned long long mnt_id,
			       const struct timespec *ctime,
			       const struct timespec *before)
{
	if (fake_ctime_refuse_upto.tv_sec != 0 &&
	    (ctime->tv_sec < fake_ctime_refuse_upto.tv_sec ||
	     (ctime->tv_sec == fake_ctime_refuse_upto.tv_sec &&
	      ctime->tv_nsec <= fake_ctime_refuse_upto.tv_nsec)))
		return false;

	switch (fake_ctime_rule) {
	case FAKE_CTIME_HOLDS:
		return true;
	case FAKE_CTIME_FAILS:
		return false;
	default:
		return __real_ctime_marks_change(mnt_id, ctime, before);
	}
}

unsigned long long __wrap_stat_mnt_id(int dfd, const char *path, int flags,
				      dev_t dev, ino_t ino)
{
	unsigned long long id;

	if (fake_no_mnt_id)
		return 0;
	id = __real_stat_mnt_id(dfd, path, flags, dev, ino);
	if (id == 0 && fake_mnt_ids)
		id = (1ULL << 40) | (unsigned long long) dev;
	return id;
}

static unsigned int failed;

static void check(const char *what, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "ctime rule: %s\n", what);
	failed++;
}

/* The coarse clock as the reference getattr's caller read it. */
static const struct timespec before = { 1700000000, 500000000 };

/* A ctime in the reference reading's own second, and one past the grain. */
#define FRESH	(before.tv_sec)
#define OLD	(before.tv_sec - 3)

static bool holds(const char *fs_type, unsigned int release, time_t sec,
		  long nsec, const struct timespec *clock)
{
	struct timespec ctime = { sec, nsec };

	return ctime_rule_holds(fs_type, release, &ctime, clock);
}

/*
 * A multigrain filesystem marks every change after a getattr from the
 * release it began in, unless it keeps whole seconds; any other listed one
 * only a ctime the coarse clock has left behind, and a filesystem that is
 * not listed nothing.
 */
static void rule_follows_the_filesystem(void)
{
	check("tmpfs on v6.13 did not mark a change",
	      holds("tmpfs", KERNEL_RELEASE(6, 13), FRESH, 123, &before));
	check("btrfs, ext4 or xfs on v7.0 did not mark a change",
	      holds("btrfs", KERNEL_RELEASE(7, 0), FRESH, 123, &before) &&
	      holds("ext4", KERNEL_RELEASE(7, 0), FRESH, 123, &before) &&
	      holds("xfs", KERNEL_RELEASE(7, 0), FRESH, 123, &before));
	check("tmpfs before v6.13 marked a change in the coarse clock's grain",
	      !holds("tmpfs", KERNEL_RELEASE(6, 12), FRESH, 123, &before));
	check("an ext4 that keeps whole seconds marked a change in its grain",
	      !holds("ext4", KERNEL_RELEASE(7, 0), FRESH, 0, &before));
	check("ext3, which has no FS_MGTIME, marked a change in the grain",
	      !holds("ext3", KERNEL_RELEASE(7, 0), FRESH, 123, &before));
	check("f2fs before 7.4 marked a change in the grain",
	      !holds("f2fs", KERNEL_RELEASE(7, 3), FRESH, 123, &before));
	check("f2fs from 7.4 did not mark a change",
	      holds("f2fs", KERNEL_RELEASE(7, 4), FRESH, 123, &before));
	check("a filesystem that is not listed marked a change",
	      !holds("nfs", KERNEL_RELEASE(7, 0), OLD, 123, &before) &&
	      !holds("", KERNEL_RELEASE(7, 0), OLD, 123, &before));
	check("an unknown filesystem marked a change",
	      !holds(NULL, KERNEL_RELEASE(7, 0), OLD, 123, &before));
	check("an unknown release took tmpfs for multigrain",
	      !holds("tmpfs", 0, FRESH, 123, &before));
}

/*
 * Anywhere the stamp is coarse, a ctime has to be more than the grain
 * margin older than the reference reading, and the clock short of where a
 * filesystem without wide timestamps clamps every stamp.
 */
static void fallback_needs_an_old_ctime(void)
{
	const struct timespec past_2038 = { (time_t) INT32_MAX + 100, 0 };
	unsigned int old = KERNEL_RELEASE(6, 12);

	check("an old ctime did not mark a change on ext2, ext3 or tmpfs",
	      holds("ext2", old, OLD, 0, &before) &&
	      holds("ext3", old, OLD, 123, &before) &&
	      holds("tmpfs", old, OLD, 123, &before));
	check("an old ctime on an ext4 that keeps whole seconds did not mark a change",
	      holds("ext4", KERNEL_RELEASE(7, 0), OLD, 0, &before));
	check("a ctime inside the grain margin marked a change",
	      !holds("tmpfs", old, before.tv_sec - 2, 999999999, &before) &&
	      !holds("tmpfs", old, before.tv_sec - 1, 0, &before));
	check("a ctime later than the reference reading marked a change",
	      !holds("tmpfs", old, before.tv_sec + 10, 0, &before));
	check("an old ctime marked a change with the clock past 2038",
	      !holds("ext4", old, before.tv_sec, 0, &past_2038));
	check("a fine-grained multigrain ctime did not mark a change past 2038",
	      holds("ext4", KERNEL_RELEASE(7, 0), before.tv_sec, 123,
		    &past_2038));
}

/*
 * The live rule needs a mount to go by, and stat_mnt_id() gives one only
 * for the inode it was told of, and only a unique id.
 */
static void live_rule_needs_its_mount(void)
{
	char path[] = "/tmp/trinity-ctime-rule-test.XXXXXX";
	struct timespec ancient = { 1, 1 };
	unsigned long long id;
	struct stat st;
	int fd;

	check("a ctime with no mount to go by marked a change",
	      !ctime_marks_change(0, &ancient, &before));

	fd = mkstemp(path);
	if (fd < 0 || fstat(fd, &st) != 0)
		BUG("ctime rule: cannot make a scratch file");
	check("a mount id came back for an inode the path does not name",
	      __real_stat_mnt_id(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW,
				 st.st_dev, st.st_ino + 1) == 0);
	id = __real_stat_mnt_id(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW,
				st.st_dev, st.st_ino);
	check("a mount id came back that is not a unique one",
	      id == 0 || id > (1ULL << 31));
	check("the fd and the path it names gave different mount ids",
	      __real_stat_mnt_id(fd, "", AT_EMPTY_PATH, st.st_dev,
				 st.st_ino) == id);
	close(fd);
	unlink(path);
}

void ctime_rule_self_check(void);
void ctime_rule_self_check(void)
{
	rule_follows_the_filesystem();
	fallback_needs_an_old_ctime();
	live_rule_needs_its_mount();
	if (failed != 0)
		BUG("ctime rule: self-check failed");
}
