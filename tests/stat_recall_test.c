/*
 * Self-check for the stat-family re-call oracles: each runs its sanitiser
 * and post handler as shipped on a file of the test's own, handed the answer
 * the fuzzed call wrote, and counts the anomalies its sampled re-call
 * reports.  A moved attribute counts only while dev, ino and ctime held and
 * the ctime rule holds (stat_recall_diverged()), and never for st_blocks or
 * st_blksize; statmount's only for the fields no mount operation moves, and
 * the statfs family's only for the fields of a filesystem nothing outside
 * the kernel moves.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "kernel/mount.h"	/* struct statmount, STATMOUNT_* */
#include "kernel/stat.h"	/* struct statx, STATX_* */
#include "kernel/unistd.h"	/* SYS_statmount */
#include "rnd.h"		/* rnd_state, rnd_modulo_u32 */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_newstat, ... */
#include "utils.h"		/* waitpid_eintr */

extern bool fake_snapshot_str_copies;		/* arg_coupling_test.c */
extern const char *fake_testfile_path;		/* arg_coupling_test.c */

/* The ctime-rule seams of ctime_rule_test.c. */
enum fake_ctime_rule { FAKE_CTIME_REAL, FAKE_CTIME_HOLDS, FAKE_CTIME_FAILS };
extern enum fake_ctime_rule fake_ctime_rule;
extern bool fake_mnt_ids;

extern bool fake_random_fd_empty;		/* fake_stubs.c */

static unsigned int failed;

static void check(const char *what, const char *oracle, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "stat recall: %s: %s\n", oracle, what);
	failed++;
}

/* Calls per case: the re-call is sampled one in a hundred. */
#define RECALL_CALLS	1500

struct recall_oracle {
	const char *name;
	/* The anomalies RECALL_CALLS calls on @path count, each of which
	 * answered @answer. */
	unsigned long (*anomalies)(const char *path, const struct stat *answer);
};

/* @entry's calls on (@path, statbuf), the shape newstat and newlstat share,
 * each of which answered @answer; *@counter counts their anomalies. */
static unsigned long path_stat_anomalies(struct syscallentry *entry,
					 const unsigned long *counter,
					 const char *path,
					 const struct stat *answer)
{
	unsigned long before = *counter;
	static struct syscallrecord rec;
	static struct stat buf;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) path;
		rec.a2 = (unsigned long) &buf;
		entry->sanitise(&rec);
		memcpy((void *) rec.a2, answer, sizeof(*answer));
		rec.retval = 0;
		entry->post(&rec);
	}
	return *counter - before;
}

static unsigned long newstat_anomalies(const char *path,
				       const struct stat *answer)
{
	return path_stat_anomalies(&syscall_newstat,
				   &shm->stats.oracle.newstat_oracle_anomalies,
				   path, answer);
}

static unsigned long newlstat_anomalies(const char *path,
					const struct stat *answer)
{
	return path_stat_anomalies(&syscall_newlstat,
				   &shm->stats.oracle.newlstat_oracle_anomalies,
				   path, answer);
}

/* newfstatat(AT_FDCWD, @path, statbuf, AT_SYMLINK_NOFOLLOW) calls. */
static unsigned long newfstatat_anomalies(const char *path,
					  const struct stat *answer)
{
	unsigned long before = shm->stats.oracle.newfstatat_oracle_anomalies;
	static struct syscallrecord rec;
	static struct stat buf;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) AT_FDCWD;
		rec.a2 = (unsigned long) path;
		rec.a3 = (unsigned long) &buf;
		rec.a4 = AT_SYMLINK_NOFOLLOW;
		syscall_newfstatat.sanitise(&rec);
		memcpy((void *) rec.a3, answer, sizeof(*answer));
		rec.retval = 0;
		syscall_newfstatat.post(&rec);
	}
	return shm->stats.oracle.newfstatat_oracle_anomalies - before;
}

/* newfstat() calls on an fd it opens on @path. */
static unsigned long newfstat_anomalies(const char *path,
					const struct stat *answer)
{
	unsigned long before = shm->stats.oracle.newfstat_oracle_anomalies;
	static struct syscallrecord rec;
	static struct stat buf;
	unsigned int i;
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		BUG("stat recall: cannot open the scratch file");
	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) fd;
		rec.a2 = (unsigned long) &buf;
		syscall_newfstat.sanitise(&rec);
		memcpy((void *) rec.a2, answer, sizeof(*answer));
		rec.retval = 0;
		syscall_newfstat.post(&rec);
	}
	close(fd);
	return shm->stats.oracle.newfstat_oracle_anomalies - before;
}

static const struct recall_oracle newstat_oracle = {
	.name = "newstat", .anomalies = newstat_anomalies,
};

static const struct recall_oracle newlstat_oracle = {
	.name = "newlstat", .anomalies = newlstat_anomalies,
};

static const struct recall_oracle newfstatat_oracle = {
	.name = "newfstatat", .anomalies = newfstatat_anomalies,
};

static const struct recall_oracle newfstat_oracle = {
	.name = "newfstat", .anomalies = newfstat_anomalies,
};

static char scratch[] = "/tmp/trinity-stat-recall-test.XXXXXX";

/* A fresh scratch file, its attributes in @st. */
static void scratch_file(struct stat *st)
{
	int fd;

	memcpy(scratch + sizeof(scratch) - 7, "XXXXXX", 6);
	fd = mkstemp(scratch);
	if (fd < 0 || fstat(fd, st) != 0)
		BUG("stat recall: cannot make a scratch file");
	close(fd);
}

/*
 * The cases every oracle shares.  An attribute the inode does not have is
 * reported, and so is not one that moves with no ctime stamped, nor one the
 * ctime rule cannot vouch for, nor a mode a sibling's chmod moved between
 * the calls, nor the attributes of a file renamed over the path, which
 * newfstat meets as an fd on another inode than its answer's.
 */
static void recall_cases(const struct recall_oracle *o)
{
	char other[sizeof(scratch) + 2];
	struct stat st, moved;
	int fd;

	scratch_file(&st);
	fake_ctime_rule = FAKE_CTIME_HOLDS;

	moved = st;
	moved.st_mode ^= S_IXUSR;
	check("a mode that moved under a held ctime was not reported", o->name,
	      o->anomalies(scratch, &moved) > 0);

	moved = st;
	moved.st_blocks += 8;
	moved.st_blksize *= 2;
	check("st_blocks or st_blksize was judged", o->name,
	      o->anomalies(scratch, &moved) == 0);

	fake_ctime_rule = FAKE_CTIME_FAILS;
	moved = st;
	moved.st_mode ^= S_IXUSR;
	check("a moved mode the ctime cannot vouch for was reported", o->name,
	      o->anomalies(scratch, &moved) == 0);
	fake_ctime_rule = FAKE_CTIME_HOLDS;

	/* A tick of the coarse clock passes first, so the chmod moves the
	 * ctime on any filesystem. */
	nanosleep(&(const struct timespec) { 0, 20 * 1000 * 1000 }, NULL);
	if (chmod(scratch, (st.st_mode ^ S_IXUSR) & 07777) != 0)
		BUG("stat recall: cannot chmod the scratch file");
	check("a sibling's chmod between the calls was reported", o->name,
	      o->anomalies(scratch, &st) == 0);

	snprintf(other, sizeof(other), "%s.o", scratch);
	fd = open(other, O_CREAT | O_WRONLY, 0600);
	if (fd < 0 || stat(scratch, &st) != 0 || rename(other, scratch) != 0)
		BUG("stat recall: cannot rename over the scratch file");
	close(fd);
	check("the attributes of a file renamed over the path were reported",
	      o->name, o->anomalies(scratch, &st) == 0);

	fake_ctime_rule = FAKE_CTIME_REAL;
	unlink(scratch);
}

/*
 * newstat pins half its calls to a testfile, and the re-call has to go to
 * the path the kernel was handed, not the one the pin replaced: a pinned
 * call is judged on the testfile.  The calls' own path names nothing, so
 * only the pinned half can report.
 */
static void newstat_judges_pinned_calls(void)
{
	unsigned long before = shm->stats.oracle.newstat_oracle_anomalies;
	char missing[sizeof(scratch) + 2];
	static struct syscallrecord rec;
	static struct stat buf;
	struct stat st, moved;
	unsigned int i;

	scratch_file(&st);
	snprintf(missing, sizeof(missing), "%s.m", scratch);
	fake_testfile_path = scratch;
	fake_ctime_rule = FAKE_CTIME_HOLDS;
	moved = st;
	moved.st_mode ^= S_IXUSR;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) missing;
		rec.a2 = (unsigned long) &buf;
		syscall_newstat.sanitise(&rec);
		memcpy((void *) rec.a2, &moved, sizeof(moved));
		rec.retval = 0;
		syscall_newstat.post(&rec);
		if (rec.a1 != (unsigned long) missing)
			free((void *) rec.a1);
	}
	check("a pinned call was not judged on the testfile it was pinned to",
	      "newstat", shm->stats.oracle.newstat_oracle_anomalies != before);

	fake_ctime_rule = FAKE_CTIME_REAL;
	fake_testfile_path = NULL;
	unlink(scratch);
}

/* Calls per statx case: its sanitiser draws the mask, and only a mask
 * that fills stx_ctime can judge a sample. */
#define STATX_RECALL_CALLS	4000

/* statx(AT_FDCWD, @path, ...) calls, each of which answered @answer. */
static unsigned long statx_anomalies(const char *path,
				     const struct statx *answer)
{
	unsigned long before = shm->stats.oracle.statx_oracle_anomalies;
	static struct syscallrecord rec;
	static struct statx buf;
	unsigned int i;

	for (i = 0; i < STATX_RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) AT_FDCWD;
		rec.a2 = (unsigned long) path;
		rec.a5 = (unsigned long) &buf;
		syscall_statx.sanitise(&rec);
		memcpy((void *) rec.a5, answer, sizeof(*answer));
		rec.retval = 0;
		syscall_statx.post(&rec);
	}
	return shm->stats.oracle.statx_oracle_anomalies - before;
}

static void scratch_statx(struct statx *stx)
{
	if (syscall(SYS_statx, AT_FDCWD, scratch, AT_SYMLINK_NOFOLLOW,
		    STATX_BASIC_STATS, stx) != 0)
		BUG("stat recall: cannot statx the scratch file");
}

/*
 * The shared cases, for statx: and since its sanitiser draws the mask, an
 * answer that filled no stx_ctime, which leaves the field 0 in both
 * answers whenever the re-call fills none either, is not judged.
 */
static void statx_recall_cases(void)
{
	char other[sizeof(scratch) + 2];
	struct statx stx, moved;
	struct stat st;
	int fd;

	scratch_file(&st);
	scratch_statx(&stx);
	fake_ctime_rule = FAKE_CTIME_HOLDS;

	moved = stx;
	moved.stx_mode ^= S_IXUSR;
	check("a mode that moved under a held ctime was not reported", "statx",
	      statx_anomalies(scratch, &moved) > 0);

	moved = stx;
	moved.stx_blocks += 8;
	moved.stx_blksize *= 2;
	check("stx_blocks or stx_blksize was judged", "statx",
	      statx_anomalies(scratch, &moved) == 0);

	fake_ctime_rule = FAKE_CTIME_FAILS;
	moved = stx;
	moved.stx_mode ^= S_IXUSR;
	check("a moved mode the ctime cannot vouch for was reported", "statx",
	      statx_anomalies(scratch, &moved) == 0);
	fake_ctime_rule = FAKE_CTIME_HOLDS;

	nanosleep(&(const struct timespec) { 0, 20 * 1000 * 1000 }, NULL);
	if (chmod(scratch, (stx.stx_mode ^ S_IXUSR) & 07777) != 0)
		BUG("stat recall: cannot chmod the scratch file");
	check("a sibling's chmod between the calls was reported", "statx",
	      statx_anomalies(scratch, &stx) == 0);

	moved = stx;
	moved.stx_mask &= ~STATX_CTIME;
	memset(&moved.stx_ctime, 0, sizeof(moved.stx_ctime));
	check("an answer that filled no stx_ctime was judged", "statx",
	      statx_anomalies(scratch, &moved) == 0);

	snprintf(other, sizeof(other), "%s.o", scratch);
	fd = open(other, O_CREAT | O_WRONLY, 0600);
	if (fd < 0 || rename(other, scratch) != 0)
		BUG("stat recall: cannot rename over the scratch file");
	close(fd);
	check("the attributes of a file renamed over the path were reported",
	      "statx", statx_anomalies(scratch, &stx) == 0);

	fake_ctime_rule = FAKE_CTIME_REAL;
	unlink(scratch);
}

#if defined(SYS_statfs) || defined(__NR_statfs)
/* statfs(@path, buf) calls, each of which answered @answer. */
static unsigned long statfs_anomalies(const char *path,
				      const struct statfs *answer)
{
	unsigned long before = shm->stats.oracle.statfs_oracle_anomalies;
	static struct syscallrecord rec;
	static struct statfs buf;
	unsigned int i;

	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) path;
		rec.a2 = (unsigned long) &buf;
		syscall_statfs.sanitise(&rec);
		memcpy((void *) rec.a2, answer, sizeof(*answer));
		rec.retval = 0;
		syscall_statfs.post(&rec);
	}
	return shm->stats.oracle.statfs_oracle_anomalies - before;
}

/* fstatfs() calls on an fd it opens on @path. */
static unsigned long fstatfs_anomalies(const char *path,
				       const struct statfs *answer)
{
	unsigned long before = shm->stats.oracle.fstatfs_oracle_anomalies;
	static struct syscallrecord rec;
	static struct statfs buf;
	unsigned int i;
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		BUG("stat recall: cannot open the scratch file");
	for (i = 0; i < RECALL_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) fd;
		rec.a2 = (unsigned long) &buf;
		syscall_fstatfs.sanitise(&rec);
		memcpy((void *) rec.a2, answer, sizeof(*answer));
		rec.retval = 0;
		syscall_fstatfs.post(&rec);
	}
	close(fd);
	return shm->stats.oracle.fstatfs_oracle_anomalies - before;
}

/*
 * The statfs family compares the fields of a filesystem that nothing
 * outside the kernel moves: a block size that moved is reported, while
 * f_blocks, f_files and f_flags, which a write, a remount or
 * mount_setattr() moves, are not.  statfs looks its path up again, so it
 * judges only an answer from the filesystem the re-call reached, and one
 * with another f_type is not reported; fstatfs's fd pins the filesystem,
 * so there a moved f_type is.
 */
static void statfs_recall_cases(void)
{
	struct statfs sfs, moved;
	struct stat st;

	scratch_file(&st);
	if (statfs(scratch, &sfs) != 0)
		BUG("stat recall: cannot statfs the scratch file");

	moved = sfs;
	moved.f_bsize *= 2;
	check("a block size that moved was not reported", "statfs",
	      statfs_anomalies(scratch, &moved) > 0);
	check("a block size that moved was not reported", "fstatfs",
	      fstatfs_anomalies(scratch, &moved) > 0);

	moved = sfs;
	moved.f_blocks += 8;
	moved.f_files += 8;
	moved.f_flags ^= 1;
	check("f_blocks, f_files or f_flags was judged", "statfs",
	      statfs_anomalies(scratch, &moved) == 0);
	check("f_blocks, f_files or f_flags was judged", "fstatfs",
	      fstatfs_anomalies(scratch, &moved) == 0);

	moved = sfs;
	moved.f_type ^= 1;
	check("an answer from another filesystem was reported", "statfs",
	      statfs_anomalies(scratch, &moved) == 0);
	check("a filesystem type that moved under the fd was not reported",
	      "fstatfs", fstatfs_anomalies(scratch, &moved) > 0);

	unlink(scratch);
}
#endif

#ifdef SYS_statmount
/*
 * Have the next ONE_IN(100) the post handler draws come up: the stream is a
 * pure function of rnd_state, so find a state it fires from.
 */
static void arm_sample(void)
{
	uint64_t s;

	for (s = 0;; s++) {
		rnd_state = s;
		if (rnd_modulo_u32(100) == 0)
			break;
	}
	rnd_state = s;
}

/*
 * One statmount() call on the mount whose unique id is @mnt_id, through
 * the sanitiser and the post handler, its re-call sampled, as a call that
 * answered @answer.  The sanitiser draws the flags and the buffer size,
 * so it runs until it draws a call by id with room for the struct, and
 * the request is then rewritten to name the mount.  Returns the anomalies
 * the call counted.
 */
static unsigned long statmount_anomalies(unsigned long long mnt_id,
					 const struct statmount *answer)
{
	unsigned long before = shm->stats.oracle.statmount_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int tries;

	for (tries = 0; tries < 1000; tries++) {
		struct mnt_id_req *req;

		memset(&rec, 0, sizeof(rec));
		syscall_statmount.sanitise(&rec);
		if (rec.a4 != 0 || rec.a3 < sizeof(struct statmount)) {
			rec.retval = (unsigned long) -1L;
			syscall_statmount.post(&rec);
			continue;
		}
		req = (struct mnt_id_req *) rec.a1;
		memset(req, 0, sizeof(*req));
		req->size = MNT_ID_REQ_SIZE_VER0;
		req->mnt_id = mnt_id;
		req->param = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC;
		memcpy((void *) rec.a2, answer, sizeof(*answer));
		rec.retval = 0;
		arm_sample();
		syscall_statmount.post(&rec);
		return shm->stats.oracle.statmount_oracle_anomalies - before;
	}
	BUG("stat recall: statmount's sanitiser never drew a call by id");
	return 0;
}

/*
 * Of the fixed struct statmount, a re-call is held only to the fields no
 * mount operation moves: a mount id that moved is reported, while the
 * superblock flags, the mount attributes, the propagation fields and the
 * parent ids, which a remount, mount_setattr(), a propagation change or
 * move_mount() moves, are not.  It runs in a child of its own, which
 * reports through its exit status: each sanitised call leaves its 64 KiB
 * buffer with deferred free, which this binary's allocator never tracked,
 * so the child takes them with it, and a kernel without statmount() or
 * unique mount ids skips the case (77).  The sanitiser draws a by-fd call
 * one time in four, whose fd comes from an empty pool here, since whether
 * the draws before a call by id hold one depends on every RNG draw earlier
 * in the binary.
 */
static void statmount_recall_cases(void)
{
	uint64_t saved = rnd_state;
	int status;
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		struct mnt_id_req req = {
			.size = MNT_ID_REQ_SIZE_VER0,
			.param = STATMOUNT_SB_BASIC | STATMOUNT_MNT_BASIC,
		};
		struct statmount real, moved;
		struct statx stx;

		fake_random_fd_empty = true;
		if (syscall(SYS_statx, AT_FDCWD, "/", 0, STATX_MNT_ID_UNIQUE,
			    &stx) != 0 || !(stx.stx_mask & STATX_MNT_ID_UNIQUE))
			_exit(77);
		req.mnt_id = stx.stx_mnt_id;
		if (syscall(SYS_statmount, &req, &real, sizeof(real), 0) != 0)
			_exit(77);

		moved = real;
		moved.mnt_id_old ^= 1;
		if (statmount_anomalies(req.mnt_id, &moved) != 1)
			_exit(1);

		moved = real;
		moved.sb_flags ^= 1;
		moved.mnt_attr ^= 1;
		moved.mnt_propagation ^= 1;
		moved.mnt_peer_group += 1;
		moved.mnt_master += 1;
		moved.propagate_from += 1;
		moved.mnt_parent_id += 1;
		moved.mnt_parent_id_old += 1;
		_exit(statmount_anomalies(req.mnt_id, &moved) == 0 ? 0 : 2);
	}
	if (pid < 0 || waitpid_eintr(pid, &status, 0) != pid ||
	    !WIFEXITED(status))
		BUG("stat recall: the statmount case did not run");
	if (WEXITSTATUS(status) == 77)
		fprintf(stderr, "stat recall: statmount: no statmount() here, the case was skipped\n");
	check("a mount id that moved was not reported", "statmount",
	      WEXITSTATUS(status) != 1);
	check("a field a mount operation moves was reported", "statmount",
	      WEXITSTATUS(status) != 2);
	rnd_state = saved;
}
#endif

void stat_recall_self_check(void);
void stat_recall_self_check(void)
{
	/* The oracles re-call the path their sanitiser snapshots, and the
	 * rule's mount lookup answers on any kernel. */
	fake_snapshot_str_copies = true;
	fake_mnt_ids = true;

	recall_cases(&newstat_oracle);
	newstat_judges_pinned_calls();
	recall_cases(&newlstat_oracle);
	recall_cases(&newfstatat_oracle);
	recall_cases(&newfstat_oracle);
	statx_recall_cases();
#if defined(SYS_statfs) || defined(__NR_statfs)
	statfs_recall_cases();
#endif
#ifdef SYS_statmount
	statmount_recall_cases();
#endif

	fake_mnt_ids = false;
	fake_snapshot_str_copies = false;
	if (failed != 0)
		BUG("stat recall: self-check failed");
}
