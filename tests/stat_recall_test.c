/*
 * Self-check for the stat-family re-call oracles: each runs its sanitiser
 * and post handler as shipped on a file of the test's own, handed the answer
 * the fuzzed call wrote, and counts the anomalies its sampled re-call
 * reports.  A moved attribute counts only while dev, ino and ctime held and
 * the ctime rule holds (stat_recall_diverged()), and never for st_blocks or
 * st_blksize.
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_newstat, ... */

extern bool fake_snapshot_str_copies;		/* arg_coupling_test.c */

/* The ctime-rule seams of ctime_rule_test.c. */
enum fake_ctime_rule { FAKE_CTIME_REAL, FAKE_CTIME_HOLDS, FAKE_CTIME_FAILS };
extern enum fake_ctime_rule fake_ctime_rule;
extern bool fake_mnt_ids;

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

static const struct recall_oracle newstat_oracle = {
	.name = "newstat", .anomalies = newstat_anomalies,
};

static const struct recall_oracle newlstat_oracle = {
	.name = "newlstat", .anomalies = newlstat_anomalies,
};

static const struct recall_oracle newfstatat_oracle = {
	.name = "newfstatat", .anomalies = newfstatat_anomalies,
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
 * The cases every path oracle shares.  An attribute the inode does not have
 * is reported, and so is not one that moves with no ctime stamped, nor one
 * the ctime rule cannot vouch for, nor a mode a sibling's chmod moved
 * between the calls, nor the attributes of a file renamed over the path.
 */
static void path_recall_cases(const struct recall_oracle *o)
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

void stat_recall_self_check(void);
void stat_recall_self_check(void)
{
	/* The oracles re-call the path their sanitiser snapshots, and the
	 * rule's mount lookup answers on any kernel. */
	fake_snapshot_str_copies = true;
	fake_mnt_ids = true;

	path_recall_cases(&newstat_oracle);
	path_recall_cases(&newlstat_oracle);
	path_recall_cases(&newfstatat_oracle);

	fake_mnt_ids = false;
	fake_snapshot_str_copies = false;
	if (failed != 0)
		BUG("stat recall: self-check failed");
}
