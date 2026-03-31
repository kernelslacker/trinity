#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "pids.h"
#include "shm.h"
#include "taint.h"
#include "trinity.h"
#include "syscall.h"
#include "post-mortem.h"
#include "utils.h"

struct child_sort_entry {
	unsigned int idx;
	struct timespec tp;
};

static int cmp_timespec(const void *a, const void *b)
{
	const struct child_sort_entry *ea = a;
	const struct child_sort_entry *eb = b;

	if (ea->tp.tv_sec != eb->tp.tv_sec)
		return (ea->tp.tv_sec < eb->tp.tv_sec) ? -1 : 1;
	if (ea->tp.tv_nsec != eb->tp.tv_nsec)
		return (ea->tp.tv_nsec < eb->tp.tv_nsec) ? -1 : 1;
	return 0;
}

static bool ts_before(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec != b->tv_sec)
		return a->tv_sec < b->tv_sec;
	return a->tv_nsec < b->tv_nsec;
}

static void dump_syscall_rec(FILE *fp, struct syscallrecord *rec)
{
	switch (rec->state) {
	case UNKNOWN:
		/* new child, so nothing to dump. */
		break;
	case PREP:
		/* haven't finished setting up, so don't dump. */
		break;
	case BEFORE:
		fprintf(fp, "%.*s\n", PREBUFFER_LEN, rec->prebuffer);
		break;
	case AFTER:
	case GOING_AWAY:
		fprintf(fp, "%.*s%.*s\n", PREBUFFER_LEN, rec->prebuffer,
			POSTBUFFER_LEN, rec->postbuffer);
		break;
	}
}

static void dump_syscall_records(const struct timespec *taint_tp)
{
	FILE *fd;
	unsigned int i, nr_active;
	struct child_sort_entry *entries;
	bool taint_marked = false;

	fd = fopen("trinity-post-mortem.log", "w");
	if (!fd) {
		outputerr("Failed to write post mortem log (%s)\n", strerror(errno));
		return;
	}

	entries = malloc(max_children * sizeof(*entries));
	if (!entries) {
		outputerr("Failed to allocate sort buffer\n");
		fclose(fd);
		return;
	}

	nr_active = 0;
	for_each_child(i) {
		struct syscallrecord *rec = &shm->children[i]->syscall;

		if (rec->state == UNKNOWN || rec->state == PREP)
			continue;

		entries[nr_active].idx = i;
		entries[nr_active].tp = rec->tp;
		nr_active++;
	}

	qsort(entries, nr_active, sizeof(*entries), cmp_timespec);

	for (i = 0; i < nr_active; i++) {
		struct syscallrecord *rec = &shm->children[entries[i].idx]->syscall;

		if (!taint_marked && ts_before(taint_tp, &entries[i].tp)) {
			fprintf(fd, "--- taint detected at %ld.%09ld ---\n",
				(long) taint_tp->tv_sec, taint_tp->tv_nsec);
			taint_marked = true;
		}

		fprintf(fd, "[child %u @ %ld.%09ld] ", entries[i].idx,
			(long) rec->tp.tv_sec, rec->tp.tv_nsec);
		dump_syscall_rec(fd, rec);
		fprintf(fd, "\n");
	}

	if (!taint_marked) {
		fprintf(fd, "--- taint detected at %ld.%09ld (after all recorded syscalls) ---\n",
			(long) taint_tp->tv_sec, taint_tp->tv_nsec);
	}

	free(entries);
	fclose(fd);
}

void tainted_postmortem(void)
{
	int taint = get_taint();

	struct timespec taint_tp;

	__atomic_store_n(&shm->postmortem_in_progress, true, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &taint_tp);

	panic(EXIT_KERNEL_TAINTED);

	output(0, "kernel became tainted! (%d/%d) Last seed was %u\n",
		taint, kernel_taint_initial, shm->seed);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Detected kernel tainting. Last seed was %u\n", shm->seed);
	closelog();

	dump_syscall_records(&taint_tp);

	__atomic_store_n(&shm->postmortem_in_progress, false, __ATOMIC_RELAXED);
}
