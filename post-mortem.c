#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "child.h"
#include "pids.h"
#include "shm.h"
#include "taint.h"
#include "trinity.h"
#include "syscall.h"
#include "post-mortem.h"
#include "utils.h"

struct ring_entry {
	unsigned int child_idx;
	struct syscallrecord rec;
};

static int cmp_ring_entry(const void *a, const void *b)
{
	const struct ring_entry *ea = a;
	const struct ring_entry *eb = b;

	if (ea->rec.tp.tv_sec != eb->rec.tp.tv_sec)
		return (ea->rec.tp.tv_sec < eb->rec.tp.tv_sec) ? -1 : 1;
	if (ea->rec.tp.tv_nsec != eb->rec.tp.tv_nsec)
		return (ea->rec.tp.tv_nsec < eb->rec.tp.tv_nsec) ? -1 : 1;
	return 0;
}

static bool ts_before(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec != b->tv_sec)
		return a->tv_sec < b->tv_sec;
	return a->tv_nsec < b->tv_nsec;
}

static void dump_syscall_rec(FILE *fp, const struct syscallrecord *rec)
{
	switch (rec->state) {
	case UNKNOWN:
	case PREP:
		/* unwritten or in-flight: filtered before we get here. */
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

/*
 * Drain one child's syscall ring into the entries array.  Returns the
 * number of entries copied.  Lock-free SPSC: acquire-load on head pairs
 * with the child's release-store after writing the slot, so any entry
 * we observe in [head-N, head-1] was fully written before head was
 * published.  A straggling write from a still-running child can only
 * race against the slot at (head % N), which we don't read.
 */
static unsigned int drain_child_ring(unsigned int idx,
				     struct ring_entry *out)
{
	struct child_syscall_ring *ring = &children[idx]->syscall_ring;
	uint32_t head, count, j;
	unsigned int n = 0;

	head = atomic_load_explicit(&ring->head, memory_order_acquire);
	count = head < CHILD_SYSCALL_RING_SIZE ? head : CHILD_SYSCALL_RING_SIZE;

	for (j = 0; j < count; j++) {
		uint32_t slot = (head - count + j) & (CHILD_SYSCALL_RING_SIZE - 1);
		struct syscallrecord *rec = &ring->recent[slot];

		/* Skip slots that haven't received a completed syscall yet. */
		if (rec->state != AFTER && rec->state != GOING_AWAY)
			continue;

		out[n].child_idx = idx;
		out[n].rec = *rec;
		n++;
	}
	return n;
}

static void dump_syscall_records(FILE *fp, const struct timespec *taint_tp)
{
	struct ring_entry *entries;
	unsigned int i, total = 0;
	bool taint_marked = false;
	size_t cap;

	cap = (size_t)max_children * CHILD_SYSCALL_RING_SIZE;
	entries = malloc(cap * sizeof(*entries));
	if (!entries) {
		outputerr("post-mortem: failed to allocate ring snapshot buffer\n");
		return;
	}

	for_each_child(i)
		total += drain_child_ring(i, entries + total);

	qsort(entries, total, sizeof(*entries), cmp_ring_entry);

	for (i = 0; i < total; i++) {
		const struct syscallrecord *rec = &entries[i].rec;

		if (!taint_marked && ts_before(taint_tp, &rec->tp)) {
			fprintf(fp, "--- taint detected at %ld.%09ld ---\n",
				(long) taint_tp->tv_sec, taint_tp->tv_nsec);
			taint_marked = true;
		}

		fprintf(fp, "[child %u @ %ld.%09ld] ", entries[i].child_idx,
			(long) rec->tp.tv_sec, rec->tp.tv_nsec);
		dump_syscall_rec(fp, rec);
		fprintf(fp, "\n");
	}

	if (!taint_marked) {
		fprintf(fp, "--- taint detected at %ld.%09ld (after all recorded syscalls) ---\n",
			(long) taint_tp->tv_sec, taint_tp->tv_nsec);
	}

	free(entries);
}

void tainted_postmortem(void)
{
	int taint = get_taint();
	struct timespec taint_tp;
	FILE *fp;

	__atomic_store_n(&shm->postmortem_in_progress, true, __ATOMIC_RELAXED);

	clock_gettime(CLOCK_MONOTONIC, &taint_tp);

	panic(EXIT_KERNEL_TAINTED);

	output(0, "kernel became tainted! (%d/%d) Last seed was %u\n",
		taint, kernel_taint_initial, shm->seed);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Detected kernel tainting. Last seed was %u\n", shm->seed);
	closelog();

	fp = fopen("trinity-post-mortem.log", "w");
	if (!fp) {
		outputerr("Failed to write post mortem log (%s)\n", strerror(errno));
		goto out;
	}

	dump_syscall_records(fp, &taint_tp);
	fclose(fp);

out:
	__atomic_store_n(&shm->postmortem_in_progress, false, __ATOMIC_RELAXED);
}
