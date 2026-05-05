#include <sys/klog.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include "arch.h"
#include "child.h"
#include "edgepair.h"
#include "kcov.h"
#include "pids.h"
#include "shm.h"
#include "tables.h"
#include "taint.h"
#include "trinity.h"
#include "syscall.h"
#include "post-mortem.h"
#include "utils.h"

/* From <sys/klog.h>; redeclared so a missing or stripped header
 * (some embedded toolchains) doesn't break the build. */
#ifndef SYSLOG_ACTION_READ_ALL
#define SYSLOG_ACTION_READ_ALL 3
#endif
#ifndef SYSLOG_ACTION_SIZE_BUFFER
#define SYSLOG_ACTION_SIZE_BUFFER 10
#endif

struct ring_entry {
	unsigned int child_idx;
	struct chronicle_slot slot;
};

static int cmp_ring_entry(const void *a, const void *b)
{
	const struct ring_entry *ea = a;
	const struct ring_entry *eb = b;

	if (ea->slot.tp.tv_sec != eb->slot.tp.tv_sec)
		return (ea->slot.tp.tv_sec < eb->slot.tp.tv_sec) ? -1 : 1;
	if (ea->slot.tp.tv_nsec != eb->slot.tp.tv_nsec)
		return (ea->slot.tp.tv_nsec < eb->slot.tp.tv_nsec) ? -1 : 1;
	return 0;
}

static bool ts_before(const struct timespec *a, const struct timespec *b)
{
	if (a->tv_sec != b->tv_sec)
		return a->tv_sec < b->tv_sec;
	return a->tv_nsec < b->tv_nsec;
}

/*
 * Render one chronicle slot to fp.  The child no longer stages a fully
 * pre-rendered prebuffer/postbuffer for us — those would have cost a
 * 4 KiB struct copy on every push — so we reconstruct a one-line summary
 * here from the structured fields.  Args are printed as raw hex with the
 * syscall table's argname[] labels; per-arg decode() callbacks aren't
 * usable from the parent because they may dereference user-space
 * pointers from the child's address space.
 */
static void dump_syscall_slot(FILE *fp, const struct chronicle_slot *slot)
{
	struct syscallentry *entry = get_syscall_entry(slot->nr, slot->do32bit);
	const unsigned long args[6] = {
		slot->a1, slot->a2, slot->a3, slot->a4, slot->a5, slot->a6,
	};
	const char *name = entry ? entry->name : "?";
	unsigned int n_args = entry ? entry->num_args : 6;
	unsigned int i;

	fprintf(fp, "%s%s(", slot->do32bit ? "[32BIT] " : "", name);
	for (i = 0; i < n_args; i++) {
		const char *argname = (entry && entry->argname[i]) ?
			entry->argname[i] : NULL;
		if (i > 0)
			fprintf(fp, ", ");
		if (argname)
			fprintf(fp, "%s=0x%lx", argname, args[i]);
		else
			fprintf(fp, "0x%lx", args[i]);
	}
	if (IS_ERR(slot->retval))
		fprintf(fp, ") = %ld (%s)\n", (long) slot->retval,
			strerror(slot->errno_post));
	else
		fprintf(fp, ") = %ld\n", (long) slot->retval);
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
		uint32_t idx_slot = (head - count + j) & (CHILD_SYSCALL_RING_SIZE - 1);
		struct chronicle_slot *slot = &ring->recent[idx_slot];

		/* Skip slots that a freshly spawned child has not yet filled. */
		if (!slot->valid)
			continue;

		out[n].child_idx = idx;
		out[n].slot = *slot;
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
		const struct chronicle_slot *slot = &entries[i].slot;

		if (!taint_marked && ts_before(taint_tp, &slot->tp)) {
			fprintf(fp, "--- taint detected at %ld.%09ld ---\n",
				(long) taint_tp->tv_sec, taint_tp->tv_nsec);
			taint_marked = true;
		}

		fprintf(fp, "[child %u @ %ld.%09ld] ", entries[i].child_idx,
			(long) slot->tp.tv_sec, slot->tp.tv_nsec);
		dump_syscall_slot(fp, slot);
	}

	if (!taint_marked) {
		fprintf(fp, "--- taint detected at %ld.%09ld (after all recorded syscalls) ---\n",
			(long) taint_tp->tv_sec, taint_tp->tv_nsec);
	}

	free(entries);
}

/*
 * Snapshot the current contents of the kernel ring buffer.  klogctl is
 * easier to reason about than a polled /dev/kmsg reader: one syscall,
 * one allocation, no fd lifecycle.  Returns a NUL-terminated, malloc'd
 * buffer (caller frees) and writes the byte count via *out_len.  NULL
 * on failure (kernel.dmesg_restrict + non-root, OOM, etc).
 */
static char *slurp_kmsg(size_t *out_len)
{
	int total_size, n;
	char *buf;

	total_size = klogctl(SYSLOG_ACTION_SIZE_BUFFER, NULL, 0);
	if (total_size <= 0)
		return NULL;

	buf = malloc((size_t) total_size + 1);
	if (!buf)
		return NULL;

	n = klogctl(SYSLOG_ACTION_READ_ALL, buf, total_size);
	if (n < 0) {
		free(buf);
		return NULL;
	}

	buf[n] = '\0';
	*out_len = (size_t) n;
	return buf;
}

/*
 * Walk the kmsg buffer looking for the first line that names a kernel
 * fault class — WARN/BUG/Oops/KASAN/etc.  Use the *latest* match in the
 * buffer: when the kernel piles on multiple reports (panic_on_warn off,
 * or a cascade) the most recent line is the one our taint poll just
 * caught.  Returns true and fills out[] if a match was found.
 */
static bool extract_kernel_header(const char *kmsg, size_t kmsg_len,
				  char *out, size_t outlen)
{
	static const char * const triggers[] = {
		"WARNING:", "BUG:", "Oops:", "general protection fault",
		"KASAN:", "UBSAN:", "Kernel panic", "Internal error",
		"Unable to handle kernel",
	};
	const char *p = kmsg;
	const char *end = kmsg + kmsg_len;
	const char *best_body = NULL;
	const char *best_trigger = NULL;
	size_t best_len = 0;

	while (p < end) {
		const char *eol = memchr(p, '\n', (size_t)(end - p));
		size_t linelen = eol ? (size_t)(eol - p) : (size_t)(end - p);
		unsigned int i;

		for (i = 0; i < ARRAY_SIZE(triggers); i++) {
			size_t tlen = strlen(triggers[i]);
			const char *m = memmem(p, linelen, triggers[i], tlen);

			if (m == NULL)
				continue;
			best_body = m;
			best_len = linelen - (size_t)(m - p);
			best_trigger = triggers[i];
			break;
		}
		if (!eol)
			break;
		p = eol + 1;
	}

	if (!best_body)
		return false;

	/* For WARNING: lines, the post-" at " payload (file:line + symbol)
	 * is what's actionable; the leading "CPU: N PID: M" tells us little
	 * we don't already know.  Drop it but keep the WARNING tag. */
	if (strncmp(best_trigger, "WARNING:", strlen("WARNING:")) == 0) {
		const char *at = memmem(best_body, best_len, " at ", 4);

		if (at != NULL) {
			size_t skip = (size_t)(at + 4 - best_body);

			best_body += skip;
			best_len -= skip;
		}
		snprintf(out, outlen, "WARNING %.*s",
			 (int) best_len, best_body);
	} else {
		snprintf(out, outlen, "%.*s", (int) best_len, best_body);
	}

	/* rtrim — kernel lines sometimes carry CR or trailing spaces. */
	{
		size_t n = strlen(out);

		while (n && (out[n - 1] == ' ' || out[n - 1] == '\r' ||
			     out[n - 1] == '\n' || out[n - 1] == '\t'))
			out[--n] = '\0';
	}
	return true;
}

/*
 * Slurp a tiny /proc/<pid>/<name> file into fp.  Silent on any error:
 * the child may have just exited, the file may be unreadable for this
 * uid, or the kernel may not export it on this build.  Trinity runs
 * unprivileged often enough that EACCES is expected, not exceptional.
 */
static void slurp_proc_file(FILE *fp, pid_t pid, const char *name)
{
	char path[64];
	char buf[4096];
	FILE *src;
	size_t n;
	int last = -1;

	snprintf(path, sizeof(path), "/proc/%d/%s", (int) pid, name);
	src = fopen(path, "r");
	if (src == NULL)
		return;

	fprintf(fp, "%s:\n", name);
	while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
		fwrite(buf, 1, n, fp);
		last = (unsigned char) buf[n - 1];
	}
	if (last != -1 && last != '\n')
		fputc('\n', fp);
	fclose(src);
}

/*
 * Capture per-child kernel state from /proc just before panic() flips
 * the spawn_no_more flag.  Children may move on the moment we tell them
 * to wind down, so the snapshot has to happen while they're still doing
 * whatever caused the taint.  Buffered into memory rather than written
 * straight to the log because the log file isn't open yet.
 *
 * Returns a malloc'd buffer (caller frees) or NULL on allocation failure.
 * *out_len is the number of bytes written; zero is legitimate (no live
 * children, all opens failed) and the caller should treat that as
 * "nothing to dump".
 */
static char *capture_child_runtime_state(size_t *out_len)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *fp;
	unsigned int i;

	fp = open_memstream(&buf, &len);
	if (fp == NULL)
		return NULL;

	for_each_child(i) {
		pid_t pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);

		if (pid == EMPTY_PIDSLOT)
			continue;
		fprintf(fp, "--- child %u (pid %d) runtime state ---\n",
			i, (int) pid);
		slurp_proc_file(fp, pid, "stack");
		slurp_proc_file(fp, pid, "syscall");
		slurp_proc_file(fp, pid, "wchan");
	}

	fclose(fp);
	*out_len = len;
	return buf;
}

/*
 * Build "trinity-post-mortem-YYYYMMDD-HHMMSS-<seed>" into out[].  The
 * sortable date plus the seed suffix keep neighbour taints from
 * colliding when multiple hosts dump into a shared collection point.
 * Returns 0 on success, -1 on truncation or time conversion failure.
 */
static int format_artifact_dirname(char *out, size_t outlen, unsigned int seed)
{
	time_t now = time(NULL);
	struct tm tm;
	char ts[32];
	int n;

	if (localtime_r(&now, &tm) == NULL)
		return -1;
	if (strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tm) == 0)
		return -1;
	n = snprintf(out, outlen, "trinity-post-mortem-%s-%u", ts, seed);
	if (n < 0 || (size_t) n >= outlen)
		return -1;
	return 0;
}

static FILE *open_artifact(const char *dir, const char *name)
{
	char path[256];
	int n;

	n = snprintf(path, sizeof(path), "%s/%s", dir, name);
	if (n < 0 || (size_t) n >= sizeof(path))
		return NULL;
	return fopen(path, "w");
}

static void write_artifact_buf(const char *dir, const char *name,
			       const char *buf, size_t len)
{
	FILE *fp = open_artifact(dir, name);

	if (fp == NULL)
		return;
	if (len > 0) {
		fwrite(buf, 1, len, fp);
		if (buf[len - 1] != '\n')
			fputc('\n', fp);
	}
	fclose(fp);
}

static void dump_kcov_state(FILE *fp)
{
	unsigned long edges, pcs, calls, remote, truncated;
	unsigned long cmp_records, cmp_truncated;
	unsigned int i, cold = 0;
	unsigned int nr_to_scan;

	if (kcov_shm == NULL) {
		fprintf(fp, "KCOV: not available\n");
		return;
	}

	edges         = __atomic_load_n(&kcov_shm->edges_found,           __ATOMIC_RELAXED);
	pcs           = __atomic_load_n(&kcov_shm->total_pcs,             __ATOMIC_RELAXED);
	calls         = __atomic_load_n(&kcov_shm->total_calls,           __ATOMIC_RELAXED);
	remote        = __atomic_load_n(&kcov_shm->remote_calls,          __ATOMIC_RELAXED);
	truncated     = __atomic_load_n(&kcov_shm->trace_truncated,       __ATOMIC_RELAXED);
	cmp_records   = __atomic_load_n(&kcov_shm->cmp_records_collected, __ATOMIC_RELAXED);
	cmp_truncated = __atomic_load_n(&kcov_shm->cmp_trace_truncated,   __ATOMIC_RELAXED);

	fprintf(fp, "KCOV: %lu unique edges, %lu total PCs, %lu calls (%lu remote)\n",
		edges, pcs, calls, remote);
	if (truncated > 0)
		fprintf(fp, "KCOV: %lu calls truncated trace buffer (%.2f%% of calls) — consider raising KCOV_TRACE_SIZE\n",
			truncated,
			calls > 0 ? (100.0 * truncated) / calls : 0.0);
	fprintf(fp, "KCOV: %lu CMP records collected\n", cmp_records);
	if (cmp_truncated > 0)
		fprintf(fp, "KCOV: %lu calls truncated cmp buffer (%.2f%% of calls) — consider raising KCOV_CMP_BUFFER_SIZE\n",
			cmp_truncated,
			calls > 0 ? (100.0 * cmp_truncated) / calls : 0.0);

	nr_to_scan = biarch ? max_nr_64bit_syscalls : max_nr_syscalls;
	for (i = 0; i < nr_to_scan; i++) {
		if (kcov_syscall_is_cold(i))
			cold++;
	}
	fprintf(fp, "KCOV: %u cold syscalls\n", cold);

	if (edgepair_shm != NULL)
		fprintf(fp, "KCOV: edgepairs: %lu unique, %lu dropped\n",
			edgepair_shm->pairs_tracked,
			edgepair_shm->pairs_dropped);
}

void tainted_postmortem(void)
{
	int taint = get_taint();
	struct timespec taint_tp;
	FILE *fp;
	char *kmsg;
	size_t kmsg_len = 0;
	char header[256];
	bool have_header = false;
	char *runtime_buf;
	size_t runtime_len = 0;
	unsigned int seed;
	char dirname[128];

	__atomic_store_n(&shm->postmortem_in_progress, true, __ATOMIC_RELEASE);

	clock_gettime(CLOCK_MONOTONIC, &taint_tp);
	seed = __atomic_load_n(&shm->seed, __ATOMIC_RELAXED);

	/* Slurp the kernel ring buffer first — closer in time to the taint
	 * event means a smaller chance the WARN/Oops has aged out under
	 * other kernel chatter. */
	kmsg = slurp_kmsg(&kmsg_len);
	if (kmsg != NULL)
		have_header = extract_kernel_header(kmsg, kmsg_len,
						    header, sizeof(header));

	/* Same urgency for /proc per-child state: must happen before panic()
	 * tells children to stop, while they're still parked in whatever
	 * syscall tripped the taint flag. */
	runtime_buf = capture_child_runtime_state(&runtime_len);

	panic(EXIT_KERNEL_TAINTED);

	output(0, "kernel became tainted! (%d/%d) Last seed was %u\n",
		taint, kernel_taint_initial, seed);

	openlog("trinity", LOG_CONS|LOG_PERROR, LOG_USER);
	syslog(LOG_CRIT, "Detected kernel tainting. Last seed was %u\n", seed);
	closelog();

	if (format_artifact_dirname(dirname, sizeof(dirname), seed) < 0 ||
	    mkdir(dirname, 0755) != 0) {
		outputerr("Failed to create post-mortem dir (%s)\n",
			  strerror(errno));
		goto out;
	}
	output(0, "Post-mortem artifact: %s/\n", dirname);

	/* Small triage header. The bulky data lives in sibling files. */
	fp = open_artifact(dirname, "summary.log");
	if (fp != NULL) {
		if (have_header)
			fprintf(fp, "KERNEL: %s\n", header);
		fprintf(fp, "taint:  0x%x (was 0x%x at startup)\n",
			taint, kernel_taint_initial);
		fprintf(fp, "seed:   %u\n", seed);
		fclose(fp);
	}

	fp = open_artifact(dirname, "syscall-rings.log");
	if (fp != NULL) {
		dump_syscall_records(fp, &taint_tp);
		fclose(fp);
	}

	if (runtime_buf != NULL && runtime_len > 0)
		write_artifact_buf(dirname, "child-state.log",
				   runtime_buf, runtime_len);

	if (kmsg != NULL && kmsg_len > 0)
		write_artifact_buf(dirname, "dmesg.txt", kmsg, kmsg_len);

	/* Replay marker: `trinity -s $(cat seed)` reproduces this run. */
	fp = open_artifact(dirname, "seed");
	if (fp != NULL) {
		fprintf(fp, "%u\n", seed);
		fclose(fp);
	}

	fp = open_artifact(dirname, "kcov.log");
	if (fp != NULL) {
		dump_kcov_state(fp);
		fclose(fp);
	}

out:
	free(kmsg);
	free(runtime_buf);
	__atomic_store_n(&shm->postmortem_in_progress, false, __ATOMIC_RELEASE);
}
