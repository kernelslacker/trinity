#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "child.h"
#include "childops-util.h"
#include "fd.h"
#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"
#include "trinity.h"
#include "utils.h"
#include "main-internal.h"
#include "reap-internal.h"

void dump_pid_stack(int pid)
{
	FILE *fp;
	char filename[80];

	snprintf(filename, sizeof(filename), "/proc/%d/stack", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return;

	size_t n = 0;
	char *line = NULL;

	while (getline(&line, &n, fp) != -1)
		output(0, "pid %d stack: %s", pid, line);

	if (ferror(fp))
		output(0, "Error reading /proc/%d/stack :%s\n", pid, strerror(errno));
	else
		output(0, "------------------------------------------------\n");

	free(line);
	fclose(fp);
}

void dump_pid_syscall(int pid)
{
	FILE *fp;
	char filename[80];
	char buf[256];

	snprintf(filename, sizeof(filename), "/proc/%d/syscall", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return;

	if (fgets(buf, sizeof(buf), fp) != NULL)
		output(0, "pid %d syscall: %s", pid, buf);

	fclose(fp);
}

/*
 * Bounded /proc/<pid>/wchan reader used by the D-state diagnostic
 * snapshot.  open(O_RDONLY) + single read into a stack buffer + close
 * keeps the reap loop allocation-free and bounded against a wedged
 * task: wchan is at most a kernel symbol name (a few dozen bytes) so a
 * 256 B scratch space is generous and the read returns whatever was
 * ready without blocking on the task's state.  Silent on any open or
 * read error -- the snapshot caller treats missing wchan as an omitted
 * line, not a failure to investigate further.
 */
ssize_t read_pid_wchan(int pid, char *buf, size_t bufsz)
{
	char filename[80];
	int fd;
	ssize_t n;

	if (bufsz == 0)
		return 0;
	buf[0] = '\0';

	snprintf(filename, sizeof(filename), "/proc/%d/wchan", pid);

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n <= 0) {
		buf[0] = '\0';
		return 0;
	}
	buf[n] = '\0';
	/* wchan typically omits a trailing newline but be defensive. */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	return n;
}

static void dump_pid_wchan(int pid)
{
	char buf[256];

	if (read_pid_wchan(pid, buf, sizeof(buf)) <= 0)
		return;
	output(0, "pid %d wchan: %s\n", pid, buf);
}

/*
 * Bounded /proc/<pid>/stack reader.  Distinct from the existing
 * dump_pid_stack() (which uses fopen/getline and allocates per call)
 * because the D-state diagnostic path runs unconditionally -- not
 * gated on shm->debug -- and must stay quiet about permission failures
 * (most production kernels reject /proc/<pid>/stack reads without
 * CAP_SYS_ADMIN, returning EACCES; some configs hide it entirely with
 * ENOENT).  Silent on any open/read failure.
 */
static void dump_pid_stack_bounded(int pid)
{
	char filename[80];
	char buf[2048];
	int fd;
	ssize_t n;
	char *p, *eol;

	snprintf(filename, sizeof(filename), "/proc/%d/stack", pid);

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';

	for (p = buf; *p != '\0'; p = eol + 1) {
		eol = strchr(p, '\n');
		if (eol == NULL) {
			if (*p != '\0')
				output(0, "pid %d stack: %s\n", pid, p);
			break;
		}
		*eol = '\0';
		if (*p != '\0')
			output(0, "pid %d stack: %s\n", pid, p);
	}
}

/*
 * Bounded /proc/<pid>/fdinfo/ reader.  fdinfo is a directory of
 * per-fd files, so a wedged child with many open descriptors could
 * stream unbounded text into the watchdog snapshot, and individual
 * entries (eventpoll, in particular) can dump every watched fd.
 * Cap both the number of entries walked and the bytes read per
 * entry; truncate the rest silently rather than chase the long
 * tail.  Uses getdents64 directly to stay allocation-free on the
 * reap/watchdog path (opendir/readdir would malloc), and a single
 * O_RDONLY read per fdinfo file to match the wchan/stack helpers.
 * Silent on any open/read failure -- the snapshot treats missing
 * fdinfo as an omitted line, not a failure to investigate further.
 */
#define DSTATE_FDINFO_MAX_ENTRIES 64
#define DSTATE_FDINFO_MAX_BYTES   512

static void dump_pid_fdinfo_bounded(int pid)
{
	struct linux_dirent64 {
		uint64_t       d_ino;
		int64_t        d_off;
		unsigned short d_reclen;
		unsigned char  d_type;
		char           d_name[];
	};
	char dirpath[80];
	char filename[96];
	char dirbuf[4096];
	char buf[DSTATE_FDINFO_MAX_BYTES];
	int dirfd, fd;
	long nread, pos;
	unsigned int seen = 0;
	ssize_t n;
	char *p, *eol;

	snprintf(dirpath, sizeof(dirpath), "/proc/%d/fdinfo", pid);

	dirfd = open(dirpath, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return;

	while (seen < DSTATE_FDINFO_MAX_ENTRIES &&
	       (nread = syscall(SYS_getdents64, dirfd, dirbuf,
				sizeof(dirbuf))) > 0) {
		for (pos = 0; pos < nread &&
		     seen < DSTATE_FDINFO_MAX_ENTRIES; ) {
			struct linux_dirent64 *de =
				(struct linux_dirent64 *)(dirbuf + pos);
			const char *name = de->d_name;

			pos += de->d_reclen;

			/* Skip "." / ".." and any non-numeric entry. */
			if (name[0] < '0' || name[0] > '9')
				continue;

			snprintf(filename, sizeof(filename),
				 "/proc/%d/fdinfo/%s", pid, name);
			fd = open(filename, O_RDONLY | O_CLOEXEC);
			if (fd < 0)
				continue;
			n = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			if (n <= 0)
				continue;
			buf[n] = '\0';
			seen++;

			for (p = buf; *p != '\0'; p = eol + 1) {
				eol = strchr(p, '\n');
				if (eol == NULL) {
					if (*p != '\0')
						output(0, "pid %d fdinfo[%s]: %s\n",
						       pid, name, p);
					break;
				}
				*eol = '\0';
				if (*p != '\0')
					output(0, "pid %d fdinfo[%s]: %s\n",
					       pid, name, p);
			}
		}
	}

	close(dirfd);
}

struct dstate_fd_print_ctx {
	char buf[128];
	int off;
	unsigned int n;
};

static void dstate_print_fd_arg(int fd, void *vctx)
{
	struct dstate_fd_print_ctx *c = vctx;
	int written;

	if (c->off >= (int)sizeof(c->buf))
		return;
	written = snprintf(c->buf + c->off, sizeof(c->buf) - c->off,
			   "%s%d", c->n ? "," : "", fd);
	if (written < 0)
		return;
	c->off += written;
	c->n++;
}

/*
 * Targeted fd-topology line for the epoll/select syscall families.
 * These dominated a recent unkillable-D-state survey (14 of 25 wedged
 * children were in epoll_ctl alone); a generic "fd args" dump is opaque
 * for these because the syscall's semantics make different aN slots
 * mean very different things (epfd vs target_fd vs maxevents vs nfds).
 * Returns true if it handled the syscall, false otherwise so the
 * generic fd-args fallback can fire.
 */
static bool dump_dstate_epoll_select_topology(const char *name,
					      const unsigned long *args)
{
	if (strcmp(name, "epoll_ctl") == 0) {
		output(0, "  fd topology: epfd=%ld op=%ld target_fd=%ld\n",
			(long)args[0], (long)args[1], (long)args[2]);
		return true;
	}
	if (strcmp(name, "epoll_wait") == 0 ||
	    strcmp(name, "epoll_pwait") == 0 ||
	    strcmp(name, "epoll_pwait2") == 0) {
		output(0, "  fd topology: epfd=%ld maxevents=%ld\n",
			(long)args[0], (long)args[2]);
		return true;
	}
	if (strcmp(name, "select") == 0 ||
	    strcmp(name, "pselect6") == 0) {
		output(0, "  fd topology: nfds=%ld\n", (long)args[0]);
		return true;
	}
	return false;
}

/*
 * One-shot D-state diagnostic snapshot.  Fires at the first watchdog
 * detection of TASK_UNINTERRUPTIBLE for a child and prints a richer
 * forensic than the bare "watchdog: kill ..." line:
 *
 *   - child op (when the wedged child is running a non-syscall childop,
 *     so the dispatch context is recoverable).
 *   - the targeted fd-topology line for the epoll/select families that
 *     dominate the observed unkillable population, or the generic
 *     fd-bearing arg values for every other syscall.
 *   - /proc/<pid>/wchan: the kernel sleep address/symbol.
 *   - /proc/<pid>/stack: the kernel call stack (silently omitted when
 *     the kernel hides it from unprivileged readers).
 *   - /proc/<pid>/fdinfo/: per-fd state (pos/flags + driver-specific
 *     bits like eventpoll/inotify watches) for the wedged task's open
 *     descriptors, capped at DSTATE_FDINFO_MAX_ENTRIES entries and
 *     DSTATE_FDINFO_MAX_BYTES per entry so a fd-heavy child cannot
 *     stream unbounded text into the snapshot.
 *
 * Runs on the parent's reap/watchdog path.  All /proc reads go through
 * the bounded helpers above so a wedged task cannot stall the reap
 * loop: open(O_RDONLY) + single read into a stack buffer + close, no
 * heap allocation, no looped reads.  The caller is responsible for
 * gating this on the per-child dstate_diag_dumped latch so the snapshot
 * fires once per stuck child rather than every watchdog tick.
 */
void dump_dstate_diagnostics(struct childdata *child, int childno,
			     pid_t pid)
{
	struct syscallrecord *rec = &child->syscall;
	struct syscallentry *entry = NULL;
	unsigned long args[6] = { 0 };
	unsigned int callno;
	bool do32;
	bool got;
	enum syscallstate state;
	const char *name;

	SREC_SNAPSHOT(rec, {
		do32 = rec->do32bit;
		callno = rec->nr;
		state = __atomic_load_n(&rec->state, __ATOMIC_RELAXED);
		args[0] = rec->a1;
		args[1] = rec->a2;
		args[2] = rec->a3;
		args[3] = rec->a4;
		args[4] = rec->a5;
		args[5] = rec->a6;
	}, got);

	output(0, "  D-state diag: child %d pid %u\n", childno, pid);

	if (child->op_type != CHILD_OP_SYSCALL)
		output(0, "  child op: %s\n", alt_op_name(child->op_type));

	if (got) {
		entry = get_syscall_entry(callno, do32);
		name = (entry != NULL) ? entry->name : NULL;

		/* The watchdog kill line printed by stuck_syscall_info()
		 * already names the syscall; only emit fd-topology / fd-args
		 * here, since those are what the kill line omits. */
		if (name != NULL) {
			if (!dump_dstate_epoll_select_topology(name, args) &&
			    state == BEFORE) {
				struct dstate_fd_print_ctx fdctx = { .off = 0, .n = 0 };

				for_each_fd_arg(entry, args,
						dstate_print_fd_arg, &fdctx);
				if (fdctx.n > 0)
					output(0, "  fd args (%s): %s\n",
						name, fdctx.buf);
			}
		}
	} else {
		output(0, "  syscall arg snapshot unavailable (writer churn)\n");
	}

	dump_pid_wchan(pid);
	dump_pid_stack_bounded(pid);
	dump_pid_fdinfo_bounded(pid);
}

/*
 * Global budget for the verbose dump_dstate_diagnostics() snapshot.
 * Bounds two axes so a run that wedges thousands of distinct children
 * (each already gated to one snapshot by child->dstate_diag_dumped)
 * cannot produce unbounded aggregate output:
 *
 *   - DSTATE_DIAG_RUN_BUDGET caps the total number of verbose dumps
 *     printed across the whole run.
 *   - DSTATE_DIAG_PER_SIG_MAX caps how many samples a single
 *     (op_type, syscall nr, wchan-string) signature may burn from the
 *     budget, so one hot wedge pattern cannot consume the entire budget
 *     and starve rarer signatures.
 *
 * State is a plain file-static -- the reap/watchdog path runs
 * single-threaded in the parent, so no atomic/lock is needed and
 * nothing lives in shm.  The signature table is fixed-size (no alloc);
 * on collision or table-full we linear-probe within the table and, if
 * still no slot, fall through to the run-budget gate only.
 *
 * The one-line "STUCK CHILD:" summary is *not* budgeted -- it is one
 * greppable line per stuck child and is the always-on operator signal.
 * The omitted-count is surfaced two ways: an inline notice the first
 * time the run budget is exhausted, and a final "D-state diag summary"
 * line printed by log_main_loop_exit() at shutdown.
 */
#define DSTATE_DIAG_RUN_BUDGET  256
#define DSTATE_DIAG_PER_SIG_MAX 8
#define DSTATE_DIAG_SIG_SLOTS   128

struct dstate_diag_sig {
	uint32_t hash;		/* zero means slot unused */
	uint16_t count;		/* verbose dumps printed for this signature */
};

static struct dstate_diag_sig dstate_diag_sigs[DSTATE_DIAG_SIG_SLOTS];
static unsigned int dstate_diag_printed;
static unsigned int dstate_diag_omitted;
static unsigned int dstate_diag_sig_used;
static bool dstate_diag_notice_emitted;

static uint32_t dstate_diag_hash(int op_type, unsigned int callno,
				 const char *wchan)
{
	/* FNV-1a over (op_type, callno, wchan bytes).  Force nonzero so
	 * hash==0 can mark an empty slot without a separate valid bit. */
	uint32_t h = 2166136261u;

	h ^= (uint32_t)op_type;
	h *= 16777619u;
	h ^= callno;
	h *= 16777619u;
	while (*wchan) {
		h ^= (unsigned char)*wchan++;
		h *= 16777619u;
	}
	return h ? h : 1;
}

static void dstate_diag_note_budget_exhausted(void)
{
	if (dstate_diag_notice_emitted)
		return;
	output(0,
	       "D-state diag: run budget %u reached -- further verbose"
	       " snapshots suppressed (STUCK CHILD summaries continue)\n",
	       DSTATE_DIAG_RUN_BUDGET);
	dstate_diag_notice_emitted = true;
}

/*
 * Decide whether to emit a verbose D-state diagnostic snapshot for this
 * (child, wchan).  Returns true if the caller should print, false if
 * either the per-signature cap or the run budget is exhausted.  Also
 * bumps the internal counters that log_main_loop_exit() reads via
 * dstate_diag_get_counts().
 */
bool dstate_diag_budget_take(struct childdata *child,
			     const char *wchan)
{
	unsigned int callno = 0;
	uint32_t h;
	unsigned int slot;
	unsigned int i;

	if (child->op_type == CHILD_OP_SYSCALL) {
		struct syscallrecord *rec = &child->syscall;
		bool got;

		SREC_SNAPSHOT(rec, {
			callno = rec->nr;
		}, got);
		if (!got)
			callno = ~0u;
	}

	h = dstate_diag_hash(child->op_type, callno, wchan);
	slot = h % DSTATE_DIAG_SIG_SLOTS;

	for (i = 0; i < DSTATE_DIAG_SIG_SLOTS; i++) {
		struct dstate_diag_sig *s =
			&dstate_diag_sigs[(slot + i) % DSTATE_DIAG_SIG_SLOTS];

		if (s->hash == 0) {
			if (dstate_diag_printed >= DSTATE_DIAG_RUN_BUDGET) {
				dstate_diag_omitted++;
				dstate_diag_note_budget_exhausted();
				return false;
			}
			s->hash = h;
			s->count = 1;
			dstate_diag_sig_used++;
			dstate_diag_printed++;
			return true;
		}
		if (s->hash == h) {
			if (s->count >= DSTATE_DIAG_PER_SIG_MAX) {
				dstate_diag_omitted++;
				return false;
			}
			if (dstate_diag_printed >= DSTATE_DIAG_RUN_BUDGET) {
				dstate_diag_omitted++;
				dstate_diag_note_budget_exhausted();
				return false;
			}
			s->count++;
			dstate_diag_printed++;
			return true;
		}
	}

	/* Table full -- fall through to the run-budget gate only. */
	if (dstate_diag_printed >= DSTATE_DIAG_RUN_BUDGET) {
		dstate_diag_omitted++;
		dstate_diag_note_budget_exhausted();
		return false;
	}
	dstate_diag_printed++;
	return true;
}

void dstate_diag_get_counts(unsigned int *printed, unsigned int *omitted,
			    unsigned int *sigs)
{
	*printed = dstate_diag_printed;
	*omitted = dstate_diag_omitted;
	*sigs = dstate_diag_sig_used;
}
