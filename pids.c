#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include "objects.h"
#include "params.h"	// dangerous
#include "pids.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"	// shared_size_mul

#include <debug.h>

pid_t *pids;

/* Per-child cache: set once in init_child(), avoids O(n) scans. */
static int cached_childno = CHILD_NOT_FOUND;
pid_t cached_pid = EMPTY_PIDSLOT;
static struct childdata *cached_child = NULL;

void set_child_cache(int childno, pid_t pid, struct childdata *child)
{
	cached_childno = childno;
	cached_pid = pid;
	cached_child = child;
}

/*
 * Returns true if the process exists in the kernel's task table AND is
 * actually runnable.  Zombies (state Z) and dying tasks (state X) are
 * counted as NOT alive — they can't release locks, can't write to shm,
 * can't do anything except wait to be reaped.  Treating a zombie as
 * "alive" deadlocks any path that's waiting for the holder to do
 * something (notably check_lock() in locks.c).
 */
bool pid_alive(pid_t pid)
{
	char path[64];
	char buf[512];
	char state = '?';
	ssize_t n;
	int fd;

	if (pid < -1) {
		syslogf("kill_pid tried to kill %d!\n", pid);
		show_backtrace();
		return true;
	}
	if (pid == -1) {
		syslogf("kill_pid tried to kill -1!\n");
		show_backtrace();
		return true;
	}
	if (pid == 0) {
		syslogf("tried to kill_pid 0!\n");
		show_backtrace();
		return true;
	}

	if (kill(pid, 0) != 0)
		return false;

	/* kill() returned 0, so the task struct exists.  Check whether
	 * it's a zombie via /proc/<pid>/stat — third whitespace-separated
	 * field is a single-char state.  Use raw open/read into a stack
	 * buffer rather than fopen/fread/fclose: this is the parent's
	 * hottest path (called per held lock per check_all_locks tick AND
	 * once per just-spawned child in init_child) and stdio's per-call
	 * malloc of FILE struct + IO buffer is heap traffic we don't need
	 * here.  Under ASAN, every one of those mallocs is a candidate
	 * abort site; under normal builds it's just wasted work. */
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		/* Race: process exited between kill() and open.  Treat as
		 * not alive — caller will recover. */
		errno = ESRCH;
		return false;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		errno = ESRCH;
		return false;
	}
	buf[n] = '\0';
	/* Format: pid (comm with possible spaces) state ppid ...
	 * The comm may contain ')' so look for the LAST ')' then read
	 * the next whitespace token. */
	{
		char *rparen = strrchr(buf, ')');
		if (rparen != NULL && rparen[1] == ' ' && rparen[2] != '\0')
			state = rparen[2];
	}

	if (state == 'Z' || state == 'X') {
		/* Set errno so callers (notably check_lock) treat this
		 * the same as a fully-dead pid and release the lock
		 * instead of bailing on the EPERM-style guard. */
		errno = ESRCH;
		return false;
	}

	return true;
}

struct childdata * this_child(void)
{
	if (cached_childno != CHILD_NOT_FOUND && cached_pid == getpid())
		return cached_child;

	/* Fallback for main process or before cache is set */
	pid_t mypid = getpid();
	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) == mypid)
			return children[i];
	}
	return NULL;
}

int find_childno(pid_t mypid)
{
	if (cached_childno != CHILD_NOT_FOUND && cached_pid == mypid)
		return cached_childno;

	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) == mypid)
			return i;
	}
	return CHILD_NOT_FOUND;
}

bool pidmap_empty(void)
{
	unsigned int i;

	for_each_child(i) {
		if (__atomic_load_n(&pids[i], __ATOMIC_RELAXED) != EMPTY_PIDSLOT)
			return false;
	}
	return true;
}

void dump_childnos(void)
{
	unsigned int i, j = 0;
	char string[512], *sptr = string;
	char *end = string + sizeof(string);
	int n;

	n = snprintf(sptr, end - sptr, "## pids: (%u active)\n",
		     __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED));
	if (n > 0 && n < end - sptr)
		sptr += n;

	for (i = 0; i < max_children; i += 8) {
		n = snprintf(sptr, end - sptr, "%u-%u: ", i, i + 7);
		if (n > 0 && n < end - sptr)
			sptr += n;
		for (j = 0; j < 8; j++) {
			if (i + j >= max_children)
				break;

			if (__atomic_load_n(&pids[i + j], __ATOMIC_RELAXED) == EMPTY_PIDSLOT) {
				n = snprintf(sptr, end - sptr, "[empty] ");
			} else {
				pid_t pid = __atomic_load_n(&pids[i + j], __ATOMIC_RELAXED);

				n = snprintf(sptr, end - sptr, "%d ", (int)pid);
			}
			if (n > 0 && n < end - sptr)
				sptr += n;
		}
		n = snprintf(sptr, end - sptr, "\n");
		if (n > 0 && n < end - sptr)
			sptr += n;
		*sptr = '\0';
		outputerr("%s", string);
		sptr = string;
	}
}

/*
 * Diagnostic dump of the pids[] page contents and the parent's view
 * of its VMA permissions, called from the shm-corruption path when
 * sanity_check() trips on an out-of-range pid.  Tells us whether the
 * corruption is a single wild write (one slot bad), a wider memset
 * (many slots bad), or a page-level event such as MAP_FIXED replacement
 * or MADV_DONTNEED on the shared backing (whole page zeroed).  Also
 * confirms whether the parent's mprotect freeze is still in effect at
 * trip time (r-- vs rw-) — silent loss of the freeze would let parent
 * paths scribble without bracketing.
 */
void dump_pids_page_state(void)
{
	uintptr_t base = (uintptr_t) pids;
	uintptr_t page = base & ~((uintptr_t) 4095);
	const unsigned char *p = (const unsigned char *) page;
	unsigned int dump_bytes = 512;
	unsigned int i, nz = 0;
	int fd;

	outputerr("=== pids[] page state at corruption ===\n");
	outputerr("pids base=%p page_aligned=0x%lx max_children=%u array_bytes=%zu\n",
		  pids, (unsigned long) page, max_children,
		  max_children * sizeof(pid_t));

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd >= 0) {
		char buf[8192];
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0) {
			char *line = buf;
			char *end = buf + n;
			buf[n] = '\0';
			while (line < end) {
				char *nl = memchr(line, '\n', end - line);
				unsigned long lo = 0, hi = 0;
				if (nl != NULL)
					*nl = '\0';
				if (sscanf(line, "%lx-%lx", &lo, &hi) == 2 &&
				    page >= lo && page < hi) {
					outputerr("/proc/self/maps: %s\n", line);
				}
				if (nl == NULL)
					break;
				line = nl + 1;
			}
		}
	}

	outputerr("page hexdump [0..%u):\n", dump_bytes);
	for (i = 0; i < dump_bytes; i += 16) {
		outputerr("  +0x%03x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
			  i,
			  p[i+0], p[i+1], p[i+2],  p[i+3],
			  p[i+4], p[i+5], p[i+6],  p[i+7],
			  p[i+8], p[i+9], p[i+10], p[i+11],
			  p[i+12], p[i+13], p[i+14], p[i+15]);
	}

	for (i = dump_bytes; i < 4096; i++)
		if (p[i] != 0)
			nz++;
	outputerr("page tail [%u..4096): %u non-zero bytes\n", dump_bytes, nz);
	outputerr("running_childs=%u\n",
		  __atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED));
	outputerr("=== end pids[] page state ===\n");
}

static unsigned long pidmax;

static int read_pid_max(void)
{
	unsigned long result;
	char *end, buf[32];
	FILE *fp;
	int rc;

	fp = fopen("/proc/sys/kernel/pid_max", "r");
	if (!fp) {
		perror("fopen");
		return -1;
	}

	rc = -1;
	if (!fgets(buf, sizeof(buf), fp))
		goto out;

	errno = 0;
	result = strtoul(buf, &end, 10);
	if (end == buf)
		goto out;
	if (errno == ERANGE)
		goto out;

	pidmax = result;
	rc = 0;
out:
	fclose(fp);
	return rc;
}

void pids_init(void)
{
	unsigned int i;

	if (read_pid_max()) {
#ifdef __x86_64__
		pidmax = 4194304;
#else
		pidmax = 32768;
#endif
		outputerr("Couldn't read pid_max from proc\n");
	}

	output(0, "Using pid_max = %lu\n", pidmax);

	/*
	 * pids[] is read by children (get_pid() biases random pid args
	 * toward live children) but written ONLY by the parent (spawn_child
	 * stores the new pid, reap_child clears to EMPTY_PIDSLOT).
	 */
	{
		size_t pids_bytes;

		if (!shared_size_mul(max_children, sizeof(pid_t), &pids_bytes)) {
			outputerr("pids_init: max_children=%u * sizeof(pid_t) overflows size_t\n",
				  max_children);
			exit(EXIT_FAILURE);
		}
		pids = alloc_shared_global(pids_bytes);
	}
	for_each_child(i)
		__atomic_store_n(&pids[i], EMPTY_PIDSLOT, __ATOMIC_RELAXED);
}

int pid_is_valid(pid_t pid)
{
	if ((pid < 1) || ((unsigned long)pid > pidmax))
		return false;

	return true;
}

unsigned int get_pid(void)
{
	unsigned int i;
	pid_t pid = 0;
	unsigned int dice;

	/* If we get called from the parent, and there are no
	 * children around yet, we need to not look at the pidmap. */
	if (__atomic_load_n(&shm->running_childs, __ATOMIC_RELAXED) == 0)
		return 0;

	/*
	 * Bias heavily toward real live child PIDs so that process-targeting
	 * syscalls (kill, ptrace, waitpid, etc.) actually reach running
	 * processes rather than failing with ESRCH.
	 *
	 *  70%: a real child from pids[]
	 *  15%: our own PID (valid, exercises self-targeting)
	 *  10%: 0 (process group semantics)
	 *   5%: 1 (init; only when dangerous flag set)
	 */
	dice = rand() % 100;

	if (dice < 70) {
		pid_t ppid = mainpid;
		unsigned int retries = 0;
retry:		i = rand() % max_children;
		pid = __atomic_load_n(&pids[i], __ATOMIC_RELAXED);
		if (pid == EMPTY_PIDSLOT || pid == ppid) {
			if (++retries >= 100)
				return cached_pid;
			goto retry;
		}
		return pid;
	}

	if (dice < 85)
		return cached_pid;

	if (dice < 95)
		return 0;

	/* dice 95-99: return 1 only when dangerous is set */
	if (dangerous)
		return 1;

	return cached_pid;
}

/*
 * OBJ_PID pool helpers.
 *
 * The pool is fed by the seven pid-returning syscalls
 * (fork, vfork, clone, clone3, getpid, gettid, getppid) via the
 * generic .ret_objtype = OBJ_PID dispatch hook in handle_syscall_ret;
 * mirrors the OBJ_KEY_SERIAL / OBJ_TIMERID / OBJ_AIO_CTX shape but
 * with no destructor -- pids are non-resource handles, nothing to
 * release at child teardown.  Consumed by ARG_PIDs fill_arg branch
 * in generate-args.c so the 12+ ARG_PID consumers (kill, tkill,
 * tgkill, ptrace, setpgid, getpgid, getsid, setpriority, getpriority,
 * waitpid, wait4, sched_set..., sched_get..., perf_event_open, ...)
 * can pick pids the fuzz session has actually produced instead of
 * rolling the same single random distribution every call.  Cold-pool
 * fallback defers to get_pids existing live-children bias so runtime
 * behaviour does not regress when the pool is empty.
 */
pid_t get_random_pid_from_pool(void)
{
	struct object *obj;

	if (objects_empty(OBJ_PID) == true)
		return (pid_t) get_pid();

	obj = get_random_object(OBJ_PID, OBJ_LOCAL);
	if (obj == NULL)
		return (pid_t) get_pid();
	return obj->pidobj.pid;
}

void register_returned_pid(pid_t pid)
{
	struct object *obj;

	if (pid <= 0)
		return;

	obj = alloc_object();
	obj->pidobj.pid = pid;
	add_object(obj, OBJ_LOCAL, OBJ_PID);
}
