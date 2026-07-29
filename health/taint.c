#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "child-api.h"
#include "params.h"
#include "types.h"
#include "taint.h"
#include "trinity.h"

#include "kernel/fcntl.h"
int kernel_taint_initial = 0;

static bool taint_available = false;

/*
 * Parent-only cached fd for /proc/sys/kernel/tainted.  The parent
 * process never fuzzes its own fd table, so a persistent fd here is
 * safe.  Child processes MUST NOT cache in this static: is_tainted()
 * runs after every fuzzed syscall (dispatch/syscall-exec.c), and a
 * cached long-lived fd in the child's fd table is directly reachable
 * from fuzzed dup2 / dup3 / close_range / close -- a successful
 * rewire would make the next get_taint() read an unrelated file,
 * strtol() an arbitrary byte stream, and fabricate a spurious taint
 * bit that panics the run.  Children therefore open/read/close per
 * call (see the this_child() branch below); the per-childop watcher
 * in child.c has its own long-lived child->tainted_fd which is kept
 * out of the picker pool via the fds-protected registry.
 */
static int tainted_fd_cached = -1;

void close_parent_tainted_fd(void)
{
	if (tainted_fd_cached != -1) {
		close(tainted_fd_cached);
		tainted_fd_cached = -1;
	}
}

/*
 * Uncached child-context read: open, read, close.  Called from
 * get_taint() on the child hot path so no long-lived fd number lands
 * in the child's fd table for a fuzzed close-family syscall to
 * hijack.  Returns -1 on any error so the caller can degrade to
 * "unknown taint" rather than fabricating a value.
 */
static int read_taint_uncached(void)
{
	char buffer[11];
	ssize_t n;
	int fd;

	fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	buffer[10] = 0;
	n = read(fd, buffer, 10);
	close(fd);
	if (n <= 0)
		return -1;

	{
		char *endptr;
		long val;

		buffer[n] = '\0';
		errno = 0;
		val = strtol(buffer, &endptr, 10);
		if (errno != 0 || endptr == buffer)
			return -1;
		return (int)val;
	}
}

int get_taint(void)
{
	char buffer[11];
	ssize_t n;
	int retried = 0;

	if (!taint_available)
		return 0;

	/* Child context: no long-lived fd number that a fuzzed
	 * dup2/dup3/close_range can rewire.  Parent context (init and
	 * shutdown paths, plus this_child()==NULL early in bring-up
	 * before pids[]/children[] are mapped) keeps using the cache. */
	if (this_child() != NULL) {
		int ret = read_taint_uncached();

		return ret < 0 ? 0 : ret;
	}

reopen:
	if (tainted_fd_cached == -1) {
		int fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			return 0;
		tainted_fd_cached = fd;
	}

	if (lseek(tainted_fd_cached, 0, SEEK_SET) == (off_t) -1) {
		if (errno == EBADF && !retried) {
			tainted_fd_cached = -1;
			retried = 1;
			goto reopen;
		}
		return 0;
	}

	buffer[10] = 0;
	n = read(tainted_fd_cached, buffer, 10);
	if (n < 0 && errno == EBADF && !retried) {
		tainted_fd_cached = -1;
		retried = 1;
		goto reopen;
	}
	if (n <= 0)
		return 0;

	{
		char *endptr;
		long val;

		buffer[n] = '\0';
		errno = 0;
		val = strtol(buffer, &endptr, 10);
		if (errno != 0 || endptr == buffer)
			return 0;
		return (int)val;
	}
}

static bool became_tainted = false;

bool is_tainted(void)
{
	/*
	 * Microoptimise the case where we became tainted. We don't need
	 * multiple reads of /proc.
	 */
	if (became_tainted == true)
		return true;

	/* Only check taint if the mask allows it */
	if (kernel_taint_mask != 0) {
		int ret = 0;

		ret = get_taint();
		if (((ret & kernel_taint_mask) & (~kernel_taint_initial)) != 0) {
			became_tainted = true;
			return true;
		}
	}
	return false;
}
static void toggle_taint_flag(int bit)
{
	kernel_taint_mask |= (1U << bit);
}

static void toggle_taint_flag_by_name(char *beg, char *end)
{
	char flagname[TAINT_NAME_LEN];
	char *name;

	if (end == NULL) {
		name = beg;
	} else {
		int maxlen;

		name = flagname;
		maxlen = end - beg;
		if (maxlen > (TAINT_NAME_LEN - 1))
			maxlen = TAINT_NAME_LEN - 1;
		strncpy(flagname, beg, maxlen);
		flagname[maxlen] = 0;
	}

	if (strcmp(name,"PROPRIETARY_MODULE") == 0)
		toggle_taint_flag(TAINT_PROPRIETARY_MODULE);
	else if (strcmp(name,"FORCED_MODULE") == 0)
		toggle_taint_flag(TAINT_FORCED_MODULE);
	else if (strcmp(name,"UNSAFE_SMP") == 0)
		toggle_taint_flag(TAINT_UNSAFE_SMP);
	else if (strcmp(name,"FORCED_RMMOD") == 0)
		toggle_taint_flag(TAINT_FORCED_RMMOD);
	else if (strcmp(name,"MACHINE_CHECK") == 0)
		toggle_taint_flag(TAINT_MACHINE_CHECK);
	else if (strcmp(name,"BAD_PAGE") == 0)
		toggle_taint_flag(TAINT_BAD_PAGE);
	else if (strcmp(name,"USER") == 0)
		toggle_taint_flag(TAINT_USER);
	else if (strcmp(name,"DIE") == 0)
		toggle_taint_flag(TAINT_DIE);
	else if (strcmp(name,"OVERRIDDEN_ACPI_TABLE") == 0)
		toggle_taint_flag(TAINT_OVERRIDDEN_ACPI_TABLE);
	else if (strcmp(name,"WARN") == 0)
		toggle_taint_flag(TAINT_WARN);
	else if (strcmp(name,"CRAP") == 0)
		toggle_taint_flag(TAINT_CRAP);
	else if (strcmp(name,"FIRMWARE_WORKAROUND") == 0)
		toggle_taint_flag(TAINT_FIRMWARE_WORKAROUND);
	else if (strcmp(name,"OOT_MODULE") == 0)
		toggle_taint_flag(TAINT_OOT_MODULE);
	else if (strcmp(name,"UNSIGNED_MODULE") == 0)
		toggle_taint_flag(TAINT_UNSIGNED_MODULE);
	else if (strcmp(name,"SOFTLOCKUP") == 0)
		toggle_taint_flag(TAINT_SOFTLOCKUP);
	else if (strcmp(name,"LIVEPATCH") == 0)
		toggle_taint_flag(TAINT_LIVEPATCH);
	else if (strcmp(name,"AUX") == 0)
		toggle_taint_flag(TAINT_AUX);
	else if (strcmp(name,"RANDSTRUCT") == 0)
		toggle_taint_flag(TAINT_RANDSTRUCT);
	else if (strcmp(name,"TEST") == 0)
		toggle_taint_flag(TAINT_TEST);
	else {
		outputerr("Unrecognizable kernel taint flag \"%s\".\n", name);
		exit(EXIT_FAILURE);
	}
}

void process_taint_arg(char *taintarg)
{
	char *beg, *end;

	if (kernel_taint_param_occured == false) {
		kernel_taint_param_occured = true;
		kernel_taint_mask = 0; //We now only care about flags that user specified.
	}

	beg = taintarg;
	end = strchr(beg, ',');
	while(end != NULL) {
		toggle_taint_flag_by_name(beg,end);
		beg = end + 1;
		end = strchr(beg, ',');
	}
	toggle_taint_flag_by_name(beg,end);
}

void init_taint_checking(void)
{
	int fd;

	fd = open("/proc/sys/kernel/tainted", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		taint_available = true;
		close(fd);
	}

	kernel_taint_initial = get_taint();
	if (kernel_taint_initial != 0)
		output(0, "Kernel was tainted on startup. Will ignore flags that are already set.\n");
}
