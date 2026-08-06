/*
 * health/signals-precrash.c — pre-crash stderr capture and bug-log setup.
 *
 * Provides:
 *  - glibc __abort_msg capture so SIGABRT handlers can retrieve the
 *    malloc_printerr / __libc_message text before it races with the
 *    shared stderr memfd drain.
 *  - An anonymous in-memory file (memfd) that backs the child's stderr
 *    after init_stderr_memfd() runs, buffering pre-fault glibc output
 *    for the fault handler to flush into the on-disk bug log.
 *  - open_buglog_and_drain_stderr(): opens the per-pid bug log, drains
 *    the buffered stderr content into it, and redirects STDERR_FILENO
 *    to the bug log file so subsequent in-handler writes land there.
 *    Called from child_fault_handler() in signals-fault-handler.c.
 *
 * See Documentation/signals.md.
 */
#include <dlfcn.h>
#include <limits.h>	/* PATH_MAX */
#include <stdio.h>	/* snprintf */
#include <string.h>	/* strnlen */
#include <sys/syscall.h>	/* SYS_write (raw syscall, bypassing libc stdio) */
#include <unistd.h>	/* dup2, lseek, read, write, close, getpid */
#include <fcntl.h>	/* O_WRONLY, O_CREAT, O_APPEND, O_CLOEXEC */
#include <sys/mman.h>	/* memfd_create() */

#include "trinity.h"	/* trinity_tmpdir_abs() */
#include "signals.h"
#include "signals-internal.h"

#include "kernel/memfd.h"

/*
 * Cached pointer to glibc's __abort_msg.  Resolved once at child init
 * so there is no link-time GLIBC_PRIVATE dependency: a glibc upgrade
 * that drops the symbol leaves this NULL and the SIGABRT handler
 * silently skips the capture.  This mirrors gdb's pattern for reading
 * the same symbol.  Neither dlvsym() nor dlsym() is async-signal-safe;
 * both are called only from init_abort_msg_capture() below.
 *
 * __abort_msg points at a glibc-internal struct whose layout has been
 * stable since 2.34: a 4-byte size field followed by a NUL-terminated
 * message in a flexible array.  The struct is mirrored locally rather
 * than pulled from a private glibc header.
 */
static struct abort_msg_s {
	unsigned int size;
	char msg[];
} **glibc_abort_msg_p;

void init_abort_msg_capture(void)
{
	/*
	 * Most distros export __abort_msg only under @GLIBC_PRIVATE
	 * with no default-version alias, so a bare dlsym() returns
	 * NULL.  Bind the private version explicitly via dlvsym(), and
	 * fall back to dlsym() for libcs that do expose an unversioned
	 * alias.
	 */
	glibc_abort_msg_p = dlvsym(RTLD_DEFAULT, "__abort_msg", "GLIBC_PRIVATE");
	if (glibc_abort_msg_p == NULL)
		glibc_abort_msg_p = dlsym(RTLD_DEFAULT, "__abort_msg");
}

/*
 * Capture glibc's __abort_msg directly into the per-pid bug log via
 * raw syscall.  The shared stderr memfd is fork-shared and races
 * between siblings; __abort_msg is per-process (glibc mmap()s it in
 * the abort()ing child's own address space) and race-free.
 * See Documentation/signals.md.
 *
 * Async-signal-safe: raw SYS_write and strnlen only, no allocation,
 * no locale, no lock.  m->size is treated as advisory and capped at
 * ABORT_MSG_MAX because it lives in the same glibc allocation we're
 * salvaging post-corruption and may itself be scribbled.
 *
 * The m->msg[0] == '\0' early-out catches the rare path where glibc
 * allocated the buffer but bailed before formatting; don't emit a
 * bare "abort_msg: \n".
 */
static void capture_abort_msg_to_buglog(int bug_fd)
{
	/*
	 * Hard upper bound on how many bytes we'll trust m->size to
	 * authorise reading.  m and m->size both live in the same glibc
	 * abort allocation we're salvaging post-corruption -- if the
	 * upstream bug is "heap got scribbled", m->size is just another
	 * scribbled field.  Real __abort_msg payloads are short single
	 * lines (a few hundred bytes); 16 KiB is far above anything glibc
	 * produces and far below any value that would let a corrupt
	 * size_t run strnlen() off a mapping.
	 */
	static const size_t ABORT_MSG_MAX = 16384;
	struct abort_msg_s *m;
	size_t cap, len;
	static const char prefix[] = "abort_msg: ";

	if (glibc_abort_msg_p == NULL)
		return;
	m = *glibc_abort_msg_p;
	if (m == NULL)
		return;
	cap = m->size;
	if (cap > ABORT_MSG_MAX)
		cap = ABORT_MSG_MAX;
	if (cap == 0 || m->msg[0] == '\0')
		return;

	len = strnlen(m->msg, cap);
	(void)syscall(SYS_write, bug_fd, prefix, sizeof(prefix) - 1);
	(void)syscall(SYS_write, bug_fd, m->msg, len);
	if (len == 0 || m->msg[len - 1] != '\n')
		(void)syscall(SYS_write, bug_fd, "\n", 1);
}

/*
 * In-process anonymous file that backs the child's stderr after
 * init_stderr_memfd() runs.  The fd is kept open past the dup2 so
 * child_fault_handler() can lseek+read the buffered text back into
 * the on-disk bug log when the child actually crashes.  -1 means
 * the memfd_create() failed (e.g. CONFIG_MEMFD_CREATE=n on a
 * stripped kernel) and stderr stays at its previous /dev/null
 * baseline -- the handler then skips the drain and produces only
 * the in-handler backtrace + siginfo, same as before this feature
 * existed.
 */
static int stderr_memfd = -1;

/*
 * Bug-log path pre-formatted at init time so the signal handler
 * never has to call snprintf() (not async-signal-safe per POSIX
 * 2024 §2.4.3).  Sized like the existing on-stack PATH_MAX + 64
 * buffer in child_fault_handler so a long trinity_tmpdir_abs() plus
 * "/trinity-bug-<pid>.log" cannot truncate.
 */
static char buglog_path[PATH_MAX + 64];

/*
 * Buffer the child's stderr writes in an anonymous in-memory file
 * so pre-fault glibc text (malloc_printerr / __libc_message /
 * __fortify_fail / __stack_chk_fail) survives long enough for the
 * fault handler to flush it into the on-disk bug log on a real
 * crash.  Clean exits discard the memfd with the process.  Paired
 * with the drain block at the top of child_fault_handler.
 * See Documentation/signals.md.
 *
 * snprintf() is NOT async-signal-safe, so buglog_path[] is
 * pre-formatted here under the inherited non-fuzzed locale.
 * trinity_tmpdir_abs() guards against a fuzzed chdir(); getpid()
 * is used instead of mypid() because cached_pid isn't populated
 * until set_child_cache runs later in init_child_rendezvous_parent.
 *
 * The fd is intentionally NOT closed after dup2 onto STDERR_FILENO
 * -- the handler reads it back from the same fd.
 */
void init_stderr_memfd(void)
{
	int fd;

	snprintf(buglog_path, sizeof(buglog_path),
		 "%s/trinity-bug-%d.log",
		 trinity_tmpdir_abs(), (int)getpid());

	fd = memfd_create("trinity-stderr", MFD_CLOEXEC);
	if (fd < 0)
		return;
	dup2(fd, STDERR_FILENO);
	stderr_memfd = fd;
}

int trinity_stderr_memfd(void)
{
	return stderr_memfd;
}

/*
 * Open the per-pid bug log, drain any buffered pre-crash stderr text
 * into it, then dup2 it onto STDERR_FILENO so the in-handler
 * backtrace + siginfo writes below land in the same on-disk file.
 *
 * Carries no_sanitize for parity with child_fault_handler -- not
 * strictly required (no childdata deref here), but matches the
 * attribute every other extracted helper carries so ASAN behaviour
 * is uniform across the post-extraction handler.
 */
__attribute__((no_sanitize("address")))
void open_buglog_and_drain_stderr(int sig)
{
	int bug_fd;

	bug_fd = open(buglog_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
	if (bug_fd >= 0) {
		/*
		 * Capture __abort_msg directly into the per-pid bug
		 * log BEFORE the shared-memfd drain.  The memfd is
		 * fork-shared (one struct file, one offset) so the
		 * writev() that glibc's __libc_message emitted to
		 * STDERR_FILENO almost certainly raced with a sibling
		 * child's drain.  __abort_msg lives in this child's
		 * private address space and has no such race -- read
		 * it now while we are guaranteed exclusive access to
		 * our own per-pid bug_fd.  See
		 * capture_abort_msg_to_buglog() above for the full
		 * rationale and the raw-syscall justification.
		 */
		if (sig == SIGABRT)
			capture_abort_msg_to_buglog(bug_fd);

		if (stderr_memfd >= 0) {
			char drain_buf[4096];
			ssize_t n, w;
			size_t drained = 0;
			static const size_t STDERR_DRAIN_MAX = 1u << 20;	/* 1 MiB */

			/*
			 * Cap the drain.  A fuzzed child can extend the
			 * stderr memfd to a huge sparse size; an
			 * uncapped read/write loop materialises the NUL
			 * holes as real bytes on tmpfs and can produce
			 * multi-GB bug logs (log-DoS).  Bound the copy
			 * at 1 MiB -- well past any plausible real
			 * diagnostic payload.
			 */
			(void)lseek(stderr_memfd, 0, SEEK_SET);
			while (drained < STDERR_DRAIN_MAX &&
			       (n = read(stderr_memfd, drain_buf,
					 sizeof(drain_buf))) > 0) {
				size_t want = (size_t)n;
				if (want > STDERR_DRAIN_MAX - drained)
					want = STDERR_DRAIN_MAX - drained;
				w = write(bug_fd, drain_buf, want);
				(void)w;	/* dying anyway; short write irrelevant */
				drained += want;
			}
		}
		dup2(bug_fd, STDERR_FILENO);
		close(bug_fd);
	} else {
		/*
		 * Buglog open failed (e.g. /tmp full, stripped mode bits
		 * from a fuzzed umask run before our umask(0) reset, or a
		 * namespace fault on the path).  Write a BUGLOG-FAIL reason
		 * marker to STDERR_FILENO -- still the pre-dup2 stderr memfd
		 * at this point -- so the parent's memfd drain at reap time
		 * surfaces the open failure as the explanation for why the
		 * per-pid bug log is absent from the archive.  The parent's
		 * dump_child_fault_beacon() will annotate the FAULT! line;
		 * classify_child_buglog() (called from the reap path after the
		 * child exits) will increment the no-buglog counter.  write() is on the
		 * POSIX 2024 §2.4.3 async-signal-safe list.
		 */
		static const char fail_marker[] =
			"BUGLOG-FAIL: buglog open() failed -- no per-pid log\n";
		(void)syscall(SYS_write, STDERR_FILENO,
			      fail_marker, sizeof(fail_marker) - 1);
	}
}
