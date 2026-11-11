/*
 * Self-check for the D-state diagnostic's fdinfo walk (main/reap-dstate.c).
 * Reading a file's fdinfo runs its ->show_fdinfo(), and eventpoll's, tun's,
 * perf's and the fsnotify groups' sleep on a mutex a wedged child may hold,
 * where the reading parent would sleep too.  A helper process holds an epoll
 * fd, a pipe, /dev/null and a directory: the walk must print the directory's
 * fdinfo and none of the others'.
 */

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>

#include "child.h"		/* struct childdata */
#include "debug.h"		/* BUG */
#include "main/reap-internal.h"	/* dump_dstate_diagnostics */
#include "utils.h"		/* waitpid_eintr */

#include "fake_parent.h"	/* fake_output_log */

struct helper_fds {
	int dir, epoll, pipe, null;
};

/* Keep only stdio and @ready, open the four files and report their numbers,
 * then wait to be killed. */
static void __attribute__((noreturn)) run_helper(int ready)
{
	struct helper_fds fds;
	int p[2];

	if (ready > 3)
		syscall(SYS_close_range, 3U, (unsigned int) ready - 1, 0U);
	syscall(SYS_close_range, (unsigned int) ready + 1, ~0U, 0U);

	fds.dir = open("/", O_RDONLY | O_DIRECTORY);
	fds.epoll = epoll_create1(0);
	fds.pipe = pipe(p) == 0 ? p[0] : -1;
	fds.null = open("/dev/null", O_RDONLY);
	if (write(ready, &fds, sizeof(fds)) != sizeof(fds))
		_exit(1);
	for (;;)
		pause();
}

static bool printed_fdinfo(int fd)
{
	char tag[32];

	snprintf(tag, sizeof(tag), "fdinfo[%d]:", fd);
	return strstr(fake_output_log, tag) != NULL;
}

static void fdinfo_walk_reads_only_files_with_a_path(void)
{
	static struct childdata child;
	struct helper_fds fds;
	int ready[2];
	pid_t pid;
	ssize_t n;

	if (pipe(ready) != 0)
		BUG("reap_dstate: pipe failed");
	pid = fork();
	if (pid < 0)
		BUG("reap_dstate: fork failed");
	if (pid == 0)
		run_helper(ready[1]);
	close(ready[1]);
	n = read(ready[0], &fds, sizeof(fds));
	close(ready[0]);
	if (n != sizeof(fds) || fds.dir < 0 || fds.epoll < 0 ||
	    fds.pipe < 0 || fds.null < 0)
		BUG("reap_dstate: the helper did not open its files");

	child.op_type = CHILD_OP_SYSCALL;
	fake_output_log[0] = '\0';
	dump_dstate_diagnostics(&child, 0, pid);

	kill(pid, SIGKILL);
	waitpid_eintr(pid, NULL, 0);

	if (!printed_fdinfo(fds.dir)) {
		fprintf(stderr, "%s", fake_output_log);
		BUG("reap_dstate: the fdinfo walk left out a directory");
	}
	if (printed_fdinfo(fds.epoll) || printed_fdinfo(fds.pipe) ||
	    printed_fdinfo(fds.null)) {
		fprintf(stderr, "%s", fake_output_log);
		BUG("reap_dstate: the fdinfo walk read an epoll fd, a pipe or a device's fdinfo");
	}
	fake_output_log[0] = '\0';
}

void reap_dstate_self_check(void);
void reap_dstate_self_check(void)
{
	fdinfo_walk_reads_only_files_with_a_path();
}
