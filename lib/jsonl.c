/*
 * JSON-Lines sink -- see include/jsonl.h.
 *
 * Deliberately free-standing: only libc open/writev/close.  This is
 * the first telemetry pipe brought up during a fuzz run, so it cannot
 * depend on trinity's output(), shm, or logging infrastructure.
 *
 * The sink is opened once in the parent before fork(), so every child
 * inherits the same open file description with a shared write offset.
 * O_APPEND makes each writev() atomically seek to end-of-file, and
 * emitting the JSON payload plus the trailing newline as a single
 * writev() keeps a record contiguous on disk (regular files accept
 * writes up to PIPE_BUF as one extent), so concurrent children cannot
 * braid their records into each other.
 */

#include <fcntl.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "jsonl.h"

int jsonl_open(const char *path)
{
	return open(path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
}

void jsonl_write(int fd, const char *json_line)
{
	struct iovec iov[2];
	ssize_t ret;

	if (fd < 0 || json_line == NULL)
		return;

	iov[0].iov_base = (void *)json_line;
	iov[0].iov_len = strlen(json_line);
	iov[1].iov_base = (void *)"\n";
	iov[1].iov_len = 1;

	ret = writev(fd, iov, 2);
	(void)ret;
}
