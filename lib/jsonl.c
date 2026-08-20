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

int jsonl_write(int fd, const char *json_line)
{
	struct iovec iov[2];
	ssize_t ret;
	ssize_t expected;

	if (fd < 0 || json_line == NULL)
		return 0;

	iov[0].iov_base = (void *)json_line;
	iov[0].iov_len = strlen(json_line);
	iov[1].iov_base = (void *)"\n";
	iov[1].iov_len = 1;
	expected = (ssize_t)(iov[0].iov_len + 1);

	ret = writev(fd, iov, 2);
	if (ret < 0 || ret != expected) {
		/* A short write leaves a partial record with no terminating
		 * newline, which corrupts the JSONL stream for any reader
		 * that relies on newline framing.  Treat it identically to
		 * a full write error.
		 *
		 * Emit a truncation marker so a downstream reader can
		 * distinguish a sink-failure truncation from a clean
		 * end-of-run.  The leading '\n' ensures the marker begins
		 * on its own line even if the failed record left a partial
		 * line without a terminating newline. */
		const char *marker =
			"\n{\"truncated\":true,\"reason\":\"write_error\"}\n";
		if (write(fd, marker, strlen(marker)) < 0) {
			/* nothing to do -- sink is already dead */
		}
		return -1;
	}
	return 0;
}
