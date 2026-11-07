#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "fd.h"

/* Robust full-buffer write loop.  Restarts on EINTR; treats a
 * short-write of 0 as an error.  Shared by every persistence format
 * trinity emits so the loop lives in one place instead of being
 * copy-pasted with no semantic divergence between callers. */
ssize_t write_all(int fd, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = write(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += n;
		left -= n;
	}
	return (ssize_t)len;
}

/* Robust full-buffer read loop.  Restarts on EINTR; returns the number
 * of bytes successfully read, which may be less than @len at EOF.
 * Counterpart to write_all() and shared by the same callers. */
ssize_t read_all(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t left = len;

	while (left > 0) {
		ssize_t n = read(fd, p, left);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		p += n;
		left -= n;
	}
	return (ssize_t)(len - left);
}

/* A task that is not dumpable owns its /proc files as root
 * (task_dump_owner()), so one that cleared the flag, as
 * disable_coredumps() does, cannot open an S_IRUSR file of its own such
 * as pagemap: set the flag for the open and put it back, as 0 if it was
 * 2, which prctl() cannot set. */
int open_owner_only(const char *path)
{
	bool toggled = prctl(PR_GET_DUMPABLE) != 1;
	int fd;

	if (toggled)
		prctl(PR_SET_DUMPABLE, 1);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (toggled)
		prctl(PR_SET_DUMPABLE, 0);
	return fd;
}
