#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

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
