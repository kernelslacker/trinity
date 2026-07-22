/*
 * JSON-Lines sink -- see include/jsonl.h.
 *
 * Deliberately free-standing: only libc open/write/close.  This is the
 * first telemetry pipe brought up during a fuzz run, so it cannot
 * depend on trinity's output(), shm, or logging infrastructure.
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "fd.h"
#include "jsonl.h"

int jsonl_open(const char *path)
{
	return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

void jsonl_write(int fd, const char *json_line)
{
	size_t len;
	ssize_t ret;

	if (fd < 0 || json_line == NULL)
		return;

	len = strlen(json_line);
	if (len > 0) {
		ret = write_all(fd, json_line, len);
		(void)ret;
	}
	ret = write_all(fd, "\n", 1);
	(void)ret;
}
