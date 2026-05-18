#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "proc-status.h"

ssize_t proc_status_read(char *buf, size_t bufsz)
{
	ssize_t n;
	int fd;

	if (buf == NULL || bufsz < 2)
		return -1;

	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, bufsz - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	return n;
}

const char *proc_status_find_field(const char *buf, const char *name)
{
	char needle[64];
	const char *hit;
	int len;

	if (buf == NULL || name == NULL)
		return NULL;

	/*
	 * Build "\n<name>:" so the match cannot land inside an earlier field's
	 * value (e.g. a process Name: that contains "Uid") and cannot collide
	 * with a sibling field that shares a prefix (Cpus_allowed vs
	 * Cpus_allowed_list).  Trailing ':' is part of the anchor.
	 */
	len = snprintf(needle, sizeof(needle), "\n%s:", name);
	if (len <= 0 || (size_t)len >= sizeof(needle))
		return NULL;

	hit = strstr(buf, needle);
	if (hit == NULL)
		return NULL;
	return hit + len;
}

bool proc_status_parse_u(const char *value, unsigned long *out)
{
	if (value == NULL || out == NULL)
		return false;
	return sscanf(value, "%lu", out) == 1;
}

bool proc_status_parse_uid_gid_quad(const char *value, unsigned long out[4])
{
	if (value == NULL || out == NULL)
		return false;
	return sscanf(value, "%lu %lu %lu %lu",
		      &out[0], &out[1], &out[2], &out[3]) == 4;
}

bool proc_status_parse_hex_mask(const char *value, uint64_t *out)
{
	unsigned long long v;

	if (value == NULL || out == NULL)
		return false;
	if (sscanf(value, "%llx", &v) != 1)
		return false;
	*out = (uint64_t)v;
	return true;
}
