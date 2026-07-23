#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/types.h>

#include "proc-status.h"

ssize_t proc_status_read(char *buf, size_t bufsz)
{
	size_t off = 0;
	int fd;

	if (buf == NULL || bufsz < 2)
		return -1;

	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return -1;

	/*
	 * /proc/self/status is a seq_file; a single read() can return short
	 * before EOF, silently truncating late fields (SigPnd/ShdPnd, the
	 * *_allowed masks) that the field parsers then fail to find.  Loop
	 * read() into the caller-provided fixed buffer until EOF or the
	 * buffer is full, mirroring the grow/read loop in proc_status_slurp.
	 */
	for (;;) {
		ssize_t n;

		if (off >= bufsz - 1)
			break;

		n = read(fd, buf + off, bufsz - off - 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -1;
		}
		if (n == 0)
			break;
		off += (size_t) n;
	}

	close(fd);
	if (off == 0)
		return -1;
	buf[off] = '\0';
	return (ssize_t) off;
}

char *proc_status_slurp(void)
{
	char *buf = NULL;
	size_t cap = 0, off = 0;
	int fd;

	fd = open("/proc/self/status", O_RDONLY);
	if (fd < 0)
		return NULL;

	for (;;) {
		ssize_t n;

		/* Grow on demand, leaving room for the trailing NUL. */
		if (off + 2 > cap) {
			size_t newcap = cap ? cap * 2 : 4096;
			char *nb = malloc(newcap);

			if (nb == NULL) {
				/*
				 * Fuzzer may have called mlockall(MCL_FUTURE),
				 * which pins the heap and can short-circuit
				 * allocation.  Undo the pin and retry once.
				 */
				munlockall();
				nb = malloc(newcap);
			}
			if (nb == NULL) {
				free(buf);
				close(fd);
				return NULL;
			}
			if (buf != NULL) {
				memcpy(nb, buf, off);
				free(buf);
			}
			buf = nb;
			cap = newcap;
		}

		n = read(fd, buf + off, cap - off - 1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			free(buf);
			close(fd);
			return NULL;
		}
		if (n == 0)
			break;
		off += (size_t) n;
	}

	close(fd);
	buf[off] = '\0';
	return buf;
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

/*
 * Coarse-grained field readers below.  Each one collapses the
 * read-then-find-then-parse triplet that every oracle currently open-codes
 * into a single call, so the buffer-size choice and the slurp-vs-fixed
 * decision live in one place.  Stack buffer sized 8 KB (4x the historical
 * 2 KB) for the bounded fields; sigmask reader uses the growing slurp so
 * truncation cannot recur on SigPnd/ShdPnd which land
 * late in /proc/self/status.
 */

bool proc_status_read_uint_field(const char *name, unsigned long *out)
{
	char buf[8192];
	const char *value;

	if (name == NULL || out == NULL)
		return false;
	if (proc_status_read(buf, sizeof(buf)) < 0)
		return false;
	value = proc_status_find_field(buf, name);
	if (value == NULL)
		return false;
	return proc_status_parse_u(value, out);
}

bool proc_status_read_id_quad(const char *name, unsigned long out[4])
{
	char buf[8192];
	const char *value;

	if (name == NULL || out == NULL)
		return false;
	if (proc_status_read(buf, sizeof(buf)) < 0)
		return false;
	value = proc_status_find_field(buf, name);
	if (value == NULL)
		return false;
	return proc_status_parse_uid_gid_quad(value, out);
}

bool proc_status_read_sigmask(const char *name, uint64_t *out)
{
	char *buf;
	const char *value;
	bool ok;

	if (name == NULL || out == NULL)
		return false;
	buf = proc_status_slurp();
	if (buf == NULL)
		return false;
	value = proc_status_find_field(buf, name);
	ok = value != NULL && proc_status_parse_hex_mask(value, out);
	free(buf);
	return ok;
}

/*
 * Pair-read SigPnd: and ShdPnd: from a single /proc/self/status snapshot
 * so the rt_sigpending oracle compares the syscall's union against two
 * masks captured at one kernel instant.  Two back-to-back single-mask
 * reads can straddle a signal moving shared->thread-pending and yield a
 * (SigPnd | ShdPnd) union that no single proc_pid_status() render ever
 * produced, which the oracle would then flag as a spurious anomaly.
 * Shares proc_status_slurp + proc_status_find_field + parse_hex_mask
 * with the single-mask helper -- no scanner duplication.
 */
bool proc_status_read_sigmask_pair(uint64_t *sigpnd_out, uint64_t *shdpnd_out)
{
	char *buf;
	const char *v_sig, *v_shd;
	bool ok;

	if (sigpnd_out == NULL || shdpnd_out == NULL)
		return false;
	buf = proc_status_slurp();
	if (buf == NULL)
		return false;
	v_sig = proc_status_find_field(buf, "SigPnd");
	v_shd = proc_status_find_field(buf, "ShdPnd");
	ok = v_sig != NULL && v_shd != NULL &&
	     proc_status_parse_hex_mask(v_sig, sigpnd_out) &&
	     proc_status_parse_hex_mask(v_shd, shdpnd_out);
	free(buf);
	return ok;
}

bool proc_status_read_ns_last_uint(const char *name, unsigned int *out)
{
	char buf[8192];
	const char *value;
	char *line, *eol, *tok, *saveptr = NULL;
	unsigned int last = 0;
	bool found = false;

	if (name == NULL || out == NULL)
		return false;
	if (proc_status_read(buf, sizeof(buf)) < 0)
		return false;
	value = proc_status_find_field(buf, name);
	if (value == NULL)
		return false;

	/*
	 * Bound strtok_r to this one line.  value points into buf which is
	 * a writable stack array, so casting away const is safe.
	 */
	line = (char *) value;
	eol = strchr(line, '\n');
	if (eol != NULL)
		*eol = '\0';

	for (tok = strtok_r(line, " \t", &saveptr); tok != NULL;
	     tok = strtok_r(NULL, " \t", &saveptr)) {
		unsigned int v;

		if (sscanf(tok, "%u", &v) == 1) {
			last = v;
			found = true;
		}
	}
	if (found)
		*out = last;
	return found;
}
