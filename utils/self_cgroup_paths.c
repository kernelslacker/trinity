#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "self_cgroup.h"
#include "trinity.h"
#include "utils.h"

#include "self-cgroup-internal.h"

uint64_t mem_total_bytes(void)
{
	FILE *f;
	char line[256];
	uint64_t kb = 0;

	f = fopen("/proc/meminfo", "re");
	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "MemTotal: %" SCNu64 " kB", &kb) == 1)
			break;
	}
	fclose(f);
	return kb * UINT64_C(1024);
}

/*
 * Parse a size argument and produce a byte-count (out_bytes) plus the
 * canonical string we write into the cgroup file (out_str).  Accepted forms:
 *   "max"          → out_str="max", *out_is_max=true, out_bytes=0 (unused)
 *   "<n>%"         → percentage of MemTotal (1..100)
 *   "<n>[KMG]"     → bytes, with optional K/M/G binary suffix (1024)
 *
 * out_is_max is the explicit "uncapped" flag: callers that need to branch
 * on the "max" sentinel test it directly instead of comparing out_bytes
 * against an in-band magic value.  out_is_max may be NULL when the caller
 * has no interest in the distinction.
 *
 * On success returns true; *out_str is malloc'd, caller frees.
 * On failure returns false and outputs are untouched.
 */
bool parse_size_arg(const char *arg, uint64_t mem_total,
		    char **out_str, uint64_t *out_bytes,
		    bool *out_is_max)
{
	char *end;
	uint64_t val;
	uint64_t mult = 1;

	if (arg == NULL || *arg == '\0')
		return false;

	if (strcmp(arg, "max") == 0) {
		*out_str = strdup("max");
		if (*out_str == NULL)
			return false;
		*out_bytes = 0;
		if (out_is_max != NULL)
			*out_is_max = true;
		return true;
	}

	/*
	 * strtoull() silently accepts a leading '-' and wraps the result
	 * into ULLONG_MAX-adjacent values that look like enormous byte
	 * counts; '+' is equally surprising in a size context.  Reject
	 * both signs up front, matching parse_unsigned()'s contract in
	 * params.c.
	 */
	if (*arg == '-' || *arg == '+')
		return false;

	errno = 0;
	val = strtoull(arg, &end, 10);
	if (end == arg || errno == ERANGE)
		return false;

	if (*end == '%') {
		if (end[1] != '\0')
			return false;
		if (val == 0 || val > 100)
			return false;
		if (mem_total == 0)
			return false;
		val = mem_total * val / 100;
	} else if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 'k': case 'K': mult = UINT64_C(1024); break;
		case 'm': case 'M': mult = UINT64_C(1024) * 1024; break;
		case 'g': case 'G': mult = UINT64_C(1024) * 1024 * 1024; break;
		default: return false;
		}
		if (val > UINT64_MAX / mult)
			return false;
		val *= mult;
	}

	if (asprintf(out_str, "%" PRIu64, val) < 0)
		return false;
	*out_bytes = val;
	if (out_is_max != NULL)
		*out_is_max = false;
	return true;
}

/*
 * Parse-time validation hook for --memory-max / --memory-high /
 * --memory-swap-max.  parse_args() calls this immediately after
 * strdup'ing the optarg so --dry-run rejects malformed inputs the
 * same way a live run would.  self_cgroup_setup() retains its own
 * parse_size_arg() call as defense-in-depth -- a future code path
 * that mutates the *_arg globals after parse_args() (env override,
 * config file, etc.) still gets caught before being written to
 * memory.max.
 *
 * mem_total=1 is sufficient for a syntactic pass: percentage range
 * (1..100) is enforced before the multiply, and the absolute /
 * suffix branches don't read mem_total.  The canonicalised string
 * is discarded.
 */
bool validate_cgroup_size_arg(const char *flag_name, const char *arg)
{
	char *out_str = NULL;
	uint64_t out_bytes = 0;

	if (parse_size_arg(arg, 1, &out_str, &out_bytes, NULL)) {
		free(out_str);
		return true;
	}

	outputerr("%s: invalid memory-size '%s' "
		  "(accepted: 'max', '<n>%%' with 1..100, '<n>[KMG]')\n",
		  flag_name, arg ? arg : "(null)");
	return false;
}

/*
 * Read the cgroup v2 path of the calling process from /proc/self/cgroup.
 * The v2 line is the only one prefixed with "0::".  Returns a malloc'd
 * NUL-terminated path (e.g. "/user.slice/user-1000.slice/session-3.scope")
 * with the trailing newline stripped, or NULL if the file is unreadable
 * or no v2 line is present (e.g. pure cgroup v1 systems).
 */
char *read_self_cg_path(void)
{
	FILE *f;
	char line[PATH_MAX + 32];
	char *result = NULL;

	f = fopen("/proc/self/cgroup", "re");
	if (f == NULL)
		return NULL;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (strncmp(line, "0::", 3) != 0)
			continue;
		char *p = line + 3;
		size_t len = strlen(p);
		while (len > 0 && (p[len - 1] == '\n' || p[len - 1] == '\r'))
			p[--len] = '\0';
		if (len == 0)
			break;
		result = strdup(p);
		break;
	}
	fclose(f);
	return result;
}

bool write_cg_file(const char *cg_path, const char *name,
		   const char *value)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;
	size_t len;
	int saved_errno;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", cg_path, name) >= sizeof(path))
		return false;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	len = strlen(value);
	n = write(fd, value, len);
	if (n == (ssize_t)len) {
		close(fd);
		return true;
	}
	/* Preserve write()'s errno across close() so callers' strerror(errno)
	 * reports the real cgroup-write failure cause, not a stray close
	 * errno. */
	if (n >= 0)
		errno = EIO;
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	return false;
}
