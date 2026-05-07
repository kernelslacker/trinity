#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "params.h"
#include "self_cgroup.h"
#include "trinity.h"
#include "utils.h"

/*
 * The cgroup directory we created and own.  NULL when no cgroup was made
 * (either disabled, parse failure, or already capped by a wrapper scope).
 * Cleanup at exit is best-effort: the kernel reclaims the cgroup when the
 * last process exits anyway, but rmdir keeps the tree tidy on clean exit.
 */
static char *self_cg_path;

static unsigned long mem_total_bytes(void)
{
	FILE *f;
	char line[256];
	unsigned long kb = 0;

	f = fopen("/proc/meminfo", "re");
	if (f == NULL)
		return 0;
	while (fgets(line, sizeof(line), f) != NULL) {
		if (sscanf(line, "MemTotal: %lu kB", &kb) == 1)
			break;
	}
	fclose(f);
	return kb * 1024UL;
}

/*
 * Parse a size argument and produce the canonical byte-count string we
 * write into the cgroup file.  Accepted forms:
 *   "max"          → out is set to "max" (cgroup sentinel for uncapped)
 *   "<n>%"         → percentage of MemTotal (1..100)
 *   "<n>[KMG]"     → bytes, with optional K/M/G binary suffix (1024)
 *
 * On success returns true and *out points to a malloc'd NUL-terminated
 * string the caller must free.  On failure returns false and *out is
 * untouched.
 */
static bool parse_size_arg(const char *arg, unsigned long mem_total,
			   char **out)
{
	char *end;
	unsigned long long val;
	unsigned long long mult = 1;

	if (arg == NULL || *arg == '\0')
		return false;

	if (strcmp(arg, "max") == 0) {
		*out = strdup("max");
		return *out != NULL;
	}

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
		val = (unsigned long long)mem_total * val / 100ULL;
	} else if (*end != '\0') {
		if (end[1] != '\0')
			return false;
		switch (*end) {
		case 'k': case 'K': mult = 1024ULL; break;
		case 'm': case 'M': mult = 1024ULL * 1024; break;
		case 'g': case 'G': mult = 1024ULL * 1024 * 1024; break;
		default: return false;
		}
		if (val > ULLONG_MAX / mult)
			return false;
		val *= mult;
	}

	if (asprintf(out, "%llu", val) < 0)
		return false;
	return true;
}

/*
 * Read the cgroup v2 path of the calling process from /proc/self/cgroup.
 * The v2 line is the only one prefixed with "0::".  Returns a malloc'd
 * NUL-terminated path (e.g. "/user.slice/user-1000.slice/session-3.scope")
 * with the trailing newline stripped, or NULL if the file is unreadable
 * or no v2 line is present (e.g. pure cgroup v1 systems).
 */
static char *read_self_cg_path(void)
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

static bool write_cg_file(const char *cg_path, const char *name,
			  const char *value)
{
	char path[PATH_MAX];
	int fd;
	ssize_t n;
	size_t len;

	if ((size_t)snprintf(path, sizeof(path), "%s/%s", cg_path, name) >= sizeof(path))
		return false;
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	len = strlen(value);
	n = write(fd, value, len);
	close(fd);
	return n == (ssize_t)len;
}

/*
 * Detect a wrapper scope: if our current cgroup already has a non-"max"
 * memory.max, an outer agent (systemd-run, kubelet, the run-trinity.sh
 * stopgap) has already capped us.  Defer to it: nesting our own
 * sub-cgroup inside would just confuse exit accounting and leak rmdir
 * permission errors when the wrapper tears its scope down before us.
 */
static bool already_capped(const char *parent_cg_path)
{
	char path[PATH_MAX];
	FILE *f;
	char buf[64];
	bool capped = false;

	if ((size_t)snprintf(path, sizeof(path), "/sys/fs/cgroup%s/memory.max",
			     parent_cg_path) >= sizeof(path))
		return false;
	f = fopen(path, "re");
	if (f == NULL)
		return false;
	if (fgets(buf, sizeof(buf), f) != NULL) {
		size_t len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';
		if (strcmp(buf, "max") != 0)
			capped = true;
	}
	fclose(f);
	return capped;
}

void self_cgroup_setup(void)
{
	char *parent_cg = NULL;
	char *new_cg = NULL;
	unsigned long memtotal;
	char *max_value = NULL;
	char *high_value = NULL;
	char *swap_value = NULL;
	char pidbuf[32];
	int n;

	if (no_cgroup)
		return;

	parent_cg = read_self_cg_path();
	if (parent_cg == NULL) {
		outputerr("self-cgroup: /proc/self/cgroup has no v2 entry; "
			  "running without memory cap\n");
		goto out;
	}

	if (already_capped(parent_cg)) {
		output(1, "self-cgroup: parent cgroup %s already capped; "
		       "deferring to wrapper\n", parent_cg);
		goto out;
	}

	memtotal = mem_total_bytes();
	if (memtotal == 0) {
		outputerr("self-cgroup: cannot read MemTotal; "
			  "running without memory cap\n");
		goto out;
	}

	if (!parse_size_arg(memory_max_arg ? memory_max_arg : "60%",
			    memtotal, &max_value)) {
		outputerr("self-cgroup: invalid --memory-max '%s'; "
			  "running without memory cap\n",
			  memory_max_arg ? memory_max_arg : "60%");
		goto out;
	}
	if (!parse_size_arg(memory_high_arg ? memory_high_arg : "50%",
			    memtotal, &high_value)) {
		outputerr("self-cgroup: invalid --memory-high '%s'; "
			  "running without memory cap\n",
			  memory_high_arg ? memory_high_arg : "50%");
		goto out;
	}
	if (!parse_size_arg(memory_swap_max_arg ? memory_swap_max_arg : "20%",
			    memtotal, &swap_value)) {
		outputerr("self-cgroup: invalid --memory-swap-max '%s'; "
			  "running without memory cap\n",
			  memory_swap_max_arg ? memory_swap_max_arg : "20%");
		goto out;
	}

	if (asprintf(&new_cg, "/sys/fs/cgroup%s/trinity-%d",
		     parent_cg, (int)getpid()) < 0) {
		new_cg = NULL;
		outputerr("self-cgroup: asprintf failed; "
			  "running without memory cap\n");
		goto out;
	}

	if (mkdir(new_cg, 0755) != 0) {
		outputerr("self-cgroup: mkdir(%s) failed: %s; "
			  "running without memory cap\n",
			  new_cg, strerror(errno));
		goto out;
	}

	if (!write_cg_file(new_cg, "memory.max", max_value)) {
		outputerr("self-cgroup: write memory.max=%s failed: %s; "
			  "running without memory cap\n",
			  max_value, strerror(errno));
		rmdir(new_cg);
		goto out;
	}

	/* memory.high and memory.swap.max are best-effort.  A kernel that
	 * doesn't expose memory.swap.max (swap accounting disabled) is fine
	 * — memory.max alone is the load-bearing safety net. */
	if (!write_cg_file(new_cg, "memory.high", high_value))
		output(1, "self-cgroup: write memory.high=%s failed: %s\n",
		       high_value, strerror(errno));
	if (!write_cg_file(new_cg, "memory.swap.max", swap_value))
		output(1, "self-cgroup: write memory.swap.max=%s failed: %s\n",
		       swap_value, strerror(errno));

	n = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
	if (n < 0 || (size_t)n >= sizeof(pidbuf) ||
	    !write_cg_file(new_cg, "cgroup.procs", pidbuf)) {
		outputerr("self-cgroup: cgroup.procs write failed: %s; "
			  "running without memory cap\n", strerror(errno));
		rmdir(new_cg);
		goto out;
	}

	output(0, "self-cgroup: in %s/trinity-%d (memory.max=%s memory.high=%s memory.swap.max=%s)\n",
	       parent_cg, (int)getpid(), max_value, high_value, swap_value);
	self_cg_path = new_cg;
	new_cg = NULL;

out:
	free(parent_cg);
	free(new_cg);
	free(max_value);
	free(high_value);
	free(swap_value);
}

void self_cgroup_cleanup(void)
{
	if (self_cg_path == NULL)
		return;
	rmdir(self_cg_path);
	free(self_cg_path);
	self_cg_path = NULL;
}
