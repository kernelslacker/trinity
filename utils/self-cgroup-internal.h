#pragma once

/*
 * Private API shared between the utils/self_cgroup_*.c sibling files.
 * Not for use outside utils/self_cgroup*.  Public API lives in
 * include/self_cgroup.h.
 */

#include <stdbool.h>
#include <stdint.h>

/*
 * Read MemTotal from /proc/meminfo and return it as bytes.  Returns 0
 * on read failure -- callers treat that as "cannot determine host
 * memory" and abort setup.
 */
uint64_t mem_total_bytes(void);

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
		    bool *out_is_max);

/*
 * Read the cgroup v2 path of the calling process from /proc/self/cgroup.
 * The v2 line is the only one prefixed with "0::".  Returns a malloc'd
 * NUL-terminated path (e.g. "/user.slice/user-1000.slice/session-3.scope")
 * with the trailing newline stripped, or NULL if the file is unreadable
 * or no v2 line is present (e.g. pure cgroup v1 systems).
 */
char *read_self_cg_path(void);

/*
 * Write value into <cg_path>/<name>.  Returns true on full write, false
 * on any error (short write, open failure, path overflow); errno is
 * preserved across close() so callers can strerror(errno) the real
 * cgroup-write failure cause.
 */
bool write_cg_file(const char *cg_path, const char *name, const char *value);
