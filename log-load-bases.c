/*
 * Log the load bases of the trinity binary, libc, ld-linux, and the
 * vDSO at startup so post-mortem crash analysis can map raw IPs
 * (from bug logs, FAULT! lines, kernel-side oops reports referencing
 * userspace addresses) back to function+offset without needing
 * /proc/<pid>/maps from a live process.  Trinity is PIE; ASLR
 * reshuffles the layout each run, and by the time a crash report is
 * read the process is long gone.  The four objects covered here are
 * where almost every interesting IP in a trinity crash lands: trinity
 * code itself, libc helpers, the dynamic linker, and the vDSO clock
 * fast paths.
 *
 * Uses dl_iterate_phdr() rather than parsing /proc/self/maps -- the
 * callback hands us dlpi_addr (the PIE/DSO load base) and dlpi_name
 * (the on-disk path) directly, no string parsing required.  Glibc's
 * first callback is always the main executable, distinguished by
 * dlpi_name == "".
 *
 * Must run before fork_children() so the logged bases match what
 * children inherit via fork (the bases are stable for the process
 * lifetime; children share the same mappings COW).  Only enumerates
 * objects loaded at the call site -- a later dlopen() (trinity does
 * not currently do this) would not be logged.
 */

#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "trinity.h"
#include "utils.h"

struct load_base_state {
	bool main_logged;
};

static const char *basename_of(const char *path)
{
	const char *slash;

	if (path == NULL)
		return "";
	slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

static int load_base_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	struct load_base_state *st = data;
	const char *name = info->dlpi_name ? info->dlpi_name : "";
	const char *base = basename_of(name);
	unsigned long addr = (unsigned long)info->dlpi_addr;

	(void)size;

	/* Main executable: glibc's first dl_iterate_phdr callback hands
	 * back dlpi_name == "".  Guard with main_logged so a stray empty
	 * name later in the chain (unexpected, but cheap to defend
	 * against) cannot relabel a DSO as trinity. */
	if (!st->main_logged && name[0] == '\0') {
		outputerr("[load-bases] trinity: 0x%lx\n", addr);
		st->main_logged = true;
		return 0;
	}

	/* libc: glibc names it libc.so.6 on modern distros, libc-2.NN.so
	 * on older ones.  Match both prefixes. */
	if (strncmp(base, "libc.so", 7) == 0 ||
	    strncmp(base, "libc-", 5) == 0) {
		outputerr("[load-bases] libc: 0x%lx (%s)\n", addr, name);
		return 0;
	}

	/* Dynamic linker: ld-linux-x86-64.so.2, ld-linux-aarch64.so.1,
	 * ld-linux.so.2 on i386, ld-2.NN.so on pre-2.34 glibc, plus
	 * ld-musl-* for musl-libc builds. */
	if (strncmp(base, "ld-linux", 8) == 0 ||
	    strncmp(base, "ld-musl", 7) == 0 ||
	    strncmp(base, "ld-2.", 5) == 0) {
		outputerr("[load-bases] ld-linux: 0x%lx (%s)\n", addr, name);
		return 0;
	}

	/* vDSO: kernel-injected, no on-disk path.  Linux exports it as
	 * linux-vdso.so.1 on most arches; i386 historically used
	 * linux-gate.so.1. */
	if (strncmp(base, "linux-vdso", 10) == 0 ||
	    strncmp(base, "linux-gate", 10) == 0) {
		outputerr("[load-bases] vdso: 0x%lx\n", addr);
		return 0;
	}

	return 0;
}

void log_load_bases(void)
{
	struct load_base_state st = { false };

	dl_iterate_phdr(load_base_callback, &st);
}
