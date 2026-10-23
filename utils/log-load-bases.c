/*
 * Log the load bases of the trinity binary, libc, ld-linux and the vDSO at
 * startup, so post-mortem analysis can map raw IPs (bug logs, FAULT! lines,
 * oops reports naming userspace addresses) back to function+offset without a
 * live /proc/<pid>/maps: ASLR reshuffles a PIE layout every run, and the
 * process is long gone by the time a crash report is read.
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
		trinity_load_base = addr;
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

/*
 * Load base of the main executable, latched by load_base_callback() so the
 * async-signal-safe crash paths can print it into the per-pid bug log: the
 * [load-bases] line reaches only the parent's stderr, and a bug log shipped
 * on its own would carry raw PCs with no way to resolve them.  A plain
 * unsigned long read is safe in a handler where dl_iterate_phdr() is not.
 * Zero until log_load_bases() runs, and zero for a non-PIE build --
 * consumers print it unconditionally, and 0x0 is the honest answer in
 * both cases (a non-PIE binary needs no adjustment).
 */
unsigned long trinity_load_base;

/*
 * Must run before fork_children(): the bases are stable for the process
 * lifetime and children share the same mappings COW, so the logged bases
 * hold for them.  Only objects loaded at the call are logged; a later
 * dlopen() (trinity does not do this) would not be.
 */
void log_load_bases(void)
{
	struct load_base_state st = { false };

	dl_iterate_phdr(load_base_callback, &st);
}
