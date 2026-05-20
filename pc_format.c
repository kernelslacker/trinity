/*
 * pc_to_string(): render a captured code pointer as "binary+0xOFFSET".
 *
 * The offset is computed against the dynamic linker's load bias
 * (link_map->l_addr), not against dli_fbase.  This matters because the
 * two diverge for EXEC binaries:
 *
 *   - For EXEC (non-PIE) builds, glibc's dladdr() sets dli_fbase to the
 *     first LOAD segment's mapping address (e.g. 0x400000 on x86-64),
 *     so (pc - dli_fbase) is a file-relative offset that addr2line
 *     CANNOT resolve -- addr2line wants the raw VMA for EXEC objects.
 *   - For PIE/DYN builds, l_addr == the random load base, so
 *     (pc - l_addr) == the link-time VMA, which is what addr2line wants
 *     for shared/PIE objects.
 *
 * Using link_map->l_addr makes the rendered offset addr2line-friendly
 * in both cases:
 *
 *     addr2line -e ./trinity 0xOFFSET
 *
 * Trinity currently builds as an EXEC binary (no -fPIE/-pie in the
 * Makefile), so l_addr is 0 and the rendered offset is the raw VMA;
 * the PIE path is kept correct so the same code works if/when the
 * build flips.
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pc_format.h"

/*
 * Resolve a PC to its containing object and that object's load bias.
 * Prefers dladdr1(RTLD_DL_LINKMAP) so we get link_map->l_addr (correct
 * for both EXEC and PIE/DYN); falls back to dli_fbase if the link_map
 * isn't available, which preserves prior behavior for PIE builds.
 * Returns 1 on success, 0 if the PC can't be attributed to an object.
 */
static int pc_resolve(void *pc, Dl_info *info, uintptr_t *bias)
{
	struct link_map *lm = NULL;

	if (dladdr1(pc, info, (void **)&lm, RTLD_DL_LINKMAP) == 0 ||
	    info->dli_fname == NULL)
		return 0;

	if (lm != NULL)
		*bias = (uintptr_t)lm->l_addr;
	else if (info->dli_fbase != NULL)
		*bias = (uintptr_t)info->dli_fbase;
	else
		return 0;
	return 1;
}

const char *pc_to_string(void *pc, char *buf, size_t buflen)
{
	Dl_info info;
	uintptr_t bias;
	const char *base;

	if (buf == NULL || buflen == 0)
		return buf;

	if (!pc_resolve(pc, &info, &bias)) {
		snprintf(buf, buflen, "%p", pc);
		return buf;
	}

	base = strrchr(info.dli_fname, '/');
	base = (base != NULL) ? base + 1 : info.dli_fname;

	snprintf(buf, buflen, "%s+0x%lx", base,
		 (unsigned long)((uintptr_t)pc - bias));
	return buf;
}

/*
 * pc_to_source_line(): best-effort source-file:line resolution for a
 * captured PC by shelling out to addr2line(1).  Returns a pointer into
 * buf on success, NULL on any failure (no addr2line on PATH, dladdr
 * miss, fork/pipe error, addr2line unable to resolve).
 *
 * The offset fed to addr2line is computed exactly as pc_to_string()
 * does (via link_map->l_addr), so the rendered "binary+0xOFFSET" and
 * the resolved file:line refer to the same byte for both EXEC and PIE
 * builds.  Uses fork+execlp rather than popen() so the loaded-binary
 * path never traverses a shell -- a trinity invocation with a path
 * containing shell metacharacters would otherwise mis-quote.
 *
 * Exists because pc_to_string() can only render an offset, and
 * operators reading the per-PC ring dumps need file:line to
 * disambiguate LTO-inlined-helper PCs from the non-static symbols
 * addr2line rounds DOWN to.  Without source coordinates a row whose
 * captured PC lives inside an inlined wrapper body appears under
 * whichever adjacent global symbol happens to precede it -- misleading
 * for triage, since the actual source site is in a different file
 * entirely.
 *
 * Cost: one fork+exec per resolved PC.  Acceptable for the periodic
 * defense-counter dump that consumes this -- not for hot paths.
 */
const char *pc_to_source_line(void *pc, char *buf, size_t buflen)
{
	static int resolver_disabled;
	Dl_info info;
	uintptr_t bias;
	char addr_arg[32];
	int pipefd[2];
	pid_t pid;
	int status;
	ssize_t n;
	char *nl;

	if (buf == NULL || buflen == 0)
		return NULL;
	buf[0] = '\0';

	/* Latched off after a prior abnormal exit -- see waitpid() below. */
	if (__atomic_load_n(&resolver_disabled, __ATOMIC_RELAXED))
		return NULL;

	if (!pc_resolve(pc, &info, &bias))
		return NULL;

	snprintf(addr_arg, sizeof(addr_arg), "0x%lx",
		 (unsigned long)((uintptr_t)pc - bias));

	if (pipe(pipefd) < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}

	if (pid == 0) {
		struct rlimit no_core = { 0, 0 };
		int devnull;

		/*
		 * Suppress core dumps from the helper.  GNU binutils
		 * addr2line has been observed to SEGV mid-DWARF-resolution
		 * on some installs (binutils version + binary's DWARF shape
		 * interaction); the parent already treats abnormal exit as
		 * a resolve miss via the n <= 0 read check below, but the
		 * kernel still drops a per-spawn core that says nothing
		 * about trinity itself and fills the spool with addr2line
		 * dumps -- one per top-N PC per periodic stats dump.
		 */
		(void)setrlimit(RLIMIT_CORE, &no_core);

		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);
		devnull = open("/dev/null", O_WRONLY);
		if (devnull >= 0) {
			dup2(devnull, STDERR_FILENO);
			close(devnull);
		}
		execlp("addr2line", "addr2line", "-e",
		       (char *)info.dli_fname, addr_arg, (char *)NULL);
		_exit(127);
	}

	close(pipefd[1]);
	n = read(pipefd[0], buf, buflen - 1);
	close(pipefd[0]);
	if (waitpid(pid, &status, 0) > 0 && WIFSIGNALED(status)) {
		/*
		 * addr2line died by signal (SEGV etc).  If binutils is
		 * broken on this binary, every subsequent invocation will
		 * hit the same wall -- latch the resolver off for the rest
		 * of the run rather than re-fork()ing per top-N PC across
		 * every periodic stats dump.  Resets naturally on parent
		 * restart.
		 */
		__atomic_store_n(&resolver_disabled, 1, __ATOMIC_RELAXED);
	}

	if (n <= 0)
		return NULL;
	buf[n] = '\0';

	nl = strchr(buf, '\n');
	if (nl != NULL)
		*nl = '\0';

	/* addr2line emits "??:0" or "??:?" when it can't resolve.  Treat
	 * those as misses so the dump falls back to the bare offset
	 * rather than printing a placeholder that looks like a real
	 * source coordinate. */
	if (buf[0] == '?' || buf[0] == '\0')
		return NULL;

	return buf;
}
