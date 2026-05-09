/*
 * pc_to_string(): render a captured code pointer as "binary+0xOFFSET".
 *
 * Trinity is built as a PIE, so raw absolute PCs printed via "%p" are
 * useless to addr2line without also knowing the random per-process load
 * base.  Resolving the PC down to a load-relative offset here lets the
 * operator paste the value straight into:
 *
 *     addr2line -e ./trinity 0xOFFSET
 *
 * and get a file:line back, regardless of which child process emitted
 * the diagnostic.
 */

#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "pc_format.h"

const char *pc_to_string(void *pc, char *buf, size_t buflen)
{
	Dl_info info;
	const char *base;

	if (buf == NULL || buflen == 0)
		return buf;

	if (dladdr(pc, &info) == 0 || info.dli_fname == NULL ||
	    info.dli_fbase == NULL) {
		snprintf(buf, buflen, "%p", pc);
		return buf;
	}

	base = strrchr(info.dli_fname, '/');
	base = (base != NULL) ? base + 1 : info.dli_fname;

	snprintf(buf, buflen, "%s+0x%lx", base,
		 (unsigned long)((uintptr_t)pc - (uintptr_t)info.dli_fbase));
	return buf;
}

/*
 * pc_to_source_line(): best-effort source-file:line resolution for a
 * captured PC by shelling out to addr2line(1).  Returns a pointer into
 * buf on success, NULL on any failure (no addr2line on PATH, dladdr
 * miss, fork/pipe error, addr2line unable to resolve).
 *
 * The PIE-relative offset fed to addr2line is computed exactly as
 * pc_to_string() does, so the rendered "binary+0xOFFSET" and the
 * resolved file:line refer to the same byte.  Uses fork+execlp rather
 * than popen() so the loaded-binary path never traverses a shell -- a
 * trinity invocation with a path containing shell metacharacters would
 * otherwise mis-quote.
 *
 * Exists because pc_to_string() can only render a load-relative
 * offset, and operators reading the per-PC ring dumps need file:line
 * to disambiguate LTO-inlined-helper PCs from the non-static symbols
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
	Dl_info info;
	char addr_arg[32];
	int pipefd[2];
	pid_t pid;
	ssize_t n;
	char *nl;

	if (buf == NULL || buflen == 0)
		return NULL;
	buf[0] = '\0';

	if (dladdr(pc, &info) == 0 || info.dli_fname == NULL ||
	    info.dli_fbase == NULL)
		return NULL;

	snprintf(addr_arg, sizeof(addr_arg), "0x%lx",
		 (unsigned long)((uintptr_t)pc - (uintptr_t)info.dli_fbase));

	if (pipe(pipefd) < 0)
		return NULL;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}

	if (pid == 0) {
		int devnull;

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
	waitpid(pid, NULL, 0);

	if (n <= 0)
		return NULL;
	buf[n] = '\0';

	nl = strchr(buf, '\n');
	if (nl != NULL)
		*nl = '\0';

	/* addr2line emits "??:0" or "??:?" when it can't resolve.  Treat
	 * those as misses so the dump falls back to the load-relative
	 * offset rather than printing a placeholder that looks like a
	 * real source coordinate. */
	if (buf[0] == '?' || buf[0] == '\0')
		return NULL;

	return buf;
}
