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
#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
